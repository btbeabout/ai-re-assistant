import json
import os
import re
import sys
import requests
import pyghidra

pyghidra.start(install_dir="/opt/ghidra")

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor
from ghidra.program.model.symbol import SourceType

LLM_URL      = "http://192.168.56.1:11434/v1/chat/completions"
MODEL        = "qwen2.5-coder:14b"
PROJECT_DIR  = os.path.expanduser("~/Desktop/AI-Malware-RE/lab/projects")
PROJECT_NAME = "ai-re"

MAX_CALLEES              = 8     # cap how many callee summaries to inject
MAX_CALLEE_SUMMARY_CHARS = 160   # inject ~first sentence, not the whole paragraph
MAX_STRINGS              = 12    # cap injected strings
MAX_STRING_CHARS         = 120   # truncate any single oversized string
MAX_CODE_CHARS           = 6000  # truncate very long decompiled bodies
MAX_PROFILE_IMPORTS      = 30
MAX_PROFILE_STRINGS      = 25
MAX_PROFILE_STRING_CHARS = 80
TIMEOUT_BASE             = 120   # seconds; adaptive timeout floor
TIMEOUT_PER_1K           = 20    # +N seconds per 1000 prompt chars
TIMEOUT_MAX              = 360   # ceiling

REASK_ON_COLLISION = True   # False = fall straight to address suffix (A/B baseline)

GLUE_SYMBOLS = (
    "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable",
    "__cxa_finalize", "__gmon_start__",
)

def _first_sentence(text, limit):
    text = text.strip()
    dot = text.find(". ")
    if 0 < dot < limit:
        return text[:dot + 1]
    return text[:limit].rstrip() + ("…" if len(text) > limit else "")


def _budget_callees(callee_ctx):
    kept = [(name, _first_sentence(summary, MAX_CALLEE_SUMMARY_CHARS))
            for name, summary in callee_ctx[:MAX_CALLEES]]
    return kept, len(callee_ctx) - len(kept)


def _budget_strings(strings):
    uniq = list(dict.fromkeys(strings))             # dedupe, keep order
    ranked = sorted(uniq, key=len, reverse=True)    # longer == more distinctive
    kept = [s[:MAX_STRING_CHARS] for s in ranked[:MAX_STRINGS]]
    return kept, len(uniq) - len(kept)


def _budget_code(code):
    if len(code) <= MAX_CODE_CHARS:
        return code, False
    head = int(MAX_CODE_CHARS * 0.7)                # keep signature + early logic
    tail = MAX_CODE_CHARS - head                    # and how it returns
    return (code[:head] + "\n/* ... decompilation truncated ... */\n"
            + code[-tail:]), True

def summarize_program(profile, results, user_context=""):
    """Whole-program purpose synthesis from recovered summaries + profile. With
    analyst context, reports whether the evidence supports/contradicts it."""
    informative = [r for r in results
                   if not r["new_name"].startswith("fun_")
                   and r["summary"].strip()]
    if not informative:
        return None

    lines = ["Recovered functions (name: summary):"]
    for r in informative:
        s = r["summary"].strip()
        dot = s.find(". ")
        if 0 < dot < 200:
            s = s[:dot + 1]
        lines.append(f"- {r['new_name']}: {s[:200]}")
    functions_block = "\n".join(lines)

    system = (
        "You are a reverse-engineering assistant. Given a binary's profile and "
        "the recovered names and summaries of its functions, infer what the "
        "program IS and does overall. Base the answer ONLY on the evidence "
        "given; if it's ambiguous, say so rather than guessing."
    )
    if user_context:
        system += (
            " The analyst believes the following about this binary (ANALYST "
            "CONTEXT). State whether the recovered evidence SUPPORTS, PARTIALLY "
            "supports, or CONTRADICTS that belief, and why — do not simply echo "
            "it back."
        )
    system += (
        ' Respond with ONLY a JSON object, no prose, no fences: {"purpose": '
        '"<one or two sentences on what this binary is and does>", "category": '
        '"<short label e.g. compression tool, network client, credential '
        'stealer>", "confidence": "<high|medium|low>", '
        '"matches_analyst_context": "<supports|partial|contradicts|n/a>"}'
    )

    user = ""
    if user_context:
        user += f"=== ANALYST CONTEXT ===\n{user_context}\n\n"
    if profile:
        user += f"=== Binary profile ===\n{profile}\n\n"
    user += functions_block

    payload = {
        "model": MODEL, "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    timeout_s = min(TIMEOUT_MAX,
                    TIMEOUT_BASE + (len(user) // 1000) * TIMEOUT_PER_1K)
    try:
        r = requests.post(LLM_URL, json=payload, timeout=timeout_s)
        r.raise_for_status()
        return parse_json_lenient(r.json()["choices"][0]["message"]["content"])
    except Exception as e:
        print(f"[!] program summary failed: {e}")
        return None

def binary_profile(program):
    """Compact whole-program context from metadata Ghidra: format,
    imports, and notable strings. Gives every per-function prompt a shared sense
    of what kind of program this is, so a function isn't named in a vacuum."""
    lines = []

    try:
        lines.append(f"Format: {program.getExecutableFormat()}, "
                     f"{program.getLanguageID()}")
    except Exception:
        pass

    # Imported library functions: diagnostic for some binaries (network/crypto
    # APIs reveal purpose); mostly libc for self-contained tools.
    imports = []
    try:
        for f in program.getFunctionManager().getExternalFunctions():
            imports.append(str(f.getName()))
    except Exception:
        pass
    imports = sorted(set(imports))
    if imports:
        shown = imports[:MAX_PROFILE_IMPORTS]
        more = f" (+{len(imports) - len(shown)} more)" if len(imports) > len(shown) else ""
        lines.append("Imported functions: " + ", ".join(shown) + more)

    # Notable strings program-wide.
    strings = []
    try:
        listing = program.getListing()
        for data in listing.getDefinedData(True):   # all defined data, forward
            if data.hasStringValue():
                s = str(data.getValue()).strip()
                if len(s) >= 4:
                    strings.append(s)
    except Exception as e:
        print(f"    [!] profile strings failed: {e}")
    strings = list(dict.fromkeys(strings))
    strings = sorted(strings, key=len, reverse=True)[:MAX_PROFILE_STRINGS]
    if strings:
        shown = [s[:MAX_PROFILE_STRING_CHARS] for s in strings]
        lines.append("Notable strings: " + " | ".join(f'"{s}"' for s in shown))

    return "\n".join(lines)

def parse_json_lenient(text):
    """Extract the first {...} JSON object from a model response, tolerating
    markdown fences or prose preamble around it."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError(f"no JSON object in response: {text[:80]!r}")
    return json.loads(m.group(0))

def referenced_strings(program, fn):
    """Strings referenced from within this function's body."""
    strings, seen = [], set()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    for instr in listing.getInstructions(fn.getBody(), True):
        for ref in ref_mgr.getReferencesFrom(instr.getAddress()):
            data = listing.getDataAt(ref.getToAddress())
            if data is not None and data.hasStringValue():
                s = str(data.getValue())
                if s not in seen:
                    seen.add(s)
                    strings.append(s)
    return strings

def order_functions(functions):
    """Order functions callees-before-callers (bottom-up post-order DFS).
    Tolerant of recursion and mutual recursion via back-edge detection."""
    # Key everything by entry-point address — a stable identity across the
    # Python/Java boundary, safer than relying on Java object hashing.
    by_addr = {str(f.getEntryPoint()): f for f in functions}

    # Dependency edges, restricted to the target set. A callee that isn't in
    # the set is already named, so it imposes no ordering constraint.
    deps = {}
    for addr, fn in by_addr.items():
        called = fn.getCalledFunctions(TaskMonitor.DUMMY)
        deps[addr] = {str(c.getEntryPoint()) for c in called
                      if str(c.getEntryPoint()) in by_addr
                      and str(c.getEntryPoint()) != addr}   # ignore self-recursion

    ordered, visited, on_stack = [], set(), set()

    def visit(addr):
        if addr in visited or addr in on_stack:
            return                       # done, or a cycle back-edge: skip
        on_stack.add(addr)
        for dep in deps[addr]:
            visit(dep)                   # callees first
        on_stack.discard(addr)
        visited.add(addr)
        ordered.append(by_addr[addr])    # then this function

    for addr in by_addr:
        visit(addr)
    return ordered

def is_worth_analyzing(fn):
    if fn.isThunk() or fn.isExternal():
        return False
    # Only Ghidra's default FUN_<addr> names are unidentified. Anything
    # already named — by Ghidra (entry, _DT_INIT) or a prior AI pass —
    # we skip, so we never spend a model call re-describing known code.
    if not str(fn.getName()).startswith("FUN_"):
        return False
    return True

def decompile(function, decomp):
    res = decomp.decompileFunction(function, 60, ConsoleTaskMonitor())
    if res.decompileCompleted():
        return res.getDecompiledFunction().getC()
    return None


def ask_llm(code, current_name, callee_ctx, strings, profile="",
            user_context="", retries=1, avoid_name=None):
    base_system = (
        "You are a reverse-engineering assistant. You are given decompiled C "
        "output from Ghidra, context about the functions it calls and the "
        "strings it references, and a profile of the whole binary. Use ALL of "
        "it — the program's overall purpose constrains what each function is "
        "likely doing. Respond with ONLY a JSON object, no prose, no markdown "
        'fences, of the form: {"name": "<snake_case_identifier>", '
        '"summary": "<one paragraph>"}'
    )
    if user_context:
        base_system += (
            " The analyst has provided context about this binary (below, under "
            "ANALYST CONTEXT). Treat it as a HYPOTHESIS to verify against the "
            "code, NOT as fact: if the code supports it, name the function by "
            "its specific role in that context; if the code does NOT support "
            "it, name the function by what the code actually does and do not "
            "force the hypothesis onto it."
        )
    if avoid_name:
        base_system += (
            f' NOTE: the name "{avoid_name}" is already used by another function '
            "and is too generic. Give a DISTINCT, more specific name that "
            "captures what makes THIS function different from others doing "
            "similar work — name it by its specific role, data, or algorithm."
        )

    parts = []
    if user_context:
        parts.append("=== ANALYST CONTEXT (hypothesis to verify) ===")
        parts.append(user_context)
        parts.append("=== End analyst context ===")
        parts.append("")
    if profile:
        parts.append("=== Binary context (whole program) ===")
        parts.append(profile)
        parts.append("=== End binary context ===")
        parts.append("")
    if callee_ctx:
        parts.append("Functions this one calls (already analyzed):")
        for name, summary in callee_ctx:
            parts.append(f"- {name}: {summary}")
        parts.append("")
    if strings:
        parts.append("String literals referenced by this function:")
        for s in strings:
            parts.append(f'  - "{s}"')
        parts.append("")
    parts.append(f"Decompiled function (currently named {current_name}):")
    parts.append("")
    parts.append(code)
    user = "\n".join(parts)

    timeout_s = min(TIMEOUT_MAX,
                    TIMEOUT_BASE + (len(user) // 1000) * TIMEOUT_PER_1K)

    last_err = None
    for attempt in range(retries + 1):
        system, temperature = base_system, 0.1
        if attempt > 0:
            system = base_system + (" Output ONLY the JSON object, nothing "
                                    "before or after it.")
            temperature = 0.4
            print(f"    [~] retrying {current_name} (bad format)")
        payload = {
            "model": MODEL, "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            r = requests.post(LLM_URL, json=payload, timeout=timeout_s)
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            obj = parse_json_lenient(content)
            if "name" not in obj or "summary" not in obj:
                raise ValueError(f"missing keys: {obj!r}")
            return obj
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            last_err = e
            continue
    raise last_err

def annotate(program, user_context=""):
    decomp = DecompInterface()
    decomp.openProgram(program)

    fm = program.getFunctionManager()
    functions = [f for f in fm.getFunctions(True) if is_worth_analyzing(f)]
    all_funcs = list(fm.getFunctions(True))
    skipped = len(all_funcs) - len(functions)
    print(f"[*] {len(functions)} functions to analyze, "
          f"{skipped} skipped as already-named/boilerplate")

    functions = order_functions(functions)
    print("[*] Order (callees first): "
          + " -> ".join(str(f.getName()) for f in functions))

    profile = binary_profile(program)
    if profile:
        print("[*] Binary profile:\n" + profile + "\n")
    if user_context:
        print(f"[*] Analyst context (hypothesis): {user_context}\n")

    recovered = {}
    results = []
    used_names = set()

    with pyghidra.transaction(program):
        for fn in functions:
            code = decompile(fn, decomp)
            if not code:
                continue

            raw_callees = []
            for callee in fn.getCalledFunctions(TaskMonitor.DUMMY):
                rec = recovered.get(str(callee.getEntryPoint()))
                if rec:
                    raw_callees.append((rec["name"], rec["summary"]))
            raw_strings = referenced_strings(program, fn)

            callee_ctx, dropped_c = _budget_callees(raw_callees)
            strings,    dropped_s = _budget_strings(raw_strings)
            code_sent,  code_cut  = _budget_code(code)

            try:
                ai = ask_llm(code_sent, fn.getName(), callee_ctx, strings,
                             profile=profile, user_context=user_context)
            except Exception as e:
                print(f"[!] {fn.getName()}: {e}")
                continue

            old = fn.getName()
            name = ai["name"]
            reasked = False
            baseline_name = None

            if name in used_names:
                if REASK_ON_COLLISION:
                    baseline_name = name
                    print(f"    [~] '{name}' taken — re-asking for a specific name")
                    try:
                        ai = ask_llm(code_sent, fn.getName(), callee_ctx, strings,
                                     profile=profile, user_context=user_context,
                                     avoid_name=name)
                        name = ai["name"]
                        reasked = True
                    except Exception as e:
                        print(f"    [!] re-ask failed for {old}: {e}")
                if name in used_names:
                    name = f"{name}_{fn.getEntryPoint()}"
                    print(f"    [~] still colliding — using {name}")

            used_names.add(name)

            fn.setComment(ai["summary"])
            try:
                fn.setName(name, SourceType.USER_DEFINED)
            except Exception as e:
                print(f"    [!] rename failed for {old} -> {name}: {e}")
                name = old

            recovered[str(fn.getEntryPoint())] = {
                "name": name, "summary": ai["summary"]}
            results.append({
                "address":       str(fn.getEntryPoint()),
                "old_name":      old,
                "new_name":      name,
                "summary":       ai["summary"],
                "reasked":       reasked,
                "baseline_name": baseline_name,
            })

            sent = []
            if callee_ctx: sent.append(f"{len(callee_ctx)} callees")
            if strings:    sent.append(f"{len(strings)} strings")
            trims = []
            if dropped_c:  trims.append(f"-{dropped_c} callees")
            if dropped_s:  trims.append(f"-{dropped_s} strings")
            if code_cut:   trims.append("code cut")
            tag = ("  sent " + ", ".join(sent)) if sent else ""
            if reasked:    tag += "  [re-asked]"
            if trims:      tag += "  [budget " + ", ".join(trims) + "]"
            print(f"[+] {old} -> {name}{tag}")

    return results

def delete_program(project, name):
    """Remove a program from the project so the next run re-imports it fresh."""
    try:
        df = project.getProjectData().getRootFolder().getFile(name)
        if df is not None:
            df.delete()
            print(f"[*] Deleted existing '{name}' from project (fresh run).")
            return True
    except Exception as e:
        print(f"[!] couldn't delete '{name}': {e}")
    return False

def program_exists(project, name):
    try:
        return project.getProjectData().getRootFolder().getFile(name) is not None
    except Exception:
        return False


def main(binary_path, fresh=False, user_context=""):
    binary_path = os.path.abspath(binary_path)
    prog_name   = os.path.basename(binary_path)
    in_project  = "/" + prog_name
    os.makedirs(PROJECT_DIR, exist_ok=True)

    results = []
    profile = ""

    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=True) as project:

        if fresh:
            delete_program(project, prog_name)

        if not program_exists(project, prog_name):
            print(f"[*] Importing and analyzing {prog_name} (first run)...")
            loader = (pyghidra.program_loader()
                      .project(project)
                      .source(binary_path)
                      .name(prog_name))
            load_results = loader.load()
            load_results.save(pyghidra.task_monitor())
            with pyghidra.program_context(project, in_project) as program:
                pyghidra.analyze(program, pyghidra.task_monitor())
                program.save("Initial analysis", pyghidra.task_monitor())
            load_results.release(load_results)
        else:
            print(f"[*] {prog_name} already in project — reusing analysis.")

        print("[*] Annotating...")
        with pyghidra.program_context(project, in_project) as program:
            results = annotate(program, user_context=user_context)
            profile = binary_profile(program)
            program.save("AI annotations", pyghidra.task_monitor())

    summary = summarize_program(profile, results, user_context=user_context)
    if summary:
        print("\n" + "=" * 60)
        print("PROGRAM PURPOSE")
        print(f"  Category:   {summary.get('category', '?')}")
        print(f"  Confidence: {summary.get('confidence', '?')}")
        if user_context:
            print(f"  vs context: {summary.get('matches_analyst_context', '?')}")
        print(f"  Purpose:    {summary.get('purpose', '?')}")
        print("=" * 60)

    os.makedirs("results", exist_ok=True)
    out = {"program_summary": summary, "functions": results}
    with open("results/results.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n[*] Saved {len(results)} annotations to the project and results.json")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AI-assisted RE: name functions and "
                                            "infer binary purpose from a stripped binary.")
    p.add_argument("binary", help="path to the binary to analyze")
    p.add_argument("--fresh", action="store_true",
                   help="re-import and re-analyze even if already in the project")
    p.add_argument("--context", default="",
                   help="analyst hypothesis about the binary, e.g. 'CTF reversing "
                        "challenge; find input that prints the flag'")
    a = p.parse_args()
    main(a.binary, fresh=a.fresh, user_context=a.context)