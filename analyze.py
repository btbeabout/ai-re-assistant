import json
import os
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

GLUE_SYMBOLS = (
    "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable",
    "__cxa_finalize", "__gmon_start__",
)

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


def ask_llm(code, current_name):
    system = (
        "You are a reverse-engineering assistant. You are given decompiled C "
        "output from Ghidra. Respond with ONLY a JSON object, no prose, no "
        'markdown fences, of the form: '
        '{"name": "<snake_case_identifier>", "summary": "<one paragraph>"}'
    )
    user = f"Function currently named {current_name}:\n\n{code}"
    payload = {
        "model": MODEL,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    r = requests.post(LLM_URL, json=payload, timeout=180)
    r.raise_for_status()
    content = r.json()["choices"][0]["message"]["content"]
    return json.loads(content)


def annotate(program):
    decomp = DecompInterface()
    decomp.openProgram(program)

    fm = program.getFunctionManager()
    all_funcs = list(fm.getFunctions(True))
    functions = [f for f in all_funcs if is_worth_analyzing(f)]
    
    skipped = len(all_funcs) - len(functions)
    print(f"[*] {len(functions)} functions to analyze, "
          f"{skipped} skipped as already-named/boilerplate")
    
    functions = order_functions(functions)
    print("[*] Order (callees first): "
          + " -> ".join(str(f.getName()) for f in functions))

    results = []
    with pyghidra.transaction(program):
        for fn in functions:
            code = decompile(fn, decomp)
            if not code:
                continue
            try:
                if any(sym in code for sym in GLUE_SYMBOLS):
                    print(f"[-] skipping runtime glue: {fn.getName()}")
                    continue
                ai = ask_llm(code, fn.getName())
            except Exception as e:
                print(f"[!] {fn.getName()}: {e}")
                continue

            old = fn.getName()
            fn.setComment(ai["summary"])
            try:
                fn.setName(ai["name"], SourceType.USER_DEFINED)
            except Exception:
                pass  # DuplicateNameException etc.

            results.append({
                "address":  str(fn.getEntryPoint()),
                "old_name": old,
                "new_name": ai["name"],
                "summary":  ai["summary"],
            })
            print(f"[+] {old} -> {ai['name']}")
    return results


def program_exists(project, name):
    try:
        return project.getProjectData().getRootFolder().getFile(name) is not None
    except Exception:
        return False


def main(binary_path):
    binary_path = os.path.abspath(binary_path)
    prog_name   = os.path.basename(binary_path)
    in_project  = "/" + prog_name
    os.makedirs(PROJECT_DIR, exist_ok=True)

    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=True) as project:

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
            results = annotate(program)
            program.save("AI annotations", pyghidra.task_monitor())

    os.makedirs("results", exist_ok=True)
    with open("results/results.json", "w") as f:
        json.dump(results, f, indent=2)

    with open("results/results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] Saved {len(results)} annotations to the project and results.json")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze.py <binary_path>")
        sys.exit(1)
    main(sys.argv[1])