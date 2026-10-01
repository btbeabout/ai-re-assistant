import json
import re
import sys
import requests

LLM_URL     = "http://192.168.56.1:11434/v1/chat/completions"
JUDGE_MODEL = "gemma3:12b"   # different model than wrote the names

CONVENTIONAL = {"main", "_start", "start", "entry"}


def parse_json_lenient(text):
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError("no JSON object in response")
    return json.loads(m.group(0))


def normalize(name):
    return {t for t in name.lower().replace("-", "_").split("_") if t}


def lexical_verdict(truth_name, rec_name):
    t, r = normalize(truth_name), normalize(rec_name)
    if t == r:
        return "match"
    if t & r:
        return "partial"
    return "miss"


def _ask_judge(system, user):
    payload = {
        "model": JUDGE_MODEL, "temperature": 0.0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    try:
        r = requests.post(LLM_URL, json=payload, timeout=180)
        r.raise_for_status()
        obj = parse_json_lenient(r.json()["choices"][0]["message"]["content"])
        return obj.get("verdict", "?"), obj.get("reason", "")
    except Exception as e:
        return "error", str(e)[:50]


def judge_names(truth_name, rec_name):
    system = (
        "You evaluate whether two function names describe the same function. "
        "One is the original, the other was recovered by a tool from a stripped "
        "binary. Allow synonyms and differing detail. Respond with ONLY a JSON "
        'object, no prose, no fences: {"verdict": "match|partial|miss", '
        '"reason": "<short phrase>"}. match = same purpose; partial = related '
        "but meaningfully different; miss = unrelated."
    )
    return _ask_judge(system, f'Original name: "{truth_name}"\n'
                              f'Recovered name: "{rec_name}"')


def judge_behavior(rec_name, truth_code):
    system = (
        "You evaluate whether a function name accurately describes what a "
        "function does. You are given the decompiled C of a function (with "
        "meaningful names) and a candidate name a tool recovered for it from a "
        "stripped copy. Judge whether the candidate fits the actual behavior; a "
        "name more or less detailed than the original is fine if it fits. "
        'Respond with ONLY a JSON object, no prose, no fences: {"verdict": '
        '"match|partial|miss", "reason": "<short phrase>"}. match = fits the '
        "code; partial = related but misleading or too vague; miss = does not fit."
    )
    return _ask_judge(system, f'Candidate name: "{rec_name}"\n\n'
                              f'Decompiled function:\n{truth_code}')


def rate(counts):
    scored = sum(counts[k] for k in ("match", "partial", "miss"))
    hit = counts["match"] + counts["partial"]
    pct = f"{100 * hit / scored:.0f}%" if scored else "n/a"
    return (f"{hit}/{scored} = {pct}  ({counts['match']} match, "
            f"{counts['partial']} partial, {counts['miss']} miss)")


def tally(counts, verdict):
    if verdict in counts:
        counts[verdict] += 1


def main(truth_path, results_path):
    truth = json.load(open(truth_path))
    results = json.load(open(results_path))
    recovered = {r["address"]: r["new_name"] for r in results}

    sample = next(iter(truth.values()), {})
    if not isinstance(sample, dict) or "code" not in sample:
        print("[!] This truth file predates the behavior judge. Regenerate it:")
        print(f"    python ground_truth.py <unstripped_binary> {truth_path}")
        sys.exit(1)

    lex  = {"match": 0, "partial": 0, "miss": 0}
    name = {"match": 0, "partial": 0, "miss": 0}
    beh  = {"match": 0, "partial": 0, "miss": 0}
    rows = []

    to_score = [(a, truth[a]) for a in sorted(truth) if a in recovered]
    print(f"[*] Judging {len(to_score)} functions with {JUDGE_MODEL} "
          f"(name-based and behavior-based)...\n")

    for addr, entry in to_score:
        real, code, rec = entry["name"], entry.get("code", ""), recovered[addr]

        if real in CONVENTIONAL:                 # name scorers skip these
            lv = nv = "—"
            why = "name-excluded (conventional)"
        else:
            lv = lexical_verdict(real, rec); tally(lex, lv)
            nv, _ = judge_names(real, rec);  tally(name, nv)
            why = ""

        if code.strip():                         # behavior scorer runs on all
            bv, breason = judge_behavior(rec, code); tally(beh, bv)
            why = breason or why
        else:
            bv = "no-code"

        rows.append((real, rec, lv, nv, bv, why))

    print(f"{'GROUND TRUTH':<22}{'RECOVERED':<28}{'LEX':<7}{'NAME':<7}"
          f"{'BEHAV':<8}WHY (behavior judge)")
    for real, rec, lv, nv, bv, why in rows:
        print(f"{real:<22}{rec:<28}{lv:<7}{nv:<7}{bv:<8}{why[:38]}")
    print()
    print(f"Lexical (name vs name):   {rate(lex)}")
    print(f"Judge   (name vs name):   {rate(name)}")
    print(f"Judge   (name vs CODE):   {rate(beh)}")

    missing = len(truth) - len(to_score)
    if missing:
        print(f"\n({missing} ground-truth functions not attempted — skipped "
              f"as already-named/boilerplate)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python eval.py <truth.json> <results.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])