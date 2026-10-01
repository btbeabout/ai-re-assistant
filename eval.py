import collections
import json
import re
import sys
import requests

LLM_URL     = "http://192.168.56.1:11434/v1/chat/completions"
JUDGE_MODEL = "gemma3:12b"   # different model than wrote the names

N_JUDGE    = 5     # repeat each LLM judgment this many times
JUDGE_TEMP = 0.7   # raised on purpose: probe the verdict's decision boundary

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


def _ask_judge(system, user, temperature):
    payload = {
        "model": JUDGE_MODEL, "temperature": temperature,
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


def judge_names(truth_name, rec_name, temperature):
    system = (
        "You evaluate whether two function names describe the same function. "
        "One is the original, the other was recovered by a tool from a stripped "
        "binary. Allow synonyms and differing detail. Respond with ONLY a JSON "
        'object, no prose, no fences: {"verdict": "match|partial|miss", '
        '"reason": "<short phrase>"}. match = same purpose; partial = related '
        "but meaningfully different; miss = unrelated."
    )
    return _ask_judge(system, f'Original name: "{truth_name}"\n'
                              f'Recovered name: "{rec_name}"', temperature)


def judge_behavior(rec_name, truth_code, temperature):
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
                              f'Decompiled function:\n{truth_code}', temperature)


def judge_consistent(judge_fn, *args):
    """Call a judge N_JUDGE times at JUDGE_TEMP; return the majority verdict,
    its vote count, the full distribution, and a representative reason."""
    verdicts, reasons = [], {}
    for _ in range(N_JUDGE):
        v, reason = judge_fn(*args, JUDGE_TEMP)
        verdicts.append(v)
        reasons.setdefault(v, reason)
    dist = collections.Counter(verdicts)
    majority, top = dist.most_common(1)[0]
    return majority, top, dist, reasons.get(majority, "")


def rate(counts):
    scored = sum(counts[k] for k in ("match", "partial", "miss"))
    hit = counts["match"] + counts["partial"]
    pct = f"{100 * hit / scored:.0f}%" if scored else "n/a"
    return (f"{hit}/{scored} = {pct}  ({counts['match']} match, "
            f"{counts['partial']} partial, {counts['miss']} miss)")


def tally(counts, verdict):
    if verdict in counts:
        counts[verdict] += 1


def fmt_dist(dist):
    order = ["match", "partial", "miss", "error", "?"]
    seen = [f"{dist[k]} {k}" for k in order if dist.get(k)]
    seen += [f"{c} {k}" for k, c in dist.items() if k not in order and c]
    return ", ".join(seen)


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
    rows, name_agr, beh_agr, unstable = [], [], [], []

    to_score = [(a, truth[a]) for a in sorted(truth) if a in recovered]
    print(f"[*] Judging {len(to_score)} functions with {JUDGE_MODEL}, "
          f"{N_JUDGE}x each at temp {JUDGE_TEMP}...\n")

    for addr, entry in to_score:
        real, code, rec = entry["name"], entry.get("code", ""), recovered[addr]

        if real in CONVENTIONAL:
            lv, nv, ntop = "—", "—", None
        else:
            lv = lexical_verdict(real, rec); tally(lex, lv)
            nv, ntop, ndist, _ = judge_consistent(judge_names, real, rec)
            tally(name, nv); name_agr.append(ntop / N_JUDGE)
            if ntop / N_JUDGE < 0.6:
                unstable.append((real, "name", nv, ndist))

        if code.strip():
            bv, btop, bdist, _ = judge_consistent(judge_behavior, rec, code)
            tally(beh, bv); beh_agr.append(btop / N_JUDGE)
            if btop / N_JUDGE < 0.6:
                unstable.append((real, "behavior", bv, bdist))
        else:
            bv, btop = "no-code", None

        rows.append((real, rec, lv, nv, ntop, bv, btop))

    print(f"{'GROUND TRUTH':<20}{'RECOVERED':<26}{'LEX':<7}"
          f"{'NAME (agr)':<15}{'BEHAV (agr)':<15}")
    for real, rec, lv, nv, ntop, bv, btop in rows:
        ncell = nv if ntop is None else f"{nv} {ntop}/{N_JUDGE}"
        bcell = bv if btop is None else f"{bv} {btop}/{N_JUDGE}"
        print(f"{real:<20}{rec:<26}{lv:<7}{ncell:<15}{bcell:<15}")
    print()

    avg = lambda xs: f"   avg agreement {sum(xs)/len(xs):.2f}" if xs else ""
    print(f"Lexical (name vs name):   {rate(lex)}")
    print(f"Judge   (name vs name):   {rate(name)}{avg(name_agr)}")
    print(f"Judge   (name vs CODE):   {rate(beh)}{avg(beh_agr)}")

    if unstable:
        print(f"\nLow-confidence verdicts (self-agreement < 0.6 — the judge "
              f"could not decide; do not trust these):")
        for real, which, maj, dist in unstable:
            print(f"  {real} [{which}]: majority '{maj}', but split — "
                  f"{fmt_dist(dist)}")

    missing = len(truth) - len(to_score)
    if missing:
        print(f"\n({missing} functions not attempted — skipped as "
              f"already-named/boilerplate)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python eval.py <truth.json> <results.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])