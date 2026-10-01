import json
import sys


def normalize(name):
    return {t for t in name.lower().replace("-", "_").split("_") if t}


def verdict(truth_name, rec_name):
    t, r = normalize(truth_name), normalize(rec_name)
    if t == r:
        return "exact"
    if t & r:
        return "partial"
    return "miss"


def main(truth_path, results_path):
    truth = json.load(open(truth_path))
    results = json.load(open(results_path))
    recovered = {r["address"]: r["new_name"] for r in results}

    rows, counts = [], {"exact": 0, "partial": 0, "miss": 0}
    for addr, real in sorted(truth.items()):
        if addr not in recovered:
            continue  # tool didn't attempt it (skipped as already-named)
        v = verdict(real, recovered[addr])
        counts[v] += 1
        rows.append((addr, real, recovered[addr], v))

    print(f"{'ADDRESS':<12}{'GROUND TRUTH':<22}{'RECOVERED':<34}VERDICT")
    for addr, real, rec, v in rows:
        print(f"{addr:<12}{real:<22}{rec:<34}{v}")
    print()

    scored = sum(counts.values())
    if scored:
        hit = counts["exact"] + counts["partial"]
        print(f"Scored {scored}: {counts['exact']} exact, "
              f"{counts['partial']} partial, {counts['miss']} miss")
        print(f"Lexical hit rate: {hit}/{scored} = {100 * hit / scored:.0f}%")
    missing = len(truth) - scored
    if missing:
        print(f"({missing} ground-truth functions not attempted — skipped as "
              f"already-named/boilerplate)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python eval.py <truth.json> <results.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])