import json
import sys
from eval import judge_consistent, judge_behavior  # reuse existing judge

RANK = {"miss": 0, "partial": 1, "match": 2}


def main(truth_path, results_path):
    truth = json.load(open(truth_path))
    results = json.load(open(results_path))

    pairs = [r for r in results if r.get("reasked") and r.get("baseline_name")]
    if not pairs:
        print("No re-asked functions in results. Run analyze.py with "
              "REASK_ON_COLLISION=True first.")
        return

    print(f"[*] Comparing {len(pairs)} re-asked functions "
          f"(generic vs specific) against ground-truth code...\n")

    better = worse = same = 0
    print(f"{'GENERIC':<24}{'SPECIFIC':<30}{'BASE':<8}{'REASK':<8}MOVED")
    for r in pairs:
        entry = truth.get(r["address"])
        if not entry or not entry.get("code", "").strip():
            continue
        code = entry["code"]
        base_v, _, _, _ = judge_consistent(judge_behavior, r["baseline_name"], code)
        new_v,  _, _, _ = judge_consistent(judge_behavior, r["new_name"], code)
        d = RANK.get(new_v, 0) - RANK.get(base_v, 0)
        moved = "better ↑" if d > 0 else "worse ↓" if d < 0 else "same"
        if d > 0: better += 1
        elif d < 0: worse += 1
        else: same += 1
        print(f"{r['baseline_name']:<24}{r['new_name']:<30}"
              f"{base_v:<8}{new_v:<8}{moved}")

    print(f"\nRe-ask effect on {better + worse + same} functions: "
          f"{better} better, {same} same, {worse} worse")
    if worse > better:
        print("⚠ The re-ask made names WORSE on balance — specificity hurt here.")
    elif better > worse:
        print("✓ The re-ask improved names on balance.")
    else:
        print("~ No net effect — re-ask changed names without improving fit.")