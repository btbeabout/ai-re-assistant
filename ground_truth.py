import json
import sys
import pyghidra

pyghidra.start(install_dir="/opt/ghidra")


def main(binary_path, out_path):
    truth = {}
    with pyghidra.open_program(binary_path) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        for fn in fm.getFunctions(True):
            if fn.isThunk() or fn.isExternal():
                continue
            name = str(fn.getName())
            if name.startswith("FUN_"):
                continue  # shouldn't happen in an unstripped binary; guard anyway
            truth[str(fn.getEntryPoint())] = name
    with open(out_path, "w") as f:
        json.dump(truth, f, indent=2)
    print(f"[*] Wrote {len(truth)} ground-truth names to {out_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python ground_truth.py <unstripped_binary> <out.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])