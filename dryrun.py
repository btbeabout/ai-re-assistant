import os, json, requests, pyghidra

pyghidra.start(install_dir="/opt/ghidra")
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

LLM_URL = "http://192.168.56.1:11434/v1/chat/completions"
MODEL   = "qwen2.5-coder:14b"
BINARY  = os.path.expanduser("~/Desktop/AI-Malware-RE/lab/samples/testbin")

with pyghidra.open_program(BINARY) as flat_api:
    program = flat_api.getCurrentProgram()
    decomp = DecompInterface()
    decomp.openProgram(program)

    fm = program.getFunctionManager()
    funcs = [f for f in fm.getFunctions(True)
             if not f.isThunk() and not f.isExternal()]
    print(f"\n[*] Found {len(funcs)} functions: {[f.getName() for f in funcs]}\n")

    fn = funcs[0]
    res = decomp.decompileFunction(fn, 60, ConsoleTaskMonitor())
    code = res.getDecompiledFunction().getC()
    print("----- DECOMPILED -----")
    print(code)

    payload = {
        "model": MODEL, "temperature": 0.1,
        "messages": [
            {"role": "system", "content":
             'Reverse-engineering assistant. Given decompiled C, reply ONLY '
             'with JSON: {"name": "<snake_case>", "summary": "<one sentence>"}'},
            {"role": "user", "content": code},
        ],
    }
    r = requests.post(LLM_URL, json=payload, timeout=180)
    content = r.json()["choices"][0]["message"]["content"]
    print("----- RAW LLM RESPONSE -----")
    print(repr(content))                    # repr() shows fences/whitespace
    print("----- PARSED -----")
    print(json.loads(content))