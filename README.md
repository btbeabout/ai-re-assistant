# ai-re-assistant

A headless PyGhidra tool that uses a locally-hosted LLM to recover function
names and summaries from stripped binaries, writing the results back into a
persistent Ghidra project. Runs fully offline against a local model, with the
analysis environment isolated from the network.

## How it works

For each binary, the tool decompiles every function to pseudo-C, filters out
functions not worth a model call (thunks, external imports, already-named and
ELF-structural functions), and orders the rest callees-before-callers via a
post-order traversal of the call graph. Each function's prompt is enriched with
the already-recovered summaries of its callees and the string literals it
references, then sent to a locally-hosted model through an OpenAI-compatible
endpoint. The model returns a snake_case name and a one-paragraph summary, both
written back into a persistent Ghidra project as a rename and a plate comment --
so reopening the binary in the Ghidra GUI shows the recovered names and
summaries inline, and later functions benefit from the recovered meaning of
earlier ones.

Because real binaries are large, the prompt context is budgeted (callee count,
string count, and decompiled body are capped) and the request timeout scales
with prompt size, so big functions complete instead of timing out. Model output
is parsed leniently with a retry on malformed responses, and recovered names are
disambiguated so the Ghidra database and the JSON report never disagree.

## Features

- Recovers function names and summaries from stripped binaries via a local LLM.
- Persists results into a reopenable Ghidra project (renames + plate comments).
- Skips functions that don't need a model call: thunks, external imports,
  already-named functions, and ELF-structural glue.
- Processes functions callees-before-callers so recovered names and summaries
  propagate deterministically instead of depending on address layout.
- Enriches each function's prompt with its callees' recovered summaries and its
  referenced strings, so the model reasons over a function's subtree.
- Budgets prompt context (caps callees/strings, truncates oversized bodies) and
  scales the timeout to prompt size, so full real-world binaries complete.
- Parses model output leniently and retries once on malformed responses.
- Guarantees unique recovered names so the database, caller decompilation, and
  results.json stay consistent.
- Ships an evaluation harness (see Evaluation) with lexical and LLM-judge
  scorers.

## Validation

Developed and tested against real stripped binaries, not only toy examples. A
representative run analyzes a stripped /usr/bin/gzip (67 non-library functions)
end to end with no failures, recovering accurate names for much of the program:
file/archive handling, buffered I/O, the fcntl retry logic, and the
decompression core. Known failure modes observed on real binaries, documented
rather than hidden:

- Generic names for functions the model cannot distinguish from local context
  alone (e.g. several buffer-processing routines named process_data). Being
  addressed by re-asking the model for a more specific name on collision.
- Misreads that require whole-program context: an AVX/XOR checksum routine in a
  compression tool can read as "encryption" when judged in isolation. Motivates
  adding binary-level triage context and a whole-program purpose summary.
- Throughput ceiling on modest hardware (32 GB RAM, modest GPU): very large
  functions are the slowest; context budgeting keeps them within the timeout,
  but a smaller/faster model is the answer if the ceiling is hit.

## Prerequisites

The only pip-installable dependencies are in requirements.txt. The dependencies
that actually make this work are system-level and installed separately:

- A Linux environment. Built and tested on Ubuntu 26.04 LTS in a VirtualBox VM.
- JDK 25 (64-bit). Required by Ghidra 12.1.x.
- Ghidra 12.1.x, with the install path set in the scripts (GHIDRA_INSTALL_DIR
  or the hardcoded path).
- A C/C++ build toolchain: build-essential and python3-dev. PyGhidra depends on
  JPype1, which compiles from source on recent Python versions.
- A locally-hosted LLM exposing an OpenAI-compatible /v1/chat/completions
  endpoint. Built with Ollama serving qwen2.5-coder:14b for naming and
  gemma3:12b as the evaluation judge.

## Setup

1. System packages:

        sudo apt update
        sudo apt install build-essential python3-dev openjdk-25-jdk

2. Install Ghidra. Download a 12.1.x release, verify its SHA-256 against the
   release page, then extract and symlink a stable path:

        sudo unzip ghidra_*_PUBLIC_*.zip -d /opt/
        sudo ln -s /opt/ghidra_12.1.4_PUBLIC /opt/ghidra
        echo 'export GHIDRA_INSTALL_DIR=/opt/ghidra' >> ~/.bashrc
        source ~/.bashrc

   Launch /opt/ghidra/ghidraRun once to confirm it finds JDK 25 and starts.

3. Start the LLM server on the host so the VM can reach it, then pull the model:

        export OLLAMA_HOST=0.0.0.0     # then restart the ollama service
        ollama pull qwen2.5-coder:14b

   Confirm connectivity from the guest (host-only address shown):

        curl http://192.168.56.1:11434/v1/models

4. Python environment:

        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt

5. Configure the scripts. Edit the constants at the top of analyze.py (and
   dryrun.py / eval.py) to match your setup:

        LLM_URL = "http://192.168.56.1:11434/v1/chat/completions"
        MODEL   = "qwen2.5-coder:14b"

   The scripts call pyghidra.start(install_dir="/opt/ghidra"); change that path
   if Ghidra is installed elsewhere.

## Usage

Smoke test (single function, prints the raw model response to confirm the full
pipeline end to end):

        python dryrun.py

Full analysis over every function in a binary:

        python analyze.py <binary>

On first run this imports and analyzes the binary, annotates every function,
saves the results into a Ghidra project under ~/lab/projects/, and writes
results/results.json. Re-running reuses the existing analysis. The Ghidra GUI
must be closed while the script runs, since a project cannot be open in both at
once.

To view the annotations, open the project in the Ghidra GUI and open the binary;
recovered names and summaries appear in the decompiler.

## Evaluation

The harness (ground_truth.py + eval.py) measures naming quality against ground
truth recovered from an unstripped copy of the binary (same Ghidra address frame
as analysis, so the join is exact). It reports several scorers side by side, by
design rather than redundancy:

- Lexical (name vs name): token-set overlap. A deliberately weak baseline that
  scores semantically-correct names like verify -> check_password as misses,
  motivating the judges.
- LLM judge, name vs name: a separate model (gemma3:12b, not the model that
  wrote the names) rates whether two names mean the same thing.
- LLM judge, name vs code: rates whether a recovered name fits the function's
  actual decompiled behavior, which also scores conventional names like main.
- Self-consistency: each judgment is repeated and agreement reported, flagging
  low-agreement verdicts as untrustworthy.

Documented finding: the LLM judge is useful but not blindly trustworthy. Cross-
referencing scorers surfaced systematic (not merely noisy) judge errors -- e.g.
rewarding trivial empty functions, and scoring a good name a "miss" because the
password semantics it captures live in the caller, not the function being
judged. The harness's value is less a single accuracy number than this: it makes
such errors visible instead of letting a confident wrong number stand.

## Security and isolation

Inference runs on a separate host, reached over a host-only network, so the
analysis environment has a path to the model but no route to the internet or the
wider LAN. The tool operates only on static decompiler output; it never executes
the binary. Samples and Ghidra projects are kept outside the repository and
excluded by .gitignore.

## Status

Working: full analysis pipeline -- decompile, filter, call-graph ordering,
context enrichment, context budgeting, robust parsing, unique-name
disambiguation, and persisted annotations -- validated on real stripped
binaries, plus an evaluation harness with lexical and LLM-judge scorers.

Roadmap:
1. [done] Boilerplate filtering.
2. [done] Call-graph-ordered analysis.
3. [done] Context enrichment (callee summaries + referenced strings).
4. [done] Evaluation harness (lexical + LLM-judge, with self-consistency).
5. [done] Robustness for real binaries: context budgeting, adaptive timeout,
   lenient parsing/retry, unique-name disambiguation.

Next:
- Re-ask the model for a specific name on collision (address suffix as fallback)
  to fix generic/duplicated names at the root instead of masking them.
- Whole-program context: binary-level triage (strings, imports, file type) and a
  whole-program purpose summary, to fix context-starved misreads.
- Smart context assembly: relevance-rank callees/strings before budgeting,
  rather than first-N.
- Scale evaluation to a corpus of many binaries (current N is illustrative).
- Optional agentic/MCP fork for interactive, tool-driven investigation.
