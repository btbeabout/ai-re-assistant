# ai-re-assistant

A headless PyGhidra tool that uses a locally-hosted LLM to recover function
names and summaries from stripped binaries, writing the results back into a
persistent Ghidra project.

## How it works

For each binary, the tool decompiles every function to pseudo-C, then filters
out functions not worth a model call (thunks, external imports, already-named
and ELF-structural functions). The remaining functions are ordered
callees-before-callers via a post-order traversal of the call graph, so that by
the time any function is analyzed, everything it calls has already been
recovered. Each function's prompt is then enriched with the already-recovered
summaries of its callees and the string literals it references, and sent to a
locally-hosted model through an OpenAI-compatible chat endpoint. The model
returns a suggested snake_case name and a one-paragraph summary, both written
back into a persistent Ghidra project as a rename and a plate comment -- so
reopening the binary in the Ghidra GUI shows the recovered names and summaries
inline, and later functions benefit from the recovered meaning of earlier ones.

## Features

- Recovers function names and summaries from stripped binaries via a local LLM.
- Persists results into a reopenable Ghidra project (renames + plate comments).
- Skips functions that don't need a model call: thunks, external imports,
  already-named functions (whether named by Ghidra or a prior AI pass), and
  ELF-structural functions, so inference isn't spent on library and startup
  scaffolding.
- Processes functions callees-before-callers (call-graph post-order, tolerant
  of recursion) so recovered names and summaries propagate deterministically
  instead of depending on address layout.
- Enriches each function's prompt with its callees' recovered summaries and its
  referenced string literals, letting the model reason over a function's whole
  subtree rather than in isolation.

## Prerequisites

The only pip-installable dependencies are in requirements.txt. The dependencies
that actually make this work are system-level and must be installed separately:

- A Linux environment. Built and tested on Ubuntu 26.04 LTS in a VirtualBox VM.
- JDK 25 (64-bit). Required by Ghidra 12.1.x.
- Ghidra 12.1.x, with GHIDRA_INSTALL_DIR (or the hardcoded path in the scripts)
  pointing at the install.
- A C/C++ build toolchain: build-essential and python3-dev. PyGhidra depends on
  JPype1, which compiles from source on recent Python versions and fails
  without a compiler and the Python headers.
- A locally-hosted LLM exposing an OpenAI-compatible /v1/chat/completions
  endpoint. Built with Ollama serving qwen2.5-coder:14b.

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

3. Start the LLM server on the host. With Ollama, bind it so the VM can reach
   it, then pull the model:

        export OLLAMA_HOST=0.0.0.0     # then restart the ollama service
        ollama pull qwen2.5-coder:14b

   Note the address at which the guest reaches the host (e.g. 192.168.56.1 over
   a VirtualBox host-only network) and confirm connectivity from the guest:

        curl http://192.168.56.1:11434/v1/models

4. Python environment:

        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt

5. Configure the scripts. Edit the two constants at the top of analyze.py and
   dryrun.py to match your setup:

        LLM_URL = "http://192.168.56.1:11434/v1/chat/completions"
        MODEL   = "qwen2.5-coder:14b"

   The scripts call pyghidra.start(install_dir="/opt/ghidra"); change that path
   if Ghidra is installed elsewhere.

## Usage

Create a stripped test binary to analyze:

        cat > /tmp/test.c << 'END'
        #include <stdio.h>
        int add(int a, int b) { return a + b; }
        int main() { printf("%d\n", add(2, 3)); return 0; }
        END
        gcc -o testbin /tmp/test.c
        strip testbin

Run the single-function smoke test first. It prints the raw model response so
you can confirm the full pipeline -- JVM start, analysis, decompilation, the
network call, and parsing -- end to end:

        python dryrun.py

Then run the full pass over every function in a binary:

        python analyze.py testbin

On first run this imports and analyzes the binary (slower), annotates every
function, saves the results into a Ghidra project under ~/lab/projects/, and
writes results/results.json. Re-running reuses the existing analysis.

To see the annotations, open the ai-re project in the Ghidra GUI and open the
binary; recovered names and summaries appear in the decompiler. The Ghidra GUI
must be closed while the script runs, since a project cannot be open in both at
once.

## Security and isolation

Inference runs on a separate host, reached over a host-only network, so the
analysis environment has a path to the model but no route to the internet or
the wider LAN. The tool operates only on static decompiler output; it never
executes the binary. Samples and Ghidra projects are kept outside the
repository and excluded by .gitignore.

## Evaluation

The tool ships with an evaluation harness (ground_truth.py + eval.py) that
measures naming quality against ground truth recovered from an unstripped copy
of the binary (same Ghidra address frame as analysis, so the join is exact).

It reports three scorers side by side, by design rather than redundancy:

- Lexical (name vs name): token-set overlap. A deliberately weak baseline --
  it scores semantically-correct names like verify -> check_password as misses,
  which motivates the judges.
- Judge, name vs name: a separate model (gemma3:12b, not the model that wrote
  the names, to blunt self-preference bias) rates whether two names mean the
  same thing.
- Judge, name vs code: the same judge rates whether a recovered name fits the
  function's actual decompiled behavior -- which also lets it score
  conventional names like main that have no behavioral label to match.

### Known limitation: the judge is not yet trustworthy

Cross-referencing the three scorers surfaced two failure modes in the behavior
judge, both well-documented in the LLM-as-a-judge literature:

- Trivial-function shortcut: empty compiler-glue stubs are scored "match" on
  the reasoning "name irrelevant", rewarding meaningless names.
- Reason/verdict contradiction: a function whose rationale confirms the name
  fits is nonetheless labelled "miss" -- sound reasoning mapped to the wrong
  verdict.

The single-shot semantic numbers are therefore reported but not yet relied on.
The three-scorer layout is itself the mitigation: disagreement between scorers
is how these defects became visible instead of silently inflating a headline
number. Planned work: self-consistency (repeat each judgment and report
agreement, so unstable verdicts are flagged) and a triviality guard for
empty/boilerplate functions.

## Status

Working: full analysis pipeline -- decompile, filter, call-graph ordering,
context enrichment, structured output, persisted annotations -- plus an
evaluation harness with lexical and LLM-judge scorers.

Roadmap:
1. [done] Boilerplate filtering.
2. [done] Call-graph-ordered analysis.
3. [done] Context enrichment (callee summaries + referenced strings).
4. [done] Evaluation harness (lexical + name-judge + behavior-judge scorers).

Next:
- Judge reliability: self-consistency across repeated judgments; triviality
  guard; optionally feed the judge function summaries as well as code.
- Robust JSON parsing in analyze.py for models that wrap output in fences.
- Smart context assembly: prioritize/truncate callee+string context before it
  overflows the model's context window on large binaries.
- Scale evaluation to a corpus of many binaries (current N is illustrative).
- Optional agentic/MCP fork for interactive, tool-driven investigation.