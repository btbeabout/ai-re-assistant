# ai-re-assistant

A headless PyGhidra tool that uses a locally-hosted LLM to recover function
names and summaries from stripped binaries, and to infer what the binary does
as a whole — writing the results back into a persistent Ghidra project. Runs
fully offline against a local model, with the analysis environment isolated from
the network.

## How it works

For each binary, the tool decompiles every function to pseudo-C, filters out
functions not worth a model call (thunks, external imports, already-named and
ELF-structural glue), and orders the rest callees-before-callers via a post-order
traversal of the call graph. Each function's prompt is enriched with three kinds
of context: a whole-program profile (format, imports, notable strings) so the
model knows what kind of program it is looking at; the already-recovered
summaries of the function's callees; and the string literals the function
references. The model returns a snake_case name and a one-paragraph summary, both
written back into a persistent Ghidra project as a rename and a plate comment, so
reopening the binary in the Ghidra GUI shows the recovered names and summaries
inline, and later functions benefit from the recovered meaning of earlier ones.

After every function is named, a final synthesis pass reads the recovered names
and summaries and infers the binary's overall purpose, category, and a confidence
level.

Because real binaries are large, prompt context is budgeted (callee count, string
count, and decompiled body are capped) and the request timeout scales with prompt
size, so big functions complete instead of timing out. Model output is parsed
leniently with a retry on malformed responses, and recovered names are
disambiguated — on a collision the model is re-asked for a more specific name,
with an address suffix as a last-resort fallback — so the Ghidra database and the
JSON report never disagree.

## Features

- Recovers function names and one-paragraph summaries from stripped binaries via
  a local LLM.
- Infers whole-program purpose/category/confidence from the recovered functions.
- Persists results into a reopenable Ghidra project (renames + plate comments).
- Whole-program context: injects a binary profile (format, imports, notable
  strings) into every prompt, so functions are named with knowledge of what the
  program is.
- Call-graph-ordered analysis so recovered names and summaries propagate
  deterministically rather than depending on address layout.
- Per-function enrichment with callee summaries and referenced strings.
- Skips functions that don't need a model call (thunks, imports, already-named,
  ELF glue).
- Context budgeting + adaptive timeout so full real-world binaries complete.
- Lenient parsing with retry on malformed model output.
- Unique-name guarantee via re-ask-on-collision, keeping the database, caller
  decompilation, and JSON report consistent.

## Validation

Developed and tested against real stripped binaries, not only toy examples. On a
stripped /usr/bin/gzip (67 non-library functions), the tool runs end to end with
no failures and:

- Recovers domain-aware names across the binary — e.g. huffman_tree_build,
  build_huffman_table, find_compression_match, decompress_huffman_data,
  process_and_compress_file — that a context-free pass does not produce.
- Correctly infers the whole-program purpose: category "compression tool",
  confidence "high", with a summary naming specific behaviors (in-place
  compress/decompress, force-overwrite, name/timestamp preservation, recursive
  operation). The binary's filename is deliberately excluded from the model's
  input, so this is inferred from code and strings, not from the name "gzip".

Known failure modes, documented rather than hidden:

- Whole-program context fixes domain *framing* but not specific-algorithm
  *identification*. Earlier runs misread an AVX/XOR CRC routine as "encryption";
  with compression context that misframing disappears, but the function is then
  described literally (e.g. "transform_data") rather than identified as a
  checksum. Recognizing a specific algorithm from its structure is beyond what
  whole-program context provides.
- Profile strings are ranked by length, which favors diagnostic text (usage
  strings, error messages) but can waste slots on license boilerplate;
  relevance-ranking is a pending refinement.
- Throughput ceiling on modest hardware (32 GB RAM, modest GPU): very large
  functions are slowest. Context budgeting keeps them within the timeout, but a
  smaller/faster model is the answer if the ceiling is hit.

## Prerequisites

The only pip-installable dependencies are in requirements.txt. The dependencies
that actually make this work are system-level and installed separately:

- A Linux environment. Built and tested on Ubuntu 26.04 LTS in a VirtualBox VM.
- JDK 25 (64-bit). Required by Ghidra 12.1.x.
- Ghidra 12.1.x, with the install path set in the scripts.
- A C/C++ build toolchain: build-essential and python3-dev (PyGhidra depends on
  JPype1, which compiles from source on recent Python versions).
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
   dryrun.py) to match your setup:

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
synthesizes the whole-program purpose, saves the results into a Ghidra project
under ~/lab/projects/, and writes results/results.json (a
{program_summary, functions} object). Re-running reuses the existing analysis.
The Ghidra GUI must be closed while the script runs, since a project cannot be
open in both at once.

To view the annotations, open the project in the Ghidra GUI and open the binary;
recovered names and summaries appear in the decompiler.

## Security and isolation

Inference runs on a separate host, reached over a host-only network, so the
analysis environment has a path to the model but no route to the internet or the
wider LAN. The tool operates only on static decompiler output; it never executes
the binary. Samples and Ghidra projects are kept outside the repository and
excluded by .gitignore.

## Evaluation experiment (archived)

An earlier evaluation harness (eval.py, ground_truth.py, eval_reask.py) measured
naming quality against ground truth from an unstripped copy of a binary, using
lexical and LLM-judge scorers with repeated judgments. It is archived, not part
of the active pipeline; the scripts remain for reference. Its value was the
findings, not an accuracy number: a single confident metric can be quietly wrong;
LLM-as-judge has systematic (not merely noisy) biases that cross-referencing
scorers exposed; and "more specific" is not the same as "more correct". The
robustness pieces first written for the harness — lenient JSON parsing and retry
— were ported into the main tool and remain in use.

## Status

Working, end to end and validated on real stripped binaries: decompile, filter,
call-graph ordering, whole-program context, per-function enrichment, context
budgeting, robust parsing, unique-name disambiguation, persisted annotations, and
whole-program purpose synthesis.

Roadmap:
1. [done] Boilerplate filtering.
2. [done] Call-graph-ordered analysis.
3. [done] Per-function context enrichment (callee summaries + referenced strings).
4. [archived] Evaluation harness — built, learned its limits, parked (see above).
5. [done] Robustness for real binaries: context budgeting, adaptive timeout,
   lenient parsing/retry, unique-name disambiguation.
6. [done] Whole-program context: binary profile injected into every prompt.
7. [done] Whole-program purpose synthesis.

Next (optional refinements, not load-bearing):
- Relevance-rank profile strings (prefer diagnostic text over boilerplate).
- Persist the program summary as a Ghidra comment, visible in the GUI.
- Smart context assembly: relevance-rank callees/strings before budgeting.
- Specific-algorithm identification (the documented CRC-recognition gap).
- Optional agentic/MCP fork for interactive, tool-driven investigation.
