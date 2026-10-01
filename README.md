# AI-assisted RE doodad

A headless PyGhidra tool that uses a locally-hosted LLM to recover function
names and summaries from stripped binaries, writing the results back into a
persistent Ghidra project.

## How it works

Ghidra decompiles each function to pseudo-C. That text is sent to a
locally-hosted model through an OpenAI-compatible chat endpoint, which returns
a suggested snake_case name and a one-paragraph summary. Both are written back
into a persistent Ghidra project as a rename and a plate comment, so reopening
the binary in the Ghidra GUI shows the recovered names and summaries inline.
Because renames persist, functions analyzed later benefit from the recovered
names of functions analyzed earlier.

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
writes results.json. Re-running reuses the existing analysis.

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

## Status

Working: decompile -> local model -> structured output -> persisted annotations.

Roadmap:
1. Boilerplate filtering -- skip libc/compiler glue instead of spending model
   calls on it.
2. Call-graph-ordered analysis -- process callees before callers so recovered
   names propagate.
3. Context enrichment -- feed each function its callees' recovered names and
   referenced strings.