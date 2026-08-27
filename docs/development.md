# Development & Building

Guide for developers working on the TraceForge codebase, building Go native helpers, running test suites, and compiling documentation.

---

## 1. Setting Up Development Environment

```bash
# 1. Clone repository
git clone https://github.com/paman7647/TraceForge.git
cd TraceForge

# 2. Set up Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install in editable mode with development dependencies
pip install -e .
pip install -r docs/requirements.txt
```

---

## 2. Building the Go Native Fast-Path Helpers

TraceForge includes high-throughput Go utilities under `go/`:

```bash
# Compile traceforge-native into bin/
mkdir -p bin
cd go
go build -trimpath -ldflags="-s -w" -o ../bin/traceforge-native .
cd ..
```

---

## 3. Running Diagnostics & Validation

```bash
# Run environment and runtime diagnostics
traceforge doctor

# Audit catalog integrity and toolchain depth
traceforge tools audit --integration

# Validate shell syntax across all scripts
for script in setup.sh run.sh install_all.sh main.sh lib/*.sh modules/*.sh scripts/*.sh; do
  bash -n "$script"
done
```


---

## 4. Building Read the Docs Documentation Locally

To test and build the Sphinx documentation locally:

```bash
# Build HTML documentation
python3 -m sphinx -b html docs build/docs

# Open in browser
open build/docs/index.html   # macOS
xdg-open build/docs/index.html  # Linux
```
