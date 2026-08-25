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

## 3. Running Automated Tests

```bash
# Run Python & Platform test suites
python3 -m unittest discover -s tests

# Run master shell & regression test suite
./tests/test.sh

# Run pre-flight release audit
./scripts/release_check.sh beta
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
