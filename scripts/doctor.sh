#!/usr/bin/env bash
# TraceForge 1.0.0 — scripts/doctor.sh
# Comprehensive Environment, Runtime, and Dependency Diagnostics

set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)

# Execute via primary runner
if [[ -x "$ROOT_DIR/run.sh" ]]; then
    exec "$ROOT_DIR/run.sh" doctor "$@"
elif command -v traceforge >/dev/null 2>&1; then
    exec traceforge doctor "$@"
else
    # Fallback to python in active environment
    PYTHON_BIN="python3"
    if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
        PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
    elif [[ -x "$ROOT_DIR/.osint_venv/bin/python" ]]; then
        PYTHON_BIN="$ROOT_DIR/.osint_venv/bin/python"
    fi
    exec "$PYTHON_BIN" -m traceforge.cli doctor "$@"
fi
