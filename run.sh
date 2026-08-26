#!/usr/bin/env bash
# TraceForge 1.0.0 — Thin Python CLI Launcher
# Automatically locates the active or project Python environment and forwards arguments.

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)

# 0. Initialize environment paths (bin, ~/.local/bin, go/bin, brew/bin)
# shellcheck disable=SC1091
if [[ -f "$ROOT_DIR/lib/platform.sh" ]]; then
    source "$ROOT_DIR/lib/platform.sh"
fi

# 1. Check if running inside an active virtualenv with TraceForge installed
if [[ -n "${VIRTUAL_ENV:-}" ]] && [[ -x "${VIRTUAL_ENV}/bin/python" ]]; then
    if "${VIRTUAL_ENV}/bin/python" -c 'import traceforge' 2>/dev/null; then
        exec "${VIRTUAL_ENV}/bin/python" -m traceforge "$@"
    fi
fi

# 2. Check local project .venv
if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    if "$ROOT_DIR/.venv/bin/python" -c 'import traceforge' 2>/dev/null; then
        exec "$ROOT_DIR/.venv/bin/python" -m traceforge "$@"
    fi
fi

# 2b. Check fallback .osint_venv
if [[ -x "$ROOT_DIR/.osint_venv/bin/python" ]]; then
    if "$ROOT_DIR/.osint_venv/bin/python" -c 'import traceforge' 2>/dev/null; then
        exec "$ROOT_DIR/.osint_venv/bin/python" -m traceforge "$@"
    fi
fi

# 3. Check if traceforge is directly available in PATH
if command -v traceforge >/dev/null 2>&1; then
    exec traceforge "$@"
fi

# 4. Check if standard python3 / python can import traceforge
for py_cand in python3 python; do
    if command -v "$py_cand" >/dev/null 2>&1; then
        if "$py_cand" -c 'import traceforge' 2>/dev/null; then
            exec "$py_cand" -m traceforge "$@"
        fi
    fi
done

# 5. If not found, provide a clean error and actionable instructions
cat << 'EOF' >&2
[ERROR] TraceForge is not installed or configured in this environment.

TraceForge was trying to execute the Python CLI layer.
To set up TraceForge automatically, run:
    ./setup.sh

Or set up manually:
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e .

Then run:
    ./run.sh
    # or
    traceforge
EOF
exit 1
