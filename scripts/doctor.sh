#!/usr/bin/env bash
# TraceForge 1.0.0 — scripts/doctor.sh
# Comprehensive Environment, Runtime, and Dependency Diagnostics

set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)

# shellcheck source=lib/doctor.sh
source "$ROOT_DIR/lib/doctor.sh"

run_system_diagnostics "$@"
