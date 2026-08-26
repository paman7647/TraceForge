#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# TraceForge — scripts/export_case.sh
# Standalone CLI bridge for exporting forensic cases to reports and datasets.

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/case.sh
source "$ROOT_DIR/lib/case.sh"
# shellcheck source=lib/export.sh
source "$ROOT_DIR/lib/export.sh"

usage() {
    cat << 'EOF'
TraceForge — Case Export Utility

Usage:
  ./scripts/export_case.sh <case-id> [options]

Options:
  --all                 Generate all export formats (default)
  --format <fmt>        Export specific format: markdown|html|pdf|csv|xlsx|docx|stix|misp|geo|timesketch
  --redact              Mask sensitive IPs and emails in generated outputs
  --package <zip|tar.gz> Bundle outputs into a compressed archive with SHA-256 digests
  --help, -h            Show this help message
EOF
    exit 0
}

if [[ $# -eq 0 ]]; then
    usage
fi

CASE_ID=""
FORMAT="all"
REDACT="false"
PACKAGE_FMT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            FORMAT="all"
            shift
            ;;
        --format)
            FORMAT="${2:-all}"
            shift 2
            ;;
        --redact)
            REDACT="true"
            shift
            ;;
        --package)
            PACKAGE_FMT="${2:-zip}"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            if [[ -z "$CASE_ID" ]]; then
                CASE_ID="$1"
                shift
            else
                log_err "Unknown argument: $1"
                usage
            fi
            ;;
    esac
done

if [[ -z "$CASE_ID" ]]; then
    log_err "Case ID is required."
    exit 1
fi

case_export "$CASE_ID" "$FORMAT" "$REDACT" "" ""

if [[ -n "$PACKAGE_FMT" ]]; then
    case_package_archive "$CASE_ID" "$PACKAGE_FMT"
fi
