#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — Module 03: Identity, Social & Username Intelligence
# Public account and handle correlation across open online sources.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"

USERNAME=""
SCAN_MODE=""
CASE_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            printf 'TraceForge Module 03 — Identity & Social Media Intelligence\n\nUsage:\n  %s <username-or-handle> [options]\n\nOptions:\n  --mode <quick|full>  Scan depth profile (default: quick)\n  --quick              Execute quick triage scan\n  --deep, --full       Execute full deep scan (all 12 catalog domain tools)\n  --case-id <id>       Attach to case ID\n  --help, -h           Show this help message\n' "$0"
            exit 0
            ;;
        --mode)
            SCAN_MODE="$2"
            shift 2
            ;;
        --quick)
            SCAN_MODE="quick"
            shift
            ;;
        --deep|--full)
            SCAN_MODE="full"
            shift
            ;;
        --case-id)
            CASE_ID="$2"
            shift 2
            ;;
        *)
            if [[ -z "$USERNAME" ]]; then
                USERNAME="$1"
            elif [[ "$1" == CASE-* || "$1" == case_* ]]; then
                CASE_ID="$1"
            elif [[ -z "$SCAN_MODE" && ( "$1" == "quick" || "$1" == "full" || "$1" == "deep" ) ]]; then
                SCAN_MODE="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$USERNAME" || "$USERNAME" == -* ]]; then
    printf 'Usage: %s <username-or-handle> [--mode <quick|full>] [--case-id <id>]\n' "$0" >&2
    exit 1
fi


SCAN_MODE="$(prompt_scan_mode "quick" "$SCAN_MODE")"
SCAN_MODE_UPPER="$(echo "$SCAN_MODE" | tr '[:lower:]' '[:upper:]')"
CLEAN_USER="$(printf '%s' "$USERNAME" | tr -cd '[:alnum:]._-')"
if [[ -z "$CLEAN_USER" ]]; then
    die "Invalid username input supplied."
fi

RUN_DIR="$(make_run_dir "$ROOT_DIR" "identity_${CLEAN_USER}")"
REPORT="$RUN_DIR/report.txt"

info "Initiating Identity & Social Intelligence ($SCAN_MODE_UPPER SCAN) on: $CLEAN_USER"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Identity & Social Media Intelligence Report\n'
    printf '===============================================================================\n'
    printf 'Target Handle : %s\n' "$CLEAN_USER"
    printf 'Scan Depth    : %s SCAN\n' "$SCAN_MODE_UPPER"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"


# 1. Sherlock Enumeration
if need_cmd sherlock; then
    run_spinner_cmd "Querying social media sites (Sherlock)" "$RUN_DIR/sherlock.txt" sherlock --timeout 15 --print-found "$CLEAN_USER"
    {
        echo '[1] SOCIAL MEDIA ACCOUNTS (Sherlock)'
        grep -v '\[\*\]' "$RUN_DIR/sherlock.txt" || echo 'No active profiles detected.'
        echo
    } >> "$REPORT"
else
    echo 'Sherlock is not installed.' > "$RUN_DIR/sherlock.txt"
    log_skip "Sherlock not installed."
fi

# 2. Maigret Dossier Builder
if need_cmd maigret; then
    run_spinner_cmd "Building identity dossier (Maigret)" "$RUN_DIR/maigret.txt" maigret --timeout 15 "$CLEAN_USER" --txt
    {
        echo '[2] IDENTITY DOSSIER (Maigret)'
        head -n 40 "$RUN_DIR/maigret.txt"
        echo
    } >> "$REPORT"
else
    echo 'Maigret is not installed.' > "$RUN_DIR/maigret.txt"
    log_skip "Maigret not installed."
fi

# 3. Blackbird Search
if need_cmd blackbird; then
    run_spinner_cmd "Searching username accounts (Blackbird)" "$RUN_DIR/blackbird.txt" blackbird -u "$CLEAN_USER"
    {
        echo '[3] ONLINE PLATFORMS (Blackbird)'
        grep -E '\[\+\]' "$RUN_DIR/blackbird.txt" || echo 'No additional platforms found.'
        echo
    } >> "$REPORT"
else
    echo 'Blackbird is not installed.' > "$RUN_DIR/blackbird.txt"
    log_skip "Blackbird not installed."
fi

# 4. Socialscan Availability
if need_cmd socialscan; then
    run_spinner_cmd "Checking handle availability (Socialscan)" "$RUN_DIR/socialscan.txt" socialscan "$CLEAN_USER"
    {
        echo '[4] ACCOUNT AVAILABILITY (Socialscan)'
        cat "$RUN_DIR/socialscan.txt"
        echo
    } >> "$REPORT"
else
    echo 'Socialscan is not installed.' > "$RUN_DIR/socialscan.txt"
    log_skip "Socialscan not installed."
fi

# =============================================================================
# EXTENDED DEEP SCAN CAPABILITIES (FULL SCAN MODE)
# =============================================================================
if [[ "$SCAN_MODE" == "full" ]]; then
    # 5. SpiderFoot OSINT Automation
    if need_cmd spiderfoot; then
        run_spinner_cmd "Automating footprint correlation (SpiderFoot)" "$RUN_DIR/spiderfoot.txt" spiderfoot -s "$CLEAN_USER" -t "USERNAME" -q
        {
            echo '[5] FOOTPRINT CORRELATION (SpiderFoot)'
            cat "$RUN_DIR/spiderfoot.txt"
            echo
        } >> "$REPORT"
    else
        log_skip "SpiderFoot not installed."
    fi

    # 6. Sn0int OSINT Framework
    if need_cmd sn0int; then
        run_spinner_cmd "Querying semi-autonomous recon (sn0int)" "$RUN_DIR/sn0int.txt" sn0int run -t "$CLEAN_USER"
        {
            echo '[6] SEMI-AUTONOMOUS RECON (sn0int)'
            cat "$RUN_DIR/sn0int.txt"
            echo
        } >> "$REPORT"
    fi

    # 7. Recon-ng Web Reconnaissance
    if need_cmd recon-cli; then
        run_spinner_cmd "Running Recon-ng analytics (recon-cli)" "$RUN_DIR/recon_ng.txt" recon-cli -C "workspaces create tf; modules load recon/profiles-profiles/namechk; options set SOURCE $CLEAN_USER; run; exit"
        {
            echo '[7] RECON-NG DISCOVERY'
            cat "$RUN_DIR/recon_ng.txt"
            echo
        } >> "$REPORT"
    fi
fi

# Extract and aggregate discovered URLs
{
    echo '[DISCOVERED PROFILE URLS]'
    grep -Eho 'https?://[^[:space:]"'\''<>]+' "$RUN_DIR"/*.txt 2>/dev/null \
        | sed -e 's/[),.;]$//' -e 's/\x1b\[[0-9;]*m//g' \
        | grep -v 'github.com/sherlock-project' \
        | grep -v 'github.com/soxoj/maigret' \
        | grep -v 'github.com/p1ngul1n0/blackbird' \
        | sort -u || true
    echo
} > "$RUN_DIR/aggregated_profiles.txt"

{
    cat "$RUN_DIR/aggregated_profiles.txt"
    printf 'Unique Discovered URLs: %s\n' "$(wc -l < "$RUN_DIR/aggregated_profiles.txt" | tr -d ' ')"
    printf 'Analysis Completed    : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} >> "$REPORT"

# Finalize multi-format reporting (TXT, MD, HTML, JSON, IOCs, Manifest)
finalize_module_run "03_identity_social" "Identity & Social Media Intelligence" "$CLEAN_USER" "$SCAN_MODE" "$RUN_DIR"

