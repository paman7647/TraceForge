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

USERNAME=${1:-""}

if [[ -z "$USERNAME" ]]; then
    printf 'Usage: %s <username-or-handle>\n' "$0" >&2
    exit 1
fi

# Sanitize username handle (only safe alphanumeric, dot, underscore, hyphen)
CLEAN_USER="$(printf '%s' "$USERNAME" | tr -cd '[:alnum:]._-')"
if [[ -z "$CLEAN_USER" ]]; then
    die "Invalid username input supplied."
fi

RUN_DIR="$(make_run_dir "$ROOT_DIR" "identity_${CLEAN_USER}")"
REPORT="$RUN_DIR/report.txt"

info "Initiating Identity & Username correlation on: $CLEAN_USER"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Identity & Social Media Intelligence Report\n'
    printf '===============================================================================\n'
    printf 'Target Handle : %s\n' "$CLEAN_USER"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. Sherlock Enumeration
step "Querying Sherlock username engine..."
if need_cmd sherlock; then
    sherlock --timeout 15 --print-found "$CLEAN_USER" > "$RUN_DIR/sherlock.txt" 2>&1 || true
else
    echo 'Sherlock is not installed.' > "$RUN_DIR/sherlock.txt"
fi

# 2. Maigret Dossier Builder
step "Querying Maigret dossier builder..."
if need_cmd maigret; then
    maigret --timeout 15 "$CLEAN_USER" --txt > "$RUN_DIR/maigret.txt" 2>&1 || true
else
    echo 'Maigret is not installed.' > "$RUN_DIR/maigret.txt"
fi

# 3. Blackbird Search
step "Querying Blackbird account engine..."
if need_cmd blackbird; then
    blackbird -u "$CLEAN_USER" > "$RUN_DIR/blackbird.txt" 2>&1 || true
else
    echo 'Blackbird is not installed.' > "$RUN_DIR/blackbird.txt"
fi

# 4. Socialscan Availability
step "Querying Socialscan availability checker..."
if need_cmd socialscan; then
    socialscan "$CLEAN_USER" > "$RUN_DIR/socialscan.txt" 2>&1 || true
else
    echo 'Socialscan is not installed.' > "$RUN_DIR/socialscan.txt"
fi

# 5. Extract and aggregate discovered URLs
step "Aggregating discovered profile URLs..."
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

find "$RUN_DIR" -maxdepth 2 -type f | sort > "$RUN_DIR/manifest.txt"

info "Identity correlation completed successfully."
info "Full report written to: $REPORT"
