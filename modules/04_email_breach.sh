#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — Module 04: Email, Breach & Leak Intelligence
# Lawful email reputation, breach exposure, and passive domain contact triage.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"

TARGET_EMAIL=${1:-""}

if [[ "$TARGET_EMAIL" == "--help" || "$TARGET_EMAIL" == "-h" ]]; then
    printf 'TraceForge Module 04 — Email & Breach Exposure Triage\n\nUsage:\n  %s <target-email-address>\n' "$0"
    exit 0
fi

if [[ -z "$TARGET_EMAIL" || "$TARGET_EMAIL" == -* || "$TARGET_EMAIL" != *"@"*"."* ]]; then
    printf 'Usage: %s <target-email-address (user@domain.tld)>\n' "$0" >&2
    exit 1
fi


# Basic email syntax sanity check
if [[ "$TARGET_EMAIL" != *"@"*"."* ]]; then
    warn "The supplied input '$TARGET_EMAIL' does not match standard email structure (user@domain.tld)."
fi

EMAIL_USER="${TARGET_EMAIL%%@*}"
EMAIL_DOMAIN="${TARGET_EMAIL#*@}"

RUN_DIR="$(make_run_dir "$ROOT_DIR" "email_${EMAIL_USER}")"
REPORT="$RUN_DIR/report.txt"

info "Initiating Email & Breach Intelligence triage on: $TARGET_EMAIL"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Email & Breach Exposure Report\n'
    printf '===============================================================================\n'
    printf 'Target Email  : %s\n' "$TARGET_EMAIL"
    printf 'Domain        : %s\n' "$EMAIL_DOMAIN"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. Holehe Account Registration Check
step "Checking account registrations via Holehe..."
if need_cmd holehe; then
    holehe "$TARGET_EMAIL" --only-used > "$RUN_DIR/holehe_registered.txt" 2>&1 || true
    holehe "$TARGET_EMAIL" > "$RUN_DIR/holehe_full.txt" 2>&1 || true
    {
        echo '[1] REGISTERED ONLINE SERVICES (Holehe)'
        grep -E '\[\+\]' "$RUN_DIR/holehe_registered.txt" || echo 'No active registered accounts identified on supported sites.'
        echo
    } >> "$REPORT"
else
    echo 'Holehe is not installed.' > "$RUN_DIR/holehe_registered.txt"
fi

# 2. h8mail Breach & Leak Audit
step "Querying breach intelligence via h8mail..."
if need_cmd h8mail; then
    h8mail -t "$TARGET_EMAIL" -c "$RUN_DIR/h8mail_out.csv" > "$RUN_DIR/h8mail.txt" 2>&1 || true
    {
        echo '[2] BREACH INTELLIGENCE (h8mail)'
        cat "$RUN_DIR/h8mail.txt" || echo 'No breach records found.'
        echo
    } >> "$REPORT"
else
    echo 'h8mail is not installed.' > "$RUN_DIR/h8mail.txt"
fi

# 3. EmailRep Reputation & Delivery Signals
step "Querying EmailRep reputation signals..."
if need_cmd emailrep; then
    emailrep "$TARGET_EMAIL" > "$RUN_DIR/emailrep.json" 2>&1 || true
    {
        echo '[3] EMAIL REPUTATION SIGNALS (EmailRep)'
        if need_cmd jq && [[ -s "$RUN_DIR/emailrep.json" ]]; then
            jq . "$RUN_DIR/emailrep.json" 2>/dev/null || cat "$RUN_DIR/emailrep.json"
        else
            cat "$RUN_DIR/emailrep.json"
        fi
        echo
    } >> "$REPORT"
else
    echo 'EmailRep CLI is not installed.' > "$RUN_DIR/emailrep.json"
fi

# 4. theHarvester Passive Domain Enumeration
step "Querying theHarvester for passive organizational contacts on $EMAIL_DOMAIN..."
if need_cmd theHarvester; then
    theHarvester -d "$EMAIL_DOMAIN" -b duckduckgo,crtsh,certspotter,rapiddns,yahoo -l 100 \
        > "$RUN_DIR/theharvester.txt" 2>&1 || true
    {
        echo '[4] PASSIVE DOMAIN CONTACTS (theHarvester)'
        grep -A 20 -i 'emails found' "$RUN_DIR/theharvester.txt" || echo 'No additional domain emails enumerated.'
        echo
    } >> "$REPORT"
else
    echo 'theHarvester is not installed.' > "$RUN_DIR/theharvester.txt"
fi

# 5. GHunt Google Account Triage
if need_cmd ghunt; then
    step "Running GHunt Google account triage..."
    ghunt email "$TARGET_EMAIL" > "$RUN_DIR/ghunt.txt" 2>&1 || true
fi

printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

find "$RUN_DIR" -maxdepth 2 -type f | sort > "$RUN_DIR/manifest.txt"

info "Email & Breach triage completed successfully."
info "Full report written to: $REPORT"
