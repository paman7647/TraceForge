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

TARGET_EMAIL=""
SCAN_MODE=""
CASE_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            printf 'TraceForge Module 04 — Email & Breach Exposure Triage\n\nUsage:\n  %s <target-email-address> [options]\n\nOptions:\n  --mode <quick|full>  Scan depth profile (default: quick)\n  --quick              Execute quick triage scan\n  --deep, --full       Execute full deep scan (all 15 catalog domain tools)\n  --case-id <id>       Attach to case ID\n  --help, -h           Show this help message\n' "$0"
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
            if [[ -z "$TARGET_EMAIL" ]]; then
                TARGET_EMAIL="$1"
            elif [[ "$1" == CASE-* || "$1" == case_* ]]; then
                CASE_ID="$1"
            elif [[ -z "$SCAN_MODE" && ( "$1" == "quick" || "$1" == "full" || "$1" == "deep" ) ]]; then
                SCAN_MODE="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$TARGET_EMAIL" || "$TARGET_EMAIL" != *"@"*"."* ]]; then
    printf 'Usage: %s <target-email-address (user@domain.tld)> [--mode <quick|full>] [--case-id <id>]\n' "$0" >&2
    exit 1
fi


SCAN_MODE="$(prompt_scan_mode "quick" "$SCAN_MODE")"
SCAN_MODE_UPPER="$(echo "$SCAN_MODE" | tr '[:lower:]' '[:upper:]')"
EMAIL_USER="${TARGET_EMAIL%%@*}"
EMAIL_DOMAIN="${TARGET_EMAIL#*@}"


RUN_DIR="$(make_run_dir "$ROOT_DIR" "email_${EMAIL_USER}")"
REPORT="$RUN_DIR/report.txt"

info "Initiating Email & Breach Intelligence ($SCAN_MODE_UPPER SCAN) on: $TARGET_EMAIL"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Email & Breach Exposure Report\n'
    printf '===============================================================================\n'
    printf 'Target Email  : %s\n' "$TARGET_EMAIL"
    printf 'Domain        : %s\n' "$EMAIL_DOMAIN"
    printf 'Scan Depth    : %s SCAN\n' "$SCAN_MODE_UPPER"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"


# 1. Holehe Account Registration Check
if need_cmd holehe; then
    run_spinner_cmd "Checking online service registrations (Holehe)" "$RUN_DIR/holehe_registered.txt" holehe "$TARGET_EMAIL" --only-used
    holehe "$TARGET_EMAIL" > "$RUN_DIR/holehe_full.txt" 2>&1 || true
    {
        echo '[1] REGISTERED ONLINE SERVICES (Holehe)'
        grep -E '\[\+\]' "$RUN_DIR/holehe_registered.txt" || echo 'No active registered accounts identified on supported sites.'
        echo
    } >> "$REPORT"
else
    echo 'Holehe is not installed.' > "$RUN_DIR/holehe_registered.txt"
    log_skip "Holehe not installed."
fi

# 2. h8mail Breach & Leak Audit
if need_cmd h8mail; then
    run_spinner_cmd "Auditing breach and leak intelligence (h8mail)" "$RUN_DIR/h8mail_raw.txt" h8mail -t "$TARGET_EMAIL" -c "$RUN_DIR/h8mail_out.csv"
    grep -Ev '(ROCKSMASSON|h8mail posts|github\.com|___|\| \!|Use responsibly|Heartfelt Email)' "$RUN_DIR/h8mail_raw.txt" > "$RUN_DIR/h8mail.txt" 2>/dev/null || cp "$RUN_DIR/h8mail_raw.txt" "$RUN_DIR/h8mail.txt"
    {
        echo '[2] BREACH INTELLIGENCE (h8mail)'
        cat "$RUN_DIR/h8mail.txt"
        echo
    } >> "$REPORT"
else
    echo 'h8mail is not installed.' > "$RUN_DIR/h8mail.txt"
    log_skip "h8mail not installed."
fi

# 3. EmailRep Reputation & Delivery Signals
if need_cmd emailrep; then
    run_spinner_cmd "Querying email reputation signals (EmailRep)" "$RUN_DIR/emailrep.json" emailrep "$TARGET_EMAIL"
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
    log_skip "EmailRep CLI not installed."
fi

# 4. theHarvester Passive Domain Enumeration
if need_cmd theHarvester; then
    run_spinner_cmd "Enumerating domain contacts (theHarvester)" "$RUN_DIR/theharvester.txt" theHarvester -d "$EMAIL_DOMAIN" -b duckduckgo,crtsh,certspotter,rapiddns,yahoo -l 100
    {
        echo '[4] PASSIVE DOMAIN CONTACTS (theHarvester)'
        grep -A 20 -i 'emails found' "$RUN_DIR/theharvester.txt" || echo 'No additional domain emails enumerated.'
        echo
    } >> "$REPORT"
else
    echo 'theHarvester is not installed.' > "$RUN_DIR/theharvester.txt"
    log_skip "theHarvester not installed."
fi

# 5. GHunt Google Account Triage
if need_cmd ghunt; then
    run_spinner_cmd "Extracting Google account intelligence (GHunt)" "$RUN_DIR/ghunt.txt" ghunt email "$TARGET_EMAIL"
    {
        echo '[5] GOOGLE ACCOUNT INTELLIGENCE (GHunt)'
        cat "$RUN_DIR/ghunt.txt"
        echo
    } >> "$REPORT"
fi

# =============================================================================
# EXTENDED DEEP SCAN CAPABILITIES (FULL SCAN MODE)
# =============================================================================
if [[ "$SCAN_MODE" == "full" ]]; then
    # 6. Domain Email Security Posture via checkdmarc
    if need_cmd checkdmarc; then
        run_spinner_cmd "Evaluating DMARC/SPF policy (checkdmarc)" "$RUN_DIR/checkdmarc.json" checkdmarc "$EMAIL_DOMAIN"
        {
            echo '[6] DOMAIN AUTHENTICATION & SPOOF DEFENSES (checkdmarc)'
            if need_cmd jq && [[ -s "$RUN_DIR/checkdmarc.json" ]]; then
                jq . "$RUN_DIR/checkdmarc.json" 2>/dev/null || cat "$RUN_DIR/checkdmarc.json"
            else
                cat "$RUN_DIR/checkdmarc.json"
            fi
            echo
        } >> "$REPORT"
    else
        log_skip "checkdmarc not installed."
    fi

    # 7. HaveIBeenPwned & Pastebin Triage via pwnedornot
    if need_cmd pwnedornot; then
        run_spinner_cmd "Auditing HIBP pastebins & breaches (pwnedornot)" "$RUN_DIR/pwnedornot.txt" pwnedornot -e "$TARGET_EMAIL"
        {
            echo '[7] PASTEBIN & BREACH EXPOSURES (pwnedornot)'
            cat "$RUN_DIR/pwnedornot.txt"
            echo
        } >> "$REPORT"
    fi

    # 8. Corporate & LinkedIn Handle Search via CrossLinked
    if need_cmd crosslinked; then
        run_spinner_cmd "Enumerating corporate email permutations (CrossLinked)" "$RUN_DIR/crosslinked.txt" crosslinked -f '{first}.{last}@'"$EMAIL_DOMAIN" "$EMAIL_DOMAIN"
        {
            echo '[8] CORPORATE EMAIL ENUMERATION (CrossLinked)'
            cat "$RUN_DIR/crosslinked.txt"
            echo
        } >> "$REPORT"
    fi

    # 9. Intelligence X OSINT Search via intelx
    if need_cmd intelx; then
        run_spinner_cmd "Querying Intelligence X archives (intelx)" "$RUN_DIR/intelx.txt" intelx search "$TARGET_EMAIL"
        {
            echo '[9] INTELLIGENCE X ARCHIVES (intelx)'
            cat "$RUN_DIR/intelx.txt"
            echo
        } >> "$REPORT"
    fi
fi

printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

# Finalize multi-format reporting (TXT, MD, HTML, JSON, IOCs, Manifest)
finalize_module_run "04_email_breach" "Email & Breach Intelligence" "$TARGET_EMAIL" "$SCAN_MODE" "$RUN_DIR"


