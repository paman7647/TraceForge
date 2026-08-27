#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — Module 05: Domain, DNS & Infrastructure Intelligence
# Passive DNS interrogation, asset discovery, WHOIS, probing, and permutations.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"

RAW_DOMAIN=${1:-""}

if [[ "$RAW_DOMAIN" == "--help" || "$RAW_DOMAIN" == "-h" ]]; then
    printf 'TraceForge Module 05 — Domain, DNS & Infrastructure Intelligence\n\nUsage:\n  %s <domain-name>\n' "$0"
    exit 0
fi

if [[ -z "$RAW_DOMAIN" || "$RAW_DOMAIN" == -* ]]; then
    printf 'Usage: %s <domain-name>\n' "$0" >&2
    exit 1
fi


# Clean and normalize domain name
TARGET_DOMAIN="${RAW_DOMAIN#http://}"
TARGET_DOMAIN="${TARGET_DOMAIN#https://}"
TARGET_DOMAIN="${TARGET_DOMAIN%%/*}"
TARGET_DOMAIN="${TARGET_DOMAIN%%:*}"
TARGET_DOMAIN="$(printf '%s' "$TARGET_DOMAIN" | tr '[:upper:]' '[:lower:]')"

if [[ -z "$TARGET_DOMAIN" ]]; then
    die "Invalid domain name input."
fi

RUN_DIR="$(make_run_dir "$ROOT_DIR" "domain_${TARGET_DOMAIN}")"
REPORT="$RUN_DIR/report.txt"

info "Initiating Domain & DNS Intelligence on: $TARGET_DOMAIN"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Domain & DNS Intelligence Report\n'
    printf '===============================================================================\n'
    printf 'Target Domain : %s\n' "$TARGET_DOMAIN"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. DNS Record Queries via dig
step "Querying authoritative DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)..."
mkdir -p "$RUN_DIR/dns"
if need_cmd dig; then
    for r_type in A AAAA MX NS TXT CNAME SOA; do
        dig +noall +answer "$TARGET_DOMAIN" "$r_type" > "$RUN_DIR/dns/record_${r_type}.txt" 2>&1 || true
    done
    {
        echo '[1] CORE DNS RECORDS'
        for r_type in A AAAA MX NS TXT CNAME SOA; do
            if [[ -s "$RUN_DIR/dns/record_${r_type}.txt" ]]; then
                printf '%s\n' "--- $r_type Records ---"
                cat "$RUN_DIR/dns/record_${r_type}.txt"
            fi
        done
        echo
    } >> "$REPORT"
else
    echo 'dig utility not installed.' > "$RUN_DIR/dns/dns_error.txt"
fi

# 2. WHOIS Registration Lookup
step "Querying WHOIS registration data..."
if need_cmd whois; then
    whois "$TARGET_DOMAIN" > "$RUN_DIR/whois.txt" 2>&1 || true
    {
        echo '[2] WHOIS REGISTRATION SUMMARY'
        grep -Ei 'Registrar:|Creation Date:|Registry Expiry Date:|Registrant Organization:|Name Server:' \
            "$RUN_DIR/whois.txt" | head -n 15 || head -n 20 "$RUN_DIR/whois.txt"
        echo
    } >> "$REPORT"
else
    echo 'whois utility not installed.' > "$RUN_DIR/whois.txt"
fi

# 3. Passive Subdomain Enumeration
step "Gathering subdomains via Subfinder, Amass, and Assetfinder..."
mkdir -p "$RUN_DIR/subdomains"

if need_cmd subfinder; then
    subfinder -d "$TARGET_DOMAIN" -silent -timeout 5 > "$RUN_DIR/subdomains/subfinder.txt" 2>&1 || true
fi

if need_cmd amass; then
    amass enum -passive -timeout 2 -d "$TARGET_DOMAIN" > "$RUN_DIR/subdomains/amass_passive.txt" 2>&1 || true
fi

if need_cmd assetfinder; then
    assetfinder --subs-only "$TARGET_DOMAIN" > "$RUN_DIR/subdomains/assetfinder.txt" 2>&1 || true
fi

# Consolidate and deduplicate subdomains
cat "$RUN_DIR/subdomains"/*.txt 2>/dev/null | sed '/^$/d' | sort -u > "$RUN_DIR/unique_subdomains.txt" || true
SUBDOMAIN_COUNT="$(wc -l < "$RUN_DIR/unique_subdomains.txt" | tr -d ' ')"
head -n 250 "$RUN_DIR/unique_subdomains.txt" > "$RUN_DIR/subdomains_sample.txt"

{
    echo '[3] SUBDOMAIN DISCOVERY SUMMARY'
    printf 'Unique Subdomains Discovered: %s\n\n' "$SUBDOMAIN_COUNT"
} >> "$REPORT"

# 4. Active Resolution via dnsx
if need_cmd dnsx && [[ "$SUBDOMAIN_COUNT" -gt 0 ]]; then
    step "Resolving live subdomains via dnsx..."
    dnsx -l "$RUN_DIR/subdomains_sample.txt" -silent -resp -a -aaaa -cname -t 50 \
        > "$RUN_DIR/dnsx_resolved.txt" 2>&1 || true
fi

# 5. Web Technology Fingerprinting via httpx
if need_cmd httpx && [[ "$SUBDOMAIN_COUNT" -gt 0 ]]; then
    step "Probing HTTP/HTTPS services and technologies via httpx..."
    httpx -l "$RUN_DIR/subdomains_sample.txt" -silent -title -status-code -tech-detect -cdn -timeout 5 -threads 25 \
        > "$RUN_DIR/httpx_probed.txt" 2>&1 || true
    {
        echo '[4] HTTP PROBING & TECHNOLOGY FINGERPRINTS (httpx)'
        cat "$RUN_DIR/httpx_probed.txt"
        echo
    } >> "$REPORT"
fi

# 6. Typosquatting / Permutation Triage via dnstwist
if need_cmd dnstwist; then
    step "Checking domain permutations and typosquats via dnstwist..."
    dnstwist --registered "$TARGET_DOMAIN" > "$RUN_DIR/dnstwist_registered.txt" 2>&1 || true
    {
        echo '[5] REGISTERED TYPOSQUATS (dnstwist)'
        cat "$RUN_DIR/dnstwist_registered.txt"
        echo
    } >> "$REPORT"
fi

printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

find "$RUN_DIR" -maxdepth 2 -type f | sort > "$RUN_DIR/manifest.txt"

info "Domain & DNS intelligence completed successfully."
info "Full report written to: $REPORT"
