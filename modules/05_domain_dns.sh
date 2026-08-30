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

RAW_DOMAIN=""
SCAN_MODE=""
CASE_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            printf 'TraceForge Module 05 — Domain, DNS & Infrastructure Intelligence\n\nUsage:\n  %s <domain-name> [options]\n\nOptions:\n  --mode <quick|full>  Scan depth profile (default: quick)\n  --quick              Execute quick triage scan\n  --deep, --full       Execute full deep scan (all 30 catalog domain tools)\n  --case-id <id>       Attach to case ID\n  --help, -h           Show this help message\n' "$0"
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
            if [[ -z "$RAW_DOMAIN" ]]; then
                RAW_DOMAIN="$1"
            elif [[ "$1" == CASE-* || "$1" == case_* ]]; then
                CASE_ID="$1"
            elif [[ -z "$SCAN_MODE" && ( "$1" == "quick" || "$1" == "full" || "$1" == "deep" ) ]]; then
                SCAN_MODE="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$RAW_DOMAIN" || "$RAW_DOMAIN" == -* ]]; then
    printf 'Usage: %s <domain-name> [--mode <quick|full>] [--case-id <id>]\n' "$0" >&2
    exit 1
fi


SCAN_MODE="$(prompt_scan_mode "quick" "$SCAN_MODE")"
SCAN_MODE_UPPER="$(echo "$SCAN_MODE" | tr '[:lower:]' '[:upper:]')"

# Clean and normalize domain name
TARGET_DOMAIN="$(printf '%s' "$RAW_DOMAIN" | sed -e 's|^https\?://||' -e 's|/.*$||' -e 's|:[0-9]\+$||' | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]._-')"
if [[ -z "$TARGET_DOMAIN" || "$TARGET_DOMAIN" != *"."* ]]; then
    die "Invalid domain name supplied: $RAW_DOMAIN"
fi

RUN_DIR="$(make_run_dir "$ROOT_DIR" "domain_${TARGET_DOMAIN}")"
REPORT="$RUN_DIR/report.txt"

info "Initiating Domain & DNS Intelligence ($SCAN_MODE_UPPER SCAN) on: $TARGET_DOMAIN"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Domain, DNS & Infrastructure Intelligence Report\n'
    printf '===============================================================================\n'
    printf 'Target Domain : %s\n' "$TARGET_DOMAIN"
    printf 'Scan Depth    : %s SCAN\n' "$SCAN_MODE_UPPER"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. DNS Record Queries via dig
mkdir -p "$RUN_DIR/dns"
if need_cmd dig; then
    run_spinner_cmd "Querying authoritative DNS records (dig)" "$RUN_DIR/dns/dns_all.txt" bash -c 'for r in A AAAA MX NS TXT CNAME SOA; do dig +noall +answer "'"$TARGET_DOMAIN"'" "$r" > "'"$RUN_DIR"'/dns/record_${r}.txt" 2>&1 || true; done'
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
    log_skip "dig utility not installed."
fi

# 2. WHOIS Registration Lookup
if need_cmd whois; then
    run_spinner_cmd "Querying WHOIS registration data (whois)" "$RUN_DIR/whois.txt" whois "$TARGET_DOMAIN"
    {
        echo '[2] WHOIS REGISTRATION SUMMARY'
        grep -Ei 'Registrar:|Creation Date:|Registry Expiry Date:|Registrant Organization:|Name Server:' \
            "$RUN_DIR/whois.txt" | head -n 15 || head -n 20 "$RUN_DIR/whois.txt"
        echo
    } >> "$REPORT"
else
    echo 'whois utility not installed.' > "$RUN_DIR/whois.txt"
    log_skip "whois utility not installed."
fi

# 3. Passive Subdomain Enumeration
mkdir -p "$RUN_DIR/subdomains"

if need_cmd subfinder; then
    run_spinner_cmd "Enumerating passive subdomains (Subfinder)" "$RUN_DIR/subdomains/subfinder.txt" subfinder -d "$TARGET_DOMAIN" -silent -timeout 5
fi

if need_cmd amass; then
    run_spinner_cmd "Enumerating passive subdomains (Amass)" "$RUN_DIR/subdomains/amass_passive.txt" amass enum -passive -timeout 2 -d "$TARGET_DOMAIN"
fi

if need_cmd assetfinder; then
    run_spinner_cmd "Enumerating asset subdomains (Assetfinder)" "$RUN_DIR/subdomains/assetfinder.txt" assetfinder --subs-only "$TARGET_DOMAIN"
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
    run_spinner_cmd "Resolving active subdomains (dnsx)" "$RUN_DIR/dnsx_resolved.txt" dnsx -l "$RUN_DIR/subdomains_sample.txt" -silent -resp -a -aaaa -cname -t 50
fi

# 5. Web Technology Fingerprinting via httpx
if need_cmd httpx && [[ "$SUBDOMAIN_COUNT" -gt 0 ]]; then
    run_spinner_cmd "Probing HTTP/HTTPS services and tech (httpx)" "$RUN_DIR/httpx_probed.txt" httpx -l "$RUN_DIR/subdomains_sample.txt" -silent -title -status-code -tech-detect -cdn -timeout 5 -threads 25
    {
        echo '[4] HTTP PROBING & TECHNOLOGY FINGERPRINTS (httpx)'
        cat "$RUN_DIR/httpx_probed.txt"
        echo
    } >> "$REPORT"
fi

# 6. Typosquatting / Permutation Triage via dnstwist
if need_cmd dnstwist; then
    run_spinner_cmd "Checking domain permutations (dnstwist)" "$RUN_DIR/dnstwist_registered.txt" dnstwist --registered "$TARGET_DOMAIN"
    {
        echo '[5] REGISTERED TYPOSQUATS (dnstwist)'
        cat "$RUN_DIR/dnstwist_registered.txt"
        echo
    } >> "$REPORT"
fi

# =============================================================================
# EXTENDED DEEP SCAN CAPABILITIES (FULL SCAN MODE)
# =============================================================================
if [[ "$SCAN_MODE" == "full" ]]; then
    # 7. WAF & Reverse Proxy Detection via wafw00f
    if need_cmd wafw00f; then
        run_spinner_cmd "Detecting Web Application Firewall (wafw00f)" "$RUN_DIR/wafw00f.txt" wafw00f "https://$TARGET_DOMAIN"
        {
            echo '[6] WEB APPLICATION FIREWALL (wafw00f)'
            cat "$RUN_DIR/wafw00f.txt"
            echo
        } >> "$REPORT"
    else
        log_skip "wafw00f not installed."
    fi

    # 8. Certificate & TLS Fingerprinting via tlsx
    if need_cmd tlsx; then
        run_spinner_cmd "Extracting TLS certificate metadata (tlsx)" "$RUN_DIR/tlsx.txt" tlsx -u "$TARGET_DOMAIN" -san -cn -resp
        {
            echo '[7] TLS CERTIFICATE FINGERPRINTS (tlsx)'
            cat "$RUN_DIR/tlsx.txt"
            echo
        } >> "$REPORT"
    fi

    # 9. Historical Endpoint Harvesting via waybackurls / gau
    if need_cmd waybackurls; then
        run_spinner_cmd "Harvesting historical Wayback URLs (waybackurls)" "$RUN_DIR/waybackurls.txt" waybackurls "$TARGET_DOMAIN"
        {
            echo '[8] HISTORICAL ARCHIVE ENDPOINTS (waybackurls)'
            head -n 50 "$RUN_DIR/waybackurls.txt"
            printf 'Total Wayback Endpoints Found: %s\n\n' "$(wc -l < "$RUN_DIR/waybackurls.txt" | tr -d ' ')"
        } >> "$REPORT"
    fi

    # 10. Web Crawling & Endpoint Discovery via katana
    if need_cmd katana; then
        run_spinner_cmd "Crawling active web endpoints (katana)" "$RUN_DIR/katana.txt" katana -u "https://$TARGET_DOMAIN" -silent -ct 5s -jc
        {
            echo '[9] WEB CRAWLER ENDPOINTS (katana)'
            head -n 50 "$RUN_DIR/katana.txt"
            echo
        } >> "$REPORT"
    fi

    # 11. Port & Service Discovery via naabu
    if need_cmd naabu; then
        run_spinner_cmd "Scanning fast top service ports (naabu)" "$RUN_DIR/naabu.txt" naabu -host "$TARGET_DOMAIN" -top-ports 100 -silent
        {
            echo '[10] OPEN PORT DISCOVERY (naabu)'
            cat "$RUN_DIR/naabu.txt"
            echo
        } >> "$REPORT"
    fi
fi

printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

# Finalize multi-format reporting (TXT, MD, HTML, JSON, IOCs, Manifest)
finalize_module_run "05_domain_dns" "Domain & DNS Intelligence" "$TARGET_DOMAIN" "$SCAN_MODE" "$RUN_DIR"

