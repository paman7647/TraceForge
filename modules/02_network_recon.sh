#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — Module 02: Network, PCAP & Wireless Forensics
# Offline capture triage: protocol hierarchy, conversations, DNS, TLS SNI, 802.11.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"

INPUT_PCAP=""
SCAN_MODE=""
CASE_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            printf 'TraceForge Module 02 — Network, PCAP & Wireless Forensics\n\nUsage:\n  %s <capture-file (.pcap|.cap|.pcapng)> [options]\n\nOptions:\n  --mode <quick|full>  Scan depth profile (default: quick)\n  --quick              Execute quick triage scan\n  --deep, --full       Execute full deep scan (all 18 catalog network tools)\n  --case-id <id>       Attach to case ID\n  --help, -h           Show this help message\n' "$0"
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
            if [[ -z "$INPUT_PCAP" ]]; then
                INPUT_PCAP="$1"
            elif [[ "$1" == CASE-* || "$1" == case_* ]]; then
                CASE_ID="$1"
            elif [[ -z "$SCAN_MODE" && ( "$1" == "quick" || "$1" == "full" || "$1" == "deep" ) ]]; then
                SCAN_MODE="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$INPUT_PCAP" ]]; then
    printf 'Usage: %s <capture-file (.pcap|.cap|.pcapng)> [--mode <quick|full>] [--case-id <id>]\n' "$0" >&2
    exit 1
fi


SCAN_MODE="$(prompt_scan_mode "quick" "$SCAN_MODE")"

if [[ ! -f "$INPUT_PCAP" ]]; then
    die "Capture file does not exist: $INPUT_PCAP"
fi

if [[ ! -r "$INPUT_PCAP" ]]; then
    die "Capture file is not readable (check permissions): $INPUT_PCAP"
fi

# Validate PCAP extension
case "${INPUT_PCAP##*.}" in
    pcap|PCAP|cap|CAP|pcapng|PCAPNG) ;;
    *) die "Expected packet capture file (.pcap, .cap, .pcapng), got: $INPUT_PCAP" ;;
esac

SCAN_MODE="$(prompt_scan_mode "quick" "$SCAN_MODE")"
SCAN_MODE_UPPER="$(echo "$SCAN_MODE" | tr '[:lower:]' '[:upper:]')"

if [[ ! -f "$INPUT_PCAP" ]]; then
    die "Network capture file does not exist: $INPUT_PCAP"
fi

if [[ ! -r "$INPUT_PCAP" ]]; then
    die "Capture file is not readable (check permissions): $INPUT_PCAP"
fi

ABS_PCAP="$(CDPATH='' cd -- "$(dirname -- "$INPUT_PCAP")" && pwd -P)/$(basename -- "$INPUT_PCAP")"
BASE_NAME="$(basename "$INPUT_PCAP")"

RUN_DIR="$(make_run_dir "$ROOT_DIR" "pcap_${BASE_NAME}")"
REPORT="$RUN_DIR/report.txt"

info "Initiating Network & PCAP Forensics ($SCAN_MODE_UPPER SCAN) on: $BASE_NAME"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Network & PCAP Forensics Report\n'
    printf '===============================================================================\n'
    printf 'Capture File  : %s\n' "$BASE_NAME"
    printf 'Full Path     : %s\n' "$INPUT_PCAP"
    printf 'Scan Depth    : %s SCAN\n' "$SCAN_MODE_UPPER"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. Capinfos Capture Summary
if need_cmd capinfos; then
    run_spinner_cmd "Analyzing capture statistics (capinfos)" "$RUN_DIR/capinfos.txt" capinfos "$ABS_PCAP"
    {
        echo '[1] CAPTURE FILE OVERVIEW'
        grep -E 'File type|File encapsulation|Number of packets|File size|Data size|Capture duration|First packet time|Last packet time' \
            "$RUN_DIR/capinfos.txt" || cat "$RUN_DIR/capinfos.txt"
        echo
    } >> "$REPORT"
else
    echo 'capinfos utility not installed.' > "$RUN_DIR/capinfos.txt"
    log_skip "capinfos utility not installed."
fi

# 2. TShark Deep Dissection
if need_cmd tshark; then
    run_spinner_cmd "Extracting protocol hierarchy & conversations" "$RUN_DIR/protocol_hierarchy.txt" tshark -r "$ABS_PCAP" -q -z io,phs
    tshark -r "$ABS_PCAP" -q -z conv,ip > "$RUN_DIR/ip_conversations.txt" 2>&1 || true
    tshark -r "$ABS_PCAP" -q -z endpoints,ip > "$RUN_DIR/ip_endpoints.txt" 2>&1 || true

    mkdir -p "$RUN_DIR/dns"
    run_spinner_cmd "Extracting DNS queries & lookups (tshark)" "$RUN_DIR/dns/dns_queries.tsv" tshark -r "$ABS_PCAP" -Y 'dns.qry.name' -T fields -E header=y -E separator=$'\t' -e frame.number -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type

    tshark -r "$ABS_PCAP" -T fields -e dns.qry.name 2>/dev/null | sed '/^$/d' | sort -u \
        > "$RUN_DIR/dns/unique_queried_domains.txt" || true

    mkdir -p "$RUN_DIR/http"
    run_spinner_cmd "Extracting HTTP requests & User-Agents (tshark)" "$RUN_DIR/http/http_requests.tsv" tshark -r "$ABS_PCAP" -Y 'http.request' -T fields -E header=y -E separator=$'\t' -e frame.number -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri

    tshark -r "$ABS_PCAP" -Y 'http.user_agent' -T fields -E header=y -E separator=$'\t' \
        -e frame.number -e ip.src -e ip.dst -e http.host -e http.user_agent \
        > "$RUN_DIR/http/user_agents.tsv" 2>&1 || true

    mkdir -p "$RUN_DIR/tls"
    run_spinner_cmd "Extracting TLS SNI server names (tshark)" "$RUN_DIR/tls/tls_server_names.tsv" tshark -r "$ABS_PCAP" -Y 'tls.handshake.extensions_server_name' -T fields -E header=y -E separator=$'\t' -e frame.number -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

    tshark -r "$ABS_PCAP" -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sed '/^$/d' | sort -u \
        > "$RUN_DIR/tls/unique_tls_sni.txt" || true

    tshark -r "$ABS_PCAP" -T fields -E header=n -E separator=$'\t' \
        -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst 2>/dev/null \
        | tr '\t' '\n' | sed '/^$/d' | sort -u \
        > "$RUN_DIR/unique_ip_addresses.txt" || true

    mkdir -p "$RUN_DIR/wireless"
    run_spinner_cmd "Auditing 802.11 & EAPOL wireless frames (tshark)" "$RUN_DIR/wireless/wlan_frames.tsv" tshark -r "$ABS_PCAP" -Y 'wlan' -T fields -E header=y -E separator=$'\t' -e frame.number -e wlan.fc.type -e wlan.fc.subtype -e wlan.sa -e wlan.da -e wlan.bssid

    tshark -r "$ABS_PCAP" -Y 'eapol' -T fields -E header=y -E separator=$'\t' \
        -e frame.number -e wlan.sa -e wlan.da -e wlan.bssid -e eapol.type \
        > "$RUN_DIR/wireless/eapol_frames.tsv" 2>&1 || true

    {
        echo '[2] TRAFFIC & PROTOCOL SUMMARY'
        printf 'Unique IP Endpoints      : %s\n' "$(wc -l < "$RUN_DIR/unique_ip_addresses.txt" | tr -d ' ')"
        printf 'Unique DNS Domains       : %s\n' "$(wc -l < "$RUN_DIR/dns/unique_queried_domains.txt" | tr -d ' ')"
        printf 'Unique TLS SNI Hosts     : %s\n' "$(wc -l < "$RUN_DIR/tls/unique_tls_sni.txt" | tr -d ' ')"
        printf 'WLAN Frame Count         : %s\n' "$(wc -l < "$RUN_DIR/wireless/wlan_frames.tsv" | tr -d ' ')"
        printf 'EAPOL Frame Count        : %s\n\n' "$(wc -l < "$RUN_DIR/wireless/eapol_frames.tsv" | tr -d ' ')"
    } >> "$REPORT"

else
    log_warn "TShark is not installed. Deep packet dissection was skipped."
    echo 'TShark was not found on PATH.' > "$RUN_DIR/protocol_hierarchy.txt"
fi

# 3. Wireless Handshake Verification via Aircrack-NG
if need_cmd aircrack-ng; then
    run_spinner_cmd "Evaluating 802.11 handshakes (Aircrack-NG)" "$RUN_DIR/wireless/aircrack_assessment.txt" aircrack-ng "$ABS_PCAP"

    {
        echo '[3] WIRELESS ASSESSMENT'
        if grep -qi 'WPA' "$RUN_DIR/wireless/aircrack_assessment.txt"; then
            grep -E 'Index|BSSID|ESSID|Encryption|Key' "$RUN_DIR/wireless/aircrack_assessment.txt" || cat "$RUN_DIR/wireless/aircrack_assessment.txt"
        else
            echo 'No 802.11 wireless network handshakes or BSSIDs identified.'
        fi
        echo
    } >> "$REPORT"
else
    echo 'aircrack-ng utility not installed.' > "$RUN_DIR/wireless/aircrack_assessment.txt"
fi

# =============================================================================
# EXTENDED DEEP SCAN CAPABILITIES (FULL SCAN MODE)
# =============================================================================
if [[ "$SCAN_MODE" == "full" ]]; then
    # 4. Pattern & Cleartext Credential Search via ngrep
    if need_cmd ngrep; then
        run_spinner_cmd "Scanning cleartext credentials (ngrep)" "$RUN_DIR/ngrep_credentials.txt" ngrep -I "$ABS_PCAP" -i -q 'pass|pwd|user|auth|bearer|login|token|cookie'
        {
            echo '[4] CLEARTEXT CREDENTIAL PATTERNS (ngrep)'
            head -n 40 "$RUN_DIR/ngrep_credentials.txt"
            echo
        } >> "$REPORT"
    fi

    # 5. TCP Flow Metrics via tcptrace
    if need_cmd tcptrace; then
        run_spinner_cmd "Calculating TCP flow analytics (tcptrace)" "$RUN_DIR/tcptrace.txt" tcptrace -r -s "$ABS_PCAP"
        {
            echo '[5] TCP FLOW METRICS (tcptrace)'
            cat "$RUN_DIR/tcptrace.txt"
            echo
        } >> "$REPORT"
    fi

    # 6. TCPDump Raw Summary
    if need_cmd tcpdump; then
        run_spinner_cmd "Parsing link-layer headers (tcpdump)" "$RUN_DIR/tcpdump_summary.txt" tcpdump -r "$ABS_PCAP" -nn -c 100
    fi
fi

# Integrity Hashes and Run Manifest
hash_file "$ABS_PCAP" > "$RUN_DIR/sha256.txt"
printf 'SHA-256 Hash      : %s\n' "$(cat "$RUN_DIR/sha256.txt")" >> "$REPORT"
printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

# Finalize multi-format reporting (TXT, MD, HTML, JSON, IOCs, Manifest)
finalize_module_run "02_network_recon" "Network & PCAP Forensics" "$BASE_NAME" "$SCAN_MODE" "$RUN_DIR"

