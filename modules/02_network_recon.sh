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

INPUT_PCAP=${1:-""}

if [[ "$INPUT_PCAP" == "--help" || "$INPUT_PCAP" == "-h" ]]; then
    printf 'TraceForge Module 02 — Network, PCAP & Wireless Forensics\n\nUsage:\n  %s <capture-file (.pcap|.cap|.pcapng)>\n' "$0"
    exit 0
fi

if [[ -z "$INPUT_PCAP" ]]; then
    printf 'Usage: %s <capture-file (.pcap|.cap|.pcapng)>\n' "$0" >&2
    exit 1
fi


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

ABS_PCAP="$(CDPATH='' cd -- "$(dirname -- "$INPUT_PCAP")" && pwd -P)/$(basename -- "$INPUT_PCAP")"
BASE_NAME="$(basename -- "$ABS_PCAP")"

RUN_DIR="$(make_run_dir "$ROOT_DIR" "pcap_${BASE_NAME}")"
REPORT="$RUN_DIR/report.txt"

info "Initiating Offline PCAP Triage on: $BASE_NAME"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Network & PCAP Forensics Report\n'
    printf '===============================================================================\n'
    printf 'Evidence File : %s\n' "$ABS_PCAP"
    printf 'File Size     : %s bytes\n' "$(wc -c < "$ABS_PCAP" | tr -d ' ')"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. Capinfos Capture Summary
step "Analyzing capture file statistics and metadata via capinfos..."
if need_cmd capinfos; then
    capinfos "$ABS_PCAP" > "$RUN_DIR/capinfos.txt" 2>&1 || true
    {
        echo '[1] CAPTURE FILE OVERVIEW'
        grep -E 'File type|File encapsulation|Number of packets|File size|Data size|Capture duration|First packet time|Last packet time' \
            "$RUN_DIR/capinfos.txt" || cat "$RUN_DIR/capinfos.txt"
        echo
    } >> "$REPORT"
else
    echo 'capinfos utility not installed.' > "$RUN_DIR/capinfos.txt"
fi

# 2. TShark Deep Dissection
if need_cmd tshark; then
    step "Extracting Protocol Hierarchy, Conversations, and IP Endpoints..."
    tshark -r "$ABS_PCAP" -q -z io,phs > "$RUN_DIR/protocol_hierarchy.txt" 2>&1 || true
    tshark -r "$ABS_PCAP" -q -z conv,ip > "$RUN_DIR/ip_conversations.txt" 2>&1 || true
    tshark -r "$ABS_PCAP" -q -z endpoints,ip > "$RUN_DIR/ip_endpoints.txt" 2>&1 || true

    step "Extracting DNS queries and domain lookups..."
    mkdir -p "$RUN_DIR/dns"
    tshark -r "$ABS_PCAP" -Y 'dns.qry.name' -T fields -E header=y -E separator=$'\t' \
        -e frame.number -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type \
        > "$RUN_DIR/dns/dns_queries.tsv" 2>&1 || true

    tshark -r "$ABS_PCAP" -T fields -e dns.qry.name 2>/dev/null | sed '/^$/d' | sort -u \
        > "$RUN_DIR/dns/unique_queried_domains.txt" || true

    step "Extracting HTTP requests, User-Agents, and URIs..."
    mkdir -p "$RUN_DIR/http"
    tshark -r "$ABS_PCAP" -Y 'http.request' -T fields -E header=y -E separator=$'\t' \
        -e frame.number -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri \
        > "$RUN_DIR/http/http_requests.tsv" 2>&1 || true

    tshark -r "$ABS_PCAP" -Y 'http.user_agent' -T fields -E header=y -E separator=$'\t' \
        -e frame.number -e ip.src -e ip.dst -e http.host -e http.user_agent \
        > "$RUN_DIR/http/user_agents.tsv" 2>&1 || true

    step "Extracting TLS Handshake Server Name Indication (SNI)..."
    mkdir -p "$RUN_DIR/tls"
    tshark -r "$ABS_PCAP" -Y 'tls.handshake.extensions_server_name' -T fields -E header=y -E separator=$'\t' \
        -e frame.number -e ip.src -e ip.dst -e tls.handshake.extensions_server_name \
        > "$RUN_DIR/tls/tls_server_names.tsv" 2>&1 || true

    tshark -r "$ABS_PCAP" -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sed '/^$/d' | sort -u \
        > "$RUN_DIR/tls/unique_tls_sni.txt" || true

    step "Discovering unique IPv4 and IPv6 endpoints..."
    tshark -r "$ABS_PCAP" -T fields -E header=n -E separator=$'\t' \
        -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst 2>/dev/null \
        | tr '\t' '\n' | sed '/^$/d' | sort -u \
        > "$RUN_DIR/unique_ip_addresses.txt" || true

    step "Auditing 802.11 wireless and EAPOL authentication frames..."
    mkdir -p "$RUN_DIR/wireless"
    tshark -r "$ABS_PCAP" -Y 'wlan' -T fields -E header=y -E separator=$'\t' \
        -e frame.number -e wlan.fc.type -e wlan.fc.subtype -e wlan.sa -e wlan.da -e wlan.bssid \
        > "$RUN_DIR/wireless/wlan_frames.tsv" 2>&1 || true

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
    warn "TShark is not installed. Deep packet dissection was skipped."
    echo 'TShark was not found on PATH.' > "$RUN_DIR/protocol_hierarchy.txt"
fi

# 3. Wireless Handshake Verification via Aircrack-NG
step "Evaluating 802.11 handshake validity via Aircrack-NG..."
if need_cmd aircrack-ng; then
    aircrack-ng "$ABS_PCAP" > "$RUN_DIR/wireless/aircrack_assessment.txt" 2>&1 || true
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

# 4. Finalize Hashes and Manifest
step "Finalizing cryptographic hashes and evidence manifest..."
hash_file "$ABS_PCAP" > "$RUN_DIR/sha256.txt"
printf 'SHA-256 Hash      : %s\n' "$(cat "$RUN_DIR/sha256.txt")" >> "$REPORT"
printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

find "$RUN_DIR" -maxdepth 2 -type f | sort > "$RUN_DIR/manifest.txt"

info "Network / PCAP Recon completed successfully."
info "Full report written to: $REPORT"
