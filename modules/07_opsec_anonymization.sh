#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — Module 07: OPSEC & Metadata Anonymization
# Observational audit: privacy tools, DNS security, proxy routing, and crypto.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    printf 'TraceForge Module 07 — OPSEC & Anonymization Audit\n\nUsage:\n  %s\n' "$0"
    exit 0
fi


if [[ -n "${1:-}" ]]; then
    log_err "Unknown option: $1"
    printf 'Usage: %s\n' "$0" >&2
    exit 1
fi

RUN_DIR="$(make_run_dir "$ROOT_DIR" "opsec_audit")"

REPORT="$RUN_DIR/report.txt"

info "Initiating OPSEC & Anonymization environment audit..."
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — OPSEC & Privacy Environment Audit Report\n'
    printf '===============================================================================\n'
    printf 'Host Platform : %s (%s)\n' "$OS_NAME" "$OS_ARCH"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. Audit Privacy & Security Tool Availability
step "Auditing installed privacy, proxy, and cryptographic toolchains..."
local_tools=(
    "mat2:Metadata Sanitization"
    "proxychains4:SOCKS/HTTP Proxy Chaining"
    "tor:The Onion Router"
    "torsocks:Tor Traffic Wrapper"
    "macchanger:MAC Address Manipulation"
    "wg:WireGuard VPN Interface"
    "privoxy:Privacy Filtering Proxy"
    "cloudflared:DNS over HTTPS (DoH)"
    "dnscrypt-proxy:DNSCrypt / DoH Proxy"
    "stubby:DNS over TLS (DoT)"
    "ssh:OpenSSH Encrypted Dynamic Proxy"
    "socat:Multipurpose SSL Relay"
    "ncat:Netcat TLS Socket Client"
    "gpg:GnuPG OpenPGP Encryption"
    "age:Modern File Encryption"
    "openssl:OpenSSL Cryptographic Toolkit"
    "srm:Secure DoD File Deletion"
)

{
    printf '%-18s %-12s %-36s %s\n' "Tool Executable" "Status" "Security Capability" "Resolved Path"
    printf '%-18s %-12s %-36s %s\n' "------------------" "------------" "------------------------------------" "-----------------------------------"
    for item in "${local_tools[@]}"; do
        bin="${item%%:*}"
        desc="${item#*:}"
        if need_cmd "$bin"; then
            printf '%-18s %-12s %-36s %s\n' "$bin" "AVAILABLE" "$desc" "$(command -v "$bin")"
        else
            printf '%-18s %-12s %-36s %s\n' "$bin" "MISSING" "$desc" "-"
        fi
    done
} | tee "$RUN_DIR/tool_availability.txt" >> "$REPORT"

# 2. Local DNS Configuration Check
step "Inspecting local system DNS resolver configuration..."
if [[ "$OS_TYPE" == "darwin" ]] && need_cmd scutil; then
    scutil --dns > "$RUN_DIR/dns_configuration.txt" 2>&1 || true
elif [[ "$OS_TYPE" == "linux" ]] && need_cmd resolvectl; then
    resolvectl status > "$RUN_DIR/dns_configuration.txt" 2>&1 || true
elif [[ -r /etc/resolv.conf ]]; then
    cat /etc/resolv.conf > "$RUN_DIR/dns_configuration.txt" 2>&1 || true
else
    echo 'Unable to determine DNS configuration via standard utilities.' > "$RUN_DIR/dns_configuration.txt"
fi

# 3. Tool Versions
if need_cmd mat2; then mat2 --version > "$RUN_DIR/mat2_version.txt" 2>&1 || true; fi
if need_cmd tor; then tor --version > "$RUN_DIR/tor_version.txt" 2>&1 || true; fi
if need_cmd gpg; then gpg --version | head -n 2 > "$RUN_DIR/gpg_version.txt" 2>&1 || true; fi

# 4. Operational Safety Notice
cat >> "$REPORT" << 'SAFETY_NOTE'

===============================================================================
OPERATIONAL SECURITY (OPSEC) DIRECTIVES
===============================================================================
1. Non-Destructive Principle:
   This module does NOT alter network routes, modify MAC addresses, start proxy
   daemons, or delete files on your behalf.
2. Metadata Hygiene:
   Before releasing investigative artifacts publicly, execute MAT2 on a working
   copy of the evidence:
     mat2 --show <file>      # View sensitive tags
     mat2 <file>             # Sanitize metadata in place
3. Transport Anonymity:
   For passive web and API queries, route traffic through Tor using:
     torsocks <command>
   Or configure /etc/proxychains.conf with your local SOCKS5 proxy (127.0.0.1:9050).
4. Evidence Integrity:
   Always sign evidence hashes and manifests using GnuPG or age:
     gpg --clearsign manifest.txt
     age -r <recipient-public-key> -o evidence.enc evidence.tar.gz
===============================================================================
SAFETY_NOTE

printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

find "$RUN_DIR" -maxdepth 2 -type f | sort > "$RUN_DIR/manifest.txt"

info "OPSEC environment audit completed successfully."
info "Full report written to: $REPORT"
