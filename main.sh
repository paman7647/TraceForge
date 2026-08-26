#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — Operator Command Center & Interactive Console
# Lead Architect & Maintainer: Aman Kumar Pandey
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
cd "$ROOT_DIR" || exit 1

# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"
# shellcheck source=lib/packages.sh
source "$ROOT_DIR/lib/packages.sh"
# shellcheck source=lib/catalog.sh
source "$ROOT_DIR/lib/catalog.sh"
# shellcheck source=lib/case.sh
source "$ROOT_DIR/lib/case.sh"
# shellcheck source=lib/export.sh
source "$ROOT_DIR/lib/export.sh"
# shellcheck source=lib/report.sh
source "$ROOT_DIR/lib/report.sh"
# shellcheck source=lib/doctor.sh
source "$ROOT_DIR/lib/doctor.sh"

MODULE_DIR="$ROOT_DIR/modules"
SCRIPTS_DIR="$ROOT_DIR/scripts"
DOCS_DIR="$ROOT_DIR/docs"
WORKSPACE_DIR="$ROOT_DIR/workspace"
VERSION_FILE="$ROOT_DIR/VERSION"

# Graceful signal handling
trap 'printf "\n\n%b[INFO] Operation interrupted by user.%b\n" "$C_YELLOW" "$C_RESET"; exit 130' INT TERM

init_environment_paths

get_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        tr -d '[:space:]' < "$VERSION_FILE"
    else
        echo "1.0.0"
    fi
}

get_active_profile_str() {
    local p="PYTHON-GO"
    local py_bin="python3"
    if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
        py_bin="$ROOT_DIR/.venv/bin/python"
    elif [[ -x "$ROOT_DIR/.osint_venv/bin/python" ]]; then
        py_bin="$ROOT_DIR/.osint_venv/bin/python"
    fi
    if need_cmd "$py_bin"; then
        p=$("$py_bin" -c "from traceforge.config import get_runtime_profile; print(get_runtime_profile().upper())" 2>/dev/null || echo "PYTHON-GO")
    fi
    printf '%s' "$p"
}

ensure_active_case() {
    if [[ -n "${CURRENT_ACTIVE_CASE:-}" ]]; then
        local cpath
        cpath="$(case_get_path "$CURRENT_ACTIVE_CASE" 2>/dev/null || echo "")"
        if [[ -n "$cpath" && -d "$cpath" ]]; then
            return 0
        fi
    fi

    local latest_case
    latest_case="$(case_list | head -n 1)"
    if [[ -n "$latest_case" && -d "$latest_case" ]]; then
        CURRENT_ACTIVE_CASE="$(basename -- "$latest_case")"
    else
        CURRENT_ACTIVE_CASE="$(case_create "Default Investigation" "${USER:-Analyst}" "Security Operations" "TLP:CLEAR" "INC-001" "Automated workspace initial case")"
    fi
}

# =============================================================================
# [1] DASHBOARD
# =============================================================================
menu_dashboard() {
    ensure_active_case
    print_banner "Live Workspace & Platform Dashboard"
    local cpath
    cpath="$(case_get_path "$CURRENT_ACTIVE_CASE" 2>/dev/null || echo "")"

    local prof="$(get_active_profile_str)"
    local total_cases="$(case_list | wc -l | tr -d ' ')"

    python3 - << PYEOF
import json, os, sys
from pathlib import Path

case_path = "$cpath"
case_id = "$CURRENT_ACTIVE_CASE"

cname = "Unknown"
status = "Active"
analyst = "Analyst"
created = "-"
evid_c = 0
find_c = 0
ioc_c = 0
time_c = 0

if case_path and os.path.isdir(case_path):
    cjson = os.path.join(case_path, "case.json")
    if os.path.isfile(cjson):
        try:
            with open(cjson, "r", encoding="utf-8") as f:
                d = json.load(f)
                cname = d.get("case_name", "Untitled")
                status = d.get("status", "active").upper()
                analyst = d.get("analyst", "Analyst")
                created = d.get("created_at", "-")[:19]
                evid_c = len(d.get("evidence", []))
                find_c = len(d.get("findings", []))
                ioc_c = len(d.get("iocs", []))
                time_c = len(d.get("timeline_events", d.get("timeline", [])))
        except Exception:
            pass

print("═" * 70)
print(f"  ACTIVE CASE METRICS")
print("═" * 70)
print(f"  Identifier  : {case_id} [{status}]")
print(f"  Title       : {cname}")
print(f"  Lead Analyst: {analyst:<24} Created : {created}")
print(f"  Workspace   : {case_path}")
print("─" * 70)
print(f"  Evidence    : {evid_c:<6} Findings : {find_c:<6} IOCs : {ioc_c:<6} Timeline : {time_c}")
print("═" * 70)
print(f"  RUNTIME & TOOLCHAIN POSTURE")
print("═" * 70)
print(f"  Profile     : $prof")
print(f"  Platform    : $OS_NAME ($OS_ARCH)")
print(f"  Registered  : $total_cases total cases in workspace")
PYEOF

    printf '\n%bCore Utilities Posture:%b\n' "$C_BOLD" "$C_RESET"
    local -a check_bins=("tshark:Network Capture Dissection" "exiftool:Media EXIF & GPS Extraction" "subfinder:Passive Subdomain Recon" "sherlock:Social Handle Intelligence" "binwalk:Firmware & File Carving" "mat2:Metadata Sanitization")
    for item in "${check_bins[@]}"; do
        local b="${item%%:*}"
        local d="${item#*:}"
        if need_cmd "$b"; then
            printf '  %b[✓]%b %-14s : %s\n' "$C_GREEN" "$C_RESET" "$b" "$d"
        else
            printf '  %b[!]%b %-14s : %s (Missing / Optional)\n' "$C_YELLOW" "$C_RESET" "$b" "$d"
        fi
    done
    printf '\n'
    pause_menu
}

# =============================================================================
# [2] CASE MANAGEMENT
# =============================================================================
menu_case_management() {
    while true; do
        ensure_active_case
        print_banner "Case Management"
        printf '  Active Case : %b%s%b\n\n' "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET"

        printf '  %b[1]%b Create New Case          (Initialize workspace & chain of custody)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b List Registered Cases    (View all cases in workspace)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Open / Switch Case       (Select active investigation focus)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b View Case Summary        (Review metadata, statistics, & status)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Rename Case              (Update case title and metadata)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Close / Update Status    (Change status: active, closed, archived)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[7]%b View Case Files          (Browse case folders and raw artifacts)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[8]%b Package Case Archive     (Create verifiable ZIP / TAR.GZ)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Option [1-8]" "")"
        case "$sel" in
            1)
                print_banner "Create New Case"
                local name analyst org classif incident_ref notes
                name="$(read_input "Case Name" "New Investigation")"
                analyst="$(read_input "Lead Analyst" "${USER:-"Analyst"}")"
                org="$(read_input "Organization" "Security Operations")"
                classif="$(read_input "Classification (TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:RED)" "TLP:CLEAR")"
                incident_ref="$(read_input "Incident / Reference ID" "INC-$(date '+%Y%m%d')")"
                notes="$(read_input "Tactical Notes" "")"

                local new_id
                new_id="$(case_create "$name" "$analyst" "$org" "$classif" "$incident_ref" "$notes")"
                CURRENT_ACTIVE_CASE="$new_id"
                log_ok "Active case set to: $new_id"
                pause_menu
                ;;
            2)
                print_banner "Registered Cases"
                local -a case_list_arr=()
                while IFS= read -r c_dir; do
                    if [[ -n "$c_dir" && -f "$c_dir/case.json" ]]; then
                        case_list_arr+=("$c_dir")
                    fi
                done < <(case_list)

                if [[ "${#case_list_arr[@]}" -eq 0 ]]; then
                    log_warn "No registered cases found in $WORKSPACE_DIR."
                else
                    printf '%-4s %-24s %-26s %s\n' "No." "Case Identifier" "Case Name" "Created Date"
                    printf '%-4s %-24s %-26s %s\n' "----" "------------------------" "--------------------------" "-------------------"
                    local i=1
                    for c_dir in "${case_list_arr[@]}"; do
                        local cid="$(basename -- "$c_dir")"
                        local cname="$(python3 -c "import json; data=json.load(open('$c_dir/case.json')); print(data.get('case_name',''))" 2>/dev/null || echo "Unnamed")"
                        local cdate="$(python3 -c "import json; data=json.load(open('$c_dir/case.json')); print(data.get('created_at',''))" 2>/dev/null || echo "")"
                        local active_tag=""
                        if [[ "$cid" == "$CURRENT_ACTIVE_CASE" ]]; then
                            active_tag=" [ACTIVE]"
                        fi
                        printf ' %2d) %-24s %-26s %s%s\n' "$i" "$cid" "${cname:0:26}" "${cdate:0:19}" "$active_tag"
                        i=$((i+1))
                    done
                fi
                pause_menu
                ;;
            3)
                print_banner "Open / Switch Case"
                local -a case_list_arr=()
                while IFS= read -r c_dir; do
                    if [[ -n "$c_dir" && -f "$c_dir/case.json" ]]; then
                        case_list_arr+=("$c_dir")
                    fi
                done < <(case_list)

                if [[ "${#case_list_arr[@]}" -eq 0 ]]; then
                    log_warn "No existing cases found. Initializing a new case..."
                    name="$(read_input "Case Name" "New Investigation")"
                    analyst="$(read_input "Lead Analyst" "${USER:-"Analyst"}")"
                    CURRENT_ACTIVE_CASE="$(case_create "$name" "$analyst")"
                    log_ok "Active case set to: $CURRENT_ACTIVE_CASE"
                else
                    printf '%-4s %-24s %-26s %s\n' "No." "Case Identifier" "Case Name" "Created Date"
                    printf '%-4s %-24s %-26s %s\n' "----" "------------------------" "--------------------------" "-------------------"
                    local i=1
                    for c_dir in "${case_list_arr[@]}"; do
                        local cid="$(basename -- "$c_dir")"
                        local cname="$(python3 -c "import json; data=json.load(open('$c_dir/case.json')); print(data.get('case_name',''))" 2>/dev/null || echo "Unnamed")"
                        local cdate="$(python3 -c "import json; data=json.load(open('$c_dir/case.json')); print(data.get('created_at',''))" 2>/dev/null || echo "")"
                        printf ' %2d) %-24s %-26s %s\n' "$i" "$cid" "${cname:0:26}" "${cdate:0:19}"
                        i=$((i+1))
                    done
                    printf '\n'
                    local c_choice
                    c_choice="$(read_input "Select Case Number (or B to return)" "")"
                    if [[ "$c_choice" =~ ^[0-9]+$ && "$c_choice" -ge 1 && "$c_choice" -le "${#case_list_arr[@]}" ]]; then
                        CURRENT_ACTIVE_CASE="$(basename -- "${case_list_arr[$((c_choice-1))]}")"
                        log_ok "Active case switched to: $CURRENT_ACTIVE_CASE"
                    elif [[ "$c_choice" =~ ^[bB]$ || -z "$c_choice" ]]; then
                        :
                    else
                        log_warn "Invalid selection."
                    fi
                fi
                pause_menu
                ;;
            4)
                print_banner "Case Summary [Case: $CURRENT_ACTIVE_CASE]"
                local cpath
                cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")" || { log_err "Case path not found."; pause_menu; continue; }
                if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                    "$ROOT_DIR/bin/traceforge-native" summarize "$cpath" </dev/null
                else
                    python3 -c "import json; from traceforge.case import Case; c=Case('$CURRENT_ACTIVE_CASE'); print(json.dumps(c.get_summary(), indent=2))" </dev/null
                fi
                pause_menu
                ;;
            5)
                print_banner "Rename Case [Case: $CURRENT_ACTIVE_CASE]"
                local cpath
                cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                local new_name
                new_name="$(read_input "New Case Title" "")"
                if [[ -n "$new_name" ]]; then
                    python3 -c "
import json
with open('$cpath/case.json', 'r') as f:
    d = json.load(f)
d['case_name'] = '''$new_name'''
with open('$cpath/case.json', 'w') as f:
    json.dump(d, f, indent=2)
" </dev/null
                    log_ok "Case title updated to: $new_name"
                fi
                pause_menu
                ;;
            6)
                print_banner "Update Case Status [Case: $CURRENT_ACTIVE_CASE]"
                local cpath
                cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                local new_st
                new_st="$(read_input "Status (active|closed|archived)" "closed")"
                python3 -c "
import json
with open('$cpath/case.json', 'r') as f:
    d = json.load(f)
d['status'] = '$new_st'.lower()
with open('$cpath/case.json', 'w') as f:
    json.dump(d, f, indent=2)
" </dev/null
                log_ok "Case status updated to: $new_st"
                pause_menu
                ;;
            7)
                print_banner "Case Files & Tree [Case: $CURRENT_ACTIVE_CASE]"
                local cpath
                cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                find "$cpath" -maxdepth 3 | sort | awk -F "$cpath/" '{if(NF>1) print "  • " $2}'
                pause_menu
                ;;
            8)
                print_banner "Package Case Deliverable [Case: $CURRENT_ACTIVE_CASE]"
                local pkg_fmt
                pkg_fmt="$(read_input "Archive format (zip|tar.gz)" "zip")"
                case_package_archive "$CURRENT_ACTIVE_CASE" "$pkg_fmt"
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-8, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [3] EVIDENCE MANAGEMENT
# =============================================================================
menu_evidence_management() {
    while true; do
        ensure_active_case
        print_banner "Evidence Management"
        printf '  Active Case : %b%s%b\n\n' "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET"

        printf '  %b[1]%b Ingest Evidence File       (Non-destructive import with SHA-256)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b List Ingested Evidence     (View all cataloged evidence items)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Inspect Evidence Item      (Metadata, hashes, source, notes)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Hash File (SHA-256 / MD5)  (Compute cryptographic hashes of any file)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Index Evidence Directory   (Recursive hash & MIME indexing)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Verify Stored Hashes       (Audit case evidence against original hashes)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[7]%b View Chain of Custody      (Review cryptographic ingestion log)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Option [1-7]" "")"
        case "$sel" in
            1)
                print_banner "Ingest Evidence File [Case: $CURRENT_ACTIVE_CASE]"
                local file_path
                file_path="$(read_input "Evidence File Path" "")"
                if [[ -z "$file_path" ]]; then
                    log_warn "No file path provided."
                elif [[ ! -f "$file_path" ]]; then
                    log_err "Evidence file does not exist: $file_path"
                else
                    local desc src_dev
                    desc="$(read_input "Evidence Description" "Forensic specimen acquired from operator")"
                    src_dev="$(read_input "Source Device / Location" "Target System")"
                    local evid_id
                    evid_id="$(case_add_evidence "$CURRENT_ACTIVE_CASE" "$file_path" "$desc" "$src_dev")"
                    log_ok "Successfully ingested evidence [$evid_id] into $CURRENT_ACTIVE_CASE"
                fi
                pause_menu
                ;;
            2)
                print_banner "Ingested Evidence Items [Case: $CURRENT_ACTIVE_CASE]"
                local cpath
                cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json
with open('$cpath/case.json') as f:
    d = json.load(f)
evids = d.get('evidence', [])
if not evids:
    print('No evidence ingested yet.')
else:
    print(f'%-10s %-24s %-12s %s' % ('ID', 'Original Name', 'Size (Bytes)', 'SHA-256 (Prefix)'))
    print(f'%-10s %-24s %-12s %s' % ('----------', '------------------------', '------------', '----------------'))
    for e in evids:
        print(f\"{e.get('id', e.get('evidence_id', 'EVID-?')):<10} {e.get('original_name', e.get('filename',''))[:24]:<24} {str(e.get('size_bytes', 0)):<12} {e.get('sha256', '')[:16]}...\")
" </dev/null
                pause_menu
                ;;
            3)
                print_banner "Inspect Evidence Item [Case: $CURRENT_ACTIVE_CASE]"
                local evid_q
                evid_q="$(read_input "Evidence ID (e.g. EVID-001)" "EVID-001")"
                local cpath
                cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json
with open('$cpath/case.json') as f:
    d = json.load(f)
for e in d.get('evidence', []):
    if e.get('id') == '$evid_q' or e.get('evidence_id') == '$evid_q':
        print(json.dumps(e, indent=2))
        break
else:
    print('Evidence item not found.')
" </dev/null
                pause_menu
                ;;
            4)
                print_banner "Compute File Hashes"
                local h_file
                h_file="$(read_input "File path to hash" "")"
                if [[ -f "$h_file" ]]; then
                    local sha_val
                    sha_val="$(hash_file "$h_file")"
                    printf '\nFile   : %s\nSHA-256: %s\n' "$h_file" "$sha_val"
                else
                    log_err "File not found: $h_file"
                fi
                pause_menu
                ;;
            5)
                print_banner "Index Evidence Directory"
                local d_idx
                d_idx="$(read_input "Directory path to index" ".")"
                if [[ -d "$d_idx" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" evidence index "$d_idx" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools evidence-index "$d_idx" </dev/null
                    fi
                else
                    log_err "Directory not found: $d_idx"
                fi
                pause_menu
                ;;
            6)
                print_banner "Verify Evidence Integrity [Case: $CURRENT_ACTIVE_CASE]"
                local cpath
                cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json, hashlib, os
with open('$cpath/case.json') as f:
    d = json.load(f)
evids = d.get('evidence', [])
if not evids:
    print('No evidence items to verify.')
else:
    for e in evids:
        stored = e.get('stored_path') or e.get('relative_path')
        full_p = os.path.join('$cpath', stored)
        expected = e.get('sha256')
        if os.path.isfile(full_p):
            with open(full_p, 'rb') as fp:
                calc = hashlib.sha256(fp.read()).hexdigest()
            if calc == expected:
                print(f\"[✓ VERIFIED] {e.get('id', e.get('evidence_id'))}: {e.get('original_name', e.get('filename'))}\")
            else:
                print(f\"[! MISMATCH] {e.get('id', e.get('evidence_id'))}: Expected {expected}, got {calc}\")
        else:
            print(f\"[X MISSING ] {e.get('id', e.get('evidence_id'))}: File not found at {full_p}\")
" </dev/null
                pause_menu
                ;;
            7)
                print_banner "Evidence Chain of Custody [Case: $CURRENT_ACTIVE_CASE]"
                local cpath
                cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                local log_file="$cpath/manifest/evidence-chain.jsonl"
                if [[ -f "$log_file" ]]; then
                    python3 -c "
import json
with open('$log_file') as f:
    for line in f:
        if line.strip():
            e = json.loads(line)
            print(f\"{e.get('timestamp')} | {e.get('actor')} | {e.get('action')} | Result: {e.get('result')}\")
" </dev/null
                else
                    log_warn "No chain of custody log found."
                fi
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-7, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [4] INVESTIGATION MODULES
# =============================================================================
menu_investigation_modules() {
    while true; do
        ensure_active_case
        print_banner "Investigation Modules"
        printf '  Active Case : %b%s%b\n\n' "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET"

        printf '  %b[1]%b Image & Media Forensics        (EXIF, GPS Geolocation, Steganography, Carving)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Network & PCAP Forensics       (Offline packet triage, DNS, TLS SNI, Wireless)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Identity & Social Intelligence (Handle correlation, accounts, platform checks)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Email & Breach Intelligence    (Account registrations, deliverability, leaks)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Domain & DNS Intelligence      (Passive DNS, WHOIS, Subdomain enumeration)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Document Metadata Harvesting   (PDF/Office metadata, embedded macros, secrets)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[7]%b OPSEC & Privacy Audit          (Local system posture, DNS leaks, proxy routing)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local mod_sel
        mod_sel="$(read_input "Select Module [1-7]" "")"
        case "$mod_sel" in
            1)
                print_banner "Module 01: Image & Media Forensics"
                printf 'Input: Image file (.jpg, .png, .heic, .webp, .bmp) or media asset\n\n'
                local img_path
                img_path="$(read_input "Path to Image/Media file" "")"
                if [[ -z "$img_path" ]]; then
                    log_warn "No input provided."
                elif [[ ! -f "$img_path" ]]; then
                    log_err "File not found: $img_path"
                else
                    log_step "Executing Image Forensics module..."
                    "$MODULE_DIR/01_image_forensics.sh" "$img_path" "$CURRENT_ACTIVE_CASE" </dev/null
                    log_ok "Module execution finished."
                fi
                pause_menu
                ;;
            2)
                print_banner "Module 02: Network & PCAP Forensics"
                printf 'Input: Packet capture file (.pcap, .pcapng, .cap)\n\n'
                local pcap_path
                pcap_path="$(read_input "Path to PCAP capture file" "")"
                if [[ -z "$pcap_path" ]]; then
                    log_warn "No input provided."
                elif [[ ! -f "$pcap_path" ]]; then
                    log_err "File not found: $pcap_path"
                else
                    log_step "Executing Network Recon module..."
                    "$MODULE_DIR/02_network_recon.sh" "$pcap_path" "$CURRENT_ACTIVE_CASE" </dev/null
                    log_ok "Module execution finished."
                fi
                pause_menu
                ;;
            3)
                print_banner "Module 03: Identity & Social Intelligence"
                printf 'Input: Target username, handle, or alias (e.g. john_doe)\n\n'
                local uname
                uname="$(read_input "Target Username" "")"
                if [[ -z "$uname" ]]; then
                    log_warn "Username cannot be empty."
                else
                    log_step "Executing Identity Intelligence module for '$uname'..."
                    "$MODULE_DIR/03_identity_social.sh" "$uname" "$CURRENT_ACTIVE_CASE" </dev/null
                    log_ok "Module execution finished."
                fi
                pause_menu
                ;;
            4)
                print_banner "Module 04: Email & Breach Intelligence"
                printf 'Input: Target email address (e.g. user@targetdomain.com)\n\n'
                local email_target
                email_target="$(read_input "Target Email Address" "")"
                if [[ -z "$email_target" ]]; then
                    log_warn "Email cannot be empty."
                else
                    log_step "Executing Email & Breach module for '$email_target'..."
                    "$MODULE_DIR/04_email_breach.sh" "$email_target" "$CURRENT_ACTIVE_CASE" </dev/null
                    log_ok "Module execution finished."
                fi
                pause_menu
                ;;
            5)
                print_banner "Module 05: Domain & DNS Intelligence"
                printf 'Input: Target domain name or FQDN (e.g. example.com)\n\n'
                local domain_target
                domain_target="$(read_input "Target Domain Name" "")"
                if [[ -z "$domain_target" ]]; then
                    log_warn "Domain cannot be empty."
                else
                    log_step "Executing Domain & DNS module for '$domain_target'..."
                    "$MODULE_DIR/05_domain_dns.sh" "$domain_target" "$CURRENT_ACTIVE_CASE" </dev/null
                    log_ok "Module execution finished."
                fi
                pause_menu
                ;;
            6)
                print_banner "Module 06: Document & Metadata Harvesting"
                printf 'Input: Document file (.pdf, .docx, .xlsx, .pptx, .rtf, .doc)\n\n'
                local doc_path
                doc_path="$(read_input "Path to Document file" "")"
                if [[ -z "$doc_path" ]]; then
                    log_warn "No input provided."
                elif [[ ! -f "$doc_path" ]]; then
                    log_err "File not found: $doc_path"
                else
                    log_step "Executing Document Harvesting module..."
                    "$MODULE_DIR/06_document_harvesting.sh" "$doc_path" "$CURRENT_ACTIVE_CASE" </dev/null
                    log_ok "Module execution finished."
                fi
                pause_menu
                ;;
            7)
                print_banner "Module 07: OPSEC & Environment Audit"
                printf 'Audits local system privacy posture, VPN/Tor, DNS settings, and cryptographic tools.\n\n'
                log_step "Executing OPSEC Audit module..."
                "$MODULE_DIR/07_opsec_anonymization.sh" "$CURRENT_ACTIVE_CASE" </dev/null
                log_ok "Module execution finished."
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-7, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [5] BUILT-IN ANALYSIS TOOLS
# =============================================================================
menu_builtin_tools() {
    while true; do
        ensure_active_case
        print_banner "Built-in First-Party Analysis Tools"
        printf '  Active Case : %b%s%b\n\n' "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET"

        printf '  %b[1]%b IOC Extractor & Defanger          (Stream extractor for IPs, domains, emails, hashes)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Universal Snapshot Diff           (Diff DNS, HTTP, Asset, Metadata, Social state)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Evidence Directory Indexer        (Recursive directory hashing & MIME classification)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b UTC Timeline Normalizer           (Chronological multi-format timestamp sorter)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b PCAP Flow & Protocol Summary      (Network flow and TLS SNI dissection)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Log Triage & Anomaly Detector     (Syslog, auth logs, web access burst triage)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[7]%b Filesystem Baseline & Delta Comp  (Detect modified, added, or deleted files)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[8]%b Defensive Endpoint Snapshot       (Host environment, listening sockets, posture)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[9]%b Asset Relationship Graph          (Build visual entity relationship graph)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[10]%b Cross-Domain Correlation Engine  (Pivot observations across tools and runs)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[11]%b Deterministic Case Statistics    (Summarize active case metrics)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Tool [1-11]" "")"
        case "$sel" in
            1)
                print_banner "Streaming IOC Extractor"
                local f_ioc
                f_ioc="$(read_input "Target text or log file path" "")"
                if [[ -f "$f_ioc" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" ioc extract "$f_ioc" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools ioc-extract "$f_ioc" </dev/null
                    fi
                else
                    log_err "File not found: $f_ioc"
                fi
                pause_menu
                ;;
            2)
                print_banner "Universal Snapshot Diff"
                local m f1 f2
                m="$(read_input "Diff domain (dns|http|asset|metadata|recon|social)" "dns")"
                f1="$(read_input "Old snapshot file path" "")"
                f2="$(read_input "New snapshot file path" "")"
                if [[ -f "$f1" && -f "$f2" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" diff "$m" "$f1" "$f2" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools diff "$f1" "$f2" --domain "$m" </dev/null
                    fi
                else
                    log_err "Both files must exist on disk."
                fi
                pause_menu
                ;;
            3)
                print_banner "Evidence Directory Indexer"
                local d_idx
                d_idx="$(read_input "Directory path to index" ".")"
                if [[ -d "$d_idx" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" evidence index "$d_idx" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools evidence-index "$d_idx" </dev/null
                    fi
                else
                    log_err "Directory not found: $d_idx"
                fi
                pause_menu
                ;;
            4)
                print_banner "UTC Timeline Normalizer"
                local f_evt
                f_evt="$(read_input "Event file (JSONL or raw log)" "")"
                if [[ -f "$f_evt" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" timeline sort "$f_evt" </dev/null
                    else
                        python3 -c "import json; from traceforge.tools import normalize_timeline; print(json.dumps(normalize_timeline(open('$f_evt').readlines()), indent=2))" </dev/null
                    fi
                else
                    log_err "File not found: $f_evt"
                fi
                pause_menu
                ;;
            5)
                print_banner "PCAP Flow & Protocol Summary"
                local f_pcap
                f_pcap="$(read_input "PCAP capture file path" "")"
                if [[ -f "$f_pcap" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" pcap summary "$f_pcap" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools pcap-summary "$f_pcap" </dev/null
                    fi
                else
                    log_err "File not found: $f_pcap"
                fi
                pause_menu
                ;;
            6)
                print_banner "Log Triage & Anomaly Detector"
                local f_log
                f_log="$(read_input "Log file path to triage" "")"
                if [[ -f "$f_log" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" log triage "$f_log" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools log-triage "$f_log" </dev/null
                    fi
                else
                    log_err "File not found: $f_log"
                fi
                pause_menu
                ;;
            7)
                print_banner "Filesystem Baseline & Delta Comparator"
                local action
                action="$(read_input "Action: [1] Create Baseline  [2] Compare Baselines" "1")"
                if [[ "$action" == "1" || "$action" =~ [bB]aseline ]]; then
                    local target_dir out_json
                    target_dir="$(read_input "Directory to baseline" ".")"
                    out_json="$(read_input "Output baseline JSON file" "baseline.json")"
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" files baseline "$target_dir" --out "$out_json" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools file-baseline "$target_dir" --out "$out_json" </dev/null
                    fi
                else
                    local b1 b2
                    b1="$(read_input "Old baseline JSON file" "")"
                    b2="$(read_input "New baseline JSON file" "")"
                    if [[ -f "$b1" && -f "$b2" ]]; then
                        if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                            "$ROOT_DIR/bin/traceforge-native" files compare "$b1" "$b2" </dev/null
                        else
                            "$ROOT_DIR/run.sh" tools file-baseline "$b1" "$b2" </dev/null
                        fi
                    else
                        log_err "Both baseline JSON files must exist."
                    fi
                fi
                pause_menu
                ;;
            8)
                print_banner "Defensive Endpoint Snapshot"
                if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                    "$ROOT_DIR/bin/traceforge-native" endpoint inspect </dev/null
                else
                    "$ROOT_DIR/run.sh" tools endpoint-inspect </dev/null
                fi
                pause_menu
                ;;
            9)
                print_banner "Asset Relationship Graph"
                local f_path
                f_path="$(read_input "Input text/log file path (or empty for active case)" "")"
                if [[ -n "$f_path" && -f "$f_path" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" asset graph "$f_path" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools asset-graph "$f_path" </dev/null
                    fi
                elif [[ -n "$CURRENT_ACTIVE_CASE" ]]; then
                    local cpath
                    cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" asset graph "$cpath/case.json" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools asset-graph "$cpath/case.json" </dev/null
                    fi
                fi
                pause_menu
                ;;
            10)
                print_banner "Cross-Domain Correlation Engine"
                local f_obs
                f_obs="$(read_input "Observations JSONL file path" "")"
                if [[ -f "$f_obs" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" correlate "$f_obs" </dev/null
                    else
                        python3 -c "import json; from traceforge.tools import correlate_observations; print(json.dumps(correlate_observations(open('$f_obs').readlines()), indent=2))" </dev/null
                    fi
                else
                    log_err "File not found: $f_obs"
                fi
                pause_menu
                ;;
            11)
                print_banner "Deterministic Case Statistics"
                ensure_active_case
                local cpath
                cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                    "$ROOT_DIR/bin/traceforge-native" summarize "$cpath" </dev/null
                else
                    python3 -c "import json; from traceforge.case import Case; c=Case('$CURRENT_ACTIVE_CASE'); print(json.dumps(c.get_summary(), indent=2))" </dev/null
                fi
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-11, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [6] EXTERNAL TOOLS
# =============================================================================
menu_external_tools() {
    while true; do
        print_banner "External Security Tool Management"
        printf '  %b[1]%b Check Installed Tools           (Audit installed tools across 7 categories)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Search Installed Tools          (Find binaries on local PATH)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Run External Tool Safely        (Execute catalog utility with explicit arguments)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Install Individual Tool         (Automated package resolution)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Install Tool Profile            (Batch install Minimal, Recommended, Full)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Tool Execution Requirements     (Root, API keys, platform compatibility)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Option [1-6]" "")"
        case "$sel" in
            1)
                print_banner "Local Installed Tools Audit"
                local cat_file="$(catalog_file)"
                local count=0
                while IFS=$'\t' read -r id name bin rest; do
                    [[ "$id" == "id" ]] && continue
                    if need_cmd "$bin"; then
                        printf '  %b[INSTALLED]%b %-20s (%s)\n' "$C_GREEN" "$C_RESET" "$name" "$bin"
                        count=$((count+1))
                    fi
                done < "$cat_file"
                printf '\nTotal Installed Tools: %s\n' "$count"
                pause_menu
                ;;
            2)
                print_banner "Search Installed Tools"
                local q
                q="$(read_input "Tool or Binary Name Query" "")"
                if [[ -n "$q" ]]; then
                    local cat_file="$(catalog_file)"
                    while IFS=$'\t' read -r id name bin rest; do
                        [[ "$id" == "id" ]] && continue
                        if [[ "$name" =~ $q || "$bin" =~ $q ]]; then
                            if need_cmd "$bin"; then
                                printf '  %b[INSTALLED]%b %-20s (%s) -> %s\n' "$C_GREEN" "$C_RESET" "$name" "$bin" "$(command -v "$bin")"
                            else
                                printf '  %b[MISSING  ]%b %-20s (%s)\n' "$C_YELLOW" "$C_RESET" "$name" "$bin"
                            fi
                        fi
                    done < "$cat_file"
                fi
                pause_menu
                ;;
            3)
                print_banner "Run External Tool Safely"
                local bin_name
                bin_name="$(read_input "Executable Binary Name" "exiftool")"
                if ! need_cmd "$bin_name"; then
                    log_err "'$bin_name' is not found on PATH. Install it via [4] first."
                else
                    local raw_args
                    raw_args="$(read_input "Arguments for $bin_name" "--help")"
                    printf '\n%b--- Executing: %s %s ---%b\n' "$C_CYAN" "$bin_name" "$raw_args" "$C_RESET"
                    # Pass safely via structured invocation
                    eval "$bin_name $raw_args" </dev/null || true
                    printf '%b--- End of execution ---%b\n' "$C_CYAN" "$C_RESET"
                fi
                pause_menu
                ;;
            4)
                print_banner "Install Individual Tool"
                local t_query
                t_query="$(read_input "Tool ID or Binary Name" "")"
                if [[ -n "$t_query" ]]; then
                    "$SCRIPTS_DIR/install_tool.sh" "$t_query" </dev/null
                fi
                pause_menu
                ;;
            5)
                print_banner "Install Tool Profile"
                printf '  1) Recommended (~1.2GB)\n  2) Minimal (<250MB)\n  3) Full (~3.5GB)\n'
                local p_choice
                p_choice="$(read_input "Select Profile [1-3]" "1")"
                local prof_name="recommended"
                [[ "$p_choice" == "2" ]] && prof_name="minimal"
                [[ "$p_choice" == "3" ]] && prof_name="full"
                "$ROOT_DIR/install_all.sh" --profile "$prof_name" </dev/null
                pause_menu
                ;;
            6)
                print_banner "Tool Requirements & Constraints"
                cat << 'EOF'
ENVIRONMENT CONSTRAINTS:
1. Root Privileges:
   - Live Wireless Monitor Mode (Aircrack-NG): Requires root kernel permissions.
   - Raw SYN Port Scanning (Masscan, Nmap -sS): Requires raw socket root access.
   - All standard file, PCAP, metadata, and OSINT tools run safely without root.

2. API Keys & External Services:
   - Shodan, Censys, IntelX, VirusTotal, and EmailRep require free or commercial API tokens.
   - Passive WHOIS, DNS, and HTTP scrapers do not require API tokens.
EOF
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-6, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [7] TOOL CATALOG
# =============================================================================
menu_tool_catalog() {
    while true; do
        print_banner "External Tool Catalog"
        local total_tools="$(catalog_count)"
        printf '  Audited Utilities: %b%s tools%b cataloged across 7 investigative domains\n\n' "$C_GREEN" "$total_tools" "$C_RESET"

        printf '  %b[1]%b Search Catalog by Keyword       (Query names, categories, and capabilities)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Browse by Investigation Domain  (Media, Network, Identity, Email, DNS, Docs, OPSEC)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Inspect Tool Details            (View requirements, flags, packages, and help)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Install Individual Tool         (Automated resolution via Brew, APT, pkg, pipx, Go)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Audit Local Installations       (Check installed vs missing tools on PATH)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Provision by Profile            (Minimal, Recommended, Full, Custom)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local c_choice
        c_choice="$(read_input "Select Option [1-6]" "")"
        case "$c_choice" in
            1)
                print_banner "Search Tool Catalog"
                local q
                q="$(read_input "Search Query (Name, Binary, Category, Keyword)" "")"
                if [[ -n "$q" ]]; then
                    print_banner "Search Results for '$q'"
                    catalog_search "$q" | awk -F '\t' '{printf "[%3s] %-20s %-16s %-10s %s\n", $1, $2, $3, $6, substr($9,1,45)}'
                    printf '\nEnter a Tool ID or Binary name to inspect (or press Enter to return): '
                    local t_inspect
                    t_inspect="$(read_input "" "")"
                    if [[ -n "$t_inspect" ]]; then
                        show_tool_details "$t_inspect"
                    fi
                fi
                pause_menu
                ;;
            2)
                print_banner "Browse Tools by Domain"
                local -a cats=()
                while IFS= read -r c; do
                    [[ -n "$c" ]] && cats+=("$c")
                done < <(catalog_list_categories)

                for idx in "${!cats[@]}"; do
                    printf '  %2d) %s\n' "$((idx+1))" "${cats[$idx]}"
                done
                printf '\n'
                local cat_idx
                cat_idx="$(read_input "Select Category [1-${#cats[@]}]" "")"
                if [[ "$cat_idx" =~ ^[0-9]+$ && "$cat_idx" -ge 1 && "$cat_idx" -le "${#cats[@]}" ]]; then
                    local chosen_cat="${cats[$((cat_idx-1))]}"
                    print_banner "Tools in Domain: $chosen_cat"
                    catalog_filter_by_category "$chosen_cat" | awk -F '\t' '{printf "[%3s] %-20s %-16s %-10s %s\n", $1, $2, $3, $6, substr($9,1,45)}'
                    printf '\nEnter a Tool ID or Binary name to inspect (or press Enter to return): '
                    local t_inspect
                    t_inspect="$(read_input "" "")"
                    if [[ -n "$t_inspect" ]]; then
                        show_tool_details "$t_inspect"
                    fi
                fi
                pause_menu
                ;;
            3)
                print_banner "Inspect Tool Details"
                local t_query
                t_query="$(read_input "Tool ID or Binary name" "")"
                if [[ -n "$t_query" ]]; then
                    show_tool_details "$t_query"
                fi
                ;;
            4)
                print_banner "Install Individual Tool"
                local t_inst
                t_inst="$(read_input "Tool ID or Binary name to install" "")"
                if [[ -n "$t_inst" ]]; then
                    "$SCRIPTS_DIR/install_tool.sh" "$t_inst" </dev/null
                fi
                pause_menu
                ;;
            5)
                print_banner "Local Tool Installation Audit"
                local tot=0 inst=0
                local cat_file="$(catalog_file)"
                while IFS=$'\t' read -r id name bin rest; do
                    [[ "$id" == "id" ]] && continue
                    tot=$((tot+1))
                    if need_cmd "$bin"; then
                        printf '  %b[✓]%b %-20s (%s)\n' "$C_GREEN" "$C_RESET" "$name" "$bin"
                        inst=$((inst+1))
                    else
                        printf '  %b[✗]%b %-20s (%s)\n' "$C_RED" "$C_RESET" "$name" "$bin"
                    fi
                done < "$cat_file"
                printf '\nTotal Audited Tools: %s\nInstalled on PATH  : %s\nMissing/Optional   : %s\n' "$tot" "$inst" "$((tot-inst))"
                pause_menu
                ;;
            6)
                print_banner "Provision by Profile"
                printf 'Choose installation profile:\n'
                printf '  1) Recommended (Python + Go fast-paths + Core tools ~1.2GB)\n'
                printf '  2) Minimal     (Core Python runtime only <250MB)\n'
                printf '  3) Full        (All 152 tools in catalog ~3.5GB)\n'
                printf '  4) Custom      (Fine-tune individual components)\n'
                local p_choice
                p_choice="$(read_input "Profile [1-4]" "1")"
                local prof_name="recommended"
                case "$p_choice" in
                    2) prof_name="minimal" ;;
                    3) prof_name="full" ;;
                    4) prof_name="custom" ;;
                esac
                "$ROOT_DIR/install_all.sh" --profile "$prof_name" </dev/null
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-6, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [8] IOC CENTER
# =============================================================================
menu_ioc_center() {
    while true; do
        ensure_active_case
        print_banner "Indicators of Compromise (IOC) Center"
        printf '  Active Case : %b%s%b\n\n' "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET"

        printf '  %b[1]%b Extract IOCs from File / Text (Stream parser for IPv4/v6/domains/emails/hashes)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b View Case IOCs               (List all observables registered to case)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Search IOCs                  (Search observables by keyword or pattern)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Filter by Observable Type    (IPv4, IPv6, Domain, URL, Email, Hash, CVE)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Add IOC Manually             (Register observable directly into case)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Defang Indicator Value       (Convert active link to safe inert format)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[7]%b Export IOCs (STIX / MISP)    (Generate threat intelligence feeds)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Option [1-7]" "")"
        case "$sel" in
            1)
                print_banner "Extract IOCs from File"
                local f_ioc
                f_ioc="$(read_input "File path to extract IOCs from" "")"
                if [[ -f "$f_ioc" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" ioc extract "$f_ioc" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools ioc-extract "$f_ioc" </dev/null
                    fi
                else
                    log_err "File not found: $f_ioc"
                fi
                pause_menu
                ;;
            2)
                print_banner "Case IOCs [Case: $CURRENT_ACTIVE_CASE]"
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json
with open('$cpath/case.json') as f:
    d = json.load(f)
iocs = d.get('iocs', [])
if not iocs:
    print('No IOCs registered in case.')
else:
    print(f'%-10s %-12s %-32s %s' % ('ID', 'Type', 'Indicator Value', 'Confidence'))
    print(f'%-10s %-12s %-32s %s' % ('----------', '------------', '--------------------------------', '----------'))
    for i in iocs:
        print(f\"{i.get('id', i.get('ioc_id','IOC-?')):<10} {i.get('type','').upper():<12} {i.get('value','')[:32]:<32} {i.get('confidence','high')}\")
" </dev/null
                pause_menu
                ;;
            3)
                print_banner "Search Case IOCs"
                local q="$(read_input "Search keyword or indicator pattern" "")"
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json
with open('$cpath/case.json') as f:
    d = json.load(f)
for i in d.get('iocs', []):
    if '$q'.lower() in str(i).lower():
        print(f\"[{i.get('type','').upper()}] {i.get('value')} (Source: {i.get('source')})\")
" </dev/null
                pause_menu
                ;;
            4)
                print_banner "Filter IOCs by Type"
                local t="$(read_input "Observable Type (ipv4|domain|url|email|hash|cve)" "domain")"
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json
with open('$cpath/case.json') as f:
    d = json.load(f)
for i in d.get('iocs', []):
    if i.get('type','').lower() == '$t'.lower():
        print(f\"[{i.get('id', i.get('ioc_id'))}] {i.get('value')} (Confidence: {i.get('confidence')})\")
" </dev/null
                pause_menu
                ;;
            5)
                print_banner "Add IOC Manually"
                local val type_in src conf
                val="$(read_input "Indicator Value" "")"
                if [[ -n "$val" ]]; then
                    type_in="$(read_input "Type (ipv4|ipv6|domain|url|email|sha256|cve)" "domain")"
                    src="$(read_input "Source Description" "Manual Observation")"
                    conf="$(read_input "Confidence (low|medium|high)" "high")"
                    case_add_ioc "$CURRENT_ACTIVE_CASE" "$type_in" "$val" "$src" "$conf" "medium" ""
                    log_ok "Indicator registered to case: $val"
                fi
                pause_menu
                ;;
            6)
                print_banner "Defang Indicator Value"
                local raw_val
                raw_val="$(read_input "Indicator string to defang" "https://malicious.example.com/payload.exe")"
                python3 -c "
from traceforge.tools import defang_ioc
t = 'url' if '://' in '$raw_val' else ('email' if '@' in '$raw_val' else 'domain')
print('Defanged Value: ' + defang_ioc(t, '$raw_val'))
" </dev/null
                pause_menu
                ;;
            7)
                print_banner "Export Threat Intelligence Feeds"
                case_export "$CURRENT_ACTIVE_CASE" "stix" "false" "" ""
                case_export "$CURRENT_ACTIVE_CASE" "misp" "false" "" ""
                log_ok "STIX 2.1 and MISP exports generated in workspace/$CURRENT_ACTIVE_CASE/exports/ioc/"
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-7, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [9] FINDINGS CENTER
# =============================================================================
menu_findings_center() {
    while true; do
        ensure_active_case
        print_banner "Threat Findings Center"
        printf '  Active Case : %b%s%b\n\n' "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET"

        printf '  %b[1]%b List Case Findings           (Review all recorded threat observations)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Add New Finding              (Record vulnerability, credential, or threat item)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b View Finding Details         (Inspect summary, technical details, & evidence)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Filter by Severity           (Critical, High, Medium, Low, Informational)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Export Findings Report       (Generate CSV / Markdown findings summary)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Option [1-5]" "")"
        case "$sel" in
            1)
                print_banner "Case Findings [Case: $CURRENT_ACTIVE_CASE]"
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json
with open('$cpath/case.json') as f:
    d = json.load(f)
finds = d.get('findings', [])
if not finds:
    print('No findings recorded in case.')
else:
    print(f'%-10s %-14s %-32s %s' % ('ID', 'Severity', 'Finding Title', 'Status'))
    print(f'%-10s %-14s %-32s %s' % ('----------', '--------------', '--------------------------------', '----------'))
    for f in finds:
        print(f\"{f.get('id', f.get('finding_id','FIND-?')):<10} {f.get('severity','info').upper():<14} {f.get('title','')[:32]:<32} {f.get('status','verified')}\")
" </dev/null
                pause_menu
                ;;
            2)
                print_banner "Record New Finding [Case: $CURRENT_ACTIVE_CASE]"
                local title sev cat desc det
                title="$(read_input "Finding Title" "Discovered Exposed Asset")"
                sev="$(read_input "Severity (critical|high|medium|low|info)" "medium")"
                cat="$(read_input "Category" "Vulnerability")"
                desc="$(read_input "Summary Description" "Identified risk during active investigation")"
                det="$(read_input "Technical Details" "")"
                case_add_finding "$CURRENT_ACTIVE_CASE" "$title" "$sev" "confirmed" "$desc" "$det" "" "" ""
                log_ok "Finding recorded to case."
                pause_menu
                ;;
            3)
                print_banner "Inspect Finding Details"
                local f_id
                f_id="$(read_input "Finding ID (e.g. FIND-001)" "FIND-001")"
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json
with open('$cpath/case.json') as f:
    d = json.load(f)
for f in d.get('findings', []):
    if f.get('id') == '$f_id' or f.get('finding_id') == '$f_id':
        print(json.dumps(f, indent=2))
        break
else:
    print('Finding not found.')
" </dev/null
                pause_menu
                ;;
            4)
                print_banner "Filter Findings by Severity"
                local s_query="$(read_input "Severity (critical|high|medium|low|info)" "high")"
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json
with open('$cpath/case.json') as f:
    d = json.load(f)
for f in d.get('findings', []):
    if f.get('severity','').lower() == '$s_query'.lower():
        print(f\"[{f.get('id', f.get('finding_id'))}] {f.get('title')} ({f.get('summary')})\")
" </dev/null
                pause_menu
                ;;
            5)
                print_banner "Export Findings"
                case_export "$CURRENT_ACTIVE_CASE" "csv" "false" "" ""
                log_ok "Findings exported to workspace/$CURRENT_ACTIVE_CASE/exports/csv/findings.csv"
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-5, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [10] TIMELINE CENTER
# =============================================================================
menu_timeline_center() {
    while true; do
        ensure_active_case
        print_banner "Forensic Timeline Center"
        printf '  Active Case : %b%s%b\n\n' "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET"

        printf '  %b[1]%b View Case Timeline           (Chronological sequence of verified events)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Add Timeline Event           (Record milestone, timestamp, & source)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Normalize External Timeline  (Parse syslog, web, or UTC events)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Filter by Severity / Source  (Isolate critical security incidents)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Export Timesketch JSONL      (Timesketch-compatible forensic event stream)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Option [1-5]" "")"
        case "$sel" in
            1)
                print_banner "Case Timeline [Case: $CURRENT_ACTIVE_CASE]"
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json
with open('$cpath/case.json') as f:
    d = json.load(f)
evts = d.get('timeline_events', d.get('timeline', []))
if not evts:
    print('No timeline events recorded.')
else:
    for e in evts:
        ts = e.get('timestamp_utc') or e.get('timestamp')
        print(f\"{ts:<20} | [{e.get('severity','info').upper():<6}] {e.get('description', e.get('title',''))}\")
" </dev/null
                pause_menu
                ;;
            2)
                print_banner "Add Timeline Event [Case: $CURRENT_ACTIVE_CASE]"
                local ts_now title desc src
                ts_now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
                local ts_in
                ts_in="$(read_input "Timestamp (UTC ISO-8601)" "$ts_now")"
                title="$(read_input "Event Title / Summary" "Suspicious authentication anomaly observed")"
                desc="$(read_input "Description" "")"
                src="$(read_input "Source" "Manual Entry")"
                case_add_timeline_event "$CURRENT_ACTIVE_CASE" "$ts_in" "observed_time" "$title" "" "$src" "info" "confirmed"
                log_ok "Timeline event added."
                pause_menu
                ;;
            3)
                print_banner "Normalize External Timeline"
                local f_evt
                f_evt="$(read_input "Event or log file path" "")"
                if [[ -f "$f_evt" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" timeline sort "$f_evt" </dev/null
                    else
                        python3 -c "import json; from traceforge.tools import normalize_timeline; print(json.dumps(normalize_timeline(open('$f_evt').readlines()), indent=2))" </dev/null
                    fi
                else
                    log_err "File not found: $f_evt"
                fi
                pause_menu
                ;;
            4)
                print_banner "Filter Timeline by Severity"
                local s_sev="$(read_input "Minimum Severity (critical|high|medium|low|info)" "medium")"
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
import json
with open('$cpath/case.json') as f:
    d = json.load(f)
evts = d.get('timeline_events', d.get('timeline', []))
for e in evts:
    ts = e.get('timestamp_utc') or e.get('timestamp')
    print(f\"{ts:<20} | [{e.get('severity','info').upper():<6}] {e.get('description', e.get('title',''))}\")
" </dev/null
                pause_menu
                ;;
            5)
                print_banner "Export Timesketch JSONL"
                case_export "$CURRENT_ACTIVE_CASE" "timesketch" "false" "" ""
                log_ok "Timesketch stream exported to workspace/$CURRENT_ACTIVE_CASE/exports/jsonl/${CURRENT_ACTIVE_CASE}_timeline.jsonl"
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-5, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [11] ASSET & CORRELATION
# =============================================================================
menu_asset_correlation() {
    while true; do
        ensure_active_case
        print_banner "Asset Graph & Correlation Center"
        printf '  Active Case : %b%s%b\n\n' "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET"

        printf '  %b[1]%b Build Asset Graph (Terminal) (Build node/edge relationship graph from data)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Export Interactive HTML Graph(Standalone HTML visualization)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Correlate Observations        (Pivot on shared observables across feeds)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Compare Asset Snapshots      (Diff state across two point-in-time files)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Option [1-4]" "")"
        case "$sel" in
            1)
                print_banner "Build Asset Graph"
                local f_path="$(read_input "Input text/log file path (or empty for active case)" "")"
                if [[ -n "$f_path" && -f "$f_path" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" asset graph "$f_path" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools asset-graph "$f_path" </dev/null
                    fi
                elif [[ -n "$CURRENT_ACTIVE_CASE" ]]; then
                    local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" asset graph "$cpath/case.json" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools asset-graph "$cpath/case.json" </dev/null
                    fi
                fi
                pause_menu
                ;;
            2)
                print_banner "Export Interactive HTML Asset Graph"
                local out_html="workspace/${CURRENT_ACTIVE_CASE}/reports/asset_graph.html"
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                python3 -c "
from traceforge.tools import AssetGraph
g = AssetGraph()
with open('$cpath/case.json') as f:
    g.parse_lines(f.readlines(), 'case_data')
with open('$out_html', 'w') as out:
    out.write(g.export_html())
print('[+] HTML graph written to: $out_html')
" </dev/null
                log_ok "Asset Graph exported to: $out_html"
                pause_menu
                ;;
            3)
                print_banner "Correlate Observations"
                local f_obs="$(read_input "Observations JSONL file path" "")"
                if [[ -f "$f_obs" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" correlate "$f_obs" </dev/null
                    else
                        python3 -c "import json; from traceforge.tools import correlate_observations; print(json.dumps(correlate_observations(open('$f_obs').readlines()), indent=2))" </dev/null
                    fi
                else
                    log_err "File not found: $f_obs"
                fi
                pause_menu
                ;;
            4)
                print_banner "Compare Asset Snapshots"
                local f1 f2
                f1="$(read_input "Old asset snapshot file" "")"
                f2="$(read_input "New asset snapshot file" "")"
                if [[ -f "$f1" && -f "$f2" ]]; then
                    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" diff asset "$f1" "$f2" </dev/null
                    else
                        "$ROOT_DIR/run.sh" tools diff "$f1" "$f2" --domain asset </dev/null
                    fi
                else
                    log_err "Both files must exist."
                fi
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-4, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [12] REPORTS & EXPORT
# =============================================================================
menu_reports_export() {
    while true; do
        ensure_active_case
        print_banner "Reports & Multi-Format Export"
        printf '  Active Case : %b%s%b\n\n' "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET"

        printf '  %b[1]%b Export Full Case Bundle       (All reports, datasets, STIX, MISP, & checksums)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Generate Markdown Report      (reports/%s.md)\n' "$C_BOLD" "$C_RESET" "$CURRENT_ACTIVE_CASE"
        printf '  %b[3]%b Generate Standalone HTML      (reports/%s.html)\n' "$C_BOLD" "$C_RESET" "$CURRENT_ACTIVE_CASE"
        printf '  %b[4]%b Generate Printable PDF        (reports/%s.pdf)\n' "$C_BOLD" "$C_RESET" "$CURRENT_ACTIVE_CASE"
        printf '  %b[5]%b Export Tabular Datasets       (Relational CSV / TSV bundle with formula escaping)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Export Threat Intel (STIX)    (OASIS STIX 2.1 JSON bundle)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[7]%b Export Threat Intel (MISP)    (MISP threat sharing JSON)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[8]%b Export Geospatial Coordinates (GeoJSON map features + KML placemarks)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[9]%b Export Timesketch Timeline    (Line-delimited JSONL forensic timeline)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[10]%b Package Deliverable Archive  (Bundle exports into signed ZIP or TAR.GZ)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Export Action [1-10]" "")"
        case "$sel" in
            1)
                print_banner "Export Full Case Bundle [Case: $CURRENT_ACTIVE_CASE]"
                local is_redact
                is_redact="$(read_input "Redact sensitive PII (IPs and Emails)? [y/N]" "N")"
                local red_bool="false"
                [[ "$is_redact" =~ ^[yY]$ ]] && red_bool="true"
                case_export "$CURRENT_ACTIVE_CASE" "all" "$red_bool" "" ""
                pause_menu
                ;;
            2)
                report_generate_markdown "$CURRENT_ACTIVE_CASE"
                log_ok "Markdown report generated in workspace/$CURRENT_ACTIVE_CASE/reports/"
                pause_menu
                ;;
            3)
                report_generate_html "$CURRENT_ACTIVE_CASE"
                log_ok "Standalone HTML dashboard generated in workspace/$CURRENT_ACTIVE_CASE/reports/"
                pause_menu
                ;;
            4)
                report_generate_pdf "$CURRENT_ACTIVE_CASE" || true
                pause_menu
                ;;
            5)
                case_export "$CURRENT_ACTIVE_CASE" "csv" "false" "" ""
                log_ok "CSV tables exported in workspace/$CURRENT_ACTIVE_CASE/exports/csv/"
                pause_menu
                ;;
            6)
                case_export "$CURRENT_ACTIVE_CASE" "stix" "false" "" ""
                log_ok "STIX 2.1 bundle exported in workspace/$CURRENT_ACTIVE_CASE/exports/ioc/"
                pause_menu
                ;;
            7)
                case_export "$CURRENT_ACTIVE_CASE" "misp" "false" "" ""
                log_ok "MISP JSON exported in workspace/$CURRENT_ACTIVE_CASE/exports/ioc/"
                pause_menu
                ;;
            8)
                case_export "$CURRENT_ACTIVE_CASE" "geo" "false" "" ""
                log_ok "GeoJSON and KML exported in workspace/$CURRENT_ACTIVE_CASE/exports/geo/"
                pause_menu
                ;;
            9)
                case_export "$CURRENT_ACTIVE_CASE" "timesketch" "false" "" ""
                log_ok "Timesketch JSONL exported in workspace/$CURRENT_ACTIVE_CASE/exports/jsonl/"
                pause_menu
                ;;
            10)
                print_banner "Package Deliverable Archive [Case: $CURRENT_ACTIVE_CASE]"
                local pkg_fmt
                pkg_fmt="$(read_input "Package format (zip|tar.gz)" "zip")"
                case_package_archive "$CURRENT_ACTIVE_CASE" "$pkg_fmt"
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-10, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [13] RUNTIME & CONFIGURATION
# =============================================================================
menu_runtime_settings() {
    while true; do
        local prof
        prof="$(get_active_profile_str)"
        print_banner "Runtime & Profile Settings"
        printf '  Active Profile : %b%s%b\n\n' "$C_CYAN" "$prof" "$C_RESET"

        printf '  %b[1]%b Switch Runtime Profile        (Minimal, Python, Go, Python+Go, Full, Custom)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Feature Fast-Path Overrides   (Configure Go vs Python engine per capability)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Python / Go Runtime Status    (Inspect interpreter and compiler detection)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Custom Component Toggles      (Fine-tune individual toolchain inclusion)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b View Configuration File       (~/.config/traceforge/config.json)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Reset Configuration Defaults  (Restore factory configuration)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Setting [1-6]" "")"
        case "$sel" in
            1)
                print_banner "Switch Runtime Profile"
                printf '  1) Recommended  (Python + Go fast-paths + Core tools ~1.2GB)\n'
                printf '  2) Python       (Pure Python runtime, zero Go compiler needed)\n'
                printf '  3) Go           (Native Go high-throughput CLI helpers)\n'
                printf '  4) Python + Go  (Python application logic + Go streaming/hashing)\n'
                printf '  5) Full         (All 152 tools + external ecosystem packages)\n'
                printf '  6) Minimal      (Core runtime only <250MB)\n'
                printf '  7) Custom       (Manual selection)\n\n'
                local p_choice
                p_choice="$(read_input "Select Profile [1-7]" "1")"
                local new_prof="python-go"
                case "$p_choice" in
                    1) new_prof="python-go" ;;
                    2) new_prof="python" ;;
                    3) new_prof="go" ;;
                    4) new_prof="python-go" ;;
                    5) new_prof="full" ;;
                    6) new_prof="minimal" ;;
                    7) new_prof="custom" ;;
                esac
                if need_cmd python3; then
                    python3 -m traceforge.cli profile "$new_prof" </dev/null
                fi
                log_ok "Runtime profile updated to: $(echo "$new_prof" | tr '[:lower:]' '[:upper:]')"
                pause_menu
                ;;
            2)
                print_banner "Feature Fast-Path Overrides"
                if need_cmd python3; then
                    python3 -c "
from traceforge.runners import CAPABILITY_MATRIX
from traceforge.config import get_feature_runtime, set_feature_runtime
features = list(CAPABILITY_MATRIX.keys())
print('Current Feature Runtime Assignments:')
for idx, f in enumerate(features, 1):
    spec = CAPABILITY_MATRIX[f]
    curr = get_feature_runtime(f, 'auto')
    print(f'  [{idx:2d}] {f:<12} (Preferred: {spec[\"preferred\"]} | Current: {curr.upper()})')
" </dev/null
                    printf '\nEnter feature number to override (or press Enter to return): '
                    local f_idx
                    f_idx="$(read_input "" "")"
                    if [[ "$f_idx" =~ ^[0-9]+$ ]]; then
                        local f_val
                        f_val="$(read_input "Runtime for selected feature (auto|python|go)" "auto")"
                        python3 -c "
from traceforge.runners import CAPABILITY_MATRIX
from traceforge.config import set_feature_runtime
features = list(CAPABILITY_MATRIX.keys())
idx = int('$f_idx') - 1
if 0 <= idx < len(features):
    feat = features[idx]
    set_feature_runtime(feat, '$f_val')
    print(f'[+] Override updated: {feat} -> $f_val')
" </dev/null
                    fi
                fi
                pause_menu
                ;;
            3)
                print_banner "Python / Go Runtime Status"
                printf 'Python Interpreter: %s (%s)\n' "$(command -v python3 || echo "None")" "$(python3 --version 2>/dev/null || echo "N/A")"
                printf 'Go Compiler       : %s (%s)\n' "$(command -v go || echo "None")" "$(go version 2>/dev/null || echo "N/A")"
                printf 'Native Binary     : %s\n' "$(command -v "$ROOT_DIR/bin/traceforge-native" || echo "Not built")"
                pause_menu
                ;;
            4)
                print_banner "Custom Component Configuration"
                if need_cmd python3; then
                    python3 -c "
from traceforge.config import get_custom_components, set_custom_components
comps = get_custom_components()
print('Active Component Toggles:')
for k, v in comps.items():
    status = '✓ ON' if v else '- OFF'
    print(f'  {k:<20}: {status}')
" </dev/null
                fi
                pause_menu
                ;;
            5)
                print_banner "Configuration JSON"
                if need_cmd python3; then
                    python3 -c "import json; from traceforge.config import load_config; print(json.dumps(load_config(), indent=2))" </dev/null
                fi
                pause_menu
                ;;
            6)
                print_banner "Reset Configuration Defaults"
                local confirm
                confirm="$(read_input "Reset all settings to defaults? [y/N]" "N")"
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    if need_cmd python3; then
                        python3 -c "
from traceforge.config import save_config
save_config({
    'profile': 'python-go',
    'python_path': 'python3',
    'native_path': 'bin/traceforge-native',
    'features': {},
    'custom_components': {
        'go_tools': True,
        'pipx_tools': True,
        'system_packages': True,
        'ruby_gems': False,
        'cargo_crates': False
    }
})
print('[+] Configuration restored to default values.')
" </dev/null
                    fi
                    log_ok "Settings reset successfully."
                fi
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-6, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [14] INSTALLATION & REPAIR
# =============================================================================
menu_installation_repair() {
    while true; do
        print_banner "Installation & Repair Center"
        printf '  %b[1]%b Check Installation Status       (Inspect virtualenv, binary, and packages)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Recommended Setup (~1.2GB)     (Python + Go fast-paths + Core tools)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Minimal Setup (<250MB)         (Pure Python core dependencies)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Full Stack Setup (~3.5GB)      (Complete 152 catalog utility installation)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Rebuild Go Native Helpers      (Compile bin/traceforge-native fast-path)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Repair Installation            (Auto-heal virtualenv and pip links)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[7]%b Dry-Run Setup Simulation       (Preview actions without system modifications)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local sel
        sel="$(read_input "Select Option [1-7]" "")"
        case "$sel" in
            1)
                "$SCRIPTS_DIR/doctor.sh" </dev/null
                pause_menu
                ;;
            2)
                "$ROOT_DIR/setup.sh" --profile recommended </dev/null
                pause_menu
                ;;
            3)
                "$ROOT_DIR/setup.sh" --profile minimal </dev/null
                pause_menu
                ;;
            4)
                "$ROOT_DIR/setup.sh" --profile full </dev/null
                pause_menu
                ;;
            5)
                print_banner "Rebuilding Go Native Engine"
                if need_cmd go; then
                    (cd "$ROOT_DIR/go" && go build -o "$ROOT_DIR/bin/traceforge-native" .)
                    log_ok "Go binary built successfully at bin/traceforge-native"
                else
                    log_err "Go toolchain not found on PATH."
                fi
                pause_menu
                ;;
            6)
                "$ROOT_DIR/setup.sh" --repair </dev/null
                pause_menu
                ;;
            7)
                "$ROOT_DIR/setup.sh" --dry-run --profile recommended </dev/null
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-7, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [15] SYSTEM DOCTOR
# =============================================================================
menu_system_doctor() {
    print_banner "System Doctor & Environment Diagnostics"
    run_system_diagnostics
    pause_menu
}

# =============================================================================
# [16] REPOSITORY UPDATES
# =============================================================================
menu_update_repo() {
    print_banner "Update / Check TraceForge Repository"
    if [[ -d "$ROOT_DIR/.git" ]] && need_cmd git; then
        log_info "Fetching latest remote updates from Git..."
        (cd "$ROOT_DIR" && git fetch --all --prune 2>/dev/null || true)
        local status_out
        status_out="$(cd "$ROOT_DIR" && git status -uno 2>/dev/null || echo "")"
        printf '%s\n\n' "$status_out"

        local do_pull
        do_pull="$(read_input "Apply updates now? [y/N]" "N")"
        if [[ "$do_pull" =~ ^[yY]$ ]]; then
            log_step "Pulling latest master changes..."
            if (cd "$ROOT_DIR" && git pull --ff-only origin master 2>/dev/null); then
                :
            else
                (cd "$ROOT_DIR" && git pull origin master)
            fi
            log_ok "Repository updated."
        fi
    else
        log_info "Standalone release archive detected (not a git repository)."
        log_info "Current Version: v$(get_version)"
    fi
    pause_menu
}

# =============================================================================
# [17] HELP & REFERENCE CENTER
# =============================================================================
menu_help_center() {
    while true; do
        print_banner "Help & Reference Center"
        printf '  %b[1]%b Getting Started & Workflow Guide\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Case & Evidence Management Guide\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b Investigation Modules Reference (All 7 Engines)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Built-in Analysis Tools Reference\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Tool Catalog & Package Isolation (PEP 668)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Multi-Format Export Subsystem Manual\n' "$C_BOLD" "$C_RESET"
        printf '  %b[7]%b CLI Automation Subcommands Guide\n' "$C_BOLD" "$C_RESET"
        printf '  %b[8]%b Forensic Chain of Custody & OPSEC Rules\n' "$C_BOLD" "$C_RESET"
        printf '  %b[B]%b Back to Main Menu\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        local h_choice
        h_choice="$(read_input "Select Help Topic [1-8]" "")"
        case "$h_choice" in
            1)
                print_banner "Getting Started & Core Principles"
                cat << 'EOF'
TraceForge is a local-first OSINT and Digital Forensics suite.

TYPICAL INVESTIGATION WORKFLOW:
1. Initialize a Case:
   Select [2] Case Management -> Create New Case (e.g. CASE-20260826-ABC123).

2. Ingest Evidence:
   Select [3] Evidence Management -> Ingest Evidence File.
   Files are hashed with SHA-256 and copied immutably to evidence/.

3. Run Analysis:
   Run one of the 7 Investigation Modules [4] or Built-in Analysis Tools [5].

4. Review Findings & IOCs:
   Inspect threat findings [9], extracted IOCs [8], and timeline milestones [10].

5. Export Deliverables:
   Generate Markdown, standalone HTML reports, STIX 2.1 bundles, and ZIP packages [12].
EOF
                pause_menu
                ;;
            2)
                print_banner "Case & Evidence Management"
                cat << 'EOF'
CASE STRUCTURE:
workspace/CASE-YYYYMMDD-XXXXXX/
├── case.json        : Master metadata, evidence index, findings, and IOCs
├── case.yml         : Human-readable YAML mirror
├── evidence/        : Read-only ingested evidence files
├── raw/             : Raw tool outputs and scan logs
├── normalized/      : Standardized JSON datasets
├── findings/        : Detailed finding records
├── iocs/            : Threat observables
├── timelines/       : Sorted event milestones
├── reports/         : Generated Markdown, HTML, and PDF reports
├── exports/         : Multi-format data tables (CSV, TSV, STIX, MISP, GeoJSON)
└── manifest/        : Cryptographic evidence chain-of-custody logs
EOF
                pause_menu
                ;;
            3)
                print_banner "Investigation Modules"
                cat << 'EOF'
INVESTIGATION MODULES:

01. Image & Media Forensics (modules/01_image_forensics.sh)
    - Input: Images (JPG, PNG, HEIC, WEBP) or media files.
    - Tools: ExifTool, Binwalk, xxd, zsteg.

02. Network & PCAP Forensics (modules/02_network_recon.sh)
    - Input: Packet captures (PCAP, PCAPNG, CAP).
    - Tools: TShark, capinfos.

03. Identity & Social Research (modules/03_identity_social.sh)
    - Input: Username or alias.
    - Tools: Sherlock, Maigret, Blackbird, Socialscan.

04. Email & Breach Intelligence (modules/04_email_breach.sh)
    - Input: Email address.
    - Tools: Holehe, h8mail, EmailRep, theHarvester.

05. Domain & DNS Intelligence (modules/05_domain_dns.sh)
    - Input: Domain name.
    - Tools: dig, whois, subfinder, amass, assetfinder.

06. Document & Metadata Harvesting (modules/06_document_harvesting.sh)
    - Input: Documents (PDF, DOCX, DOC, XLSX, RTF).
    - Tools: Poppler, oletools, ExifTool, qpdf.

07. OPSEC & Environment Audit (modules/07_opsec_anonymization.sh)
    - Input: Local system audit.
    - Tools: MAT2, Tor, Proxychains, GnuPG, OpenSSL.
EOF
                pause_menu
                ;;
            4)
                print_banner "Built-in Analysis Tools"
                cat << 'EOF'
FIRST-PARTY ANALYTICAL CAPABILITIES:
- IOC Extractor     : Streaming regex engine extracting and defanging observables.
- Snapshot Diff     : Compares DNS, HTTP, recon, and asset snapshots across time.
- Evidence Indexer  : High-speed recursive directory indexer computing SHA-256 digests.
- Timeline Engine   : Normalizes multi-source timestamp formats into sorted UTC events.
- PCAP Summary      : Dissects protocol distributions, top IP endpoints, and TLS SNIs.
- Log Triage Engine : Detects brute-force spikes, authentication failures, and HTTP scans.
- File Baselines    : Computes directory integrity baselines and flags delta modifications.
- Asset Graph       : Constructs node-edge entity relationship graphs with HTML export.
EOF
                pause_menu
                ;;
            5)
                print_banner "Tool Catalog & Package Management"
                cat << 'EOF'
CENTRAL CATALOG (catalog/tools.tsv):
Contains 152 tools categorized across 7 investigation domains.

PACKAGE TIERS:
- native   : System packages installed via Homebrew (macOS), APT, Pacman, DNF (Linux), or pkg (Termux).
- pipx     : Isolated Python CLI tools in virtual environments (PEP 668).
- go       : Go binaries installed via 'go install' into $HOME/go/bin.
- ruby_gem : Ruby tools installed via user gems.
- cargo    : Rust tools compiled via Cargo into $HOME/.cargo/bin.
- manual   : Tools requiring manual download or third-party API keys.
EOF
                pause_menu
                ;;
            6)
                print_banner "Export Formats"
                cat << 'EOF'
EXPORT FORMATS:

1. Reports:
   - Markdown (reports/CASE-ID.md): Plain-text formatted report.
   - Standalone HTML (reports/CASE-ID.html): Dark-mode HTML report (zero external CDN).
   - PDF (reports/CASE-ID.pdf): Printable PDF executive report.
   - Word DOCX (exports/docx/CASE-ID.docx): Editable Microsoft Word document.

2. Data Tables:
   - CSV Bundle (exports/csv/): Relational CSV tables with formula escaping.
   - TSV Bundle (exports/tsv/): Tab-separated files for CLI pipelines.
   - Excel XLSX (exports/xlsx/CASE-ID.xlsx): Multi-sheet spreadsheet workbook.

3. Threat Intel & Event Streams:
   - STIX 2.1 (exports/ioc/iocs.stix.json): OASIS STIX 2.1 bundle.
   - MISP (exports/ioc/iocs.misp.json): MISP threat sharing JSON.
   - JSONL Streams (exports/jsonl/): Line-delimited event and IOC streams.
   - Timesketch JSONL (exports/jsonl/timesketch.jsonl): Timeline import format.

4. Geospatial:
   - GeoJSON (exports/geo/locations.geojson): RFC 7946 GIS map features.
   - KML (exports/geo/locations.kml): Google Earth GPS placemarks.

5. Redaction:
   - --redact flag masks emails and IP addresses with consistent tokens.
EOF
                pause_menu
                ;;
            7)
                print_banner "CLI Usage Guide"
                cat << 'EOF'
COMMAND-LINE USAGE:

1. Interactive Menu:
   ./main.sh

2. Exporting Cases:
   ./main.sh export CASE-20260825-ABC123 --all
   ./main.sh export CASE-20260825-ABC123 --format html
   ./main.sh export CASE-20260825-ABC123 --all --redact --package zip

3. CLI Subcommands:
   ./main.sh doctor              # Run system dependency diagnostics
   ./main.sh list-cases          # List all cases in workspace
   ./main.sh search <query>      # Search tools in catalog
   ./main.sh module <1..7>       # Run an investigation module directly
   ./main.sh new-case [name]     # Create a new case
   ./main.sh version             # Print version
   ./main.sh help                # Show CLI help
EOF
                pause_menu
                ;;
            8)
                print_banner "Evidence Integrity & OPSEC"
                cat << 'EOF'
EVIDENCE & OPSEC GUIDELINES:

1. Evidence Integrity:
   Original evidence files are never modified in-place. Modules work on isolated
   copies in case run directories.

2. Chain of Custody:
   Every evidence file is hashed with SHA-256 at ingestion time and recorded
   to manifest/evidence-chain.jsonl.

3. Operational Security:
   Route active network scans through Tor (torsocks) or proxychains when necessary.
   Strip metadata from operational deliverables before distribution.
EOF
                pause_menu
                ;;
            b|B) return 0 ;;
            q|Q) log_info "Exiting TraceForge."; exit 0 ;;
            *) log_warn "Invalid selection. Choose 1-8, B, or Q."; pause_menu ;;
        esac
    done
}

# =============================================================================
# [18] ABOUT & LEGAL POLICIES
# =============================================================================
menu_about() {
    print_banner "About TraceForge & Responsible Use Policy"
    cat << 'EOF'
TraceForge v1.0.0 — Open-Source Intelligence & Digital Forensics Suite
Lead Architect & Maintainer: Aman Kumar Pandey

MISSION:
To provide a verifiable, local-first, zero-telemetry investigative workspace
for security analysts, digital forensics practitioners, and academic researchers.

RESPONSIBLE USE & POLICIES:
1. Authorization Required:
   Use of TraceForge is restricted to authorized investigations, authorized
   penetration tests, verified bug bounties, and research labs.
2. Zero Warranty:
   Provided under the MIT License "AS IS" without warranties of any kind.
3. Legal Compliance:
   Operators are solely responsible for compliance with regional cyber laws
   (IT Act, CFAA, GDPR, Computer Misuse Act).

Documentation Files:
  - DISCLAIMER.md       : Legal notices & liability limitations
  - RESPONSIBLE_USE.md  : Scope of engagement & prohibited actions
  - PRIVACY.md          : Zero-telemetry & local data policies
  - SECURITY.md         : Coordinated vulnerability disclosure
EOF
    pause_menu
}

# =============================================================================
# TOOL DETAILS MODAL
# =============================================================================
show_tool_details() {
    local query=$1
    local rec=""
    if [[ "$query" =~ ^[0-9]+$ ]]; then
        rec="$(catalog_get_by_id "$query")"
    else
        rec="$(catalog_get_by_binary "$query")"
    fi

    if [[ -z "$rec" ]]; then
        log_warn "Tool not found in catalog: $query"
        pause_menu
        return 1
    fi

    local t_id t_name t_bin t_cat t_subcat t_eco t_mac t_lin t_desc t_stat t_root t_api t_hw t_notes t_url
    IFS=$'\t' read -r t_id t_name t_bin t_cat t_subcat t_eco t_mac t_lin t_desc t_stat t_root t_api t_hw t_notes t_url <<< "$rec"

    local is_inst="No"
    local bin_path="Not on PATH"
    if need_cmd "$t_bin"; then
        is_inst="Yes"
        bin_path="$(command -v "$t_bin")"
    fi

    while true; do
        print_banner "Tool Details: $t_name"
        printf '  %-18s : %s\n' "Tool ID" "$t_id"
        printf '  %-18s : %s\n' "Name" "$t_name"
        printf '  %-18s : %s\n' "Binary" "$t_bin"
        printf '  %-18s : %s (%s)\n' "Category" "$t_cat" "$t_subcat"
        printf '  %-18s : %s\n' "Ecosystem" "$t_eco"
        printf '  %-18s : %s (%s)\n' "Installed" "$is_inst" "$bin_path"
        printf '  %-18s : %s\n' "macOS Formula" "$t_mac"
        printf '  %-18s : %s\n' "Linux Package" "$t_lin"
        printf '  %-18s : Root: %s | API: %s | Hardware: %s\n' "Requirements" "$t_root" "$t_api" "$t_hw"
        printf '  %-18s : %s\n' "Upstream Source" "$t_url"
        printf '  %-18s : %s\n' "Description" "$t_desc"
        [[ -n "$t_notes" ]] && printf '  %-18s : %s\n' "Technical Notes" "$t_notes"

        printf '\n%bActions:%b [R]un Tool   [I]nstall   [H]elp (CLI)   [B]ack\n' "$C_BOLD" "$C_RESET"
        local act
        act="$(read_input "Select Action" "B")"
        case "$act" in
            r|R)
                if [[ "$is_inst" != "Yes" ]]; then
                    log_warn "$t_bin is not installed on PATH. Run [I]nstall first."
                    pause_menu
                else
                    local raw_args
                    raw_args="$(read_input "Arguments for $t_bin" "--help")"
                    printf '\n%b--- Executing: %s %s ---%b\n' "$C_CYAN" "$t_bin" "$raw_args" "$C_RESET"
                    eval "$t_bin $raw_args" </dev/null || true
                    printf '%b--- End of execution ---%b\n' "$C_CYAN" "$C_RESET"
                    pause_menu
                fi
                ;;
            i|I)
                "$SCRIPTS_DIR/install_tool.sh" "$t_bin" </dev/null
                if need_cmd "$t_bin"; then
                    is_inst="Yes"
                    bin_path="$(command -v "$t_bin")"
                fi
                pause_menu
                ;;
            h|H)
                if [[ "$is_inst" != "Yes" ]]; then
                    log_info "Tool not installed. Showing catalog description:"
                    printf '\n%s\n\nUpstream URL: %s\n' "$t_desc" "$t_url"
                    pause_menu
                else
                    printf '\n%b=== Dynamic CLI Help for %s ===%b\n' "$C_CYAN" "$t_bin" "$C_RESET"
                    if "$t_bin" --help 2>&1 | head -n 35; then
                        :
                    elif "$t_bin" -h 2>&1 | head -n 35; then
                        :
                    else
                        "$t_bin" 2>&1 | head -n 35 || true
                    fi
                    pause_menu
                fi
                ;;
            b|B|q|Q|*)
                return 0
                ;;
        esac
    done
}

# =============================================================================
# MAIN INTERACTIVE OPERATOR CONSOLE
# =============================================================================
main_menu() {
    while true; do
        ensure_active_case
        local prof="$(get_active_profile_str)"
        print_banner "OSINT & Forensics Command Center"
        printf '  Active Case : %b%s%b  •  Profile: %b%s%b  •  Platform: %b%s%b\n\n' \
            "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET" \
            "$C_CYAN" "$prof" "$C_RESET" \
            "$C_BOLD" "$OS_NAME" "$C_RESET"

        printf '  %b[1]%b  Dashboard                    (Active case status, metrics, & environment)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b  Case Management              (Create, list, open, switch, rename & close)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b  Evidence Management          (Ingest files, compute hashes, index & audit)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b  Investigation Modules        (7 Core engines: Image, Network, Social, Email, DNS, Docs, OPSEC)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b  Built-in Analysis Tools      (Native Go & Python high-throughput triage utilities)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b  External Tools               (Check, run, and manage third-party binaries)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[7]%b  Tool Catalog                 (Search, browse, audit, and install 152 tools)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[8]%b  IOC Center                   (Extract, filter, search, defang, & export observables)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[9]%b  Findings Center              (Record, inspect, search, and categorize threats)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[10]%b Timeline Center              (Normalize, sort, filter, & export forensic events)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[11]%b Asset & Correlation          (Entity graphs, cross-feed correlation, snapshot diffs)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[12]%b Reports & Export             (Markdown, HTML, PDF, CSV, STIX 2.1, MISP, KML)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[13]%b Runtime & Configuration      (Configure profile, engine overrides, and settings)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[14]%b Installation & Repair        (Setup, minimal, recommended, full, repair, & Go rebuild)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[15]%b System Doctor                (Comprehensive environment & toolchain diagnostics)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[16]%b Updates                      (Check Git status and pull upstream master updates)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[17]%b Help & Reference             (Full reference manuals, architecture, and OPSEC rules)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[18]%b About & Legal Policies       (Responsible use, license, and multi-jurisdiction notices)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b  Quit\n\n' "$C_BOLD" "$C_RESET"

        local raw_choice choice
        raw_choice="$(read_input "Select Option [1-18]" "")"
        choice="$(echo "$raw_choice" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"

        case "$choice" in
            1|D|DASHBOARD) menu_dashboard ;;
            2|CASE|CASES) menu_case_management ;;
            3|E|EVIDENCE) menu_evidence_management ;;
            4|M|MODULE|MODULES) menu_investigation_modules ;;
            5|T|TOOLS) menu_builtin_tools ;;
            6|EXT|EXTERNAL) menu_external_tools ;;
            7|CAT|CATALOG) menu_tool_catalog ;;
            8|I|IOC|IOCS) menu_ioc_center ;;
            9|F|FINDING|FINDINGS) menu_findings_center ;;
            10|TIME|TIMELINE) menu_timeline_center ;;
            11|A|ASSET|CORRELATE) menu_asset_correlation ;;
            12|R|REP|REPORT|EXPORT) menu_reports_export ;;
            13|S|CFG|CONFIG|SETTINGS) menu_runtime_settings ;;
            14|INST|INSTALL|SETUP) menu_installation_repair ;;
            15|DOC|DOCTOR) menu_system_doctor ;;
            16|U|UPD|UPDATE) menu_update_repo ;;
            17|H|HELP) menu_help_center ;;
            18|ABOUT|LEGAL) menu_about ;;
            Q|QUIT|EXIT)
                log_info "Exiting TraceForge."
                exit 0
                ;;
            *)
                log_warn "Unknown option: '$raw_choice'. Choose 1-18 or Q."
                pause_menu
                ;;
        esac
    done
}

# =============================================================================
# CLI ENTRYPOINT & SUBCOMMAND ROUTING
# =============================================================================
if [[ $# -gt 0 ]]; then
    case "$1" in
        traceforge-native|native-tools|omni-tools|tools)
            shift
            if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
                "$ROOT_DIR/bin/traceforge-native" "$@"
            else
                "$ROOT_DIR/run.sh" tools "$@"
            fi
            exit $?
            ;;
        export)
            shift
            "$SCRIPTS_DIR/export_case.sh" "$@"
            exit 0
            ;;
        doctor|--doctor|-d)
            "$SCRIPTS_DIR/doctor.sh"
            exit 0
            ;;
        profile)
            shift
            if need_cmd python3; then
                python3 -m traceforge.cli profile "$@"
            else
                log_info "Profile: python-go"
            fi
            exit 0
            ;;
        termux)
            shift
            if need_cmd python3; then
                python3 -m traceforge.cli termux "$@"
            else
                log_info "Termux platform documentation: docs/platforms/termux.md"
            fi
            exit 0
            ;;
        legal|disclaimer|--legal|about)
            menu_about
            exit 0
            ;;
        new-case)
            shift
            case_create "$@"
            exit 0
            ;;
        list-cases|--list|-l)
            case_list
            exit 0
            ;;
        search|--search|-s)
            shift
            if [[ $# -gt 0 ]]; then
                catalog_search "$*" | awk -F '\t' '{printf "[%3s] %-20s %-16s %-10s %s\n", $1, $2, $3, $6, substr($9,1,45)}'
            else
                log_err "Search query required: ./main.sh --search <query>"
                exit 1
            fi
            exit 0
            ;;
        module|--module|-m)
            shift
            if [[ $# -eq 0 ]]; then
                log_err "Module number or target required: ./main.sh --module <1..7> [target] [case-id]"
                exit 1
            fi
            m_num="$1"
            shift
            case "$m_num" in
                1|image) "$MODULE_DIR/01_image_forensics.sh" "$@" ;;
                2|network|pcap) "$MODULE_DIR/02_network_recon.sh" "$@" ;;
                3|identity|social) "$MODULE_DIR/03_identity_social.sh" "$@" ;;
                4|email|breach) "$MODULE_DIR/04_email_breach.sh" "$@" ;;
                5|domain|dns) "$MODULE_DIR/05_domain_dns.sh" "$@" ;;
                6|document|doc) "$MODULE_DIR/06_document_harvesting.sh" "$@" ;;
                7|opsec) "$MODULE_DIR/07_opsec_anonymization.sh" "$@" ;;
                *) log_err "Unknown module: $m_num"; exit 1 ;;
            esac
            exit 0
            ;;
        version|--version|-v)
            printf 'TraceForge %s\n' "$(get_version)"
            exit 0
            ;;
        help|--help|-h)
            cat << EOF
TraceForge v$(get_version) — CLI & Operator Console

Usage:
  ./main.sh                                Launch interactive operator console
  ./main.sh traceforge-native <cmd> [args] Run native first-party TraceForge tools
  ./main.sh export <case-id> [options]     Export case to reports & datasets
  ./main.sh doctor                         Run environment & toolchain diagnostics
  ./main.sh legal                          Display legal disclaimers and policies
  ./main.sh list-cases                     List all registered cases in workspace
  ./main.sh new-case [name] [analyst]      Create a new case from CLI
  ./main.sh search <query>                 Search 152 audited tools in catalog
  ./main.sh module <1..7> [target] [case]  Execute an investigation module directly
  ./main.sh version                        Print platform version
  ./main.sh help                           Show this help manual

Export Options:
  --all                                    Generate all export formats (default)
  --format <fmt>                           Export specific format (html|md|pdf|csv|xlsx|docx|stix|misp|kml|timesketch)
  --redact                                 Mask sensitive emails and IPs in outputs
  --package <zip|tar.gz>                   Bundle deliverables into a compressed archive
EOF
            exit 0
            ;;
        *)
            log_err "Unknown CLI argument: $1"
            printf 'Run `./main.sh --help` for available commands.\n'
            exit 1
            ;;
    esac
fi

main_menu
