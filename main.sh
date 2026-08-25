#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# TraceForge — Operator Command Center & CLI Dispatcher
# Core Maintainer: Aman Kumar Pandey

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$ROOT_DIR/lib/common.sh"
source "$ROOT_DIR/lib/platform.sh"
source "$ROOT_DIR/lib/packages.sh"
source "$ROOT_DIR/lib/catalog.sh"
source "$ROOT_DIR/lib/case.sh"
source "$ROOT_DIR/lib/export.sh"
source "$ROOT_DIR/lib/report.sh"

MODULE_DIR="$ROOT_DIR/modules"
SCRIPTS_DIR="$ROOT_DIR/scripts"
DOCS_DIR="$ROOT_DIR/docs"
WORKSPACE_DIR="$ROOT_DIR/workspace"
VERSION_FILE="$ROOT_DIR/VERSION"

trap 'err "Console interrupted near line $LINENO."; exit 1' ERR

init_environment_paths

get_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        tr -d '[:space:]' < "$VERSION_FILE"
    else
        echo "1.0.0"
    fi
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

# -----------------------------------------------------------------------------
# MENU [1]: New Case
# -----------------------------------------------------------------------------
menu_new_case() {
    print_banner "Create New Forensic Case"
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
    info "Active case set to: $new_id"
    pause_menu
}

# -----------------------------------------------------------------------------
# MENU [2]: Open Case
# -----------------------------------------------------------------------------
menu_open_case() {
    print_banner "Open Investigation Case"
    local -a case_list_arr=()
    while IFS= read -r c_dir; do
        if [[ -n "$c_dir" && -f "$c_dir/case.json" ]]; then
            case_list_arr+=("$c_dir")
        fi
    done < <(case_list)

    if [[ "${#case_list_arr[@]}" -eq 0 ]]; then
        warn "No existing cases found. Initializing a new case..."
        menu_new_case
        return 0
    fi

    printf '%-3s %-24s %-28s %s\n' "No." "Case Identifier" "Case Name" "Created Date"
    printf '%-3s %-24s %-28s %s\n' "---" "------------------------" "----------------------------" "-------------------"

    local i=1
    for c_dir in "${case_list_arr[@]}"; do
        local cid="$(basename -- "$c_dir")"
        local cname="$(python3 -c "import json; data=json.load(open('$c_dir/case.json')); print(data.get('case_name',''))" 2>/dev/null || echo "Unnamed")"
        local cdate="$(python3 -c "import json; data=json.load(open('$c_dir/case.json')); print(data.get('created_at',''))" 2>/dev/null || echo "")"
        printf '  %2d) %-22s %-28s %s\n' "$i" "$cid" "${cname:0:28}" "${cdate:0:19}"
        i=$((i+1))
    done

    printf '\n'
    local sel
    sel="$(read_input "Select Case Number (or 'B' to back)" "")"
    if [[ "$sel" =~ ^[bB]$ || -z "$sel" ]]; then
        return 0
    fi

    if [[ "$sel" =~ ^[0-9]+$ && "$sel" -ge 1 && "$sel" -le "${#case_list_arr[@]}" ]]; then
        local chosen_dir="${case_list_arr[$((sel-1))]}"
        CURRENT_ACTIVE_CASE="$(basename -- "$chosen_dir")"
        info "Active case switched to: $CURRENT_ACTIVE_CASE"
    else
        warn "Invalid selection."
    fi
    pause_menu
}

# -----------------------------------------------------------------------------
# MENU [3]: List Cases
# -----------------------------------------------------------------------------
menu_list_cases() {
    print_banner "Registered Investigation Cases"
    case_list
    pause_menu
}

# -----------------------------------------------------------------------------
# MENU [4]: Add Evidence
# -----------------------------------------------------------------------------
menu_add_evidence() {
    ensure_active_case
    print_banner "Ingest Evidence [Case: $CURRENT_ACTIVE_CASE]"
    printf 'Enter the absolute or relative path to the evidence file:\n'
    local file_path
    file_path="$(read_input "Evidence File Path" "")"

    if [[ -z "$file_path" ]]; then
        warn "No path provided."
        pause_menu
        return 0
    fi

    if [[ ! -f "$file_path" ]]; then
        err "File not found: $file_path"
        pause_menu
        return 0
    fi

    local desc source_device
    desc="$(read_input "Evidence Description" "Forensic specimen acquired from operator")"
    source_device="$(read_input "Source Device / Location" "Target System")"

    local evid_id
    evid_id="$(case_add_evidence "$CURRENT_ACTIVE_CASE" "$file_path" "$desc" "$source_device")"
    info "Successfully ingested evidence: $evid_id into $CURRENT_ACTIVE_CASE"
    pause_menu
}

# -----------------------------------------------------------------------------
# MENU [5]: Run Investigation
# -----------------------------------------------------------------------------
menu_run_investigation() {
    ensure_active_case
    while true; do
        print_banner "Run Investigation Module [Case: $CURRENT_ACTIVE_CASE]"
        printf '  1) Image & Media Forensics           (EXIF, GPS, Stego, Carving)\n'
        printf '  2) Network & PCAP Forensics          (Protocols, DNS, TLS SNI, Wireless)\n'
        printf '  3) Identity & Social Intelligence    (Username Dossiers, Profiles)\n'
        printf '  4) Email & Breach Exposure           (Registrations, Breaches, Deliverability)\n'
        printf '  5) Domain & DNS Intelligence         (Passive Recon, Asset Discovery, HTTP)\n'
        printf '  6) Document & Metadata Harvesting    (PDF/Office, Macros, Secret Triage)\n'
        printf '  7) OPSEC & Anonymization Audit       (Privacy Tools, DNS Security, Proxy)\n'
        printf '  B) Back to Main Menu\n\n'

        local mod_sel
        mod_sel="$(read_input "Select Module" "")"
        case "$mod_sel" in
            1)
                local img_path
                img_path="$(read_input "Path to Image/Media file" "")"
                if [[ -n "$img_path" && -f "$img_path" ]]; then
                    "$MODULE_DIR/01_image_forensics.sh" "$img_path" "$CURRENT_ACTIVE_CASE"
                    pause_menu
                else
                    warn "Valid media file required."
                    pause_menu
                fi
                ;;
            2)
                local pcap_path
                pcap_path="$(read_input "Path to PCAP/PCAPNG capture file" "")"
                if [[ -n "$pcap_path" && -f "$pcap_path" ]]; then
                    "$MODULE_DIR/02_network_recon.sh" "$pcap_path" "$CURRENT_ACTIVE_CASE"
                    pause_menu
                else
                    warn "Valid PCAP file required."
                    pause_menu
                fi
                ;;
            3)
                local uname
                uname="$(read_input "Target Username" "")"
                if [[ -n "$uname" ]]; then
                    "$MODULE_DIR/03_identity_social.sh" "$uname" "$CURRENT_ACTIVE_CASE"
                    pause_menu
                fi
                ;;
            4)
                local email_target
                email_target="$(read_input "Target Email Address" "")"
                if [[ -n "$email_target" ]]; then
                    "$MODULE_DIR/04_email_breach.sh" "$email_target" "$CURRENT_ACTIVE_CASE"
                    pause_menu
                fi
                ;;
            5)
                local domain_target
                domain_target="$(read_input "Target Domain Name" "")"
                if [[ -n "$domain_target" ]]; then
                    "$MODULE_DIR/05_domain_dns.sh" "$domain_target" "$CURRENT_ACTIVE_CASE"
                    pause_menu
                fi
                ;;
            6)
                local doc_path
                doc_path="$(read_input "Path to Document (PDF/DOCX/RTF)" "")"
                if [[ -n "$doc_path" && -f "$doc_path" ]]; then
                    "$MODULE_DIR/06_document_harvesting.sh" "$doc_path" "$CURRENT_ACTIVE_CASE"
                    pause_menu
                else
                    warn "Valid document file required."
                    pause_menu
                fi
                ;;
            7)
                "$MODULE_DIR/07_opsec_anonymization.sh" "$CURRENT_ACTIVE_CASE"
                pause_menu
                ;;
            b|B|q|Q) return 0 ;;
            *) warn "Invalid selection."; pause_menu ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# MENU [6]: Findings
# -----------------------------------------------------------------------------
menu_findings() {
    ensure_active_case
    while true; do
        print_banner "Findings Management [Case: $CURRENT_ACTIVE_CASE]"
        local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
        python3 -c "
import json
data = json.load(open('$cpath/case.json'))
findings = data.get('findings', [])
if not findings:
    print('  No findings recorded for this case yet.\n')
else:
    print(f'  Total Findings: {len(findings)}\n')
    for f in findings:
        print(f\"  [{f.get('id','-')}] {f.get('title','Untitled')} (Severity: {f.get('severity','-')}, Conf: {f.get('confidence','-')})\")
        print(f\"    Type: {f.get('type','-')} | Module: {f.get('module','-')}\")
        print(f\"    Desc: {f.get('description','')[:90]}\")
        print()
"
        printf 'Actions: [A]dd Manual Finding   [B]ack to Main Menu\n'
        local f_act="$(read_input "Action" "B")"
        case "$f_act" in
            a|A)
                local f_title="$(read_input "Finding Title" "Analytical Finding")"
                local f_type="$(read_input "Type (metadata, vulnerability, account, network, credential)" "metadata")"
                local f_sev="$(read_input "Severity (info, low, medium, high, critical)" "info")"
                local f_conf="$(read_input "Confidence (low, medium, high, confirmed)" "confirmed")"
                local f_desc="$(read_input "Description & Evidence Details" "")"
                case_add_finding "$CURRENT_ACTIVE_CASE" "$f_title" "$f_type" "$f_sev" "$f_conf" "$f_desc" "Operator Analysis" ""
                info "Finding recorded successfully."
                pause_menu
                ;;
            b|B|q|Q|*) return 0 ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# MENU [7]: Timeline
# -----------------------------------------------------------------------------
menu_timeline() {
    ensure_active_case
    while true; do
        print_banner "Timeline Sequence [Case: $CURRENT_ACTIVE_CASE]"
        local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
        python3 -c "
import json
data = json.load(open('$cpath/case.json'))
events = data.get('timeline', [])
if not events:
    print('  No timeline events recorded yet.\n')
else:
    print(f'  Total Chronological Events: {len(events)}\n')
    for e in events:
        print(f\"  [{e.get('timestamp','-')}] {e.get('title','Untitled')} (Source: {e.get('source','-')})\")
        print(f\"    {e.get('description','')[:90]}\")
        print()
"
        printf 'Actions: [A]dd Manual Event   [B]ack to Main Menu\n'
        local t_act="$(read_input "Action" "B")"
        case "$t_act" in
            a|A)
                local ts="$(read_input "Timestamp (YYYY-MM-DD HH:MM:SS)" "$(date '+%Y-%m-%d %H:%M:%S')")"
                local title="$(read_input "Event Title" "Key Forensic Milestone")"
                local desc="$(read_input "Event Description" "")"
                local src="$(read_input "Source of Observation" "Manual Record")"
                case_add_timeline_event "$CURRENT_ACTIVE_CASE" "$ts" "$title" "$desc" "$src" ""
                info "Timeline event recorded."
                pause_menu
                ;;
            b|B|q|Q|*) return 0 ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# MENU [8]: IOCs
# -----------------------------------------------------------------------------
menu_iocs() {
    ensure_active_case
    while true; do
        print_banner "Threat Observables & IOCs [Case: $CURRENT_ACTIVE_CASE]"
        local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
        python3 -c "
import json
data = json.load(open('$cpath/case.json'))
iocs = data.get('iocs', [])
if not iocs:
    print('  No IOCs recorded yet.\n')
else:
    print(f'  Total Threat Indicators: {len(iocs)}\n')
    for i in iocs:
        print(f\"  [{i.get('id','-')}] {i.get('type','-')}: {i.get('value','-')}\")
        print(f\"    Context: {i.get('context','')[:80]} | First Seen: {i.get('first_seen','-')}\")
        print()
"
        printf 'Actions: [A]dd Manual IOC   [B]ack to Main Menu\n'
        local i_act="$(read_input "Action" "B")"
        case "$i_act" in
            a|A)
                local i_val="$(read_input "Indicator Value (IP, domain, hash, email, url)" "")"
                local i_type="$(read_input "Type (ipv4, domain, email, hash_sha256, url, username)" "domain")"
                local i_ctx="$(read_input "Threat Context" "Identified during OSINT triage")"
                case_add_ioc "$CURRENT_ACTIVE_CASE" "$i_val" "$i_type" "$i_ctx" "Operator Manual Record" ""
                info "IOC added to case registry."
                pause_menu
                ;;
            b|B|q|Q|*) return 0 ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# MENU [9]: Export / Reports
# -----------------------------------------------------------------------------
menu_export_reports() {
    ensure_active_case
    while true; do
        print_banner "Export Subsystem & Reporting [Case: $CURRENT_ACTIVE_CASE]"
        printf '  1) Export All Formats (CSV, TSV, JSON, STIX, MISP, KML, GeoJSON, HTML, MD, PDF, XLSX, DOCX)\n'
        printf '  2) HTML Interactive Dashboard Report\n'
        printf '  3) Markdown Investigation Report\n'
        printf '  4) PDF Executive Document\n'
        printf '  5) CSV & TSV Relational Tables Bundle (14 tables)\n'
        printf '  6) STIX 2.1 Threat Intelligence Bundle\n'
        printf '  7) MISP Event Threat Interchange\n'
        printf '  8) KML & GeoJSON Geospatial Maps\n'
        printf '  9) Timesketch Timeline Stream (JSONL)\n'
        printf '  10) Excel Workbook (.xlsx)\n'
        printf '  11) Word Report Document (.docx)\n'
        printf '  12) Redacted Export (Mask sensitive emails/IPs with stable placeholders)\n'
        printf '  13) Package Case Archive (.zip / .tar.gz with SHA-256 manifest)\n'
        printf '  B) Back to Main Menu\n\n'

        local exp_sel
        exp_sel="$(read_input "Select Export Format" "")"
        case "$exp_sel" in
            1) export_case_all "$CURRENT_ACTIVE_CASE" "false" && pause_menu ;;
            2) report_generate_html "$CURRENT_ACTIVE_CASE" && pause_menu ;;
            3) report_generate_markdown "$CURRENT_ACTIVE_CASE" && pause_menu ;;
            4) report_generate_pdf "$CURRENT_ACTIVE_CASE" && pause_menu ;;
            5) export_case_tabular "$CURRENT_ACTIVE_CASE" "false" && pause_menu ;;
            6) export_case_stix "$CURRENT_ACTIVE_CASE" "false" && pause_menu ;;
            7) export_case_misp "$CURRENT_ACTIVE_CASE" "false" && pause_menu ;;
            8) export_case_geo "$CURRENT_ACTIVE_CASE" "false" && pause_menu ;;
            9) export_case_timesketch "$CURRENT_ACTIVE_CASE" "false" && pause_menu ;;
            10) export_case_xlsx "$CURRENT_ACTIVE_CASE" "false" && pause_menu ;;
            11) export_case_docx "$CURRENT_ACTIVE_CASE" "false" && pause_menu ;;
            12) export_case_all "$CURRENT_ACTIVE_CASE" "true" && pause_menu ;;
            13)
                local p_fmt="$(read_input "Packaging format (zip or tar.gz)" "zip")"
                export_package_case "$CURRENT_ACTIVE_CASE" "$p_fmt"
                pause_menu
                ;;
            b|B|q|Q) return 0 ;;
            *) warn "Invalid export option."; pause_menu ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# MENU [T]: First-Party Omni Tools
# -----------------------------------------------------------------------------
menu_native_tools() {
    while true; do
        print_banner "First-Party Native Tools (traceforge-native)"
        printf '  1) Asset Relationship Graph          (Build graph from DNS/IP/certs/URLs)\n'
        printf '  2) Universal Snapshot Diff           (Diff DNS, HTTP, Asset, Metadata, Social)\n'
        printf '  3) Streaming IOC Extractor           (Extract/defang IPv4/IPv6/domain/email/hash)\n'
        printf '  4) Forensic Evidence Indexer         (Recursive case indexer with SHA-256)\n'
        printf '  5) UTC Timeline Normalizer           (Multi-source timestamp engine)\n'
        printf '  6) PCAP Flow & Protocol Summary      (Network flow and TLS SNI dissection)\n'
        printf '  7) Log Triage & Anomaly Detector     (Syslog, auth logs, web access)\n'
        printf '  8) Filesystem Baseline & Comparator  (Detect filesystem modifications)\n'
        printf '  9) Defensive Endpoint Snapshot       (Host environment & listening sockets)\n'
        printf '  10) Cross-Domain Correlation Engine  (Pivot observations across tools)\n'
        printf '  11) Deterministic Case Statistics    (Summarize active case metrics)\n'
        printf '  12) Portable Case Deliverable Packer (Generate SHA256SUMS and package zip/tar.gz)\n'
        printf '  B) Back to Main Menu\n\n'

        local sel
        sel="$(read_input "Select Tool" "")"
        case "$sel" in
            1)
                local file_path="$(read_input "Input file path (or empty for current case)" "")"
                if [[ -n "$file_path" && -f "$file_path" ]]; then
                    "$ROOT_DIR/bin/traceforge-native" asset graph "$file_path"
                elif [[ -n "$CURRENT_ACTIVE_CASE" ]]; then
                    local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                    "$ROOT_DIR/bin/traceforge-native" asset graph "$cpath/case.json"
                else
                    warn "Provide a valid input file or open a case."
                fi
                pause_menu
                ;;
            2)
                local m="$(read_input "Diff mode (dns|http|asset|metadata|recon|social)" "dns")"
                local f1="$(read_input "Old file" "")"
                local f2="$(read_input "New file" "")"
                if [[ -f "$f1" && -f "$f2" ]]; then
                    "$ROOT_DIR/bin/traceforge-native" diff "$m" "$f1" "$f2"
                else
                    warn "Both files must exist."
                fi
                pause_menu
                ;;
            3)
                local f="$(read_input "Target text or log file" "")"
                if [[ -f "$f" ]]; then
                    "$ROOT_DIR/bin/traceforge-native" ioc extract "$f"
                else
                    warn "File not found: $f"
                fi
                pause_menu
                ;;
            4)
                local d="$(read_input "Directory to index" ".")"
                "$ROOT_DIR/bin/traceforge-native" evidence index "$d"
                pause_menu
                ;;
            5)
                local f="$(read_input "Event file (JSONL or text)" "")"
                if [[ -f "$f" ]]; then
                    "$ROOT_DIR/bin/traceforge-native" timeline sort "$f"
                else
                    warn "File not found: $f"
                fi
                pause_menu
                ;;
            6)
                local f="$(read_input "PCAP file" "")"
                if [[ -f "$f" ]]; then
                    "$ROOT_DIR/bin/traceforge-native" pcap summary "$f"
                else
                    warn "File not found: $f"
                fi
                pause_menu
                ;;
            7)
                local f="$(read_input "Log file to triage" "")"
                if [[ -f "$f" ]]; then
                    "$ROOT_DIR/bin/traceforge-native" log triage "$f"
                else
                    warn "File not found: $f"
                fi
                pause_menu
                ;;
            8)
                local sub="$(read_input "Action (baseline or compare)" "baseline")"
                if [[ "$sub" == "baseline" ]]; then
                    local d="$(read_input "Directory" ".")"
                    local out="$(read_input "Output file" "baseline.json")"
                    "$ROOT_DIR/bin/traceforge-native" files baseline "$d" --out "$out"
                else
                    local b1="$(read_input "Old baseline.json" "")"
                    local b2="$(read_input "New baseline.json" "")"
                    if [[ -f "$b1" && -f "$b2" ]]; then
                        "$ROOT_DIR/bin/traceforge-native" files compare "$b1" "$b2"
                    fi
                fi
                pause_menu
                ;;
            9)
                "$ROOT_DIR/bin/traceforge-native" endpoint inspect
                pause_menu
                ;;
            10)
                local f="$(read_input "Observations JSONL file" "")"
                if [[ -f "$f" ]]; then
                    "$ROOT_DIR/bin/traceforge-native" correlate "$f"
                fi
                pause_menu
                ;;
            11)
                ensure_active_case
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                "$ROOT_DIR/bin/traceforge-native" summarize "$cpath"
                pause_menu
                ;;
            12)
                ensure_active_case
                local cpath="$(case_get_path "$CURRENT_ACTIVE_CASE")"
                local fmt="$(read_input "Package format (zip|tar.gz)" "zip")"
                "$ROOT_DIR/bin/traceforge-native" case pack "$cpath" --format "$fmt"
                pause_menu
                ;;
            b|B|q|Q) return 0 ;;
            *) warn "Invalid selection."; pause_menu ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# TOOL DETAILS & DISPATCHER
# -----------------------------------------------------------------------------
show_tool_details() {
    local query=$1
    local rec=""
    if [[ "$query" =~ ^[0-9]+$ ]]; then
        rec="$(catalog_get_by_id "$query")"
    else
        rec="$(catalog_get_by_binary "$query")"
    fi

    if [[ -z "$rec" ]]; then
        warn "Tool not found in catalog: $query"
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
        printf '  %-18s : %s\n' "Installed" "$is_inst ($bin_path)"
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
                    warn "$t_bin is not installed on PATH. Run [I]nstall first."
                    pause_menu
                else
                    local raw_args
                    raw_args="$(read_input "Arguments for $t_bin" "--help")"
                    local -a p_args=($raw_args)
                    printf '\n%b--- Executing: %s %s ---%b\n' "$C_CYAN" "$t_bin" "$raw_args" "$C_RESET"
                    "$t_bin" "${p_args[@]}" || true
                    printf '%b--- End of execution ---%b\n' "$C_CYAN" "$C_RESET"
                    pause_menu
                fi
                ;;
            i|I)
                "$SCRIPTS_DIR/install_tool.sh" "$t_bin"
                if need_cmd "$t_bin"; then
                    is_inst="Yes"
                    bin_path="$(command -v "$t_bin")"
                fi
                pause_menu
                ;;
            h|H)
                if [[ "$is_inst" != "Yes" ]]; then
                    info "Tool not installed. Showing catalog description:"
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

# -----------------------------------------------------------------------------
# MENU [A]: Tool Catalog
# -----------------------------------------------------------------------------
menu_tool_catalog() {
    while true; do
        print_banner "Audited Tool Catalog (151 Verified Tools)"
        printf '  1) Browse by Domain / Category\n'
        printf '  2) Search Tools (Name, Binary, Category, Keyword)\n'
        printf '  3) Inspect / Run Tool by ID or Binary Name\n'
        printf '  4) Installed Tools Audit (Local PATH Status)\n'
        printf '  5) Install Single Tool\n'
        printf '  B) Back to Main Menu\n\n'

        local choice
        choice="$(read_input "Select Option" "")"
        case "$choice" in
            1)
                local -a categories=()
                while IFS= read -r c; do categories+=("$c"); done < <(catalog_list_categories)
                print_banner "Select Investigation Domain"
                for i in "${!categories[@]}"; do printf '  %2d) %s\n' "$((i+1))" "${categories[$i]}"; done
                local c_sel
                c_sel="$(read_input "Category Number" "")"
                if [[ "$c_sel" =~ ^[0-9]+$ && "$c_sel" -ge 1 && "$c_sel" -le "${#categories[@]}" ]]; then
                    local sel_cat="${categories[$((c_sel-1))]}"
                    print_banner "Domain: $sel_cat"
                    catalog_filter_by_category "$sel_cat" | awk -F '\t' '{printf "[%3s] %-20s %-16s %-10s %s\n", $1, $2, $3, $6, substr($9,1,45)}'
                    printf '\nEnter a Tool ID to inspect, or press [Enter] to go back: '
                    local t_inspect
                    t_inspect="$(read_input "" "")"
                    if [[ -n "$t_inspect" ]]; then
                        show_tool_details "$t_inspect"
                    fi
                fi
                ;;
            2)
                local q
                q="$(read_input "Search Query" "")"
                if [[ -n "$q" ]]; then
                    print_banner "Search Results for '$q'"
                    catalog_search "$q" | awk -F '\t' '{printf "[%3s] %-20s %-16s %-10s %s\n", $1, $2, $3, $6, substr($9,1,45)}'
                    printf '\nEnter a Tool ID to inspect, or press [Enter] to go back: '
                    local t_inspect
                    t_inspect="$(read_input "" "")"
                    if [[ -n "$t_inspect" ]]; then
                        show_tool_details "$t_inspect"
                    fi
                fi
                ;;
            3)
                local t_query
                t_query="$(read_input "Enter Tool ID or Binary" "")"
                if [[ -n "$t_query" ]]; then
                    show_tool_details "$t_query"
                fi
                ;;
            4)
                print_banner "Local Tool Installation Audit"
                local tot=0 inst=0
                while IFS=$'\t' read -r id name bin rest; do
                    [[ "$id" == "id" ]] && continue
                    tot=$((tot+1))
                    if need_cmd "$bin"; then
                        printf '  %b[✓]%b %-20s (%s)\n' "$C_GREEN" "$C_RESET" "$name" "$bin"
                        inst=$((inst+1))
                    else
                        printf '  %b[✗]%b %-20s (%s)\n' "$C_RED" "$C_RESET" "$name" "$bin"
                    fi
                done < "$CATALOG_PATH"
                printf '\nTotal Audited Tools: %s\nInstalled on PATH  : %s\nMissing/Optional   : %s\n' "$tot" "$inst" "$((tot-inst))"
                pause_menu
                ;;
            5)
                local t_in
                t_in="$(read_input "Tool ID or Binary to install" "")"
                if [[ -n "$t_in" ]]; then
                    "$SCRIPTS_DIR/install_tool.sh" "$t_in"
                    pause_menu
                fi
                ;;
            b|B|q|Q) return 0 ;;
            *) warn "Invalid selection."; pause_menu ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# MENU [H]: Descriptive Help & Reference Center
# -----------------------------------------------------------------------------
menu_help_center() {
    while true; do
        print_banner "Help & Reference Center"
        printf '  1) Master System Overview & Case Model\n'
        printf '  2) Main Menu & Console Guide\n'
        printf '  3) Investigation Modules Reference (All 7 Engines)\n'
        printf '  4) Multi-Format Export Subsystem\n'
        printf '  5) Tool Catalog & Ecosystem Isolation\n'
        printf '  6) CLI Subcommands & Automation Guide\n'
        printf '  7) Forensic Chain of Custody & OPSEC Directives\n'
        printf '  B) Back to Main Menu\n\n'

        local h_choice
        h_choice="$(read_input "Select Help Topic" "")"
        case "$h_choice" in
            1)
                print_banner "System Architecture & Case Model"
                cat << 'EOF'
TraceForge is a command-line toolkit for OSINT investigations and digital forensics.

CORE PRINCIPLES:
1. Case-Based Workspaces:
   Every investigation is stored under workspace/ with a unique ID (e.g. CASE-20260825-ABC123).
   Metadata, evidence records, findings, IOCs, and timeline events are tracked in case.json.

2. Read-Only Evidence:
   Original files are treated as read-only. Ingested files receive a SHA-256 hash
   and are copied to evidence/ with an entry logged to manifest/evidence-chain.jsonl.

3. Export Pipeline:
   Reports (Markdown, HTML, PDF, Word) and data exports (CSV, TSV, JSON, JSONL,
   XLSX, STIX 2.1, MISP, KML) are generated directly from the case model.

4. Defensive Security:
   Tool arguments are passed using structured arrays to prevent shell injection.
EOF
                pause_menu
                ;;
            2)
                print_banner "Main Menu Guide"
                cat << 'EOF'
MAIN MENU OPTIONS:

[1] New Case       : Create a new investigation folder in workspace/.
[2] Open Case      : Switch active case focus.
[3] List Cases     : View all cases in the workspace with evidence counts.
[4] Add Evidence   : Ingest external files with SHA-256 integrity hashing.
[5] Run Module     : Run one of 7 analysis modules against a target.
[6] Findings       : Record and review investigation findings.
[7] Timeline       : View chronological event milestones.
[8] IOCs           : Manage observables (IPs, domains, hashes, emails).
[9] Export/Reports : Export case data to HTML, Markdown, CSV, STIX, etc.
[A] Tool Catalog   : Search, inspect, and run 151 supported tools.
[D] Doctor         : Check dependencies and environment status.
[H] Help Center    : View usage documentation.
[Q] Quit           : Exit the suite.
EOF
                pause_menu
                ;;
            3)
                print_banner "Investigation Modules"
                cat << 'EOF'
INVESTIGATION MODULES:

01. Image & Media Forensics (modules/01_image_forensics.sh)
    - Input: Images (JPG, PNG, HEIC) or video files.
    - Tools: ExifTool, Binwalk, xxd, zsteg, SoX.
    - Extracts EXIF metadata, GPS tags, hidden strings, and embedded data.

02. Network & PCAP Forensics (modules/02_network_recon.sh)
    - Input: Packet captures (PCAP, PCAPNG, CAP).
    - Tools: TShark, capinfos, Aircrack-NG, editcap.
    - Summarizes DNS queries, HTTP requests, TLS SNI headers, and conversations.

03. Identity & Social Research (modules/03_identity_social.sh)
    - Input: Username or alias.
    - Tools: Sherlock, Maigret, Blackbird, Socialscan.
    - Checks username availability across social and web platforms.

04. Email & Breach Intelligence (modules/04_email_breach.sh)
    - Input: Email address.
    - Tools: Holehe, h8mail, EmailRep, theHarvester, checkdmarc.
    - Checks account registrations, breach dumps, and SPF/DMARC posture.

05. Domain & DNS Intelligence (modules/05_domain_dns.sh)
    - Input: Domain name.
    - Tools: dig, whois, subfinder, amass, assetfinder, dnsx, httpx, dnstwist.
    - Resolves DNS records, discovers subdomains, probes HTTP, and checks typosquats.

06. Document & Metadata Harvesting (modules/06_document_harvesting.sh)
    - Input: Documents (PDF, DOCX, DOC, XLSX, RTF).
    - Tools: Poppler, oletools, ExifTool, qpdf, mutool, ripgrep.
    - Extracts document properties, text, embedded objects, macros, and API keys.

07. OPSEC & Environment Audit (modules/07_opsec_anonymization.sh)
    - Input: Local system audit.
    - Tools: MAT2, Tor, Proxychains, WireGuard, Privoxy, GnuPG, age, OpenSSL.
    - Checks privacy tools, DNS leak protection, and local encryption tools.
EOF
                pause_menu
                ;;
            4)
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
            5)
                print_banner "Tool Catalog & Package Management"
                cat << 'EOF'
CENTRAL CATALOG (catalog/tools.tsv):
Contains 151 tools categorized across 7 investigation domains.

PACKAGE TIERS:
- native   : System packages installed via Homebrew (macOS) or APT (Linux).
- pipx     : Isolated Python CLI tools in virtual environments (PEP 668).
- go       : Go binaries installed via 'go install' into $HOME/go/bin.
- ruby_gem : Ruby tools installed via user gems.
- cargo    : Rust tools compiled via Cargo into $HOME/.cargo/bin.
- manual   : Tools requiring manual download or third-party API keys.
EOF
                pause_menu
                ;;
            6)
                print_banner "CLI Usage Guide"
                cat << 'EOF'
COMMAND-LINE USAGE:

1. Interactive Menu:
   ./main.sh

2. Exporting Cases:
   ./main.sh export CASE-20260825-ABC123 --all
   ./main.sh export CASE-20260825-ABC123 --format html
   ./main.sh export CASE-20260825-ABC123 --format csv
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
            7)
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
            b|B|q|Q) return 0 ;;
            *) warn "Invalid selection."; pause_menu ;;
        esac
    done
}

show_legal_notice() {
    print_banner "Responsible Use & Legal Notices"
    cat << 'EOF'
TraceForge is intended for lawful OSINT, digital forensics, incident response,
security research, authorized testing, education, and lab work.

KEY POLICIES:
1. Authorization Required:
   TraceForge is a software toolkit and does NOT grant permission to access,
   probe, or interact with any system, account, network, device, or API.
   Active operations require documented, explicit authorization from system owners.

2. Open-Source Information & Public Availability:
   Publicly accessible data is NOT exempt from privacy laws (GDPR, CCPA), terms of
   service, anti-harassment rules, or computer access regulations.

3. Evidence Integrity:
   Preserve original evidence. Never perform metadata removal or destructive tests
   on original files. Use derived working copies.

4. No Legal Advice:
   TraceForge documentation does not constitute legal advice. Consult qualified
   legal counsel in your jurisdiction for regulatory and compliance guidance.

Full Documentation:
  - DISCLAIMER.md       : Legal boundaries, accuracy notices, liability terms
  - RESPONSIBLE_USE.md  : Scope of engagement, active scanning, prohibited use
  - PRIVACY.md          : Local storage footprint, data minimization, redaction
  - SECURITY.md         : Coordinated vulnerability disclosure process
  - THIRD_PARTY_NOTICES : Third-party licenses and upstream attribution
EOF
}

menu_legal() {
    show_legal_notice
    pause_menu
}

# -----------------------------------------------------------------------------
# MAIN INTERACTIVE LOOP
# -----------------------------------------------------------------------------
main_menu() {
    ensure_active_case
    local raw_choice choice prof
    prof="PYTHON-GO"
    if need_cmd python3; then
        prof=$(python3 -c "from traceforge.config import get_runtime_profile; print(get_runtime_profile().upper())" 2>/dev/null || echo "PYTHON-GO")
    fi
    while true; do
        print_banner "OSINT & Forensics Command Center"
        printf '  Active Case: %b%s%b  •  Runtime Profile: %b%s%b\n\n' "$C_GREEN" "$CURRENT_ACTIVE_CASE" "$C_RESET" "$C_CYAN" "$prof" "$C_RESET"

        printf '  %b[1]%b New Case                 (Create a new investigation case)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[2]%b Open Case                (Switch active case)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[3]%b List Cases               (List all cases in workspace)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[4]%b Add Evidence             (Import files with SHA-256 integrity hash)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[5]%b Run Investigation        (Execute one of 7 analysis modules)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[6]%b Findings                 (View and record investigation findings)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[7]%b Timeline                 (View and add chronological events)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[8]%b IOCs                     (Manage threat observables and indicators)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[9]%b Export / Reports         (Export case to HTML, Markdown, CSV, STIX)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[T]%b Native Tools             (First-party native engine: graph, diff, ioc, triage)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[A]%b Tool Catalog             (Search, inspect, and run 152 tools)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[P]%b Profile / Settings       (Configure runtime profile & fast-paths)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[D]%b Doctor                   (Check dependencies and system health)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[L]%b Legal / Policy           (Responsible use, disclaimers, privacy)\n' "$C_BOLD" "$C_RESET"
        if [[ "$OS_TYPE" == "termux" ]]; then
            printf '  %b[M]%b Termux Guide             (Android storage and Termux:API status)\n' "$C_BOLD" "$C_RESET"
        fi
        printf '  %b[H]%b Help Center              (Usage guide and command reference)\n' "$C_BOLD" "$C_RESET"
        printf '  %b[Q]%b Quit\n\n' "$C_BOLD" "$C_RESET"

        raw_choice="$(read_input "Select Option" "")"
        choice="$(echo "$raw_choice" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"

        case "$choice" in
            1) menu_new_case ;;
            2) menu_open_case ;;
            3) menu_list_cases ;;
            4) menu_add_evidence ;;
            5) menu_run_investigation ;;
            6) menu_findings ;;
            7) menu_timeline ;;
            8) menu_iocs ;;
            9) menu_export_reports ;;
            T|TOOLS|OMNI-TOOLS|NATIVE) menu_native_tools ;;
            A) menu_tool_catalog ;;
            P|PROFILE|SETTINGS)
                if need_cmd python3; then
                    python3 -m traceforge.cli profile
                else
                    info "Profile: python-go"
                fi
                pause_menu
                ;;
            D|DOCTOR|STATUS) "$SCRIPTS_DIR/doctor.sh"; pause_menu ;;
            M|TERMUX)
                if need_cmd python3; then
                    python3 -m traceforge.cli termux
                else
                    info "Termux platform support active."
                fi
                pause_menu
                ;;
            L|LEGAL|DISCLAIMER) menu_legal ;;
            H|HELP|\?) menu_help_center ;;
            SEARCH|FIND)
                local q="$(read_input "Search Query" "")"
                if [[ -n "$q" ]]; then
                    print_banner "Search Results for '$q'"
                    catalog_search "$q" | awk -F '\t' '{printf "[%3s] %-20s %-16s %-10s %s\n", $1, $2, $3, $6, substr($9,1,45)}'
                    pause_menu
                fi
                ;;
            CLS|CLEAR) clear ;;
            Q|QUIT|EXIT)
                info "Exiting TraceForge."
                exit 0
                ;;
            *)
                warn "Unknown command: '$raw_choice'. Select 1-9, T, A, D, L, H, or Q."
                pause_menu
                ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# CLI ENTRYPOINT & SUBCOMMAND ROUTING
# -----------------------------------------------------------------------------
if [[ $# -gt 0 ]]; then
    case "$1" in
        traceforge-native|native-tools|omni-tools|tools)
            shift
            "$ROOT_DIR/bin/traceforge-native" "$@"
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
                info "Profile: python-go"
            fi
            exit 0
            ;;
        termux)
            shift
            if need_cmd python3; then
                python3 -m traceforge.cli termux "$@"
            else
                info "Termux platform documentation: docs/platforms/termux.md"
            fi
            exit 0
            ;;
        legal|disclaimer|--legal)
            show_legal_notice
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
                err "Search query required: ./main.sh --search <query>"
                exit 1
            fi
            exit 0
            ;;
        module|--module|-m)
            shift
            if [[ $# -eq 0 ]]; then
                err "Module number or target required: ./main.sh --module <1..7> [target] [case-id]"
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
                *) err "Unknown module: $m_num"; exit 1 ;;
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
            err "Unknown CLI argument: $1"
            printf 'Run `./main.sh --help` for available commands.\n'
            exit 1
            ;;
    esac
fi

main_menu
