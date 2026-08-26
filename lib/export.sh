#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — lib/export.sh
# Export Subsystem Coordinator & Evidence Packaging
# =============================================================================

# Prevent double inclusion
if [[ -n "${_TRACEFORGE_EXPORT_SH_LOADED:-}" ]]; then
    return 0
fi
_TRACEFORGE_EXPORT_SH_LOADED=1

# shellcheck source=lib/common.sh
source "$(project_root)/lib/common.sh"
# shellcheck source=lib/case.sh
source "$(project_root)/lib/case.sh"
# shellcheck source=lib/report.sh
source "$(project_root)/lib/report.sh"

# Master Export Function
case_export() {
    local case_id=$1
    local export_fmt=${2:-"all"}   # all, csv, tsv, json, jsonl, xlsx, docx, html, pdf, md, stix, misp, geo, timesketch
    local is_redact=${3:-"false"}
    local severity_filter=${4:-""}
    local conf_filter=${5:-""}

    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"
    local case_json="$case_path/case.json"

    local export_base_dir="$case_path/exports"
    if [[ "$is_redact" == "true" ]]; then
        export_base_dir="$case_path/exports/redacted"
    fi
    mkdir -p "$export_base_dir"

    log_info "Starting export for Case: $case_id [Format: $export_fmt | Redacted: $is_redact]"

    # 1. Generate Markdown & HTML Reports first
    report_generate_markdown "$case_id"
    report_generate_html "$case_id"
    if [[ "$export_fmt" == "pdf" || "$export_fmt" == "all" ]]; then
        report_generate_pdf "$case_id" || true
    fi

    # 2. Invoke Python Exporter Engine directly
    _run_python_exporter "$case_id" "$export_fmt" "$export_base_dir" "$is_redact"

    # Copy human reports into exports folder
    mkdir -p "$export_base_dir/report"
    cp -f "$case_path/reports"/* "$export_base_dir/report/" 2>/dev/null || true

    # 3. Generate EXPORT-MANIFEST.txt and SHA256SUMS
    log_step "Generating export manifest and cryptographic checksums..."
    find "$export_base_dir" -type f | sort > "$export_base_dir/EXPORT-MANIFEST.txt"
    (
        cd "$export_base_dir" && \
        find . -type f -not -name 'SHA256SUMS' -not -name 'EXPORT-MANIFEST.txt' -print0 | \
        (xargs -0 shasum -a 256 2>/dev/null || xargs -0 sha256sum 2>/dev/null || true)
    ) > "$export_base_dir/SHA256SUMS"

    case_log_chain "$case_id" "CASE_EXPORTED" "N/A" "N/A" "N/A" "export.sh" "Exported $export_fmt (Redacted: $is_redact)"
    log_ok "Case export completed successfully: $export_base_dir"
}

# Individual format export shortcuts
export_case_all() { case_export "$1" "all" "${2:-false}" "" ""; }
export_case_tabular() { case_export "$1" "tabular" "${2:-false}" "" ""; }
export_case_stix() { case_export "$1" "stix" "${2:-false}" "" ""; }
export_case_misp() { case_export "$1" "misp" "${2:-false}" "" ""; }
export_case_geo() { case_export "$1" "geo" "${2:-false}" "" ""; }
export_case_timesketch() { case_export "$1" "timesketch" "${2:-false}" "" ""; }
export_case_xlsx() { case_export "$1" "xlsx" "${2:-false}" "" ""; }
export_case_docx() { case_export "$1" "docx" "${2:-false}" "" ""; }

# Package case into ZIP / TAR.GZ archive
case_package_archive() {
    local case_id=$1
    local pkg_type=${2:-"zip"}     # zip or tar
    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"

    # Make sure exports exist
    case_export "$case_id" "all" "false" "" ""

    local out_archive=""
    if [[ "$pkg_type" == "zip" ]]; then
        out_archive="$case_path/${case_id}-package.zip"
        (cd "$case_path" && zip -r -q "$out_archive" reports/ exports/ manifest/ case.json case.yml 2>/dev/null || true)
    else
        out_archive="$case_path/${case_id}-package.tar.gz"
        (cd "$case_path" && tar -czf "$out_archive" reports/ exports/ manifest/ case.json case.yml 2>/dev/null || true)
    fi

    if [[ -f "$out_archive" ]]; then
        local arch_hash
        arch_hash="$(hash_file "$out_archive")"
        log_ok "Packaged case archive: $out_archive"
        log_info "Archive SHA-256 Digest: $arch_hash"
        printf '%s\n' "$out_archive"
    else
        log_warn "Archive creation failed. Verify tar or zip is installed."
    fi
}

export_package_case() {
    case_package_archive "$1" "${2:-zip}"
}
