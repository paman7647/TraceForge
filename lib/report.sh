#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — lib/report.sh
# Generates human-facing Markdown, Standalone HTML Dashboard & PDF Reports
# =============================================================================

# Prevent double inclusion
if [[ -n "${_TRACEFORGE_REPORT_SH_LOADED:-}" ]]; then
    return 0
fi
_TRACEFORGE_REPORT_SH_LOADED=1

# shellcheck source=lib/common.sh
source "$(project_root)/lib/common.sh"
# shellcheck source=lib/case.sh
source "$(project_root)/lib/case.sh"

# Generate Markdown Report: reports/CASE-ID.md
report_generate_markdown() {
    local case_id=$1
    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"
    mkdir -p "$case_path/reports"

    python3 "$(project_root)/scripts/export_engine.py" "$case_path/case.json" --out-dir "$case_path/reports" --format md >/dev/null 2>&1
    info "Generated Markdown report: $case_path/reports/${case_id}.md"
}

# Generate Standalone Responsive HTML Report: reports/CASE-ID.html
report_generate_html() {
    local case_id=$1
    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"
    mkdir -p "$case_path/reports"

    python3 "$(project_root)/scripts/export_engine.py" "$case_path/case.json" --out-dir "$case_path/reports" --format html >/dev/null 2>&1
    info "Generated HTML report: $case_path/reports/${case_id}.html"
}

# Generate PDF Report: reports/CASE-ID.pdf
report_generate_pdf() {
    local case_id=$1
    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"
    local html_file="$case_path/reports/${case_id}.html"
    local pdf_file="$case_path/reports/${case_id}.pdf"

    if [[ ! -f "$html_file" ]]; then
        report_generate_html "$case_id"
    fi

    # Try supported PDF renderers
    if need_cmd wkhtmltopdf; then
        wkhtmltopdf --enable-local-file-access "$html_file" "$pdf_file" >/dev/null 2>&1 || true
    elif need_cmd weasyprint; then
        weasyprint "$html_file" "$pdf_file" >/dev/null 2>&1 || true
    elif need_cmd google-chrome; then
        google-chrome --headless --disable-gpu --print-to-pdf="$pdf_file" "$html_file" >/dev/null 2>&1 || true
    elif need_cmd chromium; then
        chromium --headless --disable-gpu --print-to-pdf="$pdf_file" "$html_file" >/dev/null 2>&1 || true
    fi

    if [[ -f "$pdf_file" ]]; then
        info "Generated PDF report: $pdf_file"
        return 0
    else
        warn "PDF renderer (wkhtmltopdf/weasyprint/chromium) not found. HTML report preserved: $html_file"
        return 1
    fi
}
