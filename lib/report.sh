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

# Helper to run python CLI exporter
_run_python_exporter() {
    local case_id=$1
    local fmt=$2
    local out_dir=$3
    local redact=${4:-"false"}

    local py_bin="python3"
    local venv_py="$(project_root)/.venv/bin/python"
    local osint_py="$(project_root)/.osint_venv/bin/python"
    if [[ -x "$venv_py" ]]; then
        py_bin="$venv_py"
    elif [[ -x "$osint_py" ]]; then
        py_bin="$osint_py"
    fi

    "$py_bin" -c "
import sys
from traceforge.case import Case
from traceforge.exporters import CaseExporter
c = Case('$case_id')
if not c.exists():
    sys.exit(1)
exp = CaseExporter(c, redact=('$redact' == 'true'))
if '$fmt' == 'md':
    exp.export_markdown('$out_dir/$case_id.md')
elif '$fmt' == 'html':
    exp.export_html('$out_dir/$case_id.html')
elif '$fmt' == 'json':
    exp.export_json('$out_dir/$case_id.json')
elif '$fmt' == 'stix':
    exp.export_stix('$out_dir/${case_id}_stix21.json')
elif '$fmt' == 'misp':
    exp.export_misp('$out_dir/${case_id}_misp.json')
elif '$fmt' == 'geo':
    exp.export_geojson('$out_dir/$case_id.geojson')
    exp.export_kml('$out_dir/$case_id.kml')
elif '$fmt' == 'timesketch':
    exp.export_jsonl_timeline('$out_dir/${case_id}_timeline.jsonl')
elif '$fmt' == 'tabular' or '$fmt' == 'csv':
    exp.export_csv_iocs('$out_dir/iocs.csv')
    exp.export_csv_evidence('$out_dir/evidence.csv')
    exp.export_csv_findings('$out_dir/findings.csv')
    exp.export_csv_timeline('$out_dir/timeline.csv')
elif '$fmt' == 'xlsx':
    exp.export_xlsx('$out_dir/$case_id.xlsx')
elif '$fmt' == 'docx':
    exp.export_docx('$out_dir/$case_id.docx')
else:
    exp.export_all('$out_dir')
"
}

# Generate Markdown Report: reports/CASE-ID.md
report_generate_markdown() {
    local case_id=$1
    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"
    mkdir -p "$case_path/reports"

    _run_python_exporter "$case_id" "md" "$case_path/reports" "false" >/dev/null 2>&1 || true
    log_info "Generated Markdown report: $case_path/reports/${case_id}.md"
}

# Generate Standalone Responsive HTML Report: reports/CASE-ID.html
report_generate_html() {
    local case_id=$1
    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"
    mkdir -p "$case_path/reports"

    _run_python_exporter "$case_id" "html" "$case_path/reports" "false" >/dev/null 2>&1 || true
    log_info "Generated HTML report: $case_path/reports/${case_id}.html"
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
        log_info "Generated PDF report: $pdf_file"
        return 0
    else
        log_warn "PDF renderer (wkhtmltopdf/weasyprint/chromium) not found. HTML report preserved: $html_file"
        return 1
    fi
}
