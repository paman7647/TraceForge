#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — Module 06: Document & Metadata Harvesting
# Local document triage: PDF/Office metadata, text extraction, macros, secrets.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"

INPUT_DOC=${1:-""}

if [[ "$INPUT_DOC" == "--help" || "$INPUT_DOC" == "-h" ]]; then
    printf 'TraceForge Module 06 — Document & Metadata Harvesting\n\nUsage:\n  %s <document-file>\n' "$0"
    exit 0
fi

if [[ -z "$INPUT_DOC" ]]; then
    printf 'Usage: %s <document-file>\n' "$0" >&2
    exit 1
fi


if [[ ! -f "$INPUT_DOC" ]]; then
    die "Document file does not exist: $INPUT_DOC"
fi

if [[ ! -r "$INPUT_DOC" ]]; then
    die "Document file is not readable (check permissions): $INPUT_DOC"
fi

ABS_DOC="$(CDPATH='' cd -- "$(dirname -- "$INPUT_DOC")" && pwd -P)/$(basename -- "$INPUT_DOC")"
BASE_NAME="$(basename -- "$ABS_DOC")"

RUN_DIR="$(make_run_dir "$ROOT_DIR" "doc_${BASE_NAME}")"
REPORT="$RUN_DIR/report.txt"

info "Initiating Document & Metadata Harvesting on: $BASE_NAME"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Document & Metadata Harvesting Report\n'
    printf '===============================================================================\n'
    printf 'Evidence File : %s\n' "$ABS_DOC"
    printf 'File Size     : %s bytes\n' "$(wc -c < "$ABS_DOC" | tr -d ' ')"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. MIME and Document Type Identification
step "Identifying document container and MIME structure..."
DOC_MIME="$(file -b --mime-type "$ABS_DOC" 2>/dev/null || echo "unknown")"
DOC_DESC="$(file -b "$ABS_DOC" 2>/dev/null || echo "unknown")"
DOC_EXT="${BASE_NAME##*.}"
DOC_EXT="$(echo "$DOC_EXT" | tr '[:upper:]' '[:lower:]')"

{
    echo '[1] DOCUMENT IDENTIFICATION'
    printf 'MIME Type      : %s\n' "$DOC_MIME"
    printf 'Description    : %s\n' "$DOC_DESC"
    printf 'Extension      : .%s\n\n' "$DOC_EXT"
} | tee "$RUN_DIR/doc_id.txt" >> "$REPORT"

# 2. Universal ExifTool Metadata Dump
step "Extracting global document metadata via ExifTool..."
if need_cmd exiftool; then
    exiftool -a -u -g1 "$ABS_DOC" > "$RUN_DIR/exiftool_full.txt" 2>&1 || true
    exiftool -j -a -u -g1 "$ABS_DOC" > "$RUN_DIR/metadata.json" 2>&1 || true
    {
        echo '[2] KEY DOCUMENT PROPERTIES'
        printf 'Title          : %s\n' "$(exiftool -s3 -Title "$ABS_DOC" 2>/dev/null || echo "N/A")"
        printf 'Author / Artist: %s\n' "$(exiftool -s3 -Author -Artist -Creator "$ABS_DOC" 2>/dev/null | head -n 1 || echo "N/A")"
        printf 'Producer / App : %s\n' "$(exiftool -s3 -Producer -CreatorTool "$ABS_DOC" 2>/dev/null | head -n 1 || echo "N/A")"
        printf 'Creation Date  : %s\n' "$(exiftool -s3 -CreateDate -CreationDate "$ABS_DOC" 2>/dev/null | head -n 1 || echo "N/A")"
        printf 'Modify Date    : %s\n' "$(exiftool -s3 -ModifyDate -ModDate "$ABS_DOC" 2>/dev/null | head -n 1 || echo "N/A")"
        printf 'Last Modified By: %s\n' "$(exiftool -s3 -LastModifiedBy "$ABS_DOC" 2>/dev/null || echo "N/A")"
        printf 'Revision / Count: %s\n\n' "$(exiftool -s3 -RevisionNumber -PageCount "$ABS_DOC" 2>/dev/null | tr '\n' ' ' || echo "N/A")"
    } | tee "$RUN_DIR/properties_summary.txt" >> "$REPORT"
fi

# 3. PDF-Specific Analysis
if [[ "$DOC_MIME" == *"pdf"* || "$DOC_EXT" == "pdf" ]]; then
    step "Running dedicated PDF extraction suite (Poppler, QPDF)..."
    mkdir -p "$RUN_DIR/pdf_extracted"

    if need_cmd pdfinfo; then
        pdfinfo "$ABS_DOC" > "$RUN_DIR/pdf_extracted/pdfinfo.txt" 2>&1 || true
    fi

    if need_cmd pdftotext; then
        pdftotext -layout "$ABS_DOC" "$RUN_DIR/pdf_extracted/extracted_text.txt" 2>/dev/null || true
    fi

    if need_cmd pdfimages; then
        mkdir -p "$RUN_DIR/pdf_extracted/images"
        pdfimages -png "$ABS_DOC" "$RUN_DIR/pdf_extracted/images/img" 2>/dev/null || true
    fi

    if need_cmd qpdf; then
        qpdf --check "$ABS_DOC" > "$RUN_DIR/pdf_extracted/qpdf_check.txt" 2>&1 || true
    fi

    if need_cmd peepdf; then
        peepdf -f "$ABS_DOC" > "$RUN_DIR/pdf_extracted/peepdf_analysis.txt" 2>&1 || true
    fi

    if need_cmd pdfid; then
        pdfid "$ABS_DOC" > "$RUN_DIR/pdf_extracted/pdfid_scan.txt" 2>&1 || true
    fi
fi

# 4. Office Document & Macro / OLE Analysis
if [[ "$DOC_MIME" == *"msword"* || "$DOC_MIME" == *"officedocument"* || "$DOC_MIME" == *"ms-excel"* || "$DOC_EXT" =~ ^(doc|docx|xls|xlsx|ppt|pptx|docm|xlsm)$ ]]; then
    step "Running OLE and Office macro analysis (oletools)..."
    mkdir -p "$RUN_DIR/office_analysis"

    if need_cmd olevba; then
        olevba "$ABS_DOC" > "$RUN_DIR/office_analysis/olevba_macros.txt" 2>&1 || true
    fi

    if need_cmd oleid; then
        oleid "$ABS_DOC" > "$RUN_DIR/office_analysis/oleid_indicators.txt" 2>&1 || true
    fi

    if need_cmd olemeta; then
        olemeta "$ABS_DOC" > "$RUN_DIR/office_analysis/olemeta.txt" 2>&1 || true
    fi

    if need_cmd docx2txt && [[ "$DOC_EXT" == "docx" ]]; then
        docx2txt "$ABS_DOC" "$RUN_DIR/office_analysis/docx_text.txt" 2>/dev/null || true
    fi

    if need_cmd antiword && [[ "$DOC_EXT" == "doc" ]]; then
        antiword "$ABS_DOC" > "$RUN_DIR/office_analysis/doc_text.txt" 2>/dev/null || true
    fi
fi

# 5. String Extraction and Secret / Indicator Scanning
step "Harvesting strings and running secret indicator regex scans..."
mkdir -p "$RUN_DIR/text"
if need_cmd strings; then
    strings -n 4 "$ABS_DOC" > "$RUN_DIR/text/strings_full.txt" 2>&1 || true
fi

# Deep indicator scan across all extracted text files
if need_cmd rg; then
    rg -n -i 'password|secret|token|api[_ -]?key|bearer|private_key|confidential|internal|admin' \
        "$RUN_DIR" > "$RUN_DIR/high_interest_indicators.txt" 2>&1 || true
elif need_cmd grep; then
    grep -rnEi 'password|secret|token|api[_ -]?key|bearer|private_key|confidential|internal|admin' \
        "$RUN_DIR"/* > "$RUN_DIR/high_interest_indicators.txt" 2>&1 || true
fi

{
    echo '[3] SECRET & INDICATOR SCAN'
    printf 'High-Interest Regex Matches: %s\n\n' "$(wc -l < "$RUN_DIR/high_interest_indicators.txt" | tr -d ' ')"
} >> "$REPORT"

# 6. Finalize Hash and Manifest
step "Finalizing cryptographic hashes and evidence manifest..."
hash_file "$ABS_DOC" > "$RUN_DIR/sha256.txt"
printf 'SHA-256 Hash      : %s\n' "$(cat "$RUN_DIR/sha256.txt")" >> "$REPORT"
printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

find "$RUN_DIR" -maxdepth 2 -type f | sort > "$RUN_DIR/manifest.txt"

info "Document & Metadata harvesting completed successfully."
info "Full report written to: $REPORT"
