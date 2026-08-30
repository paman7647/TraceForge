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

INPUT_DOC=""
SCAN_MODE=""
CASE_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            printf 'TraceForge Module 06 — Document & Metadata Harvesting\n\nUsage:\n  %s <document-file> [options]\n\nOptions:\n  --mode <quick|full>  Scan depth profile (default: quick)\n  --quick              Execute quick triage scan\n  --deep, --full       Execute full deep scan (all 20 catalog document tools)\n  --case-id <id>       Attach to case ID\n  --help, -h           Show this help message\n' "$0"
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
            if [[ -z "$INPUT_DOC" ]]; then
                INPUT_DOC="$1"
            elif [[ "$1" == CASE-* || "$1" == case_* ]]; then
                CASE_ID="$1"
            elif [[ -z "$SCAN_MODE" && ( "$1" == "quick" || "$1" == "full" || "$1" == "deep" ) ]]; then
                SCAN_MODE="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$INPUT_DOC" ]]; then
    printf 'Usage: %s <document-file> [--mode <quick|full>] [--case-id <id>]\n' "$0" >&2
    exit 1
fi


SCAN_MODE="$(prompt_scan_mode "quick" "$SCAN_MODE")"

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

info "Initiating Document & Metadata Harvesting ($SCAN_MODE_UPPER SCAN) on: $BASE_NAME"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Document & Metadata Harvesting Report\n'
    printf '===============================================================================\n'
    printf 'Evidence File : %s\n' "$BASE_NAME"
    printf 'Full Path     : %s\n' "$ABS_DOC"
    printf 'Scan Depth    : %s SCAN\n' "$SCAN_MODE_UPPER"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. MIME and Document Type Identification
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
if need_cmd exiftool; then
    run_spinner_cmd "Extracting document properties & EXIF (ExifTool)" "$RUN_DIR/exiftool_full.txt" exiftool -a -u -g1 "$ABS_DOC"
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
else
    log_skip "ExifTool not installed."
fi

# 3. PDF-Specific Analysis
if [[ "$DOC_MIME" == *"pdf"* || "$DOC_EXT" == "pdf" ]]; then
    mkdir -p "$RUN_DIR/pdf_extracted"

    if need_cmd pdfinfo; then
        run_spinner_cmd "Extracting PDF structure info (pdfinfo)" "$RUN_DIR/pdf_extracted/pdfinfo.txt" pdfinfo "$ABS_DOC"
    fi

    if need_cmd pdftotext; then
        run_spinner_cmd "Extracting searchable text stream (pdftotext)" "$RUN_DIR/pdf_extracted/extracted_text.txt" pdftotext -layout "$ABS_DOC" "$RUN_DIR/pdf_extracted/extracted_text.txt"
    fi

    if need_cmd pdfimages; then
        mkdir -p "$RUN_DIR/pdf_extracted/images"
        run_spinner_cmd "Extracting embedded images (pdfimages)" "$RUN_DIR/pdf_extracted/images.log" pdfimages -png "$ABS_DOC" "$RUN_DIR/pdf_extracted/images/img"
    fi

    if need_cmd qpdf; then
        run_spinner_cmd "Validating PDF streams & encryption (qpdf)" "$RUN_DIR/pdf_extracted/qpdf_check.txt" qpdf --check "$ABS_DOC"
    fi

    if need_cmd peepdf; then
        run_spinner_cmd "Scanning PDF exploits & JS objects (peepdf)" "$RUN_DIR/pdf_extracted/peepdf_analysis.txt" peepdf -f "$ABS_DOC"
    fi

    if need_cmd pdfid; then
        run_spinner_cmd "Auditing suspicious PDF tags (pdfid)" "$RUN_DIR/pdf_extracted/pdfid_scan.txt" pdfid "$ABS_DOC"
    fi
fi

# 4. Office Document & Macro / OLE Analysis
if [[ "$DOC_MIME" == *"msword"* || "$DOC_MIME" == *"officedocument"* || "$DOC_MIME" == *"ms-excel"* || "$DOC_EXT" =~ ^(doc|docx|xls|xlsx|ppt|pptx|docm|xlsm)$ ]]; then
    mkdir -p "$RUN_DIR/office_analysis"

    if need_cmd olevba; then
        run_spinner_cmd "Scanning VBA macros & code (olevba)" "$RUN_DIR/office_analysis/olevba_macros.txt" olevba "$ABS_DOC"
    fi

    if need_cmd oleid; then
        run_spinner_cmd "Scanning Office exploit indicators (oleid)" "$RUN_DIR/office_analysis/oleid_indicators.txt" oleid "$ABS_DOC"
    fi

    if need_cmd olemeta; then
        run_spinner_cmd "Extracting OLE metadata streams (olemeta)" "$RUN_DIR/office_analysis/olemeta.txt" olemeta "$ABS_DOC"
    fi

    if need_cmd docx2txt && [[ "$DOC_EXT" == "docx" ]]; then
        run_spinner_cmd "Extracting Word document text (docx2txt)" "$RUN_DIR/office_analysis/docx_text.txt" docx2txt "$ABS_DOC" "$RUN_DIR/office_analysis/docx_text.txt"
    fi

    if need_cmd antiword && [[ "$DOC_EXT" == "doc" ]]; then
        run_spinner_cmd "Extracting legacy Word text (antiword)" "$RUN_DIR/office_analysis/doc_text.txt" antiword "$ABS_DOC"
    fi
fi

# 5. String Extraction and Secret / Indicator Scanning
mkdir -p "$RUN_DIR/text"
if need_cmd strings; then
    run_spinner_cmd "Harvesting raw document strings (strings)" "$RUN_DIR/text/strings_full.txt" strings -n 4 "$ABS_DOC"
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

# =============================================================================
# EXTENDED DEEP SCAN CAPABILITIES (FULL SCAN MODE)
# =============================================================================
if [[ "$SCAN_MODE" == "full" ]]; then
    # 6. MuPDF Clean Extraction via mutool
    if need_cmd mutool && [[ "$DOC_EXT" == "pdf" ]]; then
        run_spinner_cmd "Extracting PDF streams via MuPDF (mutool)" "$RUN_DIR/pdf_extracted/mutool_info.txt" mutool info "$ABS_DOC"
    fi

    # 7. OCR Processing via ocrmypdf
    if need_cmd ocrmypdf && [[ "$DOC_EXT" == "pdf" ]]; then
        run_spinner_cmd "Running Optical Character Recognition (ocrmypdf)" "$RUN_DIR/pdf_extracted/ocr.log" ocrmypdf --sidecar "$RUN_DIR/pdf_extracted/ocr_sidecar.txt" "$ABS_DOC" "$RUN_DIR/pdf_extracted/ocr_out.pdf"
    fi

    # 8. Generic Metadata via Hachoir
    if need_cmd hachoir-metadata; then
        run_spinner_cmd "Extracting container metadata (hachoir-metadata)" "$RUN_DIR/hachoir_meta.txt" hachoir-metadata "$ABS_DOC"
    fi
fi

# Finalize Hash and Manifest
hash_file "$ABS_DOC" > "$RUN_DIR/sha256.txt"
printf 'SHA-256 Hash      : %s\n' "$(cat "$RUN_DIR/sha256.txt")" >> "$REPORT"
printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

# Finalize multi-format reporting (TXT, MD, HTML, JSON, IOCs, Manifest)
finalize_module_run "06_document_harvesting" "Document & Metadata Harvesting" "$BASE_NAME" "$SCAN_MODE" "$RUN_DIR"

