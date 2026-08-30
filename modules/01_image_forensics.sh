#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — Module 01: Image & Media Forensics
# Non-destructive evidence analysis: MIME, EXIF, GPS, strings, zsteg, binwalk.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"

INPUT_FILE=""
SCAN_MODE=""
CASE_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            printf 'TraceForge Module 01 — Image & Media Forensics\n\nUsage:\n  %s <image-or-media-file> [options]\n\nOptions:\n  --mode <quick|full>  Scan depth profile (default: quick)\n  --quick              Execute quick triage scan\n  --deep, --full       Execute full deep scan (all 39 catalog media tools)\n  --case-id <id>       Attach to case ID\n  --help, -h           Show this help message\n' "$0"
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
            if [[ -z "$INPUT_FILE" ]]; then
                INPUT_FILE="$1"
            elif [[ "$1" == CASE-* || "$1" == case_* ]]; then
                CASE_ID="$1"
            elif [[ -z "$SCAN_MODE" && ( "$1" == "quick" || "$1" == "full" || "$1" == "deep" ) ]]; then
                SCAN_MODE="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$INPUT_FILE" ]]; then
    printf 'Usage: %s <image-or-media-file> [--mode <quick|full>] [--case-id <id>]\n' "$0" >&2
    exit 1
fi


SCAN_MODE="$(prompt_scan_mode "quick" "$SCAN_MODE")"

if [[ ! -f "$INPUT_FILE" ]]; then
    die "Evidence file does not exist: $INPUT_FILE"
fi
if [[ ! -r "$INPUT_FILE" ]]; then
    die "Evidence file is not readable (check permissions): $INPUT_FILE"
fi

SCAN_MODE="$(prompt_scan_mode "quick" "$SCAN_MODE")"
SCAN_MODE_UPPER="$(echo "$SCAN_MODE" | tr '[:lower:]' '[:upper:]')"

if [[ ! -f "$INPUT_FILE" ]]; then
    die "Input file does not exist: $INPUT_FILE"
fi

# Canonicalize input path
ABS_INPUT="$(CDPATH='' cd -- "$(dirname -- "$INPUT_FILE")" && pwd -P)/$(basename -- "$INPUT_FILE")"
BASE_NAME="$(basename -- "$ABS_INPUT")"

RUN_DIR="$(make_run_dir "$ROOT_DIR" "image_${BASE_NAME}")"
REPORT="$RUN_DIR/report.txt"

info "Initiating Image & Media Forensics ($SCAN_MODE_UPPER SCAN) on: $BASE_NAME"
info "Evidence output destination: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Image & Media Forensics Report\n'
    printf '===============================================================================\n'
    printf 'Evidence File : %s\n' "$BASE_NAME"
    printf 'Full Path     : %s\n' "$ABS_INPUT"
    printf 'Scan Depth    : %s SCAN\n' "$SCAN_MODE_UPPER"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. MIME and Magic Byte Identification
MIME_TYPE="$(file -b --mime-type "$ABS_INPUT" 2>/dev/null || echo "unknown")"
FILE_DESC="$(file -b "$ABS_INPUT" 2>/dev/null || echo "unknown")"
FILE_EXT="${BASE_NAME##*.}"
FILE_EXT="$(echo "$FILE_EXT" | tr '[:upper:]' '[:lower:]')"

{
    echo '[1] FILE IDENTIFICATION & SIGNATURES'
    printf 'Detected MIME  : %s\n' "$MIME_TYPE"
    printf 'File Type      : %s\n' "$FILE_DESC"
    printf 'File Extension : .%s\n\n' "$FILE_EXT"
    echo 'First 64 Header Bytes:'
    if need_cmd xxd; then
        xxd -l 64 -g 1 "$ABS_INPUT"
    elif need_cmd hexdump; then
        hexdump -C -n 64 "$ABS_INPUT"
    else
        echo 'Hexdump utility unavailable.'
    fi
    echo
} | tee "$RUN_DIR/magic_bytes.txt" >> "$REPORT"

# Mismatch sanity check
EXPECTED_MIME=""
case "$FILE_EXT" in
    jpg|jpeg) EXPECTED_MIME="image/jpeg" ;;
    png) EXPECTED_MIME="image/png" ;;
    gif) EXPECTED_MIME="image/gif" ;;
    bmp|dib) EXPECTED_MIME="image/bmp" ;;
    webp) EXPECTED_MIME="image/webp" ;;
    tif|tiff) EXPECTED_MIME="image/tiff" ;;
    heic) EXPECTED_MIME="image/heic" ;;
    heif) EXPECTED_MIME="image/heif" ;;
    avif) EXPECTED_MIME="image/avif" ;;
esac

if [[ -n "$EXPECTED_MIME" && -n "$MIME_TYPE" && "$MIME_TYPE" != "$EXPECTED_MIME" ]]; then
    warn "POTENTIAL EXTENSION MISMATCH: Extension is .$FILE_EXT but detected MIME is $MIME_TYPE"
    printf '[WARNING] File extension .%s conflicts with true MIME %s\n\n' "$FILE_EXT" "$MIME_TYPE" >> "$REPORT"
fi

# 2. EXIF & Metadata Extraction
if need_cmd exiftool; then
    run_spinner_cmd "Extracting EXIF, IPTC, and XMP metadata (ExifTool)" "$RUN_DIR/metadata_full.txt" exiftool -a -u -g1 "$ABS_INPUT"
    exiftool -j -a -u -g1 "$ABS_INPUT" > "$RUN_DIR/metadata.json" 2>&1 || true

    {
        echo '[2] TARGETED METADATA SUMMARY'
        printf 'Make / Camera     : %s\n' "$(exiftool -s3 -Make "$ABS_INPUT" 2>/dev/null || echo "N/A")"
        printf 'Model             : %s\n' "$(exiftool -s3 -Model "$ABS_INPUT" 2>/dev/null || echo "N/A")"
        printf 'Software / Editor : %s\n' "$(exiftool -s3 -Software "$ABS_INPUT" 2>/dev/null || echo "N/A")"
        printf 'Date/Time Original: %s\n' "$(exiftool -s3 -DateTimeOriginal "$ABS_INPUT" 2>/dev/null || echo "N/A")"
        printf 'Modify Date       : %s\n' "$(exiftool -s3 -ModifyDate "$ABS_INPUT" 2>/dev/null || echo "N/A")"
        printf 'Artist / Author   : %s\n' "$(exiftool -s3 -Artist "$ABS_INPUT" 2>/dev/null || echo "N/A")"
        printf 'Copyright         : %s\n' "$(exiftool -s3 -Copyright "$ABS_INPUT" 2>/dev/null || echo "N/A")"
        printf 'Comment           : %s\n' "$(exiftool -s3 -Comment "$ABS_INPUT" 2>/dev/null || echo "N/A")"
        printf 'Image Description : %s\n' "$(exiftool -s3 -ImageDescription "$ABS_INPUT" 2>/dev/null || echo "N/A")"
        echo
    } | tee "$RUN_DIR/metadata_summary.txt" >> "$REPORT"

    # GPS extraction and Google Maps coordinate conversion
    exiftool -n -p '$GPSLatitude $GPSLongitude' "$ABS_INPUT" > "$RUN_DIR/gps_raw.txt" 2>/dev/null || true
    GPS_LINE="$(grep -E '^-?[0-9]+(\.[0-9]+)?[[:space:]]+-?[0-9]+(\.[0-9]+)?$' "$RUN_DIR/gps_raw.txt" | head -n 1 || true)"
    if [[ -n "$GPS_LINE" ]]; then
        LAT="$(awk '{print $1}' <<< "$GPS_LINE")"
        LON="$(awk '{print $2}' <<< "$GPS_LINE")"
        MAPS_URL="https://www.google.com/maps/search/?api=1&query=${LAT},${LON}"
        {
            echo '[3] GEOLOCATION / GPS DATA'
            printf 'Latitude          : %s\n' "$LAT"
            printf 'Longitude         : %s\n' "$LON"
            printf 'Google Maps Link  : %s\n\n' "$MAPS_URL"
        } | tee "$RUN_DIR/gps.txt" >> "$REPORT"
    else
        echo 'No decimal GPS coordinates found in metadata.' > "$RUN_DIR/gps.txt"
    fi
else
    log_warn "ExifTool is not installed. Full metadata parsing was skipped."
    echo 'ExifTool was not found on PATH.' > "$RUN_DIR/metadata_full.txt"
fi

# 3. String Harvesting and High-Interest Indicators
if need_cmd strings; then
    run_spinner_cmd "Harvesting ASCII & Unicode strings" "$RUN_DIR/strings_all.txt" strings -n 4 "$ABS_INPUT"
    grep -iE 'flag|ctf|key|pass|password|secret|token|api[_ -]?key|hidden|steg|admin|root|http://|https://' \
        "$RUN_DIR/strings_all.txt" > "$RUN_DIR/strings_high_interest.txt" 2>&1 || true
    tail -n 30 "$RUN_DIR/strings_all.txt" > "$RUN_DIR/strings_trailer.txt" 2>&1 || true

    {
        echo '[4] STRINGS ANALYSIS'
        printf 'Total Strings Extracted  : %s\n' "$(wc -l < "$RUN_DIR/strings_all.txt" | tr -d ' ')"
        printf 'High-Interest Hits       : %s\n\n' "$(wc -l < "$RUN_DIR/strings_high_interest.txt" | tr -d ' ')"
    } >> "$REPORT"
fi

# 4. Steganography Analysis (PNG / BMP only for zsteg)
mkdir -p "$RUN_DIR/steganography"
if [[ "$MIME_TYPE" == "image/png" || "$MIME_TYPE" == "image/bmp" || "$FILE_EXT" == "png" || "$FILE_EXT" == "bmp" ]]; then
    if need_cmd zsteg; then
        run_spinner_cmd "Executing pixel channel LSB analysis (zsteg)" "$RUN_DIR/steganography/zsteg_results.txt" zsteg -a "$ABS_INPUT"
        {
            echo '[5] STEGANOGRAPHY & HIDDEN PAYLOADS (zsteg)'
            head -n 25 "$RUN_DIR/steganography/zsteg_results.txt"
            echo
        } >> "$REPORT"
    else
        echo 'zsteg is not installed.' > "$RUN_DIR/steganography/zsteg_results.txt"
        log_skip "zsteg not installed."
    fi
else
    echo "zsteg skipped: Target is not a PNG or BMP bitmap." > "$RUN_DIR/steganography/zsteg_results.txt"
fi

# 5. File Carving & Embedded Signature Scanning
mkdir -p "$RUN_DIR/carving"
if need_cmd binwalk; then
    run_spinner_cmd "Scanning signatures & file containers (Binwalk)" "$RUN_DIR/carving/binwalk_scan.txt" binwalk "$ABS_INPUT"
    {
        echo '[6] EMBEDDED CONTAINER SIGNATURES (Binwalk)'
        cat "$RUN_DIR/carving/binwalk_scan.txt"
        echo
    } >> "$REPORT"

    if grep -qiE 'zip|rar|7-zip|png image|jpeg image|gif image|gzip|bzip|tar archive|elf|executable' "$RUN_DIR/carving/binwalk_scan.txt"; then
        mkdir -p "$RUN_DIR/carving/extracted"
        run_spinner_cmd "Extracting embedded payload containers" "$RUN_DIR/carving/binwalk_extract.log" binwalk -e --directory="$RUN_DIR/carving/extracted" "$ABS_INPUT"
        find "$RUN_DIR/carving/extracted" -type f | sort > "$RUN_DIR/carving/extracted_files.txt" || true
    fi
else
    echo 'binwalk is not installed.' > "$RUN_DIR/carving/binwalk_scan.txt"
    log_skip "binwalk not installed."
fi

# =============================================================================
# EXTENDED DEEP SCAN CAPABILITIES (FULL SCAN MODE)
# =============================================================================
if [[ "$SCAN_MODE" == "full" ]]; then
    # 6. JPEG Header Integrity via jhead & jpeginfo
    if [[ "$MIME_TYPE" == *"jpeg"* || "$FILE_EXT" =~ ^(jpg|jpeg)$ ]]; then
        if need_cmd jhead; then
            run_spinner_cmd "Inspecting JPEG JFIF headers (jhead)" "$RUN_DIR/jhead.txt" jhead -v "$ABS_INPUT"
            {
                echo '[7] JPEG HEADER STRUCTURE (jhead)'
                cat "$RUN_DIR/jhead.txt"
                echo
            } >> "$REPORT"
        fi
        if need_cmd jpeginfo; then
            run_spinner_cmd "Auditing JPEG corruption & markers (jpeginfo)" "$RUN_DIR/jpeginfo.txt" jpeginfo -c "$ABS_INPUT"
        fi
    fi

    # 7. PNG Chunk Verification via pngcheck
    if [[ "$MIME_TYPE" == *"png"* || "$FILE_EXT" == "png" ]]; then
        if need_cmd pngcheck; then
            run_spinner_cmd "Auditing PNG chunks & checksums (pngcheck)" "$RUN_DIR/pngcheck.txt" pngcheck -vtp "$ABS_INPUT"
            {
                echo '[8] PNG CHUNK INTEGRITY (pngcheck)'
                cat "$RUN_DIR/pngcheck.txt"
                echo
            } >> "$REPORT"
        fi
    fi

    # 8. Steghide Embedded Passphrase Scan
    if need_cmd steghide; then
        run_spinner_cmd "Probing Steghide encrypted payload (steghide)" "$RUN_DIR/steganography/steghide_info.txt" steghide info "$ABS_INPUT"
    fi

    # 9. Optical Character Recognition via Tesseract OCR
    if need_cmd tesseract; then
        run_spinner_cmd "Extracting text via OCR (Tesseract)" "$RUN_DIR/ocr_text.txt" tesseract "$ABS_INPUT" "$RUN_DIR/ocr_text"
        if [[ -s "$RUN_DIR/ocr_text.txt" ]]; then
            {
                echo '[9] OPTICAL CHARACTER RECOGNITION (OCR)'
                cat "$RUN_DIR/ocr_text.txt"
                echo
            } >> "$REPORT"
        fi
    fi

    # 10. Media Streams & Codecs via MediaInfo / FFprobe
    if need_cmd mediainfo; then
        run_spinner_cmd "Extracting stream technical specs (MediaInfo)" "$RUN_DIR/mediainfo.txt" mediainfo "$ABS_INPUT"
    elif need_cmd ffprobe; then
        run_spinner_cmd "Probing multimedia codec container (ffprobe)" "$RUN_DIR/ffprobe.json" ffprobe -v quiet -print_format json -show_format -show_streams "$ABS_INPUT"
    fi

    # 11. Carving via foremost
    if need_cmd foremost; then
        mkdir -p "$RUN_DIR/carving/foremost_out"
        run_spinner_cmd "Carving nested file structures (foremost)" "$RUN_DIR/carving/foremost.log" foremost -T -i "$ABS_INPUT" -o "$RUN_DIR/carving/foremost_out"
    fi
fi

# Integrity Hash and Run Manifest
hash_file "$ABS_INPUT" > "$RUN_DIR/sha256.txt"
printf 'SHA-256 Hash      : %s\n' "$(cat "$RUN_DIR/sha256.txt")" >> "$REPORT"
printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

# Finalize multi-format reporting (TXT, MD, HTML, JSON, IOCs, Manifest)
finalize_module_run "01_image_forensics" "Media & Image Forensics" "$BASE_NAME" "$SCAN_MODE" "$RUN_DIR"

