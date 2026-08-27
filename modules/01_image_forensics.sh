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

INPUT_FILE=${1:-""}

if [[ "$INPUT_FILE" == "--help" || "$INPUT_FILE" == "-h" ]]; then
    printf 'TraceForge Module 01 — Image & Media Forensics\n\nUsage:\n  %s <image-or-media-file>\n' "$0"
    exit 0
fi

if [[ -z "$INPUT_FILE" ]]; then
    printf 'Usage: %s <image-or-media-file>\n' "$0" >&2
    exit 1
fi


if [[ ! -f "$INPUT_FILE" ]]; then
    die "Evidence file does not exist: $INPUT_FILE"
fi

if [[ ! -r "$INPUT_FILE" ]]; then
    die "Evidence file is not readable (check permissions): $INPUT_FILE"
fi

# Canonicalize input path
ABS_INPUT="$(CDPATH='' cd -- "$(dirname -- "$INPUT_FILE")" && pwd -P)/$(basename -- "$INPUT_FILE")"
BASE_NAME="$(basename -- "$ABS_INPUT")"

RUN_DIR="$(make_run_dir "$ROOT_DIR" "media_${BASE_NAME}")"
REPORT="$RUN_DIR/report.txt"

info "Analyzing image/media file: $BASE_NAME"
info "Output directory: $RUN_DIR"

{
    printf '===============================================================================\n'
    printf 'TraceForge — Media & Image Forensics Report\n'
    printf '===============================================================================\n'
    printf 'Evidence File : %s\n' "$ABS_INPUT"
    printf 'File Size     : %s bytes\n' "$(wc -c < "$ABS_INPUT" | tr -d ' ')"
    printf 'Analysis Start: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
} > "$REPORT"

# 1. MIME and Magic Byte Identification
step "Analyzing file signatures, MIME types, and header bytes..."
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
step "Extracting EXIF, IPTC, XMP, and MakerNotes..."
if need_cmd exiftool; then
    exiftool -a -u -g1 "$ABS_INPUT" > "$RUN_DIR/metadata_full.txt" 2>&1 || true
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
    warn "ExifTool is not installed. Full metadata parsing was skipped."
    echo 'ExifTool was not found on PATH.' > "$RUN_DIR/metadata_full.txt"
fi

# 3. String Harvesting and High-Interest Indicators
step "Harvesting ASCII / Unicode strings and scanning for indicators..."
if need_cmd strings; then
    strings -n 4 "$ABS_INPUT" > "$RUN_DIR/strings_all.txt" 2>&1 || true
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
step "Running steganographic payload checks..."
mkdir -p "$RUN_DIR/steganography"
if [[ "$MIME_TYPE" == "image/png" || "$MIME_TYPE" == "image/bmp" || "$FILE_EXT" == "png" || "$FILE_EXT" == "bmp" ]]; then
    if need_cmd zsteg; then
        info "Executing zsteg LSB analysis across pixel channels..."
        zsteg -a "$ABS_INPUT" > "$RUN_DIR/steganography/zsteg_results.txt" 2>&1 || true
    else
        echo 'zsteg is not installed.' > "$RUN_DIR/steganography/zsteg_results.txt"
    fi
else
    echo "zsteg skipped: Target is not a PNG or BMP bitmap." > "$RUN_DIR/steganography/zsteg_results.txt"
fi

# 5. File Carving & Embedded Signature Scanning
step "Running Binwalk signature scanner and carving check..."
mkdir -p "$RUN_DIR/carving"
if need_cmd binwalk; then
    binwalk "$ABS_INPUT" > "$RUN_DIR/carving/binwalk_scan.txt" 2>&1 || true
    if grep -qiE 'zip|rar|7-zip|png image|jpeg image|gif image|gzip|bzip|tar archive|elf|executable' "$RUN_DIR/carving/binwalk_scan.txt"; then
        info "Embedded signatures discovered. Running isolated extraction..."
        mkdir -p "$RUN_DIR/carving/extracted"
        binwalk -e --directory="$RUN_DIR/carving/extracted" "$ABS_INPUT" > "$RUN_DIR/carving/binwalk_extract.log" 2>&1 || true
        find "$RUN_DIR/carving/extracted" -type f | sort > "$RUN_DIR/carving/extracted_files.txt" || true
    else
        echo 'No high-interest compression or embedded container signatures triggered extraction.' > "$RUN_DIR/carving/binwalk_extract.log"
    fi
else
    echo 'binwalk is not installed.' > "$RUN_DIR/carving/binwalk_scan.txt"
fi

# 6. Integrity Hash and Run Manifest
step "Finalizing cryptographic hashes and evidence manifest..."
hash_file "$ABS_INPUT" > "$RUN_DIR/sha256.txt"
printf 'SHA-256 Hash      : %s\n' "$(cat "$RUN_DIR/sha256.txt")" >> "$REPORT"
printf 'Analysis Completed: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$REPORT"

find "$RUN_DIR" -maxdepth 2 -type f | sort > "$RUN_DIR/manifest.txt"

info "Media & Image Forensics completed successfully."
info "Full report written to: $REPORT"
