import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.case import Case, get_active_case
from traceforge.config import get_project_root
from traceforge.platform_detect import is_tool_installed, which_tool
from traceforge.runners import ToolRunner


def run_image_forensics(file_path: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    target = Path(file_path)
    if not target.is_absolute() and not target.exists():
        target = (get_project_root() / file_path).resolve()
    else:
        target = target.resolve()

    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Media file not found: {file_path}")

    case = Case(case_id) if case_id else get_active_case()
    out_dir = (
        case.case_dir / "modules" / "image_forensics"
        if case
        else Path(f"workspace/{target.stem}_image_forensics").resolve()
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    report_file = out_dir / "report.txt"
    suffix = target.suffix.lower()
    report_lines = [
        "=== TraceForge Media & Image Forensics Report ===",
        f"Target File: {target.name}",
        f"Target Path: {target}",
        f"Size: {target.stat().st_size} bytes\n",
    ]

    # 1. ExifTool — EXIF/IPTC/XMP metadata dump
    if is_tool_installed("exiftool"):
        res = ToolRunner.run("exiftool", [str(target)])
        if res.success:
            report_lines.append("--- EXIF / Metadata Properties ---")
            report_lines.append(res.stdout)

    # 2. MediaInfo — audio/video container and codec details
    av_suffixes = {".mp4", ".mov", ".avi", ".mkv", ".mp3", ".flac", ".wav", ".m4a", ".webm", ".ogg"}
    if is_tool_installed("mediainfo") and suffix in av_suffixes:
        res = ToolRunner.run("mediainfo", [str(target)])
        if res.success:
            report_lines.append("--- MediaInfo Container / Codec Details ---")
            report_lines.append(res.stdout)

    # 3. FFprobe — format and stream metadata
    if is_tool_installed("ffprobe") and suffix in av_suffixes | {".gif"}:
        res = ToolRunner.run("ffprobe", ["-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", str(target)])
        if res.success:
            report_lines.append("--- FFprobe Format & Stream Metadata ---")
            report_lines.append(res.stdout)

    # 4. PNG structural validation
    if is_tool_installed("pngcheck") and suffix == ".png":
        res = ToolRunner.run("pngcheck", ["-v", str(target)])
        report_lines.append("--- PNG Chunk Validation (pngcheck) ---")
        report_lines.append(res.stdout or res.stderr)

    # 5. JPEG header inspection
    if is_tool_installed("jhead") and suffix in (".jpg", ".jpeg"):
        res = ToolRunner.run("jhead", [str(target)])
        if res.success:
            report_lines.append("--- JPEG Header Inspection (jhead) ---")
            report_lines.append(res.stdout)

    # 6. Strings — extracted printable runs
    if is_tool_installed("strings"):
        res_str = ToolRunner.run("strings", ["-n", "8", str(target)])
        if res_str.success:
            report_lines.append("--- Extracted Strings Preview ---")
            report_lines.extend(res_str.stdout.splitlines()[:50])

    # 7. Steganography checks
    if is_tool_installed("zsteg") and suffix in (".png", ".bmp"):
        res_zsteg = ToolRunner.run("zsteg", ["-a", str(target)])
        if res_zsteg.success:
            report_lines.append("\n--- zsteg Steganography Analysis ---")
            report_lines.append(res_zsteg.stdout)

    if is_tool_installed("steghide") and suffix in (".jpg", ".jpeg", ".bmp", ".au", ".wav"):
        # Probe with empty passphrase — non-zero exit is fine, we want the info output
        res_steg = ToolRunner.run("steghide", ["info", "-p", "", str(target)])
        output = res_steg.stdout or res_steg.stderr
        if output:
            report_lines.append("\n--- Steghide Carrier Detection ---")
            report_lines.append(output)

    # 8. Binwalk — embedded file/firmware signatures
    if is_tool_installed("binwalk"):
        res_bw = ToolRunner.run("binwalk", ["-B", str(target)])
        if res_bw.success:
            report_lines.append("\n--- Binwalk Signatures ---")
            report_lines.append(res_bw.stdout)

    # 9. YARA — pattern matching against local rules directory
    yara_rules_dir = get_project_root() / "yara_rules"
    if is_tool_installed("yara") and yara_rules_dir.is_dir():
        for rule_file in list(yara_rules_dir.glob("*.yar"))[:5]:
            res_yara = ToolRunner.run("yara", [str(rule_file), str(target)])
            if res_yara.stdout:
                report_lines.append(f"\n--- YARA Matches ({rule_file.name}) ---")
                report_lines.append(res_yara.stdout)

    # 10. Tesseract OCR — extract text from raster images
    ocr_suffixes = {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".gif"}
    if is_tool_installed("tesseract") and suffix in ocr_suffixes:
        ocr_base = out_dir / "ocr_output"
        ToolRunner.run("tesseract", [str(target), str(ocr_base), "-l", "eng"])
        ocr_txt = Path(str(ocr_base) + ".txt")
        if ocr_txt.exists():
            text = ocr_txt.read_text(encoding="utf-8", errors="ignore").strip()
            if text:
                report_lines.append("\n--- OCR Text Extraction (Tesseract) ---")
                report_lines.extend(text.splitlines()[:30])

    # 11. Foremost — file carving for embedded payloads
    if is_tool_installed("foremost"):
        foremost_out = out_dir / "foremost_carved"
        foremost_out.mkdir(exist_ok=True)
        ToolRunner.run("foremost", ["-i", str(target), "-o", str(foremost_out)])
        audit_txt = foremost_out / "audit.txt"
        if audit_txt.exists():
            lines = audit_txt.read_text(encoding="utf-8", errors="ignore").splitlines()
            report_lines.append("\n--- Foremost File Carving Results ---")
            report_lines.extend(lines[:20])

    content = "\n".join(report_lines)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(content)

    if case:
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Image Forensics Executed on {target.name}",
            description=f"Extracted metadata, string indicators, and steganography scan for {target.name}",
            source="Module 01 (Image Forensics)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": str(report_file),
    }
