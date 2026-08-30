import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge.case import Case, get_active_case
from traceforge.config import get_project_root
from traceforge.modules.reporting import generate_module_reports
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner

def run_image_forensics(file_path: str, case_id: Optional[str] = None, mode: str = "quick") -> Dict[str, Any]:
    target = Path(file_path)
    if not target.is_absolute() and not target.exists():
        target = (get_project_root() / file_path).resolve()
    else:
        target = target.resolve()

    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Media file not found: {file_path}")

    mode = "full" if mode in ("full", "deep") else "quick"
    case = Case(case_id) if case_id else get_active_case()
    out_dir = (
        case.case_dir / "modules" / "image_forensics"
        if case
        else Path(f"workspace/{target.stem}_image_forensics").resolve()
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    suffix = target.suffix.lower()
    sections: List[Dict[str, Any]] = []

    # 1. File identification
    file_info = [
        f"File Name: {target.name}",
        f"File Size: {target.stat().st_size} bytes",
        f"Extension: {suffix}",
    ]
    sections.append({
        "title": "SPECIMEN INFORMATION",
        "content": "\n".join(file_info),
    })

    # 2. ExifTool — EXIF/IPTC/XMP metadata dump
    if is_tool_installed("exiftool"):
        res = ToolRunner.run("exiftool", ["-a", "-u", "-g1", str(target)])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "EXIF & METADATA PROPERTIES (ExifTool)",
                "content": res.stdout.strip(),
            })

    # 3. Strings — extracted printable runs
    if is_tool_installed("strings"):
        res_str = ToolRunner.run("strings", ["-n", "4", str(target)])
        if res_str.success and res_str.stdout.strip():
            lines = res_str.stdout.splitlines()
            sections.append({
                "title": f"EXTRACTED STRINGS ({len(lines)} total lines)",
                "content": "\n".join(lines[:60]),
            })

    # 4. Steganography checks
    if is_tool_installed("zsteg") and suffix in (".png", ".bmp"):
        res_zsteg = ToolRunner.run("zsteg", ["-a", str(target)])
        if res_zsteg.success and res_zsteg.stdout.strip():
            sections.append({
                "title": "STEGANOGRAPHY ANALYSIS (zsteg)",
                "content": res_zsteg.stdout.strip(),
            })

    # 5. Binwalk — embedded file/firmware signatures
    if is_tool_installed("binwalk"):
        res_bw = ToolRunner.run("binwalk", ["-B", str(target)])
        if res_bw.success and res_bw.stdout.strip():
            sections.append({
                "title": "EMBEDDED CONTAINER SIGNATURES (Binwalk)",
                "content": res_bw.stdout.strip(),
            })

    # Deep Scan Extended Tools
    if mode == "full":
        # MediaInfo
        av_suffixes = {".mp4", ".mov", ".avi", ".mkv", ".mp3", ".flac", ".wav", ".m4a", ".webm", ".ogg"}
        if is_tool_installed("mediainfo") and suffix in av_suffixes:
            res = ToolRunner.run("mediainfo", [str(target)])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "MEDIA CONTAINER & CODECS (MediaInfo)",
                    "content": res.stdout.strip(),
                })

        # PNG Chunk validation
        if is_tool_installed("pngcheck") and suffix == ".png":
            res = ToolRunner.run("pngcheck", ["-vtp", str(target)])
            out = res.stdout or res.stderr
            if out.strip():
                sections.append({
                    "title": "PNG CHUNK INTEGRITY (pngcheck)",
                    "content": out.strip(),
                })

        # JPEG header inspection
        if is_tool_installed("jhead") and suffix in (".jpg", ".jpeg"):
            res = ToolRunner.run("jhead", ["-v", str(target)])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "JPEG HEADER STRUCTURE (jhead)",
                    "content": res.stdout.strip(),
                })

        # Steghide
        if is_tool_installed("steghide") and suffix in (".jpg", ".jpeg", ".bmp", ".au", ".wav"):
            res_steg = ToolRunner.run("steghide", ["info", "-p", "", str(target)])
            out = res_steg.stdout or res_steg.stderr
            if out.strip():
                sections.append({
                    "title": "STEGHIDE CARRIER PROBE (steghide)",
                    "content": out.strip(),
                })

        # Tesseract OCR
        ocr_suffixes = {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".gif"}
        if is_tool_installed("tesseract") and suffix in ocr_suffixes:
            ocr_base = out_dir / "ocr_output"
            ToolRunner.run("tesseract", [str(target), str(ocr_base), "-l", "eng"])
            ocr_txt = Path(str(ocr_base) + ".txt")
            if ocr_txt.exists():
                text = ocr_txt.read_text(encoding="utf-8", errors="ignore").strip()
                if text:
                    sections.append({
                        "title": "OPTICAL CHARACTER RECOGNITION (Tesseract)",
                        "content": text[:2000],
                    })

        # YARA
        yara_rules_dir = get_project_root() / "yara_rules"
        if is_tool_installed("yara") and yara_rules_dir.is_dir():
            for rule_file in list(yara_rules_dir.glob("*.yar"))[:5]:
                res_yara = ToolRunner.run("yara", [str(rule_file), str(target)])
                if res_yara.stdout.strip():
                    sections.append({
                        "title": f"YARA RULE MATCH ({rule_file.name})",
                        "content": res_yara.stdout.strip(),
                    })

    # Generate multi-format structured reports
    generated_reports = generate_module_reports(
        module_id="01_image_forensics",
        module_title="Media & Image Forensics",
        target=target.name,
        scan_mode=mode,
        out_dir=out_dir,
        sections=sections,
    )

    if case:
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Image Forensics Executed on {target.name} ({mode.upper()} SCAN)",
            description=f"Extracted metadata, string indicators, and forensic analysis for {target.name} across {len(sections)} phases",
            source="Module 01 (Image Forensics)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": generated_reports.get("txt", str(out_dir / "report.txt")),
        "reports": generated_reports,
    }

