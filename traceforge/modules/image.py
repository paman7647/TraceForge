import datetime
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.case import Case, get_active_case
from traceforge.platform_detect import is_tool_installed, which_tool
from traceforge.runners import ToolRunner

def run_image_forensics(file_path: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    target = Path(file_path).resolve()
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Media file not found: {file_path}")

    case = Case(case_id) if case_id else get_active_case()
    out_dir = case.case_dir / "modules" / "image_forensics" if case else Path(f"workspace/{target.stem}_image_forensics").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report_file = out_dir / "report.txt"
    report_lines = [
        f"=== TraceForge Media & Image Forensics Report ===",
        f"Target File: {target.name}",
        f"Target Path: {target}",
        f"Size: {target.stat().st_size} bytes\n",
    ]

    # 1. ExifTool
    if is_tool_installed("exiftool"):
        res = ToolRunner.run("exiftool", [str(target)])
        if res.success:
            report_lines.append("--- EXIF / Metadata Properties ---")
            report_lines.append(res.stdout)

    # 2. Strings & Indicator Search
    if is_tool_installed("strings"):
        res_str = ToolRunner.run("strings", ["-n", "8", str(target)])
        if res_str.success:
            report_lines.append("--- Extracted Strings Preview ---")
            report_lines.extend(res_str.stdout.splitlines()[:50])

    # 3. Steganography Checks
    if is_tool_installed("zsteg") and target.suffix.lower() in (".png", ".bmp"):
        res_zsteg = ToolRunner.run("zsteg", ["-a", str(target)])
        if res_zsteg.success:
            report_lines.append("\n--- zsteg Steganography Analysis ---")
            report_lines.append(res_zsteg.stdout)

    # 4. Binwalk Carving / Signature Scan
    if is_tool_installed("binwalk"):
        res_bw = ToolRunner.run("binwalk", ["-B", str(target)])
        if res_bw.success:
            report_lines.append("\n--- Binwalk Signatures ---")
            report_lines.append(res_bw.stdout)

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
