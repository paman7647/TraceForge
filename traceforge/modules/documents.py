import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.case import Case, get_active_case
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner
from traceforge.tools import extract_iocs

def run_document_harvesting(doc_path: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    target = Path(doc_path).resolve()
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Document file not found: {doc_path}")

    case = Case(case_id) if case_id else get_active_case()
    out_dir = case.case_dir / "modules" / "document_harvesting" if case else Path(f"workspace/{target.stem}_doc_harvesting").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report_file = out_dir / "report.txt"
    report_lines = [
        "=== TraceForge Document & Metadata Harvesting Report ===",
        f"Document: {target.name}",
        f"Path: {target}",
        f"Size: {target.stat().st_size} bytes\n",
    ]

    # 1. ExifTool
    if is_tool_installed("exiftool"):
        res = ToolRunner.run("exiftool", [str(target)])
        if res.success:
            report_lines.append("--- Document Properties & Metadata ---")
            report_lines.append(res.stdout)

    # 2. Text/Strings Extraction & IOC Scan
    text_content = ""
    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as f:
            text_content = f.read(500000)
    except Exception:
        pass

    if text_content:
        iocs = extract_iocs(text_content, source=target.name)
        if iocs:
            report_lines.append("\n--- Extracted Observables & Indicators ---")
            for i in iocs[:30]:
                report_lines.append(f"  [{i['type']}] {i['value']} (confidence: {i['confidence']})")
                if case:
                    case.add_ioc(i["value"], i["type"], f"Extracted from document {target.name}", "Module 06 (Doc Harvesting)", i["confidence"])

    content = "\n".join(report_lines)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(content)

    if case:
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Document Harvesting on {target.name}",
            description=f"Extracted metadata and scanned for secret indicators in {target.name}",
            source="Module 06 (Document Harvesting)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": str(report_file),
    }
