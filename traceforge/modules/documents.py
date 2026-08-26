import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.case import Case, get_active_case
from traceforge.config import get_project_root
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner
from traceforge.tools import extract_iocs


def run_document_harvesting(doc_path: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    target = Path(doc_path)
    if not target.is_absolute() and not target.exists():
        target = (get_project_root() / doc_path).resolve()
    else:
        target = target.resolve()

    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Document file not found: {doc_path}")

    case = Case(case_id) if case_id else get_active_case()
    out_dir = (
        case.case_dir / "modules" / "document_harvesting"
        if case
        else Path(f"workspace/{target.stem}_doc_harvesting").resolve()
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    report_file = out_dir / "report.txt"
    suffix = target.suffix.lower()
    report_lines = [
        "=== TraceForge Document & Metadata Harvesting Report ===",
        f"Document: {target.name}",
        f"Path: {target}",
        f"Size: {target.stat().st_size} bytes\n",
    ]

    # 1. ExifTool — document metadata and embedded properties
    if is_tool_installed("exiftool"):
        res = ToolRunner.run("exiftool", [str(target)])
        if res.success:
            report_lines.append("--- Document Properties & Metadata (ExifTool) ---")
            report_lines.append(res.stdout)

    # 2. PDF tools
    if suffix == ".pdf":
        if is_tool_installed("pdfinfo"):
            res = ToolRunner.run("pdfinfo", [str(target)])
            if res.success:
                report_lines.append("--- PDF Document Information (pdfinfo) ---")
                report_lines.append(res.stdout)

        if is_tool_installed("pdftotext"):
            res = ToolRunner.run("pdftotext", [str(target), "-"])
            if res.success and res.stdout.strip():
                report_lines.append("--- PDF Text Content Preview (pdftotext) ---")
                report_lines.extend(res.stdout.splitlines()[:60])

        if is_tool_installed("pdfimages"):
            img_out = out_dir / "pdf_images"
            img_out.mkdir(exist_ok=True)
            res = ToolRunner.run("pdfimages", ["-list", str(target)])
            if res.success and res.stdout.strip():
                report_lines.append("--- Embedded Images (pdfimages) ---")
                report_lines.extend(res.stdout.splitlines()[:20])

        if is_tool_installed("mutool"):
            res = ToolRunner.run("mutool", ["info", str(target)])
            if res.success:
                report_lines.append("--- MuPDF Document Structure (mutool) ---")
                report_lines.append(res.stdout)

    # 3. Office / OLE document analysis
    ole_suffixes = {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".rtf"}
    if suffix in ole_suffixes:
        if is_tool_installed("olevba"):
            res = ToolRunner.run("olevba", ["--reveal", str(target)])
            if res.success:
                report_lines.append("--- OLE VBA Macro Analysis (olevba) ---")
                report_lines.append(res.stdout)

        if is_tool_installed("oleid"):
            res = ToolRunner.run("oleid", [str(target)])
            if res.success:
                report_lines.append("--- OLE Indicators (oleid) ---")
                report_lines.append(res.stdout)

        if is_tool_installed("antiword") and suffix == ".doc":
            res = ToolRunner.run("antiword", [str(target)])
            if res.success and res.stdout.strip():
                report_lines.append("--- Extracted Text (antiword) ---")
                report_lines.extend(res.stdout.splitlines()[:40])

    # 4. DOCX / OOXML text extraction
    if suffix in (".docx", ".odt"):
        if is_tool_installed("docx2txt"):
            res = ToolRunner.run("docx2txt", [str(target), "-"])
            if res.success and res.stdout.strip():
                report_lines.append("--- Document Text (docx2txt) ---")
                report_lines.extend(res.stdout.splitlines()[:40])

    # 5. Metadata anonymization preview
    if is_tool_installed("mat2"):
        res = ToolRunner.run("mat2", ["--show", str(target)])
        if res.success and res.stdout.strip():
            report_lines.append("--- Metadata Strippable Fields (mat2) ---")
            report_lines.append(res.stdout)

    # 6. Content search for indicators via ripgrep
    if is_tool_installed("rg"):
        # Look for common indicator patterns in the file as text
        res = ToolRunner.run("rg", [
            "--text", "--no-heading", "--max-count", "5",
            r"(https?://[^\s\"'<>]+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
            str(target),
        ])
        if res.success and res.stdout.strip():
            report_lines.append("--- Pattern Matches via ripgrep ---")
            report_lines.extend(res.stdout.splitlines()[:20])

    # 7. Raw text IOC extraction (fallback for any file type)
    text_content = ""
    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as f:
            text_content = f.read(500_000)
    except Exception:
        pass

    if text_content:
        iocs = extract_iocs(text_content, source=target.name)
        if iocs:
            report_lines.append("\n--- Extracted Observables & Indicators ---")
            for i in iocs[:30]:
                report_lines.append(f"  [{i['type']}] {i['value']} (confidence: {i['confidence']})")
                if case:
                    case.add_ioc(
                        i["value"], i["type"],
                        f"Extracted from document {target.name}",
                        "Module 06 (Doc Harvesting)",
                        i["confidence"],
                    )

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
