import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge.case import Case, get_active_case
from traceforge.config import get_project_root
from traceforge.modules.reporting import generate_module_reports
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner
from traceforge.tools import extract_iocs

def run_document_harvesting(doc_path: str, case_id: Optional[str] = None, mode: str = "quick") -> Dict[str, Any]:
    target = Path(doc_path)
    if not target.is_absolute() and not target.exists():
        target = (get_project_root() / doc_path).resolve()
    else:
        target = target.resolve()

    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Document file not found: {doc_path}")

    mode = "full" if mode in ("full", "deep") else "quick"
    case = Case(case_id) if case_id else get_active_case()
    out_dir = (
        case.case_dir / "modules" / "document_harvesting"
        if case
        else Path(f"workspace/{target.stem}_doc_harvesting").resolve()
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    suffix = target.suffix.lower()
    sections: List[Dict[str, Any]] = []

    # 1. Specimen identification
    doc_info = [
        f"Document Name: {target.name}",
        f"File Size    : {target.stat().st_size} bytes",
        f"Extension    : {suffix}",
    ]
    sections.append({
        "title": "SPECIMEN INFORMATION",
        "content": "\n".join(doc_info),
    })

    # 2. ExifTool — document metadata and embedded properties
    if is_tool_installed("exiftool"):
        res = ToolRunner.run("exiftool", ["-a", "-u", "-g1", str(target)])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "DOCUMENT PROPERTIES & METADATA (ExifTool)",
                "content": res.stdout.strip(),
            })

    # 3. PDF tools
    if suffix == ".pdf":
        if is_tool_installed("pdfinfo"):
            res = ToolRunner.run("pdfinfo", [str(target)])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "PDF DOCUMENT INFORMATION (pdfinfo)",
                    "content": res.stdout.strip(),
                })

        if is_tool_installed("pdftotext"):
            res = ToolRunner.run("pdftotext", [str(target), "-"])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "PDF EXTRACTED TEXT PREVIEW (pdftotext)",
                    "content": "\n".join(res.stdout.splitlines()[:60]),
                })

    # 4. Office / OLE document analysis
    ole_suffixes = {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".rtf"}
    if suffix in ole_suffixes:
        if is_tool_installed("olevba"):
            res = ToolRunner.run("olevba", ["--reveal", str(target)])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "OLE VBA MACRO ANALYSIS (olevba)",
                    "content": res.stdout.strip(),
                })

        if is_tool_installed("oleid"):
            res = ToolRunner.run("oleid", [str(target)])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "OLE EXPLOIT INDICATORS (oleid)",
                    "content": res.stdout.strip(),
                })

    # 5. DOCX text extraction
    if suffix in (".docx", ".odt"):
        if is_tool_installed("docx2txt"):
            res = ToolRunner.run("docx2txt", [str(target), "-"])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "DOCUMENT TEXT (docx2txt)",
                    "content": "\n".join(res.stdout.splitlines()[:50]),
                })

    # 6. Ripgrep / Secrets search
    if is_tool_installed("rg"):
        res = ToolRunner.run("rg", [
            "--text", "--no-heading", "--max-count", "15",
            r"(password|secret|token|api[_ -]?key|bearer|private_key|confidential)",
            str(target),
        ])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "HIGH INTEREST REGEX MATCHES (ripgrep)",
                "content": res.stdout.strip(),
            })

    # Deep Scan Extended Tools
    if mode == "full":
        if is_tool_installed("qpdf") and suffix == ".pdf":
            res = ToolRunner.run("qpdf", ["--check", str(target)])
            sections.append({
                "title": "PDF ENCRYPTION & STREAM CHECK (qpdf)",
                "content": res.stdout.strip() or res.stderr.strip(),
            })

        if is_tool_installed("peepdf") and suffix == ".pdf":
            res = ToolRunner.run("peepdf", ["-f", str(target)])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "PDF EXPLOIT ANALYSIS (peepdf)",
                    "content": res.stdout.strip(),
                })

        if is_tool_installed("pdfid") and suffix == ".pdf":
            res = ToolRunner.run("pdfid", [str(target)])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "SUSPICIOUS PDF TAG AUDIT (pdfid)",
                    "content": res.stdout.strip(),
                })

        if is_tool_installed("mutool") and suffix == ".pdf":
            res = ToolRunner.run("mutool", ["info", str(target)])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "MUPDF STREAM STRUCTURE (mutool)",
                    "content": res.stdout.strip(),
                })

        if is_tool_installed("hachoir-metadata"):
            res = ToolRunner.run("hachoir-metadata", [str(target)])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "CONTAINER METADATA (hachoir-metadata)",
                    "content": res.stdout.strip(),
                })

    # Generate multi-format structured reports
    generated_reports = generate_module_reports(
        module_id="06_document_harvesting",
        module_title="Document & Metadata Harvesting",
        target=target.name,
        scan_mode=mode,
        out_dir=out_dir,
        sections=sections,
    )

    if case:
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Document Harvesting on {target.name} ({mode.upper()} SCAN)",
            description=f"Extracted metadata and scanned for indicators in {target.name} across {len(sections)} phases",
            source="Module 06 (Document Harvesting)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": generated_reports.get("txt", str(out_dir / "report.txt")),
        "reports": generated_reports,
    }

