import json
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.batch import BatchResult, NormalizedToolResult
from traceforge.case import Case
from traceforge.exporters import CaseExporter
from traceforge.web.services.case_service import get_case


def export_case(case_id: str, out_dir: Optional[str] = None, redact: bool = False) -> Optional[Dict[str, str]]:
    """Exports all multi-format artifacts for a case."""
    c = get_case(case_id)
    if not c:
        return None
    exporter = CaseExporter(c, redact=redact)
    results = exporter.export_all(out_dir=out_dir)
    return {k: str(v) for k, v in results.items()}


def generate_case_report(case_id: str, fmt: str = "markdown", redact: bool = False) -> Optional[str]:
    """Generates case report string content in the requested format."""
    c = get_case(case_id)
    if not c:
        return None
    exporter = CaseExporter(c, redact=redact)
    norm_fmt = fmt.lower().strip()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        if norm_fmt == "html":
            out_file = exporter.export_html(tmp_path / "report.html")
        elif norm_fmt == "json":
            out_file = exporter.export_json(tmp_path / "report.json")
        elif norm_fmt == "stix":
            out_file = exporter.export_stix(tmp_path / "report_stix.json")
        else:
            out_file = exporter.export_markdown(tmp_path / "report.md")

        if out_file.exists():
            with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
    return ""


def generate_batch_report(batch_data: Dict[str, Any], fmt: str = "markdown") -> str:
    """Generates a merged report string for batch results."""
    tool_results = [
        NormalizedToolResult(
            tool_id=t.get("tool_id", 0),
            tool_name=t.get("tool_name", ""),
            binary=t.get("binary", ""),
            command=t.get("command", []),
            exit_code=t.get("exit_code", 0),
            stdout=t.get("stdout", ""),
            stderr=t.get("stderr", ""),
            duration_seconds=t.get("duration_seconds", 0.0),
            executed_at=t.get("executed_at", ""),
            input_target=t.get("input_target", ""),
            findings=t.get("findings", []),
            indicators=t.get("indicators", []),
            metadata=t.get("metadata", {}),
            warnings=t.get("warnings", []),
        )
        for t in batch_data.get("tool_results", [])
    ]

    res = BatchResult(
        job_id=batch_data.get("job_id", ""),
        input_target=batch_data.get("input_target", ""),
        input_type=batch_data.get("input_type", ""),
        workflow_name=batch_data.get("workflow_name", "Batch"),
        started_at=batch_data.get("started_at", ""),
        completed_at=batch_data.get("completed_at", ""),
        duration_seconds=batch_data.get("duration_seconds", 0.0),
        tool_results=tool_results,
        skipped_tools=batch_data.get("skipped_tools", []),
    )

    if fmt.lower() == "json":
        return json.dumps(res.to_dict(), indent=2)
    return res.generate_markdown_report()
