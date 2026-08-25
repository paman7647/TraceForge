import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.case import Case, get_active_case
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner

def run_identity_social(username: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    username = username.strip()
    if not username:
        raise ValueError("Target username cannot be empty")

    case = Case(case_id) if case_id else get_active_case()
    out_dir = case.case_dir / "modules" / "identity_social" if case else Path(f"workspace/{username}_identity_social").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report_file = out_dir / "report.txt"
    report_lines = [
        "=== TraceForge Identity & Social Intelligence Report ===",
        f"Target Username: {username}\n",
    ]

    # 1. Sherlock
    if is_tool_installed("sherlock"):
        res = ToolRunner.run("sherlock", ["--print-found", "--no-color", "--timeout", "10", username])
        if res.success:
            report_lines.append("--- Sherlock Results ---")
            report_lines.append(res.stdout)

    # 2. Maigret
    if is_tool_installed("maigret"):
        res = ToolRunner.run("maigret", [username, "--timeout", "10", "--no-progressbar"])
        if res.success:
            report_lines.append("\n--- Maigret Results ---")
            report_lines.append(res.stdout)

    # 3. Blackbird
    if is_tool_installed("blackbird"):
        res = ToolRunner.run("blackbird", ["-u", username])
        if res.success:
            report_lines.append("\n--- Blackbird Results ---")
            report_lines.append(res.stdout)

    content = "\n".join(report_lines)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(content)

    if case:
        case.add_ioc(username, "username", f"Social handle target {username}", "Module 03 (Identity & Social)", "high")
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Identity Enumeration for '{username}'",
            description=f"Executed multi-engine username discovery for '{username}'",
            source="Module 03 (Identity & Social)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": str(report_file),
    }
