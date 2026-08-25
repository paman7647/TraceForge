import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.case import Case, get_active_case
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner

def run_email_breach(email: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValueError(f"Invalid email address: {email}")

    case = Case(case_id) if case_id else get_active_case()
    sanitized = email.replace("@", "_at_").replace(".", "_")
    out_dir = case.case_dir / "modules" / "email_breach" if case else Path(f"workspace/{sanitized}_email_breach").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report_file = out_dir / "report.txt"
    report_lines = [
        "=== TraceForge Email & Breach Intelligence Report ===",
        f"Target Email: {email}\n",
    ]

    # 1. Holehe
    if is_tool_installed("holehe"):
        res = ToolRunner.run("holehe", ["--only-used", email])
        if res.success:
            report_lines.append("--- Holehe Registered Accounts ---")
            report_lines.append(res.stdout)

    # 2. h8mail
    if is_tool_installed("h8mail"):
        res = ToolRunner.run("h8mail", ["-t", email, "--loose"])
        if res.success:
            report_lines.append("\n--- h8mail Breach Records ---")
            report_lines.append(res.stdout)

    # 3. theHarvester
    domain = email.split("@")[1]
    if is_tool_installed("theHarvester"):
        res = ToolRunner.run("theHarvester", ["-d", domain, "-b", "duckduckgo", "-l", "50"])
        if res.success:
            report_lines.append(f"\n--- theHarvester Domain Contacts ({domain}) ---")
            report_lines.append(res.stdout)

    content = "\n".join(report_lines)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(content)

    if case:
        case.add_ioc(email, "email", f"Breach & registration target {email}", "Module 04 (Email & Breach)", "high")
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Email & Breach Triage for '{email}'",
            description=f"Queried registration and breach intelligence sources for '{email}'",
            source="Module 04 (Email & Breach)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": str(report_file),
    }
