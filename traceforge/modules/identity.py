import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge.case import Case, get_active_case
from traceforge.modules.reporting import generate_module_reports
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner

def run_identity_social(username: str, case_id: Optional[str] = None, mode: str = "quick") -> Dict[str, Any]:
    username = username.strip()
    if not username:
        raise ValueError("Target username cannot be empty")

    mode = "full" if mode in ("full", "deep") else "quick"
    case = Case(case_id) if case_id else get_active_case()
    sanitized = "".join(c for c in username if c.isalnum() or c in "._-")
    out_dir = case.case_dir / "modules" / "identity_social" if case else Path(f"workspace/{sanitized}_identity_social").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    sections: List[Dict[str, Any]] = []

    # 1. Sherlock
    if is_tool_installed("sherlock"):
        res = ToolRunner.run("sherlock", ["--print-found", "--no-color", "--timeout", "10", username])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "SOCIAL MEDIA PROFILES (Sherlock)",
                "content": res.stdout.strip(),
            })

    # 2. Maigret
    if is_tool_installed("maigret"):
        res = ToolRunner.run("maigret", [username, "--timeout", "10", "--no-progressbar", "--txt"])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "IDENTITY DOSSIER (Maigret)",
                "content": res.stdout[:3000].strip(),
            })

    # 3. Blackbird
    if is_tool_installed("blackbird"):
        res = ToolRunner.run("blackbird", ["-u", username])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "ONLINE PLATFORMS (Blackbird)",
                "content": res.stdout.strip(),
            })

    # 4. Socialscan
    if is_tool_installed("socialscan"):
        res = ToolRunner.run("socialscan", [username])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "ACCOUNT AVAILABILITY (Socialscan)",
                "content": res.stdout.strip(),
            })

    # Deep Scan Extended Tools
    if mode == "full":
        if is_tool_installed("spiderfoot"):
            res = ToolRunner.run("spiderfoot", ["-s", username, "-t", "USERNAME", "-q"])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "FOOTPRINT CORRELATION (SpiderFoot)",
                    "content": res.stdout[:2000].strip(),
                })

        if is_tool_installed("sn0int"):
            res = ToolRunner.run("sn0int", ["run", "-t", username])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "SEMI-AUTONOMOUS RECON (sn0int)",
                    "content": res.stdout.strip(),
                })

    # Generate multi-format structured reports
    generated_reports = generate_module_reports(
        module_id="03_identity_social",
        module_title="Identity & Social Media Intelligence",
        target=username,
        scan_mode=mode,
        out_dir=out_dir,
        sections=sections,
    )

    if case:
        case.add_ioc(username, "username", f"Social handle target {username}", "Module 03 (Identity & Social)", "high")
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Identity Enumeration for '{username}' ({mode.upper()} SCAN)",
            description=f"Executed multi-engine username discovery for '{username}' across {len(sections)} engines",
            source="Module 03 (Identity & Social)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": generated_reports.get("txt", str(out_dir / "report.txt")),
        "reports": generated_reports,
    }

