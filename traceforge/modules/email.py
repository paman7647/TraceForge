import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge.case import Case, get_active_case
from traceforge.modules.reporting import generate_module_reports
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner

def run_email_breach(email: str, case_id: Optional[str] = None, mode: str = "quick") -> Dict[str, Any]:
    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValueError(f"Invalid email address: {email}")

    mode = "full" if mode in ("full", "deep") else "quick"
    case = Case(case_id) if case_id else get_active_case()
    sanitized = email.replace("@", "_at_").replace(".", "_")
    out_dir = case.case_dir / "modules" / "email_breach" if case else Path(f"workspace/{sanitized}_email_breach").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    sections: List[Dict[str, Any]] = []
    domain = email.split("@")[1]

    # 1. Holehe
    if is_tool_installed("holehe"):
        res = ToolRunner.run("holehe", ["--only-used", email])
        if res.success:
            sections.append({
                "title": "REGISTERED ONLINE SERVICES (Holehe)",
                "content": res.stdout.strip(),
            })

    # 2. h8mail
    if is_tool_installed("h8mail"):
        res = ToolRunner.run("h8mail", ["-t", email, "--loose"])
        if res.success:
            clean_h8 = "\n".join(
                line for line in res.stdout.splitlines()
                if not any(k in line for k in ("ROCKSMASSON", "h8mail posts", "github.com", "___", "| !", "Use responsibly"))
            ).strip()
            sections.append({
                "title": "BREACH INTELLIGENCE (h8mail)",
                "content": clean_h8 or res.stdout.strip(),
            })

    # 3. EmailRep
    if is_tool_installed("emailrep"):
        res = ToolRunner.run("emailrep", [email])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "EMAIL REPUTATION & SIGNALS (EmailRep)",
                "content": res.stdout.strip(),
            })

    # 4. theHarvester
    if is_tool_installed("theHarvester"):
        res = ToolRunner.run("theHarvester", ["-d", domain, "-b", "duckduckgo", "-l", "50"])
        if res.success and res.stdout.strip():
            sections.append({
                "title": f"PASSIVE DOMAIN CONTACTS ({domain})",
                "content": res.stdout.strip(),
            })

    # 5. GHunt
    if is_tool_installed("ghunt"):
        res = ToolRunner.run("ghunt", ["email", email])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "GOOGLE ACCOUNT INTELLIGENCE (GHunt)",
                "content": res.stdout.strip(),
            })

    # Deep Scan Tools
    if mode == "full":
        if is_tool_installed("checkdmarc"):
            res = ToolRunner.run("checkdmarc", [domain])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "DOMAIN AUTHENTICATION & SPOOF DEFENSES (checkdmarc)",
                    "content": res.stdout.strip(),
                })

        if is_tool_installed("pwnedornot"):
            res = ToolRunner.run("pwnedornot", ["-e", email])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "PASTEBIN & BREACH EXPOSURES (pwnedornot)",
                    "content": res.stdout.strip(),
                })

        if is_tool_installed("intelx"):
            res = ToolRunner.run("intelx", ["search", email])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "INTELLIGENCE X ARCHIVES (intelx)",
                    "content": res.stdout.strip(),
                })

    # Generate multi-format structured reports
    generated_reports = generate_module_reports(
        module_id="04_email_breach",
        module_title="Email & Breach Intelligence",
        target=email,
        scan_mode=mode,
        out_dir=out_dir,
        sections=sections,
    )

    if case:
        case.add_ioc(email, "email", f"Breach & registration target {email}", "Module 04 (Email & Breach)", "high")
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Email & Breach Triage for '{email}' ({mode.upper()} SCAN)",
            description=f"Queried registration and breach intelligence sources for '{email}' with {len(sections)} analytic phases",
            source="Module 04 (Email & Breach)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": generated_reports.get("txt", str(out_dir / "report.txt")),
        "reports": generated_reports,
    }

