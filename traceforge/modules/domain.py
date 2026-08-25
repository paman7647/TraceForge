import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.case import Case, get_active_case
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner

def run_domain_dns(domain: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("Domain target cannot be empty")

    case = Case(case_id) if case_id else get_active_case()
    out_dir = case.case_dir / "modules" / "domain_dns" if case else Path(f"workspace/{domain}_domain_dns").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report_file = out_dir / "report.txt"
    report_lines = [
        "=== TraceForge Domain & DNS Intelligence Report ===",
        f"Target Domain: {domain}\n",
    ]

    # 1. Dig DNS queries
    if is_tool_installed("dig"):
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
            res = ToolRunner.run("dig", ["+noall", "+answer", domain, rtype])
            if res.success and res.stdout.strip():
                report_lines.append(f"--- DNS {rtype} Records ---")
                report_lines.append(res.stdout.strip())

    # 2. Whois
    if is_tool_installed("whois"):
        res = ToolRunner.run("whois", [domain])
        if res.success and res.stdout.strip():
            report_lines.append("\n--- WHOIS Registration Data ---")
            report_lines.append(res.stdout[:2000])

    # 3. Subfinder
    if is_tool_installed("subfinder"):
        res = ToolRunner.run("subfinder", ["-d", domain, "-silent"])
        if res.success and res.stdout.strip():
            report_lines.append("\n--- Subfinder Discovered Subdomains ---")
            report_lines.append(res.stdout)

    content = "\n".join(report_lines)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(content)

    if case:
        case.add_ioc(domain, "domain", f"Domain target {domain}", "Module 05 (Domain & DNS)", "high")
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Domain Reconnaissance for '{domain}'",
            description=f"Queried DNS infrastructure, WHOIS, and subdomains for '{domain}'",
            source="Module 05 (Domain & DNS)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": str(report_file),
    }
