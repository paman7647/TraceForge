import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge.case import Case, get_active_case
from traceforge.modules.reporting import generate_module_reports
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner

def run_domain_dns(domain: str, case_id: Optional[str] = None, mode: str = "quick") -> Dict[str, Any]:
    domain = domain.strip().lower()
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    if not domain:
        raise ValueError("Domain target cannot be empty")

    mode = "full" if mode in ("full", "deep") else "quick"
    case = Case(case_id) if case_id else get_active_case()
    out_dir = case.case_dir / "modules" / "domain_dns" if case else Path(f"workspace/{domain}_domain_dns").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    sections: List[Dict[str, Any]] = []

    # 1. Dig DNS queries
    if is_tool_installed("dig"):
        dns_records = []
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
            res = ToolRunner.run("dig", ["+noall", "+answer", domain, rtype])
            if res.success and res.stdout.strip():
                dns_records.append(f"--- {rtype} Records ---\n{res.stdout.strip()}")
        if dns_records:
            sections.append({
                "title": "CORE DNS RECORDS (dig)",
                "content": "\n\n".join(dns_records),
            })

    # 2. Whois
    if is_tool_installed("whois"):
        res = ToolRunner.run("whois", [domain])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "WHOIS REGISTRATION SUMMARY (whois)",
                "content": res.stdout[:3000].strip(),
            })

    # 3. Subfinder
    subdomains = []
    if is_tool_installed("subfinder"):
        res = ToolRunner.run("subfinder", ["-d", domain, "-silent"])
        if res.success and res.stdout.strip():
            subdomains.extend(res.stdout.splitlines())

    if is_tool_installed("assetfinder"):
        res = ToolRunner.run("assetfinder", ["--subs-only", domain])
        if res.success and res.stdout.strip():
            subdomains.extend(res.stdout.splitlines())

    if subdomains:
        unique_subs = sorted(list(set(s.strip() for s in subdomains if s.strip())))
        sections.append({
            "title": f"SUBDOMAIN DISCOVERY ({len(unique_subs)} found)",
            "content": "\n".join(unique_subs[:200]),
        })

    # 4. HTTPX Probing
    if is_tool_installed("httpx"):
        res = ToolRunner.run("httpx", ["-u", domain, "-silent", "-title", "-status-code", "-tech-detect", "-cdn"])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "HTTP SERVICE PROBING & TECH FINGERPRINTS (httpx)",
                "content": res.stdout.strip(),
            })

    # 5. dnstwist
    if is_tool_installed("dnstwist"):
        res = ToolRunner.run("dnstwist", ["--registered", domain])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "REGISTERED TYPOSQUATS (dnstwist)",
                "content": res.stdout.strip(),
            })

    # Deep Scan Extended Tools
    if mode == "full":
        if is_tool_installed("wafw00f"):
            res = ToolRunner.run("wafw00f", [f"https://{domain}"])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "WEB APPLICATION FIREWALL (wafw00f)",
                    "content": res.stdout.strip(),
                })

        if is_tool_installed("tlsx"):
            res = ToolRunner.run("tlsx", ["-u", domain, "-san", "-cn", "-resp"])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "TLS CERTIFICATE METADATA (tlsx)",
                    "content": res.stdout.strip(),
                })

        if is_tool_installed("katana"):
            res = ToolRunner.run("katana", ["-u", f"https://{domain}", "-silent", "-ct", "5s"])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "CRAWLER ENDPOINTS (katana)",
                    "content": "\n".join(res.stdout.splitlines()[:50]),
                })

        if is_tool_installed("naabu"):
            res = ToolRunner.run("naabu", ["-host", domain, "-top-ports", "100", "-silent"])
            if res.success and res.stdout.strip():
                sections.append({
                    "title": "OPEN PORT DISCOVERY (naabu)",
                    "content": res.stdout.strip(),
                })

    # Generate multi-format structured reports
    generated_reports = generate_module_reports(
        module_id="05_domain_dns",
        module_title="Domain & DNS Intelligence",
        target=domain,
        scan_mode=mode,
        out_dir=out_dir,
        sections=sections,
    )

    if case:
        case.add_ioc(domain, "domain", f"Domain target {domain}", "Module 05 (Domain & DNS)", "high")
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Domain Reconnaissance for '{domain}' ({mode.upper()} SCAN)",
            description=f"Queried DNS infrastructure, WHOIS, and subdomains for '{domain}' with {len(sections)} phases",
            source="Module 05 (Domain & DNS)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": generated_reports.get("txt", str(out_dir / "report.txt")),
        "reports": generated_reports,
    }

