import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.case import Case, get_active_case
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner
from traceforge.tools import summarize_pcap

def run_network_recon(pcap_path: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    target = Path(pcap_path).resolve()
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    case = Case(case_id) if case_id else get_active_case()
    out_dir = case.case_dir / "modules" / "network_recon" if case else Path(f"workspace/{target.stem}_network_recon").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report_file = out_dir / "report.txt"
    pcap_data = summarize_pcap(target)

    report_lines = [
        "=== TraceForge Network & PCAP Forensics Report ===",
        f"Capture File: {target.name}",
        f"File Size: {pcap_data.get('filesize_bytes', 0)} bytes\n",
        "--- Discovered Protocols ---",
        ", ".join([f"{k} ({v})" for k, v in pcap_data.get("protocols", {}).items()]) or "No protocol data",
        "\n--- Top IP Endpoints ---",
        ", ".join([f"{k} ({v})" for k, v in pcap_data.get("top_ips", {}).items()]) or "No IP endpoints identified",
        "\n--- DNS Queries ---",
        ", ".join([f"{k} ({v})" for k, v in pcap_data.get("dns_queries", {}).items()]) or "No DNS queries identified",
        "\n--- TLS SNI Hosts ---",
        ", ".join([f"{k} ({v})" for k, v in pcap_data.get("tls_sni_hosts", {}).items()]) or "No TLS SNI hosts identified",
    ]

    content = "\n".join(report_lines)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(content)

    if case:
        for ip in list(pcap_data.get("top_ips", {}).keys())[:10]:
            case.add_ioc(ip, "ipv4", f"Observed in PCAP {target.name}", "Module 02 (Network Recon)", "high")
        for domain in list(pcap_data.get("dns_queries", {}).keys())[:10]:
            case.add_ioc(domain, "domain", f"DNS query in {target.name}", "Module 02 (Network Recon)", "high")

        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Network Capture Triage on {target.name}",
            description=f"Dissected protocols and harvested endpoints from {target.name}",
            source="Module 02 (Network Recon)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": str(report_file),
        "summary": pcap_data,
    }
