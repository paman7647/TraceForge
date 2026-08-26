import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.case import Case, get_active_case
from traceforge.config import get_project_root
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner
from traceforge.tools import summarize_pcap


def run_network_recon(pcap_path: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    target = Path(pcap_path)
    if not target.is_absolute() and not target.exists():
        target = (get_project_root() / pcap_path).resolve()
    else:
        target = target.resolve()

    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    case = Case(case_id) if case_id else get_active_case()
    out_dir = (
        case.case_dir / "modules" / "network_recon"
        if case
        else Path(f"workspace/{target.stem}_network_recon").resolve()
    )
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

    # Capinfos — capture file statistics (packet count, duration, data rate)
    if is_tool_installed("capinfos"):
        res = ToolRunner.run("capinfos", [str(target)])
        if res.success and res.stdout.strip():
            report_lines.append("\n--- Capture File Statistics (capinfos) ---")
            report_lines.append(res.stdout)

    # Tcpdump fallback — basic packet header dump when tshark is absent
    if not is_tool_installed("tshark") and is_tool_installed("tcpdump"):
        res = ToolRunner.run("tcpdump", ["-nn", "-r", str(target), "-c", "50"])
        if res.success and res.stdout.strip():
            report_lines.append("\n--- Packet Headers Preview (tcpdump) ---")
            report_lines.extend(res.stdout.splitlines()[:30])

    # Zeek — connection log summary (offline analysis)
    if is_tool_installed("zeek"):
        zeek_out = out_dir / "zeek_logs"
        zeek_out.mkdir(exist_ok=True)
        res = ToolRunner.run("zeek", ["-r", str(target), "-C", f"Log::default_dir={zeek_out}"], cwd=str(zeek_out))
        conn_log = zeek_out / "conn.log"
        if conn_log.exists():
            lines = conn_log.read_text(encoding="utf-8", errors="ignore").splitlines()
            report_lines.append("\n--- Zeek Connection Log Preview ---")
            report_lines.extend(lines[:20])

    # Nmap host discovery when target is a live IP (not used on PCAP — skipped here)
    # Nmap is invoked in run_domain_dns() when the target is an IP address.

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
