import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge.case import Case, get_active_case
from traceforge.config import get_project_root
from traceforge.modules.reporting import generate_module_reports
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner
from traceforge.tools import summarize_pcap


def run_network_recon(pcap_path: str, case_id: Optional[str] = None, mode: str = "quick") -> Dict[str, Any]:
    target = Path(pcap_path)
    if not target.is_absolute() and not target.exists():
        target = (get_project_root() / pcap_path).resolve()
    else:
        target = target.resolve()

    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    mode = "full" if mode in ("full", "deep") else "quick"
    case = Case(case_id) if case_id else get_active_case()
    out_dir = (
        case.case_dir / "modules" / "network_recon"
        if case
        else Path(f"workspace/{target.stem}_network_recon").resolve()
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    pcap_data = summarize_pcap(target)
    sections: List[Dict[str, Any]] = []

    # 1. Native / Scapy overview
    overview_lines = [
        f"Capture File : {target.name}",
        f"File Size    : {pcap_data.get('filesize_bytes', 0)} bytes",
        f"Protocols    : {', '.join([f'{k} ({v})' for k, v in pcap_data.get('protocols', {}).items()]) or 'N/A'}",
        f"Top Endpoints: {', '.join([f'{k} ({v})' for k, v in pcap_data.get('top_ips', {}).items()]) or 'N/A'}",
        f"DNS Queries  : {', '.join([f'{k} ({v})' for k, v in pcap_data.get('dns_queries', {}).items()]) or 'N/A'}",
        f"TLS SNI Hosts: {', '.join([f'{k} ({v})' for k, v in pcap_data.get('tls_sni_hosts', {}).items()]) or 'N/A'}",
    ]
    sections.append({
        "title": "CAPTURE FLOW OVERVIEW",
        "content": "\n".join(overview_lines),
    })

    # 2. Capinfos
    if is_tool_installed("capinfos"):
        res = ToolRunner.run("capinfos", [str(target)])
        if res.success and res.stdout.strip():
            sections.append({
                "title": "CAPTURE FILE STATISTICS (capinfos)",
                "content": res.stdout.strip(),
            })

    # 3. TShark Protocol Hierarchy & Conversations
    if is_tool_installed("tshark"):
        res_phs = ToolRunner.run("tshark", ["-r", str(target), "-q", "-z", "io,phs"])
        if res_phs.success and res_phs.stdout.strip():
            sections.append({
                "title": "PROTOCOL HIERARCHY (TShark)",
                "content": res_phs.stdout.strip(),
            })

        res_conv = ToolRunner.run("tshark", ["-r", str(target), "-q", "-z", "conv,ip"])
        if res_conv.success and res_conv.stdout.strip():
            sections.append({
                "title": "IP CONVERSATIONS (TShark)",
                "content": res_conv.stdout.strip(),
            })

    # 4. Aircrack-NG Wireless Assessment
    if is_tool_installed("aircrack-ng"):
        res_air = ToolRunner.run("aircrack-ng", [str(target)])
        if res_air.stdout.strip():
            sections.append({
                "title": "WIRELESS 802.11 ASSESSMENT (Aircrack-NG)",
                "content": res_air.stdout.strip(),
            })

    # Deep Scan Extended Tools
    if mode == "full":
        # ngrep
        if is_tool_installed("ngrep"):
            res_ng = ToolRunner.run("ngrep", ["-I", str(target), "-i", "-q", "pass|pwd|user|auth|bearer|login|token|cookie"])
            if res_ng.stdout.strip():
                sections.append({
                    "title": "CLEARTEXT CREDENTIAL PATTERNS (ngrep)",
                    "content": "\n".join(res_ng.stdout.splitlines()[:50]),
                })

        # tcptrace
        if is_tool_installed("tcptrace"):
            res_tt = ToolRunner.run("tcptrace", ["-r", "-s", str(target)])
            if res_tt.stdout.strip():
                sections.append({
                    "title": "TCP FLOW ANALYTICS (tcptrace)",
                    "content": res_tt.stdout.strip(),
                })

        # Zeek
        if is_tool_installed("zeek"):
            zeek_out = out_dir / "zeek_logs"
            zeek_out.mkdir(exist_ok=True)
            ToolRunner.run("zeek", ["-r", str(target), "-C", f"Log::default_dir={zeek_out}"], cwd=str(zeek_out))
            conn_log = zeek_out / "conn.log"
            if conn_log.exists():
                lines = conn_log.read_text(encoding="utf-8", errors="ignore").splitlines()
                sections.append({
                    "title": "ZEEK CONNECTION LOG",
                    "content": "\n".join(lines[:30]),
                })

    # Generate multi-format structured reports
    generated_reports = generate_module_reports(
        module_id="02_network_recon",
        module_title="Network & PCAP Forensics",
        target=target.name,
        scan_mode=mode,
        out_dir=out_dir,
        sections=sections,
    )

    if case:
        for ip in list(pcap_data.get("top_ips", {}).keys())[:10]:
            case.add_ioc(ip, "ipv4", f"PCAP IP {ip}", "Module 02 (Network Recon)", "medium")
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"Network Reconnaissance on {target.name} ({mode.upper()} SCAN)",
            description=f"Parsed packets and flow metrics from {target.name} across {len(sections)} analytic phases",
            source="Module 02 (Network Recon)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": generated_reports.get("txt", str(out_dir / "report.txt")),
        "reports": generated_reports,
        "summary": pcap_data,
    }
