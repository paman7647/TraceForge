import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from traceforge.case import Case, get_active_case
from traceforge.platform_detect import is_tool_installed
from traceforge.runners import ToolRunner
from traceforge.tools import inspect_endpoint

def run_opsec_audit(case_id: Optional[str] = None) -> Dict[str, Any]:
    case = Case(case_id) if case_id else get_active_case()
    out_dir = case.case_dir / "modules" / "opsec_audit" if case else Path("workspace/opsec_audit").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report_file = out_dir / "report.txt"
    snap = inspect_endpoint()

    report_lines = [
        "=== TraceForge OPSEC & Anonymization Audit Report ===",
        f"Audited Host: {snap['hostname']}",
        f"Operating System: {snap['os']} ({snap['architecture']})",
        f"Collected At: {snap['collected_at']}\n",
        "--- System DNS Resolvers ---",
        ", ".join(snap.get("dns_resolvers", [])) or "No nameservers found in /etc/resolv.conf",
        "\n--- Active Operator Sessions ---",
        "\n".join(snap.get("active_users", [])) or "No active login sessions",
        "\n--- Open Listening Sockets ---",
        "\n".join(snap.get("listening_ports", [])) or "No listening ports identified",
    ]

    # Privacy toolchain check
    privacy_tools = ["tor", "proxychains4", "openvpn", "wireguard", "macchanger"]
    report_lines.append("\n--- Privacy & Proxy Toolchain Status ---")
    for t in privacy_tools:
        st = "INSTALLED" if is_tool_installed(t) else "NOT INSTALLED"
        report_lines.append(f"  - {t:<16}: {st}")

    content = "\n".join(report_lines)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(content)

    if case:
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title="OPSEC & Environment Audit Executed",
            description="Audited DNS resolvers, network sockets, and privacy toolchains.",
            source="Module 07 (OPSEC Audit)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": str(report_file),
    }
