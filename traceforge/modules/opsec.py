import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge.case import Case, get_active_case
from traceforge.modules.reporting import generate_module_reports
from traceforge.platform_detect import is_tool_installed, which_tool
from traceforge.runners import ToolRunner
from traceforge.tools import inspect_endpoint

def run_opsec_audit(case_id: Optional[str] = None, mode: str = "quick") -> Dict[str, Any]:
    mode = "full" if mode in ("full", "deep") else "quick"
    case = Case(case_id) if case_id else get_active_case()
    out_dir = case.case_dir / "modules" / "opsec_audit" if case else Path("workspace/opsec_audit").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    snap = inspect_endpoint()
    sections: List[Dict[str, Any]] = []

    # 1. System endpoint posture
    snap_info = [
        f"Host Name       : {snap['hostname']}",
        f"Operating System: {snap['os']} ({snap['architecture']})",
        f"DNS Resolvers   : {', '.join(snap.get('dns_resolvers', [])) or 'N/A'}",
    ]
    sections.append({
        "title": "ENDPOINT BASELINE POSTURE",
        "content": "\n".join(snap_info),
    })

    # 2. Privacy and cryptography tools availability
    privacy_tools = [
        "mat2", "proxychains4", "tor", "torsocks", "macchanger",
        "wg", "privoxy", "cloudflared", "dnscrypt-proxy", "stubby",
        "ssh", "socat", "ncat", "gpg", "age", "openssl", "srm"
    ]
    tool_lines = [f"{'Executable':<18} {'Status':<14} {'Resolved Path'}"]
    tool_lines.append(f"{'-'*18} {'-'*14} {'-'*30}")
    for t in privacy_tools:
        pth = which_tool(t)
        st = "AVAILABLE" if pth else "MISSING"
        tool_lines.append(f"{t:<18} {st:<14} {pth or '-'}")

    sections.append({
        "title": "OPSEC & CRYPTOGRAPHIC TOOLCHAINS (17 Tools)",
        "content": "\n".join(tool_lines),
    })

    # 3. Active Sessions and Network Listeners
    if snap.get("active_users"):
        sections.append({
            "title": "ACTIVE OPERATOR SESSIONS",
            "content": "\n".join(snap.get("active_users", [])),
        })

    if snap.get("listening_ports"):
        sections.append({
            "title": "OPEN LISTENING SOCKETS",
            "content": "\n".join(snap.get("listening_ports", [])),
        })

    # Generate multi-format structured reports
    generated_reports = generate_module_reports(
        module_id="07_opsec_anonymization",
        module_title="OPSEC & Privacy Environment Audit",
        target=snap['hostname'],
        scan_mode=mode,
        out_dir=out_dir,
        sections=sections,
    )

    if case:
        case.add_event(
            timestamp_str=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            title=f"OPSEC & Environment Audit Executed ({mode.upper()} SCAN)",
            description=f"Audited DNS resolvers, network sockets, and 17 privacy toolchains on {snap['hostname']}",
            source="Module 07 (OPSEC Audit)",
            severity="info",
        )
        case.save()

    return {
        "status": "success",
        "output_directory": str(out_dir),
        "report_path": generated_reports.get("txt", str(out_dir / "report.txt")),
        "reports": generated_reports,
    }

