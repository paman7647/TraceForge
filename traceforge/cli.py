import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge import __version__
from traceforge.case import (
    Case,
    create_case,
    get_active_case,
    list_all_cases,
    set_active_case,
)
from traceforge.catalog import Catalog
from traceforge.config import (
    VALID_PROFILES,
    get_custom_components,
    get_feature_runtime,
    get_project_root,
    get_runtime_profile,
    load_config,
    save_config,
    set_custom_components,
    set_feature_runtime,
    set_runtime_profile,
)
from traceforge.exporters import CaseExporter
from traceforge.modules.documents import run_document_harvesting
from traceforge.modules.domain import run_domain_dns
from traceforge.modules.email import run_email_breach
from traceforge.modules.identity import run_identity_social
from traceforge.modules.image import run_image_forensics
from traceforge.modules.network import run_network_recon
from traceforge.modules.opsec import run_opsec_audit
from traceforge.platform_detect import (
    detect_full_environment,
    detect_platform,
    get_termux_info,
    is_termux,
    is_tool_installed,
    recommend_runtime_profile,
    which_tool,
)
from traceforge.runners import (
    CAPABILITY_MATRIX,
    ToolRunner,
    select_runtime_for_feature,
)
from traceforge.tools import (
    AssetGraph,
    compare_filesystem_baselines,
    correlate_observations,
    create_filesystem_baseline,
    diff_snapshots,
    extract_iocs,
    index_evidence_directory,
    inspect_endpoint,
    normalize_timeline,
    package_case,
    summarize_pcap,
    triage_log_stream,
)

def print_banner():
    profile = get_runtime_profile()
    plat_str = "Termux / Android" if is_termux() else "Workstation"
    print(f"""╔══════════════════════════════════════════════════════════════════════╗
║                             TRACEFORGE                               ║
║           Open-Source Intelligence & Digital Forensics               ║
╠══════════════════════════════════════════════════════════════════════╣
║ Lead: Aman Kumar Pandey    Profile: {profile:<12} Platform: {plat_str:<14} ║
╚══════════════════════════════════════════════════════════════════════╝""")

def print_legal_notice():
    print("""
===============================================================================
       TRACEFORGE — RESPONSIBLE USE, DISCLAIMER & LEGAL POLICIES
===============================================================================
TraceForge is an open-source digital forensics, incident response, network
reconnaissance, and open-source intelligence (OSINT) investigation toolkit.

1. AUTHORIZED OPERATOR MANDATE
   Use of this software is strictly restricted to authorized security audits,
   defensive incident response, verified bug bounties within declared scope,
   law enforcement investigations under valid warrant, and academic research.

2. CRIMINAL CODES & MULTI-JURISDICTIONAL NOTICE
   Unauthorized computer access, unauthorized port scanning, denial-of-service,
   data interception, or private data harvesting without express permission is
   strictly prohibited under international cybercrime statutes:
   - India: Information Technology Act, 2000 (§§ 43, 66, 66B, 66C, 66D, 79)
   - United States: Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)
   - European Union: Directive 2013/40/EU (Attacks against information systems)
   - United Kingdom: Computer Misuse Act 1990 (Sections 1, 2, 3, 3A)

3. ZERO WARRANTY & LIMITATION OF LIABILITY
   TraceForge is provided "AS IS", without warranty of any kind, express or
   implied (MIT License). In no event shall the authors or copyright holders
   be liable for any claim, damages, or criminal liability arising from misuse.

Full Policy Documentation:
- Disclaimer:       docs/DISCLAIMER.md
- Responsible Use:  docs/RESPONSIBLE_USE.md
- Privacy Policy:   docs/PRIVACY.md
- License Audit:    docs/LICENSE_AUDIT.md
- Risk Assessment:  docs/LEGAL_RISK_ASSESSMENT.md
- Termux Guide:     docs/platforms/termux.md
===============================================================================
""")

def print_termux_guide():
    tinfo = get_termux_info()
    print("""
===============================================================================
             TRACEFORGE — TERMUX / ANDROID PLATFORM GUIDE
===============================================================================
TraceForge provides native support for Android execution inside Termux.

1. ENVIRONMENT & PREFIX
   • Prefix Location : """ + (tinfo['prefix'] or '$PREFIX') + """
   • Execution Model : Non-root Android Userland
   • Package Manager : pkg (APT wrapper for Termux repository)

2. SHARED STORAGE SETUP
   To allow TraceForge to ingest files from Android storage (/sdcard, Downloads, DCIM):
   Run:
     termux-setup-storage
   Then access files at: $HOME/storage/shared/

3. SUPPORTED CAPABILITIES (ZERO ROOT REQUIRED)
   ✓ Media & Image Forensics (EXIF, metadata, steganography triage)
   ✓ Document & PDF Metadata Extraction
   ✓ High-Speed SHA-256 Evidence Indexing
   ✓ Offline PCAP File Analysis & Protocol Breakdown
   ✓ IOC Extraction & Indicator Defanging
   ✓ Domain / DNS / WHOIS Intelligence
   ✓ Forensic Case Management & Chain of Custody
   ✓ Multi-Format Case Reporting (Markdown, HTML, STIX 2.1, MISP, CSV)

4. ROOT & HARDWARE BOUNDARIES
   ! Live Wireless Monitor Mode (Aircrack-NG): Requires rooted kernel or USB OTG.
   ! Live Raw Packet Capture: Requires root; offline PCAP analysis works without root.
   ! Raw SYN Port Scanning (Masscan / Nmap -sS): Requires root; TCP connect scan (-sT) works unrooted.

5. OPTIONAL TERMUX INTEGRATIONS
   • Termux:API   : `pkg install termux-api` for battery & Wi-Fi environment posture.
   • Termux:Boot  : Optional autorun scripts under $HOME/.termux/boot/.
   • Termux:Widget: Quick-launch shortcuts under $HOME/.shortcuts/.
===============================================================================
""")

def select_profile_interactive(auto_recommend: bool = True) -> str:
    """Interactively detects environment and guides user to choose a runtime profile."""
    env = detect_full_environment()
    rec = recommend_runtime_profile(env)

    print("\n" + "=" * 70)
    print("  TRACEFORGE — Runtime Profile Selector")
    print("=" * 70)
    print("  Detected Host Environment:")
    print(f"    • Operating System : {env['os_name']} ({env['distro']} {env['os_version']})")
    print(f"    • Architecture     : {env['arch']}")
    print(f"    • Python Version   : {env['python_version']} {'(Virtual Environment)' if env['in_venv'] else ''}")
    print(f"    • Go Toolchain     : {env['go_version'] or 'Not detected'}")
    print(f"    • Rust / Cargo     : {env['rust_version'] or 'Not detected'}")
    print(f"    • Package Manager  : {env['pkg_manager']}")
    print(f"    • Disk Space Free  : {env['disk_free_gb']} GB")
    if env.get("is_termux"):
        tinfo = env.get("termux", {})
        print(f"    • Termux Prefix    : {tinfo.get('prefix')}")
        print(f"    • Shared Storage   : {'Mounted ($HOME/storage)' if tinfo.get('storage_mounted') else 'Not mounted (Run: termux-setup-storage)'}")
    print("-" * 70)
    print(f"  Recommended Profile: {rec['profile'].upper()}")
    print(f"  Reason: {rec['reason']}")
    print("=" * 70)
    print("  Choose your runtime profile:\n")
    print("  [1] Recommended  — Install & run the best practical combination for this system")
    print("  [2] Python       — Pure Python runtime (full document & reporting support)")
    print("  [3] Go           — Prefer compiled Go helpers for high-throughput tasks")
    print("  [4] Python + Go  — Python application logic + Go streaming/hashing acceleration")
    print("  [5] Full         — Python + Go + optional native OSINT/DFIR tool integrations")
    print("  [6] Minimal      — Core runtime and essential built-ins only")
    print("  [7] Custom       — Choose components individually")
    print("  [Q] Cancel / Keep Current\n")

    try:
        choice = input("Select Profile [1-7] > ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return get_runtime_profile()

    selected = "python-go"
    if choice in ("1", "recommended", ""):
        selected = rec["profile"]
    elif choice in ("2", "python"):
        selected = "python"
    elif choice in ("3", "go"):
        selected = "go"
    elif choice in ("4", "python-go", "python+go"):
        selected = "python-go"
    elif choice in ("5", "full"):
        selected = "full"
    elif choice in ("6", "minimal"):
        selected = "minimal"
    elif choice in ("7", "custom"):
        selected = "custom"
        configure_custom_components_interactive()
    elif choice == "q":
        return get_runtime_profile()
    else:
        print("[!] Invalid selection, keeping current profile.")
        return get_runtime_profile()

    set_runtime_profile(selected)
    print(f"[+] Active runtime profile updated to: {selected.upper()}")
    return selected

def configure_custom_components_interactive():
    comps = get_custom_components()
    keys = list(comps.keys())
    while True:
        print("\n--- Custom Component Toggles ---")
        for idx, k in enumerate(keys, 1):
            status = "✓ ON" if comps[k] else "- OFF"
            print(f"  [{idx:2d}] {k:<16} : {status}")
        print("  [S ] Save & Apply")
        print("  [C ] Cancel\n")

        try:
            sel = input("Toggle Number or Option > ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            break

        if sel == "S":
            set_custom_components(comps)
            print("[+] Custom components saved.")
            break
        elif sel == "C":
            break
        elif sel.isdigit() and 1 <= int(sel) <= len(keys):
            target_key = keys[int(sel) - 1]
            comps[target_key] = not comps[target_key]

def menu_settings():
    while True:
        prof = get_runtime_profile()
        print("\n" + "=" * 60)
        print("  TRACEFORGE — Settings & Runtime Configuration")
        print(f"  [Active Profile: {prof.upper()}]")
        print("=" * 60)
        print("  [1] Change Runtime Profile    (Minimal, Python, Go, Python+Go, Full, Custom)")
        print("  [2] Feature Fast-Path Config  (Override runtimes for hash, pcap, ioc, etc.)")
        print("  [3] Custom Component Toggles  (Fine-tune individual component inclusion)")
        print("  [B] Back to Main Menu\n")

        try:
            sel = input("Select Setting > ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            break

        if sel == "1":
            select_profile_interactive()
            input("\nPress Enter to continue...")
        elif sel == "2":
            menu_feature_overrides()
        elif sel == "3":
            configure_custom_components_interactive()
            input("\nPress Enter to continue...")
        elif sel in ("B", "BACK", ""):
            break

def menu_feature_overrides():
    features = list(CAPABILITY_MATRIX.keys())
    while True:
        print("\n--- Feature-Level Runtime Fast-Path Overrides ---")
        for idx, feat in enumerate(features, 1):
            spec = CAPABILITY_MATRIX[feat]
            curr_override = get_feature_runtime(feat, "auto")
            print(f"  [{idx}] {feat:<10} (Preferred: {spec['preferred']:<6} | Override: {curr_override.upper()})")
        print("  [B] Back\n")

        try:
            sel = input("Select Feature to Override > ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            break

        if sel in ("B", "BACK", ""):
            break
        elif sel.isdigit() and 1 <= int(sel) <= len(features):
            target_feat = features[int(sel) - 1]
            print(f"\nOverride runtime for '{target_feat}':")
            print("  1) Auto (Recommended by profile)")
            print("  2) Force Python")
            print("  3) Force Go")
            choice = input("Select Option [1-3] > ").strip()
            if choice == "1":
                set_feature_runtime(target_feat, "auto")
                print(f"[+] '{target_feat}' runtime reset to AUTO.")
            elif choice == "2":
                set_feature_runtime(target_feat, "python")
                print(f"[+] '{target_feat}' runtime set to PYTHON.")
            elif choice == "3":
                set_feature_runtime(target_feat, "go")
                print(f"[+] '{target_feat}' runtime set to GO.")
            input("\nPress Enter to continue...")

def interactive_menu():
    catalog = Catalog()
    while True:
        active = get_active_case()
        active_str = f"Active Case: {active.case_id} ({active.data.get('case_name','')})" if active else "Active Case: None (Default Workspace)"
        profile_str = get_runtime_profile().upper()
        plat_str = "Termux / Android" if is_termux() else "Host"

        print("\n" + "=" * 70)
        print("  TRACEFORGE — Interactive Operator Console")
        print(f"  [{active_str}] • [Profile: {profile_str}] • [{plat_str}]")
        print("=" * 70)
        print("  [1] New Case                 (Initialize a new forensic case)")
        print("  [2] Open Case                (Switch active case)")
        print("  [3] List Cases               (View all registered workspaces)")
        print("  [4] Add Evidence             (Ingest evidence with SHA-256 integrity hash)")
        print("  [5] Run Investigation        (Execute one of 7 analysis modules)")
        print("  [6] TraceForge Tools         (Run native first-party analytical tools)")
        print("  [7] Tool Catalog             (Search, inspect, and audit 152 tools)")
        print("  [8] Export / Reports         (Generate Markdown, HTML, CSV, STIX, MISP)")
        print("  [S] Settings                 (Configure runtime profile & fast-paths)")
        print("  [D] Doctor                   (Check environment, dependencies & runtimes)")
        print("  [L] Legal / Policy           (Responsible use, disclaimers, privacy)")
        if is_termux():
            print("  [M] Termux Info              (Android shared storage & API status)")
        print("  [Q] Quit\n")

        try:
            choice = input("Select Option > ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting TraceForge.")
            break

        if choice in ("L", "LEGAL"):
            print_legal_notice()
            input("\nPress Enter to continue...")
        elif choice in ("M", "TERMUX"):
            print_termux_guide()
            input("\nPress Enter to continue...")
        elif choice in ("S", "SETTINGS"):
            menu_settings()
        elif choice == "1":
            name = input("Enter Case Name > ").strip() or "Forensic Investigation"
            analyst = input("Enter Analyst Name > ").strip() or "Analyst"
            c = create_case(name, analyst)
            print(f"[+] Created and activated case: {c.case_id}")
            input("\nPress Enter to continue...")
        elif choice == "2":
            cases = list_all_cases()
            if not cases:
                print("[!] No cases registered.")
            else:
                for idx, c in enumerate(cases, 1):
                    print(f"  {idx}) {c['case_id']} - {c['case_name']} ({c['created_at'][:19]})")
                sel = input("Select Case Number (or Enter to cancel) > ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(cases):
                    cid = cases[int(sel) - 1]["case_id"]
                    set_active_case(cid)
                    print(f"[+] Active case set to: {cid}")
            input("\nPress Enter to continue...")
        elif choice == "3":
            cases = list_all_cases()
            print(f"\n--- Registered Cases ({len(cases)}) ---")
            for c in cases:
                print(f"  [{c['case_id']}] {c['case_name']} | Analyst: {c.get('analyst','N/A')} | Created: {c['created_at'][:19]}")
            input("\nPress Enter to continue...")
        elif choice == "4":
            if not active:
                print("[!] No active case. Creating a default case...")
                active = create_case("Default Case", "Operator")
            path = input("Enter evidence file path > ").strip()
            if path and Path(path).is_file():
                desc = input("Description > ").strip()
                rec = active.ingest_evidence(path, description=desc)
                print(f"[+] Ingested: {rec['id']} (SHA-256: {rec['sha256'][:16]}...)")
            else:
                print("[!] File not found.")
            input("\nPress Enter to continue...")
        elif choice == "5":
            run_module_interactive(active)
        elif choice == "6":
            run_tools_interactive(active)
        elif choice == "7":
            q = input("Search catalog (or Enter to list all) > ").strip()
            res = catalog.search(q) if q else catalog.tools
            print(f"\n--- Tool Catalog ({len(res)} matches) ---")
            for t in res[:25]:
                st = "✓" if t.is_installed else " "
                print(f"  [{st}] {t.id:3d}. {t.name:<22} ({t.binary}) [{t.category}]")
            if len(res) > 25:
                print(f"  ... and {len(res) - 25} more tools.")
            input("\nPress Enter to continue...")
        elif choice == "8":
            if not active:
                print("[!] No active case to export.")
            else:
                red = input("Redact PII (IPs/Emails)? [y/N] > ").strip().lower() == "y"
                exporter = CaseExporter(active, redact=red)
                res = exporter.export_all()
                print(f"[+] Exported case {active.case_id}:")
                for k, p in res.items():
                    print(f"  - {k:<15}: {p}")
            input("\nPress Enter to continue...")
        elif choice in ("D", "DOCTOR"):
            run_doctor()
            input("\nPress Enter to continue...")
        elif choice in ("Q", "QUIT", "EXIT"):
            print("Exiting TraceForge.")
            break

def run_module_interactive(active: Optional[Case]):
    print("\n--- TraceForge Investigation Modules ---")
    print("  1) Image & Media Forensics       (EXIF, metadata, steganography)")
    print("  2) Network Recon & PCAP          (Port scan, PCAP triage, DNS)")
    print("  3) Identity & Social Recon       (Username lookup, accounts)")
    print("  4) Email & Breach Analysis       (Breach checks, MX records)")
    print("  5) Domain & DNS Intelligence     (Subdomains, WHOIS, DNS)")
    print("  6) Document Metadata Harvesting  (PDF, Office metadata)")
    print("  7) Defensive OPSEC Audit         (Host posture, local interfaces)")
    print("  B) Back\n")

    m_sel = input("Select Module [1-7] > ").strip()
    cid = active.case_id if active else None

    if m_sel == "1":
        tgt = input("Image file path > ").strip()
        if tgt and Path(tgt).is_file():
            res = run_image_forensics(tgt, cid)
            print(f"[+] Completed. Report: {res['report_path']}")
        else:
            print("[!] File not found.")
    elif m_sel == "2":
        tgt = input("PCAP file or Host IP > ").strip()
        res = run_network_recon(tgt, cid)
        print(f"[+] Completed. Report: {res['report_path']}")
    elif m_sel == "3":
        tgt = input("Username or Handle > ").strip()
        res = run_identity_social(tgt, cid)
        print(f"[+] Completed. Report: {res['report_path']}")
    elif m_sel == "4":
        tgt = input("Email address > ").strip()
        res = run_email_breach(tgt, cid)
        print(f"[+] Completed. Report: {res['report_path']}")
    elif m_sel == "5":
        tgt = input("Target domain > ").strip()
        res = run_domain_dns(tgt, cid)
        print(f"[+] Completed. Report: {res['report_path']}")
    elif m_sel == "6":
        tgt = input("Document file path > ").strip()
        if tgt and Path(tgt).is_file():
            res = run_document_harvesting(tgt, cid)
            print(f"[+] Completed. Report: {res['report_path']}")
        else:
            print("[!] File not found.")
    elif m_sel == "7":
        res = run_opsec_audit(cid)
        print(f"[+] Completed. Report: {res['report_path']}")
    input("\nPress Enter to continue...")

def run_tools_interactive(active: Optional[Case]):
    print("\n--- TraceForge First-Party Tools ---")
    print("  1) Asset Relationship Graph    (Build graph from subdomains/IPs/URLs)")
    print("  2) Universal Snapshot Diff     (Compare DNS/HTTP/Asset snapshots)")
    print("  3) Streaming IOC Extractor     (Extract/defang IPv4/IPv6/domains/emails/hashes)")
    print("  4) Evidence Directory Indexer  (Recursive indexer with SHA-256 and MIME)")
    print("  5) UTC Timeline Normalizer     (Chronological sorter & severity filter)")
    print("  6) PCAP Flow Summary           (Protocol & endpoint dissection)")
    print("  7) Log Triage Engine           (Syslog, auth logs, web access logs)")
    print("  8) Filesystem Baseline         (Snapshot integrity comparison)")
    print("  9) Defensive Endpoint Snapshot (Host posture snapshot)")
    print("  B) Back\n")

    t_sel = input("Select Tool > ").strip()
    if t_sel == "1":
        p = input("Input File (or Enter for stdin text) > ").strip()
        lines = open(p, "r", encoding="utf-8").readlines() if p and Path(p).is_file() else []
        g = AssetGraph()
        g.parse_lines(lines)
        print(json.dumps(g.to_dict(), indent=2))
    elif t_sel == "2":
        f1 = input("Old File > ").strip()
        f2 = input("New File > ").strip()
        if Path(f1).is_file() and Path(f2).is_file():
            l1 = [l.strip() for l in open(f1).readlines()]
            l2 = [l.strip() for l in open(f2).readlines()]
            res = diff_snapshots("snapshot_diff", l1, l2)
            print(json.dumps(res, indent=2))
    elif t_sel == "3":
        p = input("Target File > ").strip()
        if Path(p).is_file():
            iocs = extract_iocs(open(p, "r", encoding="utf-8", errors="ignore").read())
            print(json.dumps(iocs, indent=2))
    elif t_sel == "4":
        d = input("Directory to Index > ").strip() or "."
        items = index_evidence_directory(d)
        print(json.dumps(items, indent=2))
    elif t_sel == "9":
        snap = inspect_endpoint()
        print(json.dumps(snap, indent=2))
    input("\nPress Enter to continue...")

def run_doctor():
    print("\n=== TraceForge Environment & Runtime Diagnostics ===")
    env = detect_full_environment()
    profile = get_runtime_profile()

    print(f"\n[ Active Runtime Profile ]")
    print(f"  Profile          : {profile.upper()}")

    print(f"\n[ Host Platform ]")
    print(f"  Operating System : {env['os_name']} ({env['distro']} {env['os_version']})")
    print(f"  Architecture     : {env['arch']}")
    print(f"  Python Version   : {env['python_version']} {'(in Virtualenv)' if env['in_venv'] else ''}")
    print(f"  Go Toolchain     : {env['go_version'] or 'Not available'}")
    print(f"  Rust / Cargo     : {env['rust_version'] or 'Not available'}")
    print(f"  Package Manager  : {env['pkg_manager']}")
    print(f"  Free Disk Space  : {env['disk_free_gb']} GB (of {env['disk_total_gb']} GB)")

    if env.get("is_termux"):
        tinfo = env.get("termux", {})
        print(f"\n[ Termux Android Integration ]")
        print(f"  Prefix Path      : {tinfo.get('prefix')}")
        storage_status = "✓ Mounted ($HOME/storage)" if tinfo.get("storage_mounted") else "! Not configured (Run: termux-setup-storage)"
        print(f"  Shared Storage   : {storage_status}")
        api_status = "✓ Active" if tinfo.get("api_available") else "- Optional (pkg install termux-api)"
        print(f"  Termux:API       : {api_status}")

    print(f"\n[ First-Party Fast-Path Acceleration ]")
    for feat, spec in CAPABILITY_MATRIX.items():
        dec = select_runtime_for_feature(feat)
        status = "✓ ACCELERATED (Go)" if dec.selected_runtime == "go" else f"✓ ACTIVE ({dec.selected_runtime.upper()})"
        print(f"  {feat:<12} : {status:<22} (Preferred: {spec['preferred']})")

    print(f"\n[ External Security Toolchain ]")
    core_tools = [
        ("ExifTool", "exiftool"),
        ("TShark", "tshark"),
        ("Subfinder", "subfinder"),
        ("Sherlock", "sherlock"),
        ("Binwalk", "binwalk"),
        ("Native traceforge-native", "traceforge-native"),
    ]
    for name, bin_name in core_tools:
        found = which_tool(bin_name)
        status = f"✓ Found ({found})" if found else "! Missing (Optional fallback)"
        print(f"  {name:<24} : {status}")

    print(f"\n[ Multi-Format Reporting Capabilities ]")
    print("  Markdown Report  : ✓ Built-in (Zero Dependencies)")
    print("  HTML Report      : ✓ Built-in (Zero Dependencies)")
    print("  CSV / TSV Bundle : ✓ Built-in (Formula-Injection Protected)")
    print("  JSON / JSONL     : ✓ Built-in (Timesketch Compatible)")
    print("  STIX 2.1 / MISP  : ✓ Built-in (Threat Intel Bundles)")
    print("  KML / GeoJSON    : ✓ Built-in (Geospatial Artifacts)")
    print("=" * 60)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="traceforge",
        description="TraceForge — Open-Source OSINT, Digital Forensics & Threat Intelligence Toolkit",
    )
    parser.add_argument("--version", action="version", version=f"TraceForge {__version__}")
    parser.add_argument("--legal", action="store_true", help="Display responsible use, disclaimer, and licensing notices")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose runtime decision tracing")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # legal
    subparsers.add_parser("legal", help="Display legal disclaimer and responsible use policy")
    subparsers.add_parser("disclaimer", help="Display legal disclaimer and responsible use policy")

    # termux
    subparsers.add_parser("termux", help="Display Termux Android platform diagnostics and usage guide")

    # doctor
    subparsers.add_parser("doctor", help="Run comprehensive environment, dependency, and runtime checks")

    # profile
    prof_p = subparsers.add_parser("profile", help="View or switch the active runtime profile")
    prof_p.add_argument("name", nargs="?", help=f"Profile name to set: {', '.join(VALID_PROFILES)}")

    # config
    cfg_p = subparsers.add_parser("config", help="Manage TraceForge configuration and fast-path overrides")
    cfg_subs = cfg_p.add_subparsers(dest="config_action", help="Config action")
    cfg_get = cfg_subs.add_parser("get", help="Get a configuration key")
    cfg_get.add_argument("key", help="Configuration key")
    cfg_set = cfg_subs.add_parser("set", help="Set a configuration key")
    cfg_set.add_argument("key", help="Configuration key")
    cfg_set.add_argument("value", help="Configuration value")
    cfg_subs.add_parser("list", help="List entire configuration")

    # case
    case_p = subparsers.add_parser("case", help="Case management")
    case_subs = case_p.add_subparsers(dest="case_action", help="Case actions")
    c_new = case_subs.add_parser("new", help="Create a new case")
    c_new.add_argument("name", help="Case Name")
    c_new.add_argument("--analyst", default="Analyst", help="Lead Analyst")
    case_subs.add_parser("list", help="List all cases")
    c_open = case_subs.add_parser("open", help="Set active case")
    c_open.add_argument("case_id", help="Case ID to activate")
    c_ingest = case_subs.add_parser("add-evidence", help="Ingest evidence into case")
    c_ingest.add_argument("path", help="Evidence file path")
    c_ingest.add_argument("--desc", default="", help="Description")
    c_ingest.add_argument("--case-id", help="Target Case ID")

    # export
    exp_p = subparsers.add_parser("export", help="Export case reports & datasets")
    exp_p.add_argument("case_id", nargs="?", help="Case ID to export")
    exp_p.add_argument("--redact", action="store_true", help="Redact sensitive IPs & emails")
    exp_p.add_argument("--out", help="Output directory")

    # tools
    tools_p = subparsers.add_parser("tools", help="First-party analytical tools")
    tools_subs = tools_p.add_subparsers(dest="tool_action", help="Tool action")

    t_graph = tools_subs.add_parser("asset-graph", help="Generate asset relationship graph")
    t_graph.add_argument("file", nargs="?", help="Input file or stdin")
    t_graph.add_argument("--html", help="Export to interactive HTML file")

    t_diff = tools_subs.add_parser("diff", help="Universal snapshot differ")
    t_diff.add_argument("file1", help="Old snapshot file")
    t_diff.add_argument("file2", help="New snapshot file")
    t_diff.add_argument("--domain", default="snapshot", help="Domain or category")

    t_ioc = tools_subs.add_parser("ioc-extract", help="Stream IOC extractor and defanger")
    t_ioc.add_argument("file", nargs="?", help="Input file or stdin")
    t_ioc.add_argument("--defang", action="store_true", help="Defang indicators")
    t_ioc.add_argument("--json", action="store_true", help="Emit JSON output")

    t_index = tools_subs.add_parser("evidence-index", help="Recursively index directory files with SHA-256")
    t_index.add_argument("dir", nargs="?", default=".", help="Target directory")
    t_index.add_argument("--json", action="store_true", help="Emit JSON output")

    t_triage = tools_subs.add_parser("log-triage", help="Triage log streams for bursts and auth failures")
    t_triage.add_argument("file", nargs="?", help="Log file or stdin")

    t_pcap = tools_subs.add_parser("pcap-summary", help="Dissect packet capture protocols and endpoints")
    t_pcap.add_argument("file", help="PCAP capture file")

    t_base = tools_subs.add_parser("file-baseline", help="Create or compare filesystem baselines")
    t_base.add_argument("dir", help="Directory or baseline file 1")
    t_base.add_argument("file2", nargs="?", help="Baseline file 2 (if comparing)")
    t_base.add_argument("--out", help="Save baseline JSON")

    tools_subs.add_parser("endpoint-inspect", help="Collect defensive host environment posture")

    # modules
    mod_p = subparsers.add_parser("module", help="Execute an investigation module")
    mod_p.add_argument("module_id", help="Module name or number (1:image, 2:network, 3:identity, 4:email, 5:domain, 6:docs, 7:opsec)")
    mod_p.add_argument("target", nargs="?", help="Target file, domain, email, or username")
    mod_p.add_argument("case_id", nargs="?", help="Associated Case ID")

    # catalog
    cat_p = subparsers.add_parser("catalog", help="Query the 152-tool catalog")
    cat_p.add_argument("query", nargs="?", default="", help="Search query")

    return parser

def main(args: Optional[List[str]] = None) -> int:
    if args is None:
        args = sys.argv[1:]

    # If no arguments provided in interactive terminal, launch interactive console
    if not args and sys.stdin.isatty():
        print_banner()
        interactive_menu()
        return 0

    parser = build_parser()
    parsed = parser.parse_args(args)

    if parsed.legal or parsed.subcommand in ("legal", "disclaimer"):
        print_legal_notice()
        return 0

    if parsed.subcommand == "termux":
        print_termux_guide()
        return 0

    if not parsed.subcommand:
        parser.print_help()
        return 0

    if parsed.subcommand == "doctor":
        run_doctor()
        return 0

    if parsed.subcommand == "profile":
        if parsed.name:
            if set_runtime_profile(parsed.name):
                print(f"[+] Runtime profile set to: {parsed.name.upper()}")
                return 0
            else:
                print(f"[!] Invalid profile '{parsed.name}'. Choose from: {', '.join(VALID_PROFILES)}")
                return 1
        else:
            if sys.stdin.isatty():
                select_profile_interactive()
            else:
                print(f"Active Runtime Profile: {get_runtime_profile().upper()}")
            return 0

    if parsed.subcommand == "config":
        caction = parsed.config_action
        cfg = load_config()
        if caction == "list" or not caction:
            print(json.dumps(cfg, indent=2))
        elif caction == "get":
            k = parsed.key
            if "." in k:
                sec, sub = k.split(".", 1)
                val = cfg.get(sec, {}).get(sub) if isinstance(cfg.get(sec), dict) else None
            else:
                val = cfg.get(k)
            print(f"{k} = {val}")
        elif caction == "set":
            k, v = parsed.key, parsed.value
            if k.endswith(".runtime"):
                feat = k.split(".")[0]
                if set_feature_runtime(feat, v):
                    print(f"[+] Feature override set: {feat} -> {v.upper()}")
                else:
                    print(f"[!] Failed to set runtime override for {feat}")
            elif k == "profile" or k == "runtime_profile":
                if set_runtime_profile(v):
                    print(f"[+] Runtime profile set to: {v.upper()}")
                else:
                    print(f"[!] Invalid profile: {v}")
            else:
                cfg[k] = v
                save_config(cfg)
                print(f"[+] Config updated: {k} = {v}")
        return 0

    if parsed.subcommand == "catalog":
        cat = Catalog()
        results = cat.search(parsed.query) if parsed.query else cat.tools
        print(f"TraceForge Catalog: {len(results)} tools found")
        for t in results:
            st = "[INSTALLED]" if t.is_installed else "[AVAILABLE]"
            print(f"  {t.id:3d}. {st:<11} {t.name:<22} ({t.binary}) [{t.category}] - {t.description[:60]}")
        return 0

    if parsed.subcommand == "case":
        caction = parsed.case_action
        if caction == "new":
            c = create_case(parsed.name, parsed.analyst)
            print(f"[+] Created and activated case: {c.case_id} ({parsed.name})")
        elif caction == "list":
            cases = list_all_cases()
            print(f"Registered Cases ({len(cases)}):")
            for c in cases:
                print(f"  [{c['case_id']}] {c['case_name']} (Analyst: {c.get('analyst','N/A')}, Created: {c['created_at'][:19]})")
        elif caction == "open":
            if set_active_case(parsed.case_id):
                print(f"[+] Active case set to: {parsed.case_id}")
            else:
                print(f"[!] Case not found: {parsed.case_id}")
                return 1
        elif caction == "add-evidence":
            c = Case(parsed.case_id) if parsed.case_id else get_active_case()
            if not c or not c.exists():
                print("[!] No valid active case.")
                return 1
            rec = c.ingest_evidence(parsed.path, description=parsed.desc)
            print(f"[+] Ingested evidence into {c.case_id}: {rec['id']} (SHA-256: {rec['sha256'][:16]}...)")
        else:
            print("Usage: traceforge case <new|list|open|add-evidence>")
        return 0

    if parsed.subcommand == "export":
        cid = parsed.case_id
        c = Case(cid) if cid else get_active_case()
        if not c or not c.exists():
            print(f"[!] Case not found: {cid or 'Active Case'}")
            return 1
        exporter = CaseExporter(c, redact=parsed.redact)
        res = exporter.export_all(out_dir=parsed.out)
        print(f"[+] Case export completed for {c.case_id}:")
        for k, p in res.items():
            print(f"  - {k:<15}: {p}")
        return 0

    if parsed.subcommand == "tools":
        taction = parsed.tool_action
        verbose = parsed.verbose
        if taction == "asset-graph":
            lines = []
            if parsed.file and Path(parsed.file).is_file():
                with open(parsed.file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            elif not sys.stdin.isatty():
                lines = sys.stdin.readlines()
            g = AssetGraph()
            g.parse_lines(lines)
            if parsed.html:
                with open(parsed.html, "w", encoding="utf-8") as f:
                    f.write(g.export_html())
                print(f"[+] HTML graph exported to: {parsed.html}")
            else:
                print(json.dumps(g.to_dict(), indent=2))
        elif taction == "diff":
            l1 = [l.strip() for l in open(parsed.file1).readlines()]
            l2 = [l.strip() for l in open(parsed.file2).readlines()]
            res = diff_snapshots(parsed.domain, l1, l2)
            print(json.dumps(res, indent=2))
        elif taction == "ioc-extract":
            content = ""
            if parsed.file and Path(parsed.file).is_file():
                content = open(parsed.file, "r", encoding="utf-8", errors="ignore").read()
            elif not sys.stdin.isatty():
                content = sys.stdin.read()
            iocs = extract_iocs(content)
            if parsed.defang:
                for i in iocs:
                    i["value"] = i["defanged"]
            print(json.dumps(iocs, indent=2))
        elif taction == "evidence-index":
            items = index_evidence_directory(parsed.dir, verbose=verbose)
            print(json.dumps(items, indent=2))
        elif taction == "log-triage":
            lines = []
            if parsed.file and Path(parsed.file).is_file():
                lines = open(parsed.file, "r", encoding="utf-8", errors="ignore").readlines()
            elif not sys.stdin.isatty():
                lines = sys.stdin.readlines()
            res = triage_log_stream(lines)
            print(json.dumps(res, indent=2))
        elif taction == "pcap-summary":
            res = summarize_pcap(parsed.file, verbose=verbose)
            print(json.dumps(res, indent=2))
        elif taction == "file-baseline":
            if parsed.file2:
                b1 = json.load(open(parsed.dir))
                b2 = json.load(open(parsed.file2))
                res = compare_filesystem_baselines(b1, b2)
                print(json.dumps(res, indent=2))
            else:
                b = create_filesystem_baseline(parsed.dir)
                if parsed.out:
                    with open(parsed.out, "w", encoding="utf-8") as f:
                        json.dump(b, f, indent=2)
                    print(f"[+] Baseline saved to: {parsed.out}")
                else:
                    print(json.dumps(b, indent=2))
        elif taction == "endpoint-inspect":
            snap = inspect_endpoint()
            print(json.dumps(snap, indent=2))
        else:
            print("Usage: traceforge tools <asset-graph|diff|ioc-extract|evidence-index|log-triage|pcap-summary|file-baseline|endpoint-inspect>")
        return 0

    if parsed.subcommand == "module":
        mid = str(parsed.module_id).lower()
        target = parsed.target
        cid = parsed.case_id

        if mid in ("1", "image"):
            if not target:
                print("[!] Target media file required: traceforge module 1 <path>")
                return 1
            res = run_image_forensics(target, cid)
            print(f"[+] Media Forensics completed. Report: {res['report_path']}")
        elif mid in ("2", "network", "pcap"):
            if not target:
                print("[!] Target PCAP file required: traceforge module 2 <path>")
                return 1
            res = run_network_recon(target, cid)
            print(f"[+] Network Forensics completed. Report: {res['report_path']}")
        elif mid in ("3", "identity", "social"):
            if not target:
                print("[!] Target username required: traceforge module 3 <username>")
                return 1
            res = run_identity_social(target, cid)
            print(f"[+] Identity Intelligence completed. Report: {res['report_path']}")
        elif mid in ("4", "email", "breach"):
            if not target:
                print("[!] Target email required: traceforge module 4 <email>")
                return 1
            res = run_email_breach(target, cid)
            print(f"[+] Email Intelligence completed. Report: {res['report_path']}")
        elif mid in ("5", "domain", "dns"):
            if not target:
                print("[!] Target domain required: traceforge module 5 <domain>")
                return 1
            res = run_domain_dns(target, cid)
            print(f"[+] Domain Reconnaissance completed. Report: {res['report_path']}")
        elif mid in ("6", "document", "docs"):
            if not target:
                print("[!] Target document required: traceforge module 6 <path>")
                return 1
            res = run_document_harvesting(target, cid)
            print(f"[+] Document Harvesting completed. Report: {res['report_path']}")
        elif mid in ("7", "opsec"):
            res = run_opsec_audit(cid)
            print(f"[+] OPSEC Audit completed. Report: {res['report_path']}")
        else:
            print(f"[!] Unknown module identifier: {mid}")
            return 1
        return 0

    return 0

if __name__ == "__main__":
    sys.exit(main())
