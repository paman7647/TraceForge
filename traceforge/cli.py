import argparse
import json
import os
import subprocess
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
    ensure_shell_paths_persisted,
    get_candidate_global_bin_dirs,
    get_termux_info,
    get_user_shell_rc_path,
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

def run_doctor(repair: bool = False):
    print("\n=== TraceForge Environment & Runtime Diagnostics ===")
    env = detect_full_environment()
    profile = get_runtime_profile()
    cat = Catalog()
    pf_audit = cat.audit_platform(env)

    if repair:
        print("\n[+] Initiating Automated Environment & System Repair...")
        # 1. Verify & repair directories
        from traceforge.config import get_config_dir, get_user_data_dir, get_workspace_dir, get_cache_dir, get_logs_dir, load_config, save_config
        get_config_dir().mkdir(parents=True, exist_ok=True)
        get_user_data_dir().mkdir(parents=True, exist_ok=True)
        get_workspace_dir().mkdir(parents=True, exist_ok=True)
        get_cache_dir().mkdir(parents=True, exist_ok=True)
        get_logs_dir().mkdir(parents=True, exist_ok=True)
        print("  [✓] Verified and ensured directory hierarchy (Config, Workspace, Cache, Logs).")

        # 2. Verify and repair configuration
        cfg = load_config()
        save_config(cfg)
        print("  [✓] Configuration schema verified and synchronized.")

        # 3. Check bundled catalog
        if cat.tsv_path.exists():
            print(f"  [✓] Bundled tool catalog verified ({len(cat.tools)} entries loaded).")
        else:
            print(f"  [!] Warning: Bundled tool catalog not found at {cat.tsv_path}")

        # 4. Attempt native helper compilation if Go is available and helper is missing
        if env.get("go_version") and not which_tool("traceforge-native"):
            proj_root = get_project_root()
            if (proj_root / "go").exists():
                print("  [*] Building missing Go native helper (traceforge-native)...")
                try:
                    import subprocess
                    bin_dir = proj_root / "bin"
                    bin_dir.mkdir(parents=True, exist_ok=True)
                    subprocess.run(
                        ["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(bin_dir / "traceforge-native"), "."],
                        cwd=str(proj_root / "go"),
                        capture_output=True,
                        check=False,
                    )
                    if (bin_dir / "traceforge-native").exists():
                        print("  [✓] Successfully compiled bin/traceforge-native.")
                except Exception as e:
                    print(f"  [!] Non-fatal notice: Go build skipped ({e}).")

        # 5. Automatically configure global shell PATH if missing
        sh_res = ensure_shell_paths_persisted()
        if sh_res.get("added"):
            print(f"  [✓] Configured global CLI path(s) in {sh_res.get('rc_file')}: {', '.join(sh_res['added'])}")
        elif sh_res.get("success"):
            print(f"  [✓] Global CLI shell paths already verified in {sh_res.get('rc_file')}.")
        else:
            print(f"  [!] Notice regarding shell PATH: {sh_res.get('reason')}")

        print("[+] System repair routines completed.\n")

    print(f"\n[ Active Runtime Profile ]")
    print(f"  Profile          : {profile.upper()}")

    print(f"\n[ Host Platform ]")
    print(f"  Display Identity : {env['display_name']}")
    print(f"  Operating System : {env['os_name']} ({env['distro']} {env['os_version']})")
    print(f"  Architecture     : {env['arch']} ({env.get('hardware', 'Generic')})")
    print(f"  Package Manager  : {env['pkg_manager']}")
    print(f"  Privilege State  : {'Root / UID 0' if env.get('has_root') else ('sudo available' if env.get('sudo_available') else 'Userland (No sudo)')}")
    print(f"  Python Version   : {env['python_version']} {'(in Virtualenv)' if env['in_venv'] else ''}")
    
    import shutil
    cli_on_path = shutil.which("traceforge")
    if cli_on_path:
        print(f"  Global CLI (PATH): ✓ Available ({cli_on_path})")
    else:
        cli_loc = which_tool("traceforge")
        if cli_loc:
            print(f"  Global CLI (PATH): ! Installed at {cli_loc} (Missing from shell $PATH)")
            print(f"                     -> Run 'traceforge doctor --repair' to auto-configure shell profile")
        else:
            print(f"  Global CLI (PATH): ! Not detected on system PATH")

    print(f"  Go Toolchain     : {env['go_version'] or 'Not available'}")
    print(f"  Rust / Cargo     : {env['rust_version'] or 'Not available'}")
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

    print(f"\n[ Platform Security Toolchain Breakdown ]")
    print(f"  • Total Catalog Utilities : {pf_audit['total_catalog']}")
    print(f"  • Supported on Host        : {pf_audit['available_count']}")
    print(f"  • Installed Locally        : {pf_audit['installed_count']}")
    print(f"  • Missing on Host          : {pf_audit['missing_count']}")
    print(f"  • Manual-Only Utilities    : {pf_audit['manual_count']}")
    print(f"  • Unavailable on Host      : {pf_audit['unavailable_count']} (Platform limitations; not installation errors)")

    core_tools = [
        ("ExifTool", "exiftool"),
        ("TShark", "tshark"),
        ("Subfinder", "subfinder"),
        ("Sherlock", "sherlock"),
        ("Binwalk", "binwalk"),
        ("Native traceforge-native", "traceforge-native"),
    ]
    print(f"\n[ Core Utility Status ]")
    for name, bin_name in core_tools:
        rec = cat.find_tool(bin_name)
        found = which_tool(bin_name)
        if found:
            status = f"✓ Installed ({found})"
        elif rec and not rec.is_supported_on_platform(env):
            status = f"× Not available on {env['display_name']}"
        else:
            status = "! Missing (Installable)"
        print(f"  {name:<24} : {status}")

    print(f"\n[ Multi-Format Reporting Capabilities ]")
    print("  Markdown Report  : ✓ Built-in (Zero Dependencies)")
    print("  HTML Report      : ✓ Built-in (Zero Dependencies)")
    print("  CSV / TSV Bundle : ✓ Built-in (Formula-Injection Protected)")
    print("  JSON / JSONL     : ✓ Built-in (Timesketch Compatible)")
    print("  STIX 2.1 / MISP  : ✓ Built-in (Threat Intel Bundles)")
    print("  KML / GeoJSON    : ✓ Built-in (Geospatial Artifacts)")
    print("=" * 60)

def handle_tools_info(parsed: argparse.Namespace) -> int:
    cat = Catalog()
    env = detect_full_environment()
    tool_q = getattr(parsed, "tool", "") or getattr(parsed, "query", "")
    rec = cat.find_tool(tool_q)
    if not rec:
        print(f"[!] Tool '{tool_q}' not found in catalog.")
        return 1
    if getattr(parsed, "json", False):
        print(json.dumps(rec.to_dict(env), indent=2))
        return 0

    d = rec.to_dict(env)
    cap = rec.get_platform_capability(env)
    status_str = f"Installed ({d['binary_path']})" if d["is_installed"] else f"{cap['availability']} ({d['status_label']})"
    ver_str = d["version"] or "N/A"
    print("\n" + "═" * 74)
    print(f"  TraceForge Tool Specification: {d['name']} (#{d['id']})")
    print("═" * 74)
    print(f"  • Binary Name       : {d['binary']}")
    print(f"  • Category          : {d['category']} / {d['subcategory']}")
    print(f"  • Ecosystem         : {d['ecosystem'].upper()}")
    print(f"  • Current Platform  : {env['display_name']}")
    print(f"  • Platform Support  : {cap['availability']}")
    print(f"  • Platform Rationale: {cap['reason']}")
    print(f"  • Operational Status: {status_str}")
    print(f"  • Installed Version : {ver_str}")
    print(f"  • Install Method    : {cap['install_method']}")
    if cap["install_command"]:
        print(f"  • Host Install Cmd  : {cap['install_command']}")

    print("\n  [ Supported Platforms ]")
    for plat in rec.get_supported_platforms_list():
        print(f"    • {plat}")

    print("\n  [ Description ]")
    print(f"    {d['description']}")

    print("\n  [ Operational Constraints ]")
    print(f"    • Requires Root    : {'YES' if d['requires_root'] else 'No'}")
    print(f"    • Requires API Key : {'YES' if d['requires_api'] else 'No'}")
    print(f"    • Requires Hardware: {'YES' if d['requires_hardware'] else 'No'}")
    if d["notes"]:
        print(f"\n  [ Operational Notes ]\n    {d['notes']}")
    print(f"\n  • Source URL        : {d['source_url']}")
    print("═" * 74 + "\n")
    return 0

def handle_tools_command(parsed: argparse.Namespace) -> int:
    action = getattr(parsed, "tool_action", None)
    cat = Catalog()
    env = detect_full_environment()

    # Analytical built-in routing
    if action in (
        "asset-graph", "diff", "ioc-extract", "evidence-index",
        "log-triage", "pcap-summary", "file-baseline", "endpoint-inspect"
    ):
        return handle_analytical_tool(action, parsed)

    # 1. tools list / default
    if action == "list" or not action:
        plat_filter = getattr(parsed, "platform", "current")
        tools = cat.tools

        if getattr(parsed, "category", None):
            tools = [t for t in tools if t.category.lower() == parsed.category.lower().strip()]
        if getattr(parsed, "ecosystem", None):
            tools = [t for t in tools if t.ecosystem.lower() == parsed.ecosystem.lower().strip()]

        if getattr(parsed, "installed", False):
            tools = [t for t in tools if t.is_installed]
        elif getattr(parsed, "missing", False):
            tools = [t for t in tools if not t.is_installed and t.is_supported_on_platform(env)]
        elif getattr(parsed, "unavailable", False):
            tools = [t for t in tools if not t.is_supported_on_platform(env)]
        elif getattr(parsed, "available", False):
            tools = [t for t in tools if t.is_supported_on_platform(env)]
        elif getattr(parsed, "manual", False):
            tools = [t for t in tools if t.get_platform_capability(env)["availability"] == "MANUAL_INSTALL"]
        elif plat_filter == "current":
            # Show all for current platform with platform awareness badges
            pass

        if getattr(parsed, "json", False):
            print(json.dumps([t.to_dict(env) for t in tools], indent=2))
            return 0

        print(f"\nTraceForge Tool Catalog — Platform: {env['display_name']} ({len(tools)} matching of {len(cat.tools)} entries):")
        print(f"{'ID':<4} {'Availability':<16} {'Status':<12} {'Binary':<18} {'Ecosystem':<10} {'Name':<22} {'Platform Notes'}")
        print("─" * 105)
        for t in tools:
            cap = t.get_platform_capability(env)
            avail_str = "✓ Available" if cap["availability"] == "SUPPORTED" else (
                "! Manual" if cap["availability"] == "MANUAL_INSTALL" else (
                    "⚠ Limited" if cap["availability"] == "SUPPORTED_WITH_LIMITATIONS" else "× Unavailable"
                )
            )
            st_str = "[INSTALLED]" if t.is_installed else (
                "[MISSING]" if cap["is_available"] else "[UNAVAILABLE]"
            )
            reason_snip = cap["reason"][:30]
            print(f"{t.id:<4} {avail_str:<16} {st_str:<12} {t.binary:<18} {t.ecosystem:<10} {t.name[:21]:<22} {reason_snip}")
        print("─" * 105 + "\n")
        return 0

    # 2. tools search <query>
    elif action == "search":
        q = getattr(parsed, "query", "")
        results = cat.search(q)
        if getattr(parsed, "json", False):
            print(json.dumps([t.to_dict(env) for t in results], indent=2))
            return 0
        print(f"\nTraceForge Catalog Search: '{q}' on {env['display_name']} ({len(results)} matches):")
        print(f"{'ID':<4} {'Availability':<16} {'Status':<12} {'Binary':<18} {'Name':<22} {'Platform Rationale'}")
        print("─" * 105)
        for t in results:
            cap = t.get_platform_capability(env)
            avail_str = "✓ Available" if cap["availability"] == "SUPPORTED" else (
                "! Manual" if cap["availability"] == "MANUAL_INSTALL" else "× Unavailable"
            )
            st_str = "[INSTALLED]" if t.is_installed else (
                "[MISSING]" if cap["is_available"] else "[UNAVAILABLE]"
            )
            print(f"{t.id:<4} {avail_str:<16} {st_str:<12} {t.binary:<18} {t.name[:21]:<22} {cap['reason'][:35]}")
        print("─" * 105 + "\n")
        return 0

    # 3. tools info <tool>
    elif action == "info":
        return handle_tools_info(parsed)

    # 4. tools status [tool] [--all]
    elif action == "status":
        tool_q = getattr(parsed, "tool", None)
        show_all = getattr(parsed, "all", False)

        if show_all or not tool_q:
            data = [t.to_dict(env) for t in cat.tools]
            if getattr(parsed, "json", False):
                print(json.dumps(data, indent=2))
                return 0

            inst_count = sum(1 for d in data if d["is_installed"])
            unavail_count = sum(1 for d in data if d["availability"] == "NOT_AVAILABLE")
            print(f"\nTraceForge Tool Status Audit — Platform: {env['display_name']}")
            print(f"Installed: {inst_count}/{len(data)} | Unavailable on this platform: {unavail_count}")
            print(f"{'ID':<4} {'Status':<14} {'Binary':<18} {'Version / Location':<32} {'Platform Rationale'}")
            print("─" * 105)
            for d in data:
                st = "[INSTALLED]" if d["is_installed"] else (
                    "[UNAVAILABLE]" if d["availability"] == "NOT_AVAILABLE" else "[MISSING]"
                )
                ver_loc = (d["version"] or d["binary_path"] or "-")[:31]
                print(f"{d['id']:<4} {st:<14} {d['binary']:<18} {ver_loc:<32} {d['platform_reason'][:36]}")
            print("─" * 105 + "\n")
            return 0
        else:
            rec = cat.find_tool(tool_q)
            if not rec:
                print(f"[!] Tool '{tool_q}' not found in catalog.")
                return 1
            d = rec.to_dict(env)
            if getattr(parsed, "json", False):
                print(json.dumps(d, indent=2))
                return 0
            cap = rec.get_platform_capability(env)
            print(f"\nTool: {d['name']} ({d['binary']})")
            print(f"  • Platform        : {env['display_name']}")
            print(f"  • Availability    : {cap['availability']} ({cap['reason']})")
            print(f"  • Status          : {d['status_label'].upper()}")
            print(f"  • Installed       : {'YES' if d['is_installed'] else 'NO'}")
            print(f"  • Binary Path     : {d['binary_path'] or 'Not found on PATH'}")
            print(f"  • Version         : {d['version'] or 'N/A'}")
            print(f"  • Install Method  : {cap['install_method']}")
            if cap["install_command"]:
                print(f"  • Install Command : {cap['install_command']}")
            return 0

    # 5. tools install <tool>
    elif action == "install":
        tool_q = getattr(parsed, "tool", "")
        rec = cat.find_tool(tool_q)
        if not rec:
            print(f"[!] Tool '{tool_q}' not found in catalog.")
            return 1

        if rec.is_installed:
            print(f"[OK] '{rec.binary}' is already installed at: {rec.binary_path}")
            return 0

        cap = rec.get_platform_capability(env)

        # 1. Reject unavailable tools
        if cap["availability"] == "NOT_AVAILABLE":
            print(f"\n[ERROR] Tool '{rec.binary}' is not available on {env['display_name']}.")
            print(f"\nPlatform Analysis:")
            print(f"  • Reason              : {cap['reason']}")
            supported_plats = rec.get_supported_platforms_list()
            print(f"  • Supported Platforms : {', '.join(supported_plats) if supported_plats else 'None'}")
            print(f"\nNo installation was attempted.\n")
            return 1

        # 2. Reject manual tools with clear instructions
        if cap["availability"] == "MANUAL_INSTALL" or not cap["is_installable"]:
            print(f"\n[INFO] Tool '{rec.name}' ({rec.binary}) requires manual installation.")
            print(f"Automatic package installation is unavailable on {env['display_name']}.")
            print(f"Upstream URL / Instructions: {rec.source_url}\n")
            return 1

        # 3. Proceed with verified automated install recipe
        print(f"\n[*] Target: {rec.name} ({rec.binary}) [Method: {cap['install_method']}]")
        print(f"[*] Executing recipe: {cap['install_command']}")

        install_script = get_project_root() / "scripts" / "install_tool.sh"
        if install_script.exists():
            proc = subprocess.run([str(install_script), rec.binary], cwd=str(get_project_root()))
            code = proc.returncode
        else:
            proc = subprocess.run(cap["install_command"], shell=True)
            code = proc.returncode

        if rec.is_installed:
            print(f"[+] Verification PASSED: '{rec.binary}' is now installed at {rec.binary_path}\n")
            return 0
        else:
            print(f"[!] Installation completed with code {code}, but '{rec.binary}' was not found on PATH.\n")
            return code or 1

    # 6. tools install-profile <profile>
    elif action == "install-profile":
        prof = getattr(parsed, "profile", "recommended")
        plan = cat.get_install_plan_for_profile(prof, env)

        print("\n" + "═" * 74)
        print("  TRACEFORGE PLATFORM-AWARE INSTALLATION PLAN")
        print("═" * 74)
        print(f"  Platform:         {plan['platform']}")
        print(f"  Package Manager:  {plan['package_manager']}")
        print(f"  Profile:          {prof.upper()} ({plan['total_profile_tools']} catalog utilities)")
        print("─" * 74)
        print(f"  ✓ Already Installed ({plan['already_installed_count']}):")
        if plan["already_installed"]:
            print(f"      {', '.join(t.binary for t in plan['already_installed'][:15])}" + ("..." if len(plan["already_installed"]) > 15 else ""))
        print(f"  ⚙ To Install on Host ({plan['installable_count']}):")
        if plan["to_install"]:
            print(f"      {', '.join(t.binary for t in plan['to_install'])}")
        print(f"  — Skipped - Unavailable on this Platform ({plan['unavailable_count']}):")
        if plan["skipped_unavailable"]:
            for t, reason in plan["skipped_unavailable"]:
                print(f"      • {t.binary:<16} ({reason})")
        print(f"  — Skipped - Manual Installation Required ({plan['manual_count']}):")
        if plan["skipped_manual"]:
            for t, reason in plan["skipped_manual"]:
                print(f"      • {t.binary:<16} ({t.source_url})")
        print("═" * 74 + "\n")

        if not plan["to_install"]:
            print("[+] All supported utilities for this profile are already installed on this host.\n")
            return 0

        successes = 0
        failures = 0

        for i, t in enumerate(plan["to_install"], 1):
            t_cap = t.get_platform_capability(env)
            print(f"[{i}/{len(plan['to_install'])}] ⚙ Installing {t.name} ({t.binary}) via {t_cap['install_method']}...")
            install_script = get_project_root() / "scripts" / "install_tool.sh"
            if install_script.exists():
                subprocess.run([str(install_script), t.binary], cwd=str(get_project_root()), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                cmd = t_cap["install_command"]
                if cmd:
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            if t.is_installed:
                print(f"[{i}/{len(plan['to_install'])}] ✓ Successfully installed: {t.name} ({t.binary})")
                successes += 1
            else:
                print(f"[{i}/{len(plan['to_install'])}] ✗ Failed to install: {t.name} ({t.binary})")
                failures += 1

        print("\n" + "═" * 74)
        print("  INSTALLATION SUMMARY")
        print("═" * 74)
        print(f"  Platform:           {plan['platform']}")
        print(f"  Profile:            {prof.upper()}")
        print(f"  Successfully Added: {successes}")
        print(f"  Already Present:    {plan['already_installed_count']}")
        print(f"  Failed:             {failures}")
        print(f"  Skipped (Platform): {plan['unavailable_count']}")
        print(f"  Skipped (Manual):   {plan['manual_count']}")
        print("═" * 74 + "\n")
        return 0 if failures == 0 else 1

    # 7. tools audit-platform
    elif action == "audit-platform":
        pf_audit = cat.audit_platform(env)
        if getattr(parsed, "json", False):
            print(json.dumps(pf_audit, indent=2))
            return 0

        p = pf_audit["platform"]
        print("\n" + "═" * 74)
        print("  TRACEFORGE PLATFORM CAPABILITY AUDIT")
        print("═" * 74)
        print(f"  Host Environment      : {p['display_name']}")
        print(f"  Operating System      : {p['os']} ({p['distro']} {p['arch']})")
        print(f"  Package Manager       : {p['pkg_manager']}")
        print(f"  Root Privilege Status : {'Root / sudo Available' if (p['has_root'] or env.get('sudo_available')) else 'Userland Only'}")
        print("─" * 74)
        print(f"  • Total Catalog Utilities : {pf_audit['total_catalog']}")
        print(f"  • Supported on Platform   : {pf_audit['available_count']}")
        print(f"  • Installed Locally       : {pf_audit['installed_count']}")
        print(f"  • Missing on Platform     : {pf_audit['missing_count']}")
        print(f"  • Manual-Only Utilities   : {pf_audit['manual_count']}")
        print(f"  • Limited Functionality   : {pf_audit['limited_count']}")
        print(f"  • Unavailable on Platform : {pf_audit['unavailable_count']}")
        if pf_audit["unavailable_tools"]:
            print("\n  [ Utilities Unavailable on this Host ]")
            for ut in pf_audit["unavailable_tools"]:
                print(f"    × {ut['name']:<24} ({ut['binary']:<16}) : {ut['reason']}")
        print("═" * 74 + "\n")
        return 0

    # 8. tools run <tool> [args...]
    elif action == "run":
        tool_q = getattr(parsed, "tool", "")
        tool_args = getattr(parsed, "args", []) or []
        timeout = getattr(parsed, "timeout", 60)
        as_json = getattr(parsed, "json", False)

        if "--json" in tool_args:
            as_json = True
            tool_args = [a for a in tool_args if a != "--json"]

        clean_args = [a for a in tool_args if a != "--"]
        res = ToolRunner.run_catalog_tool(tool_q, clean_args, timeout=timeout)

        if as_json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            rec = cat.find_tool(tool_q)
            t_name = rec.name if rec else tool_q
            print("\n" + "═" * 74)
            print(f"  TraceForge Tool Execution: {t_name} ({tool_q})")
            print("═" * 74)
            print(f"  • Command     : {' '.join(res.command)}")
            print(f"  • Exit Code   : {res.exit_code}")
            print(f"  • Duration    : {round(res.duration_seconds, 3)}s")
            print(f"  • Executed At : {res.executed_at}")
            print("─" * 74)
            if res.stdout:
                print(res.stdout)
            if res.stderr:
                print(f"\n[STDERR]\n{res.stderr}", file=sys.stderr)
            print("═" * 74 + "\n")
        return res.exit_code

    # 9. tools audit
    elif action == "audit":
        audit_res = cat.audit()
        if getattr(parsed, "json", False) and not getattr(parsed, "integration", False):
            print(json.dumps(audit_res, indent=2))
            return 0

        print("\n" + "═" * 74)
        print("  TRACEFORGE CATALOG INTEGRITY AUDIT")
        print("═" * 74)
        print(f"  • Total Catalog Entries   : {audit_res['total_tools']}")
        print(f"  • Schema Adherence        : {'✓ PASS (Clean)' if audit_res['is_clean'] else '✗ FAIL (Anomalies found)'}")
        print(f"  • Duplicate Tool IDs      : {len(audit_res['duplicate_ids'])}")
        print(f"  • Duplicate Binaries      : {len(audit_res['duplicate_binaries'])}")
        print(f"  • Invalid Ecosystems      : {len(audit_res['invalid_ecosystems'])}")
        print(f"  • Missing Install Recipes : {len(audit_res['missing_recipes'])}")
        print(f"  • Manual-Only Utilities   : {len(audit_res['manual_tools'])}")
        print(f"  • Root-Required Utilities : {len(audit_res['root_required_tools'])}")
        print(f"  • API-Required Utilities  : {len(audit_res['api_required_tools'])}")
        print(f"  • Hardware-Specific Tools : {len(audit_res['hardware_required_tools'])}")
        print("═" * 74)

        if getattr(parsed, "integration", False):
            int_res = cat.integration_audit(env)
            if getattr(parsed, "json", False):
                print(json.dumps({**audit_res, "integration": int_res}, indent=2))
                return 0 if audit_res["is_clean"] else 1
            print()
            print("  INTEGRATION DEPTH REPORT")
            print("─" * 74)
            print(f"  • Fully Integrated (module handler) : {int_res['fully_integrated']}")
            print(f"  • Runnable (generic runner path)    : {int_res['runnable']}")
            print(f"  • Manual-Only                       : {int_res['manual_only']}")
            print(f"  • Unsupported on this platform      : {int_res['unsupported_on_platform']}")
            print()
            print("  [ Fully Integrated ]")
            for t in int_res["fully_integrated_tools"]:
                print(f"    [{t['id']:3}] {t['binary']:<28} {t['category']}")
            if int_res["runnable_tools"]:
                print()
                print("  [ Runnable — generic runner (no dedicated module handler) ]")
                for t in int_res["runnable_tools"]:
                    print(f"    [{t['id']:3}] {t['binary']:<28} {t['category']}")
            if int_res["manual_tools"]:
                print()
                print("  [ Manual-Only ]")
                for t in int_res["manual_tools"]:
                    print(f"    [{t['id']:3}] {t['binary']:<28} {t['category']}")
            if int_res["unsupported_tools"]:
                print()
                print("  [ Unsupported on this platform ]")
                for t in int_res["unsupported_tools"]:
                    print(f"    [{t['id']:3}] {t['binary']:<28} {t['category']}")
            print()
            print(f"  Note: {int_res['note']}")
        print("═" * 74 + "\n")
        return 0 if audit_res["is_clean"] else 1

    # 10. tools coverage
    elif action == "coverage":
        cov = cat.get_coverage_report(env)
        if getattr(parsed, "json", False):
            print(json.dumps(cov, indent=2))
            return 0
        p = cov["platform"]
        print("\n" + "═" * 74)
        print("  TRACEFORGE TOOLCHAIN COVERAGE REPORT")
        print("═" * 74)
        print(f"  Host Environment      : {p['display_name']} | Pkg Mgr: {p['pkg_manager']}")
        print("─" * 74)
        print(f"  • Total Catalog Tools : {cov['total_catalog']}")
        print(f"  • CLI Accessible      : {cov['cli_accessible']}")
        print(f"  • Web Console Exposed : {cov['web_exposed']}")
        print(f"  • Platform Supported  : {cov['platform_supported']} (of {cov['total_catalog']})")
        print(f"  • Installed Locally   : {cov['installed_locally']}")
        print(f"  • Missing on Platform : {cov['missing_locally']}")
        print(f"  • Unavailable on Host : {cov['unavailable_on_platform']}")
        print(f"  • Manual Installation : {cov['manual_only']}")
        print("\n  [ Category Breakdown ]")
        for cname, cstats in cov["categories"].items():
            print(f"    • {cname:<42} : {cstats['installed']:>2}/{cstats['total']:<2} installed ({cstats['available']} supported)")
        print("═" * 74 + "\n")
        return 0

    print("Usage: traceforge tools <list|search|info|status|install|install-profile|audit-platform|run|audit|coverage>")
    return 0

def handle_batch_command(parsed: argparse.Namespace) -> int:
    """Handles the 'batch' CLI subcommand suite."""
    from traceforge.batch import BatchEngine, PREDEFINED_WORKFLOWS, classify_input_type

    engine = BatchEngine()
    action = getattr(parsed, "batch_action", None)

    if not action:
        print("\nTraceForge Batch Investigation & Custom Tool Sets Engine")
        print("Usage:")
        print("  traceforge batch run <target> [--tools t1,t2 | --profile <name> | --all] [--parallel]")
        print("  traceforge batch plan <target> [--tools t1,t2 | --profile <name> | --all]")
        print("  traceforge batch profile <list|save|delete>")
        print("  traceforge batch history [--limit <N>]\n")
        return 0

    if action == "profile":
        p_act = getattr(parsed, "profile_action", "list")
        if p_act == "list" or not p_act:
            profiles = engine.list_saved_profiles()
            print("\n" + "═" * 74)
            print("  TRACEFORGE SAVED TOOL SETS & PROFILES")
            print("═" * 74)
            for p in profiles:
                type_tag = "[SYSTEM]" if p.get("is_system") else "[CUSTOM]"
                tools_str = ", ".join(p.get("tools", []))
                print(f"  • {type_tag:<8} {p.get('name'):<30} ({p.get('tool_count')} tools)")
                print(f"    ID: {p.get('id')} | Tools: {tools_str}")
                if p.get("description"):
                    print(f"    Desc: {p.get('description')}")
                print("  " + "─" * 70)
            print("═" * 74 + "\n")
            return 0
        elif p_act == "save":
            tools_list = [t.strip() for t in parsed.tools.split(",") if t.strip()]
            res = engine.save_custom_profile(parsed.name, parsed.desc, tools_list)
            print(f"[+] Successfully saved profile '{res['name']}' (ID: {res['id']}) with {len(tools_list)} tools.")
            return 0
        elif p_act == "delete":
            ok = engine.delete_custom_profile(parsed.id)
            if ok:
                print(f"[+] Deleted custom profile: '{parsed.id}'")
                return 0
            else:
                print(f"[!] Profile '{parsed.id}' not found or is a protected system workflow.")
                return 1

    if action == "history":
        history = engine.list_history(getattr(parsed, "limit", 20))
        print("\n" + "═" * 74)
        print("  TRACEFORGE BATCH EXECUTION HISTORY")
        print("═" * 74)
        if not history:
            print("  No previous batch investigations recorded in active workspace.")
        else:
            for h in history:
                print(f"  • Job ID   : {h.get('job_id')} ({h.get('started_at')})")
                print(f"    Target   : {h.get('input_target')} [{h.get('input_type')}]")
                print(f"    Workflow : {h.get('workflow_name')} | Duration: {h.get('duration_seconds')}s")
                print(f"    Results  : {h.get('successful')} succeeded, {h.get('failed')} failed, {h.get('skipped')} skipped | {h.get('indicators_extracted')} IOCs")
                print("  " + "─" * 70)
        print("═" * 74 + "\n")
        return 0

    if action in ("plan", "run"):
        target = parsed.target
        input_info = classify_input_type(target)

        # Resolve tool list
        tool_ids: List[str] = []
        if getattr(parsed, "tools", None):
            tool_ids = [t.strip() for t in parsed.tools.split(",") if t.strip()]
        elif getattr(parsed, "profile", None) or getattr(parsed, "category", None):
            prof_name = getattr(parsed, "profile", None) or getattr(parsed, "category", None)
            prof_name = prof_name.lower().strip()
            if prof_name in PREDEFINED_WORKFLOWS:
                tool_ids = PREDEFINED_WORKFLOWS[prof_name]["tools"]
            else:
                saved = engine.list_saved_profiles()
                match = next((p for p in saved if p.get("name", "").lower() == prof_name or p.get("id") == prof_name), None)
                if match:
                    tool_ids = match.get("tools", [])
                else:
                    print(f"[!] Unknown profile or category: '{prof_name}'")
                    print(f"    Available predefined categories: {', '.join(PREDEFINED_WORKFLOWS.keys())}")
                    return 1
        elif getattr(parsed, "all", False):
            tool_ids = [t.binary for t in engine.catalog.tools]
        else:
            print("[!] Please specify tool set: --tools <t1,t2> OR --profile <name> OR --all")
            return 1

        exec_mode = "parallel" if getattr(parsed, "parallel", False) else "sequential"
        plan = engine.create_plan(
            raw_input=target,
            tool_identifiers=tool_ids,
            execution_mode=exec_mode,
            max_workers=getattr(parsed, "workers", 3),
            per_tool_timeout=getattr(parsed, "timeout", 60),
        )

        print("\n" + "═" * 74)
        print("  TRACEFORGE BATCH INVESTIGATION PLAN")
        print("═" * 74)
        print(f"  Target Specimen       : {plan.raw_input}")
        print(f"  Detected Input Type   : {plan.input_info['type'].upper()} ({plan.input_info.get('specific', plan.input_info['type'])})")
        print(f"  Host Platform         : {plan.platform_env.get('display_name')}")
        print(f"  Execution Mode        : {plan.execution_mode.upper()} (Workers: {plan.max_workers}, Timeout: {plan.per_tool_timeout}s)")
        print("─" * 74)
        print(f"  • Total Tools Selected: {len(plan.tools)}")
        print(f"  • Executable on Host  : {len(plan.executable_tools)} (installed & compatible)")
        print(f"  • Missing Locally     : {len(plan.missing_tools)} (available to install)")
        print(f"  • Incompatible Input  : {len(plan.incompatible_tools)} (skipped)")
        print(f"  • Platform Restricted : {len(plan.unavailable_tools)} (unavailable on host)")

        if plan.executable_tools:
            print("\n  [ Executable Tools Sequence ]")
            for idx, t in enumerate(plan.executable_tools):
                active_flag = " [ACTIVE PROBE]" if t["is_active_network"] else ""
                print(f"    {idx + 1}. {t['name']:<24} ({t['binary']}){active_flag} → {t['compatibility_reason']}")

        if plan.missing_tools:
            print("\n  [ Missing Tools (Installable) ]")
            for t in plan.missing_tools:
                print(f"    ! {t['name']:<24} ({t['binary']}) → Run 'traceforge tools install {t['binary']}'")

        if plan.incompatible_tools:
            print("\n  [ Incompatible Tools (Will be Skipped) ]")
            for t in plan.incompatible_tools:
                print(f"    × {t['name']:<24} ({t['binary']}) → {t['compatibility_reason']}")

        if plan.unavailable_tools:
            print("\n  [ Unavailable on this Platform (Will be Skipped) ]")
            for t in plan.unavailable_tools:
                print(f"    — {t['name']:<24} ({t['binary']}) → {t['platform_reason']}")

        if plan.has_active_network_tools:
            print("\n  [!] CAUTION: ACTIVE NETWORK PROBES")
            print("  Selected tools include utilities that send active probes across the network.")
            print("  Ensure you have explicit authorization to test the target.")

        print("═" * 74 + "\n")

        if action == "plan":
            return 0

        # Execute Plan
        if not plan.is_executable:
            print("[!] No executable tools available for this input and platform. Execution halted.")
            return 1

        if plan.has_active_network_tools and sys.stdin.isatty():
            try:
                confirm = input("Confirm execution of active network tools against target? [y/N]: ").strip().lower()
                if confirm not in ("y", "yes"):
                    print("Execution cancelled by operator.")
                    return 0
            except KeyboardInterrupt:
                print("\nExecution cancelled.")
                return 0

        print(f"[*] Launching batch execution ({len(plan.executable_tools)} tools, mode: {plan.execution_mode})...\n")

        def _cli_log(msg: str):
            print(f"  {msg}")

        try:
            result = engine.execute_plan(plan, on_log=_cli_log)
        except KeyboardInterrupt:
            print("\n[!] Execution interrupted by operator (Ctrl+C). Cleaning up...")
            return 130

        print("\n" + "═" * 74)
        print("  BATCH INVESTIGATION RESULTS SUMMARY")
        print("═" * 74)
        print(f"  Job ID                : {result.job_id}")
        print(f"  Total Duration        : {round(result.duration_seconds, 2)}s")
        print(f"  Tools Executed        : {result.total_tools_run} (✓ {result.successful_count} passed, ✗ {result.failed_count} failed)")
        print(f"  Tools Skipped         : {result.skipped_count}")
        print(f"  Deduplicated IOCs     : {len(result.deduplicated_indicators)}")
        print(f"  Findings Extracted    : {len(result.aggregated_findings)}")

        if result.deduplicated_indicators:
            print("\n  [ Deduplicated Indicators of Compromise (IOCs) ]")
            for ioc in result.deduplicated_indicators[:25]:
                srcs = ", ".join(ioc.get("sources", []))
                print(f"    • [{ioc['type'].upper():<8}] {ioc['defanged']:<38} (Attribution: {srcs})")
            if len(result.deduplicated_indicators) > 25:
                print(f"    ... and {len(result.deduplicated_indicators) - 25} more indicators.")

        # Generate Reports if requested
        rep_fmt = getattr(parsed, "report", None)
        out_path = getattr(parsed, "output_path", None)
        if rep_fmt:
            md_content = result.generate_markdown_report()
            if not out_path:
                from traceforge.config import get_workspace_dir
                out_path = str(get_workspace_dir() / f"batch_report_{result.job_id}.md")

            with open(out_path, "w", encoding="utf-8") as f:
                f.write(md_content)
            print(f"\n[+] Merged Markdown Report generated: {out_path}")

        print("═" * 74 + "\n")
        return 0

    return 0

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
    doc_p = subparsers.add_parser("doctor", help="Run comprehensive environment, dependency, and runtime checks")
    doc_p.add_argument("--repair", action="store_true", help="Perform automated environment, config, directory, and helper repair")

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
    cfg_subs.add_parser("show", help="Display entire configuration (alias for list)")
    cfg_subs.add_parser("paths", help="Display all active user data and configuration paths")
    cfg_shell = cfg_subs.add_parser("shell", help="Inspect and configure shell PATH profile exports")
    cfg_shell.add_argument("--fix", "--persist", action="store_true", help="Automatically persist missing PATH directories into shell rc")




    # case & cases
    case_p = subparsers.add_parser("case", help="Case management")
    case_subs = case_p.add_subparsers(dest="case_action", help="Case actions")
    c_new = case_subs.add_parser("new", help="Create a new case")
    c_new.add_argument("name", help="Case Name")
    c_new.add_argument("--analyst", default="Analyst", help="Lead Analyst")
    c_create = case_subs.add_parser("create", help="Create a new case")
    c_create.add_argument("name", help="Case Name")
    c_create.add_argument("--analyst", default="Analyst", help="Lead Analyst")
    case_subs.add_parser("list", help="List all cases")
    c_open = case_subs.add_parser("open", help="Set active case")
    c_open.add_argument("case_id", help="Case ID to activate")
    c_show = case_subs.add_parser("show", help="Display case details")
    c_show.add_argument("case_id", nargs="?", help="Case ID (default: active case)")
    c_ingest = case_subs.add_parser("add-evidence", help="Ingest evidence into case")
    c_ingest.add_argument("path", help="Evidence file path")
    c_ingest.add_argument("--desc", default="", help="Description")
    c_ingest.add_argument("--case-id", help="Target Case ID")

    subparsers.add_parser("cases", help="List all registered investigation cases")

    # evidence
    evid_p = subparsers.add_parser("evidence", help="Evidence management and ingestion")
    evid_subs = evid_p.add_subparsers(dest="evidence_action", help="Evidence action")
    e_add = evid_subs.add_parser("add", help="Ingest evidence file")
    e_add.add_argument("path", help="Evidence file path")
    e_add.add_argument("--desc", default="Forensic Specimen", help="Description")
    e_add.add_argument("--case-id", help="Case ID")
    evid_subs.add_parser("list", help="List evidence in active case")

    # ioc
    ioc_p = subparsers.add_parser("ioc", help="Indicator of Compromise (IOC) operations")
    ioc_subs = ioc_p.add_subparsers(dest="ioc_action", help="IOC action")
    i_ext = ioc_subs.add_parser("extract", help="Extract and defang IOCs from file or text")
    i_ext.add_argument("file", nargs="?", help="Input file or stream")
    i_ext.add_argument("--defang", action="store_true", help="Defang indicators")
    i_ext.add_argument("--json", action="store_true", help="Emit JSON output")
    i_add = ioc_subs.add_parser("add", help="Add IOC manually to case")
    i_add.add_argument("value", help="Indicator value")
    i_add.add_argument("--type", default="domain", help="Type (domain, ipv4, url, email, sha256, cve)")
    i_add.add_argument("--case-id", help="Target Case ID")
    ioc_subs.add_parser("list", help="List IOCs in active case")

    # investigate & module
    inv_p = subparsers.add_parser("investigate", help="Run an investigation module")
    inv_p.add_argument("module_id", help="Module type (image, network, identity, email, domain, doc, opsec)")
    inv_p.add_argument("target", nargs="?", help="Target file, domain, email, or username")
    inv_p.add_argument("case_id", nargs="?", help="Associated Case ID")

    # export & report
    exp_p = subparsers.add_parser("export", help="Export case reports & datasets")
    exp_p.add_argument("case_id", nargs="?", help="Case ID to export")
    exp_p.add_argument("--redact", action="store_true", help="Redact sensitive IPs & emails")
    exp_p.add_argument("--out", help="Output directory")

    rep_p = subparsers.add_parser("report", help="Generate case reports & exports (alias for export)")
    rep_p.add_argument("case_id", nargs="?", help="Case ID to export")
    rep_p.add_argument("--redact", action="store_true", help="Redact sensitive IPs & emails")
    rep_p.add_argument("--out", help="Output directory")

    # tools & catalog
    tools_p = subparsers.add_parser("tools", help="Discover, audit, install, and execute external catalog tools & analytical engines")
    tools_subs = tools_p.add_subparsers(dest="tool_action", help="Tool action")

    # tools list
    t_list = tools_subs.add_parser("list", help="List all catalog tools with platform compatibility")
    t_list.add_argument("-c", "--category", help="Filter by category")
    t_list.add_argument("-e", "--ecosystem", help="Filter by ecosystem (native, pipx, go, cargo, ruby_gem, manual)")
    t_list.add_argument("--platform", choices=["current", "all"], default="current", help="Filter view by host platform (default: current)")
    t_list.add_argument("--available", action="store_true", help="Show tools available on current platform")
    t_list.add_argument("--unavailable", action="store_true", help="Show tools unavailable on current platform")
    t_list.add_argument("--manual", action="store_true", help="Show manual-install tools only")
    t_list.add_argument("--installed", action="store_true", help="Show installed tools only")
    t_list.add_argument("--missing", action="store_true", help="Show missing tools only")
    t_list.add_argument("--supported", action="store_true", help="Show platform-supported tools only")
    t_list.add_argument("--json", action="store_true", help="Emit JSON output")

    # tools search
    t_search = tools_subs.add_parser("search", help="Search catalog by name, binary, description, category, or tags")
    t_search.add_argument("query", help="Search query")
    t_search.add_argument("--json", action="store_true", help="Emit JSON output")

    # tools info
    t_info = tools_subs.add_parser("info", help="Display full specification, dependencies, and install recipes for a tool")
    t_info.add_argument("tool", help="Tool ID or binary name")
    t_info.add_argument("--json", action="store_true", help="Emit JSON output")

    # tools status
    t_status = tools_subs.add_parser("status", help="Inspect local installation, version, and platform status")
    t_status.add_argument("tool", nargs="?", help="Tool ID or binary name (optional)")
    t_status.add_argument("--all", action="store_true", help="Audit local status across all catalog tools")
    t_status.add_argument("--json", action="store_true", help="Emit JSON output")

    # tools install
    t_inst = tools_subs.add_parser("install", help="Install a catalog tool using platform package manager")
    t_inst.add_argument("tool", help="Tool ID or binary name")

    # tools install-profile
    t_prof = tools_subs.add_parser("install-profile", help="Install all tools for an installation profile (minimal, recommended, full)")
    t_prof.add_argument("profile", choices=["minimal", "recommended", "full"], help="Profile name")

    # tools audit-platform
    t_apf = tools_subs.add_parser("audit-platform", help="Audit toolchain availability and platform compatibility for current host")
    t_apf.add_argument("--json", action="store_true", help="Emit JSON platform audit report")

    # tools run
    t_run = tools_subs.add_parser("run", help="Safely execute an audited catalog utility")
    t_run.add_argument("tool", help="Tool ID or binary name")
    t_run.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed to the tool")
    t_run.add_argument("--timeout", type=int, default=60, help="Execution timeout in seconds (default: 60)")
    t_run.add_argument("--json", action="store_true", help="Output JSON execution summary")

    # tools audit
    t_audit = tools_subs.add_parser("audit", help="Audit catalog integrity, schema consistency, and recipe completeness")
    t_audit.add_argument("--json", action="store_true", help="Emit JSON audit report")
    t_audit.add_argument("--integration", action="store_true", help="Include per-tool integration depth classification")

    # tools coverage
    t_cov = tools_subs.add_parser("coverage", help="Display toolchain coverage statistics for host environment")
    t_cov.add_argument("--json", action="store_true", help="Emit JSON coverage report")

    # Analytical built-in tools
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

    # catalog alias
    cat_p = subparsers.add_parser("catalog", help="Query and inspect the 152-tool catalog")
    cat_p.add_argument("query", nargs="?", default="", help="Search query or tool identifier")
    cat_p.add_argument("-c", "--category", help="Filter by category")
    cat_p.add_argument("-e", "--ecosystem", help="Filter by ecosystem")
    cat_p.add_argument("--installed", action="store_true", help="Show installed tools only")
    cat_p.add_argument("--json", action="store_true", help="Emit JSON output")

    # analyze alias
    analyze_p = subparsers.add_parser("analyze", help="First-party analytical pipelines and forensic utilities")
    analyze_subs = analyze_p.add_subparsers(dest="analyze_action", help="Analysis action")
    a_graph = analyze_subs.add_parser("asset-graph", help="Generate asset relationship graph")
    a_graph.add_argument("file", nargs="?", help="Input file or stdin")
    a_graph.add_argument("--html", help="Export to interactive HTML file")
    a_diff = analyze_subs.add_parser("diff", help="Universal snapshot differ")
    a_diff.add_argument("file1", help="Old snapshot file")
    a_diff.add_argument("file2", help="New snapshot file")
    a_diff.add_argument("--domain", default="snapshot", help="Domain or category")
    a_ioc = analyze_subs.add_parser("ioc-extract", help="Stream IOC extractor and defanger")
    a_ioc.add_argument("file", nargs="?", help="Input file or stdin")
    a_ioc.add_argument("--defang", action="store_true", help="Defang indicators")
    a_ioc.add_argument("--json", action="store_true", help="Emit JSON output")
    a_index = analyze_subs.add_parser("evidence-index", help="Recursively index directory files with SHA-256")
    a_index.add_argument("dir", nargs="?", default=".", help="Target directory")
    a_index.add_argument("--json", action="store_true", help="Emit JSON output")
    a_triage = analyze_subs.add_parser("log-triage", help="Triage log streams for bursts and auth failures")
    a_triage.add_argument("file", nargs="?", help="Log file or stdin")
    a_pcap = analyze_subs.add_parser("pcap-summary", help="Dissect packet capture protocols and endpoints")
    a_pcap.add_argument("file", help="PCAP capture file")
    a_base = analyze_subs.add_parser("file-baseline", help="Create or compare filesystem baselines")
    a_base.add_argument("dir", help="Directory or baseline file 1")
    a_base.add_argument("file2", nargs="?", help="Baseline file 2 (if comparing)")
    a_base.add_argument("--out", help="Save baseline JSON")
    analyze_subs.add_parser("endpoint-inspect", help="Collect defensive host environment posture")

    # modules
    mod_p = subparsers.add_parser("module", help="Execute an investigation module (alias for investigate)")
    mod_p.add_argument("module_id", help="Module name or number (1:image, 2:network, 3:identity, 4:email, 5:domain, 6:docs, 7:opsec)")
    mod_p.add_argument("target", nargs="?", help="Target file, domain, email, or username")
    mod_p.add_argument("case_id", nargs="?", help="Associated Case ID")

    # batch
    batch_p = subparsers.add_parser("batch", help="Batch investigation & custom tool sets execution engine")
    batch_subs = batch_p.add_subparsers(dest="batch_action", help="Batch investigation action")

    # batch run
    brun_p = batch_subs.add_parser("run", help="Execute a batch investigation against a target specimen or observable")
    brun_p.add_argument("target", help="Target file, domain, email, username, IP, URL, or PCAP")
    brun_p.add_argument("--tools", help="Comma-separated catalog tools or IDs (e.g. exiftool,binwalk,strings)")
    brun_p.add_argument("--profile", help="Saved tool set or workflow profile (e.g. image, network, domain, email)")
    brun_p.add_argument("--category", help="Predefined workflow category (alias for --profile)")
    brun_p.add_argument("--all", action="store_true", help="Run all platform-compatible tools for this input")
    brun_p.add_argument("--parallel", action="store_true", help="Execute tools concurrently across worker threads")
    brun_p.add_argument("--workers", type=int, default=3, help="Max parallel worker threads (default: 3)")
    brun_p.add_argument("--timeout", type=int, default=60, help="Per-tool timeout in seconds (default: 60)")
    brun_p.add_argument("--case", dest="case_id", help="Associate findings with an active case ID")
    brun_p.add_argument("--report", choices=["markdown", "html", "json", "all"], help="Generate merged report")
    brun_p.add_argument("--output", dest="output_path", help="Path to write report file")

    # batch plan
    bplan_p = batch_subs.add_parser("plan", help="Preview pre-flight compatibility, platform availability, and execution plan")
    bplan_p.add_argument("target", help="Target file, domain, email, username, IP, URL, or PCAP")
    bplan_p.add_argument("--tools", help="Comma-separated catalog tools or IDs")
    bplan_p.add_argument("--profile", help="Saved tool set or workflow profile")
    bplan_p.add_argument("--category", help="Predefined workflow category")
    bplan_p.add_argument("--all", action="store_true", help="Run all platform-compatible tools for this input")

    # batch profile
    bprof_p = batch_subs.add_parser("profile", help="Manage custom saved tool set collections")
    bprof_subs = bprof_p.add_subparsers(dest="profile_action", help="Profile action")
    bprof_subs.add_parser("list", help="List all saved and system workflow profiles")
    bpsave = bprof_subs.add_parser("save", help="Save a new custom tool set collection")
    bpsave.add_argument("name", help="Profile name (e.g. 'Photo Deep Triage')")
    bpsave.add_argument("tools", help="Comma-separated list of tool binary names")
    bpsave.add_argument("--desc", default="", help="Profile description")
    bpdel = bprof_subs.add_parser("delete", help="Delete a user-saved custom tool set profile")
    bpdel.add_argument("id", help="Profile ID to delete")

    # batch history
    bhist_p = batch_subs.add_parser("history", help="View past batch investigation executions")
    bhist_p.add_argument("--limit", type=int, default=20, help="Max entries to display (default: 20)")

    # web
    web_p = subparsers.add_parser("web", help="Launch the local interactive TraceForge web console")
    web_p.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    web_p.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")

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
        run_doctor(repair=getattr(parsed, "repair", False))
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
        if caction == "paths":
            from traceforge.config import (
                get_config_dir,
                get_config_path,
                get_user_data_dir,
                get_workspace_dir,
                get_cache_dir,
                get_logs_dir,
                get_project_root,
            )
            from traceforge.catalog import get_bundled_catalog_path
            print("TraceForge System & User Data Paths:")
            print(f"  Configuration File: {get_config_path()}")
            print(f"  Configuration Dir : {get_config_dir()}")
            print(f"  User Data Dir     : {get_user_data_dir()}")
            print(f"  Active Workspace  : {get_workspace_dir()}")
            print(f"  Cache Directory   : {get_cache_dir()}")
            print(f"  Logs Directory    : {get_logs_dir()}")
            print(f"  Project / Pkg Root: {get_project_root()}")
            print(f"  Bundled Catalog   : {get_bundled_catalog_path()}")
        elif caction == "shell":
            rc_file = get_user_shell_rc_path()
            cand_dirs = get_candidate_global_bin_dirs()
            print("TraceForge Shell & Global Environment Configuration:")
            print(f"  Detected Shell RC : {rc_file or 'None detected'}")
            print("  Candidate Binary Directories:")
            for c in cand_dirs:
                print(f"    • {c}")
            if getattr(parsed, "fix", False):
                res = ensure_shell_paths_persisted()
                if res.get("added"):
                    print(f"\n[+] Successfully added {len(res['added'])} path(s) to {res['rc_file']}:")
                    for a in res["added"]:
                        print(f"    + export PATH=\"{a}:$PATH\"")
                    print(f"[+] Run 'source {res['rc_file']}' or open a new terminal session.")
                else:
                    print(f"\n[✓] {res.get('message') or 'Shell configuration is already up to date.'}")
            else:
                print("\nTip: Run 'traceforge config shell --fix' or 'traceforge doctor --repair' to auto-configure your shell rc.")
        elif caction in ("list", "show") or not caction:
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

    if parsed.subcommand == "case":
        caction = getattr(parsed, "case_action", None)
        if caction in ("create", "new"):
            c = create_case(name=parsed.name, analyst=parsed.analyst)
            print(f"[+] Initialized new case: {c.case_id} ({parsed.name})")
            return 0
        elif caction == "list" or not caction:
            cases = list_all_cases()
            print(f"Registered Cases ({len(cases)}):")
            for c in cases:
                print(f"  [{c['case_id']}] {c['case_name']} (Analyst: {c.get('analyst','N/A')}, Status: {c.get('status','active').upper()}, Created: {c['created_at'][:19]})")
            return 0
        elif caction == "open":
            if set_active_case(parsed.case_id):
                print(f"[+] Active case set to: {parsed.case_id}")
                return 0
            else:
                print(f"[!] Case not found: {parsed.case_id}")
                return 1
        elif caction == "show":
            cid = parsed.case_id or (get_active_case().case_id if get_active_case() else None)
            if not cid:
                print("[!] No active or specified case.")
                return 1
            c = Case(cid)
            if not c.exists():
                print(f"[!] Case '{cid}' does not exist.")
                return 1
            s = c.get_summary()
            print(f"Case Details: {s['case_id']}")
            print(f"  Name     : {s['case_name']}")
            print(f"  Analyst  : {s['analyst']}")
            print(f"  Status   : {s['status'].upper()}")
            print(f"  Evidence : {s['total_evidence']}")
            print(f"  Findings : {s['total_findings']} ({s['high_severity_findings']} High/Critical)")
            print(f"  IOCs     : {s['total_iocs']}")
            print(f"  Timeline : {s.get('total_timeline_events', 0)}")
            return 0
        elif caction == "add-evidence":
            c = Case(parsed.case_id) if hasattr(parsed, "case_id") and parsed.case_id else get_active_case()
            if not c or not c.exists():
                print("[!] No valid active case.")
                return 1
            rec = c.add_evidence(parsed.path, description=getattr(parsed, "desc", ""))
            print(f"[+] Ingested evidence into {c.case_id}: {rec['id']} (SHA-256: {rec['sha256'][:16]}...)")
            return 0

    if parsed.subcommand == "cases":
        cases = list_all_cases()
        print(f"Registered Cases ({len(cases)}):")
        for c in cases:
            print(f"  [{c['case_id']}] {c['case_name']} (Analyst: {c.get('analyst','N/A')}, Status: {c.get('status','active').upper()}, Created: {c['created_at'][:19]})")
        return 0

    if parsed.subcommand == "evidence":
        eaction = parsed.evidence_action
        c = Case(parsed.case_id) if hasattr(parsed, "case_id") and parsed.case_id else get_active_case()
        if not c or not c.exists():
            print("[!] No valid active case.")
            return 1
        if eaction == "add":
            rec = c.ingest_evidence(parsed.path, description=parsed.desc)
            print(f"[+] Ingested evidence into {c.case_id}: {rec['id']} (SHA-256: {rec['sha256'][:16]}...)")
        elif eaction == "list" or not eaction:
            evids = c.data.get("evidence", [])
            print(f"Case {c.case_id} Evidence ({len(evids)} items):")
            for e in evids:
                print(f"  [{e.get('id','-')}] {e.get('filename','-')} ({e.get('size_bytes',0)} B) SHA-256: {e.get('sha256','')[:16]}...")
        return 0

    if parsed.subcommand == "ioc":
        iaction = parsed.ioc_action
        if iaction == "extract":
            content = ""
            if parsed.file and Path(parsed.file).is_file():
                content = open(parsed.file, "r", encoding="utf-8", errors="ignore").read()
            elif not sys.stdin.isatty():
                content = sys.stdin.read()
            iocs = extract_iocs(content)
            if parsed.defang:
                for i in iocs:
                    i["value"] = i["defanged"]
            if parsed.json:
                print(json.dumps(iocs, indent=2))
            else:
                for i in iocs:
                    print(f"[{i['type'].upper():<8}] {i['value']} ({i['confidence']})")
        elif iaction == "add":
            c = Case(parsed.case_id) if parsed.case_id else get_active_case()
            if not c or not c.exists():
                print("[!] No valid active case.")
                return 1
            rec = c.add_ioc(value=parsed.value, ioc_type=parsed.type)
            print(f"[+] Added IOC to {c.case_id}: {rec['id']} ({rec['type']}: {rec['value']})")
        elif iaction == "list" or not iaction:
            c = get_active_case()
            if not c:
                print("[!] No active case.")
                return 1
            iocs = c.data.get("iocs", [])
            print(f"Case {c.case_id} Observables ({len(iocs)}):")
            for i in iocs:
                print(f"  [{i.get('type','').upper():<8}] {i.get('value')} (Confidence: {i.get('confidence','high')})")
        return 0

    if parsed.subcommand == "investigate":
        parsed.subcommand = "module"

    if parsed.subcommand == "catalog":
        # Route catalog command to tools handler
        cat = Catalog()
        query = getattr(parsed, "query", "")
        if query:
            # If query corresponds to a specific tool info request
            exact_tool = cat.find_tool(query)
            if exact_tool and not any(c in query for c in (" ", "*", "?")):
                parsed.tool = query
                return handle_tools_info(parsed)
            parsed.tool_action = "search"
        else:
            parsed.tool_action = "list"
        return handle_tools_command(parsed)

    if parsed.subcommand == "analyze":
        action = getattr(parsed, "analyze_action", None)
        if not action:
            print("Usage: traceforge analyze <asset-graph|diff|ioc-extract|evidence-index|log-triage|pcap-summary|file-baseline|endpoint-inspect>")
            return 1
        return handle_analytical_tool(action, parsed)

    if parsed.subcommand == "tools":
        return handle_tools_command(parsed)

    if parsed.subcommand == "batch":
        return handle_batch_command(parsed)

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

    if parsed.subcommand in ("export", "report"):
        cid = getattr(parsed, "case_id", None)
        c = Case(cid) if cid else get_active_case()
        if not c or not c.exists():
            print("[!] No active or specified case found to export.")
            return 1
        exporter = CaseExporter(c, redact=getattr(parsed, "redact", False))
        out_dir = getattr(parsed, "out", None)
        results = exporter.export_all(out_dir=out_dir)
        print(f"[+] Exported case artifacts for {c.case_id}:")
        for fmt_name, fpath in results.items():
            print(f"  • {fmt_name:<15}: {fpath}")
        return 0

    if parsed.subcommand == "web":
        from traceforge.web.server import run_web_server
        run_web_server(host=parsed.host, port=parsed.port)
        return 0

    return 0

if __name__ == "__main__":
    sys.exit(main())
