import datetime
import html
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Defensively extracts common observables (emails, domains, ipv4, urls, hashes)."""
    iocs: Dict[str, set] = {
        "emails": set(),
        "domains": set(),
        "ipv4": set(),
        "urls": set(),
        "sha256": set(),
        "md5": set(),
    }

    # Emails
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text):
        val = m.group(0).lower()
        if not val.endswith((".png", ".jpg", ".jpeg", ".gif")):
            iocs["emails"].add(val)

    # IPv4
    for m in re.finditer(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text):
        ip = m.group(0)
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts) and ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            iocs["ipv4"].add(ip)

    # URLs
    for m in re.finditer(r"https?://[^\s<>\"'()]+", text):
        clean_url = m.group(0).rstrip(".,;)\"'>]")
        if not any(ignored in clean_url for ignored in ("github.com/megadose", "github.com/khast3x", "khast3x.club", "twitter.com/palenath")):
            iocs["urls"].add(clean_url)

    # SHA256
    for m in re.finditer(r"\b[a-fA-F0-9]{64}\b", text):
        iocs["sha256"].add(m.group(0).lower())

    # MD5
    for m in re.finditer(r"\b[a-fA-F0-9]{32}\b", text):
        iocs["md5"].add(m.group(0).lower())

    return {k: sorted(list(v)) for k, v in iocs.items()}

def generate_module_reports(
    module_id: str,
    module_title: str,
    target: str,
    scan_mode: str,
    out_dir: Path,
    sections: List[Dict[str, Any]],
    raw_logs: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """
    Generates structured multi-format reports for an investigation run:
      - report.txt  (Sanitized, clean text)
      - report.md   (GitHub Flavored Markdown)
      - report.html (Responsive standalone dark dashboard)
      - report.json (Machine-readable metadata & findings)
      - iocs.json   (Extracted observables)
    """
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    full_text_corpus = "\n".join(
        f"{s.get('title', '')}\n{s.get('content', '')}" for s in sections
    )
    if raw_logs:
        full_text_corpus += "\n" + "\n".join(raw_logs.values())

    extracted_iocs = extract_iocs_from_text(full_text_corpus)

    # 1. Generate report.txt
    txt_lines = [
        "=" * 79,
        f"TraceForge — {module_title}",
        "=" * 79,
        f"Target      : {target}",
        f"Scan Mode   : {scan_mode.upper()} SCAN",
        f"Generated   : {timestamp_str}",
        f"Output Dir  : {out_dir}",
        "=" * 79,
        "",
    ]
    for sec in sections:
        title = sec.get("title", "Section")
        content = sec.get("content", "").strip()
        txt_lines.append(f"[{title}]")
        txt_lines.append(content if content else "(No records found)")
        txt_lines.append("")

    # Append IOCs summary to txt
    total_iocs = sum(len(v) for v in extracted_iocs.values())
    txt_lines.append("[SUMMARY OF EXTRACTED OBSERVABLES]")
    if total_iocs > 0:
        for cat, items in extracted_iocs.items():
            if items:
                txt_lines.append(f"  • {cat.upper()}: {len(items)} found ({', '.join(items[:5])}{'...' if len(items) > 5 else ''})")
    else:
        txt_lines.append("  No IOCs or external observables extracted.")
    txt_lines.append("")
    txt_lines.append(f"Analysis Completed: {timestamp_str}")

    report_txt_file = out_dir / "report.txt"
    with open(report_txt_file, "w", encoding="utf-8") as f:
        f.write("\n".join(txt_lines) + "\n")

    # 2. Generate report.md
    md_lines = [
        f"# {module_title}",
        "",
        f"> **Target:** `{target}` | **Scan Depth:** `{scan_mode.upper()}` | **Execution Time:** `{timestamp_str}`",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Target Specimen** | `{target}` |",
        f"| **Module** | `{module_id}` ({module_title}) |",
        f"| **Scan Depth** | `{scan_mode.upper()}` |",
        f"| **Discovered IOCs** | `{total_iocs}` observables |",
        f"| **Artifact Directory** | `{out_dir}` |",
        "",
        "---",
        "",
        "## Investigation Findings",
        "",
    ]
    for sec in sections:
        title = sec.get("title", "Section")
        content = sec.get("content", "").strip()
        md_lines.append(f"### {title}")
        md_lines.append("")
        if content:
            md_lines.append("```text")
            md_lines.append(content)
            md_lines.append("```")
        else:
            md_lines.append("*No data returned for this phase.*")
        md_lines.append("")

    if total_iocs > 0:
        md_lines.append("## Discovered Observables (IOCs)")
        md_lines.append("")
        for cat, items in extracted_iocs.items():
            if items:
                md_lines.append(f"#### {cat.title()} ({len(items)})")
                for it in items:
                    md_lines.append(f"- `{it}`")
                md_lines.append("")

    report_md_file = out_dir / "report.md"
    with open(report_md_file, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines) + "\n")

    # 3. Generate report.html
    html_sections = []
    for sec in sections:
        title = html.escape(sec.get("title", "Section"))
        content = html.escape(sec.get("content", "").strip() or "No records found")
        html_sections.append(f"""
        <div class="card">
            <div class="card-header">{title}</div>
            <pre class="card-body">{content}</pre>
        </div>
        """)

    ioc_pills = []
    for cat, items in extracted_iocs.items():
        if items:
            for it in items[:12]:
                ioc_pills.append(f'<span class="badge badge-{cat}">{html.escape(cat)}: {html.escape(it)}</span>')

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TraceForge — {html.escape(module_title)}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-dim: #8b949e;
            --cyan: #58a6ff;
            --green: #3fb950;
            --purple: #bc8cff;
            --red: #f85149;
            --yellow: #d29922;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            line-height: 1.6;
            padding: 24px;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        header {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        h1 {{ color: #ffffff; font-size: 24px; margin-bottom: 12px; display: flex; align-items: center; gap: 10px; }}
        .tag {{
            display: inline-block;
            background: rgba(88, 166, 255, 0.15);
            color: var(--cyan);
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-top: 16px;
            border-top: 1px solid var(--border);
            padding-top: 16px;
            font-size: 13px;
        }}
        .meta-item span {{ color: var(--text-dim); display: block; font-size: 11px; text-transform: uppercase; }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .card-header {{
            background: rgba(255, 255, 255, 0.03);
            border-bottom: 1px solid var(--border);
            padding: 12px 18px;
            font-weight: 600;
            color: var(--cyan);
            font-size: 15px;
        }}
        .card-body {{
            padding: 16px 18px;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 13px;
            color: var(--text);
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 480px;
            overflow-y: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            margin: 2px 4px 2px 0;
            background: rgba(255, 255, 255, 0.08);
        }}
        .badge-emails {{ color: var(--green); border: 1px solid rgba(63, 185, 80, 0.3); }}
        .badge-urls {{ color: var(--cyan); border: 1px solid rgba(88, 166, 255, 0.3); }}
        .badge-ipv4 {{ color: var(--yellow); border: 1px solid rgba(210, 153, 34, 0.3); }}
        .badge-domains {{ color: var(--purple); border: 1px solid rgba(188, 140, 255, 0.3); }}
        footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-dim);
            margin-top: 40px;
            padding: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>TraceForge — {html.escape(module_title)} <span class="tag">{html.escape(scan_mode.upper())} SCAN</span></h1>
            <div class="meta-grid">
                <div class="meta-item"><span>Target Specimen</span><strong>{html.escape(target)}</strong></div>
                <div class="meta-item"><span>Scan Timestamp</span><strong>{html.escape(timestamp_str)}</strong></div>
                <div class="meta-item"><span>Discovered Observables</span><strong>{total_iocs} items</strong></div>
                <div class="meta-item"><span>Status</span><strong style="color: var(--green);">✓ Completed</strong></div>
            </div>
            {f'<div style="margin-top: 16px; border-top: 1px solid var(--border); padding-top: 12px;"><strong>Observables:</strong> {" ".join(ioc_pills)}</div>' if ioc_pills else ''}
        </header>

        {''.join(html_sections)}

        <footer>
            TraceForge OSINT & Forensics Suite · Immutable Forensic Triage · Aman Kumar Pandey
        </footer>
    </div>
</body>
</html>
"""
    report_html_file = out_dir / "report.html"
    with open(report_html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    # 4. Generate report.json
    report_json_data = {
        "module_id": module_id,
        "module_title": module_title,
        "target": target,
        "scan_mode": scan_mode,
        "timestamp": timestamp_str,
        "output_directory": str(out_dir),
        "total_sections": len(sections),
        "sections": sections,
        "iocs": extracted_iocs,
        "ioc_count": total_iocs,
    }
    report_json_file = out_dir / "report.json"
    with open(report_json_file, "w", encoding="utf-8") as f:
        json.dump(report_json_data, f, indent=2)

    # 5. Generate iocs.json
    iocs_file = out_dir / "iocs.json"
    with open(iocs_file, "w", encoding="utf-8") as f:
        json.dump(extracted_iocs, f, indent=2)

    return {
        "txt": str(report_txt_file),
        "md": str(report_md_file),
        "html": str(report_html_file),
        "json": str(report_json_file),
        "iocs": str(iocs_file),
    }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="TraceForge CLI Module Report Generator")
    parser.add_argument("--module-id", required=True)
    parser.add_argument("--module-title", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--scan-mode", default="quick")
    parser.add_argument("--dir", required=True)
    parser.add_argument("--sections-json", required=True)
    args = parser.parse_args()

    with open(args.sections_json, "r", encoding="utf-8") as sf:
        secs = json.load(sf)

    res = generate_module_reports(
        module_id=args.module_id,
        module_title=args.module_title,
        target=args.target,
        scan_mode=args.scan_mode,
        out_dir=Path(args.dir),
        sections=secs,
    )
    print(json.dumps(res, indent=2))
