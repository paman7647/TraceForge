import csv
import datetime
import hashlib
import json
import mimetypes
import os
import re
import shutil
import socket
import struct
import tarfile
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from traceforge.platform_detect import which_tool
from traceforge.runners import ToolRunner, select_runtime_for_feature, RuntimeDecision

# -----------------------------------------------------------------------------
# 1. IOC Extractor & Defanger
# -----------------------------------------------------------------------------
RE_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
RE_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_URL = re.compile(r"https?://[^\s<>\"'{}|\\^`]+")
RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_CVE = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,8}\b")

def defang_ioc(ioc_type: str, value: str) -> str:
    """Defangs live indicators into inert text."""
    if ioc_type == "url":
        res = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
        return res.replace(".", "[.]")
    elif ioc_type in ("domain", "ipv4", "ipv6", "ip"):
        return value.replace(".", "[.]")
    elif ioc_type == "email":
        return value.replace("@", "[at]").replace(".", "[.]")
    return value

def extract_iocs(text: str, source: str = "stream") -> List[Dict[str, Any]]:
    """Extracts, normalizes, and deduplicates indicators of compromise."""
    iocs: Dict[str, Dict[str, Any]] = {}
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def add_ioc(t: str, val: str, conf: str = "high"):
        val = val.strip()
        if not val:
            return
        if t == "ipv4":
            parts = val.split(".")
            if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts if p.isdigit()):
                if val.startswith("127.") or val == "0.0.0.0":
                    return
            else:
                return
        if t == "domain":
            val = val.lower()
            if val.endswith((".local", ".internal", ".arpa")):
                return

        key = f"{t}:{val}"
        if key in iocs:
            iocs[key]["last_seen"] = now
            return

        h = hashlib.sha256(key.encode()).hexdigest()[:8].upper()
        iocs[key] = {
            "id": f"IOC-{h}",
            "type": t,
            "value": val,
            "defanged": defang_ioc(t, val),
            "source": source,
            "confidence": conf,
            "first_seen": now,
            "last_seen": now,
        }

    # URLs
    for m in RE_URL.findall(text):
        add_ioc("url", m, "high")
        try:
            parsed = urllib.parse.urlparse(m)
            if parsed.hostname:
                if RE_IPV4.match(parsed.hostname):
                    add_ioc("ipv4", parsed.hostname, "high")
                else:
                    add_ioc("domain", parsed.hostname, "high")
        except Exception:
            pass

    # Emails
    for m in RE_EMAIL.findall(text):
        add_ioc("email", m, "high")

    # IPv4 & IPv6
    for m in RE_IPV4.findall(text):
        add_ioc("ipv4", m, "high")
    for m in RE_IPV6.findall(text):
        add_ioc("ipv6", m, "high")

    # Hashes
    for m in RE_SHA256.findall(text):
        add_ioc("sha256", m.lower(), "high")
    for m in RE_SHA1.findall(text):
        add_ioc("sha1", m.lower(), "medium")
    for m in RE_MD5.findall(text):
        add_ioc("md5", m.lower(), "medium")

    # CVEs
    for m in RE_CVE.findall(text):
        add_ioc("cve", m, "high")

    # Domains
    for m in RE_DOMAIN.findall(text):
        if not RE_IPV4.match(m) and "@" + m not in text:
            add_ioc("domain", m.lower(), "medium")

    return sorted(list(iocs.values()), key=lambda x: (x["type"], x["value"]))

# -----------------------------------------------------------------------------
# 2. Asset Graph Generator
# -----------------------------------------------------------------------------
class AssetGraph:
    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, str]] = []

    def add_node(self, node_id: str, label: str, node_type: str, metadata: Optional[Dict[str, Any]] = None):
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "metadata": metadata or {},
            }

    def add_edge(self, src: str, dst: str, relation: str, source: str = "asset_graph"):
        self.edges.append({
            "from": src,
            "to": dst,
            "relation": relation,
            "source": source,
        })

    def parse_lines(self, lines: List[str], source_name: str = "stream"):
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Try JSON line
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = json.loads(line)
                    val = obj.get("object_value") or obj.get("value")
                    t = obj.get("object_type") or obj.get("type", "entity")
                    if val:
                        self.add_node(val, val, t, obj.get("metadata"))
                        continue
                except Exception:
                    pass

            # Delimited format: domain,IP or domain: IP
            parts = None
            if "\t" in line:
                parts = line.split("\t")
            elif "," in line:
                parts = line.split(",")
            elif ": " in line:
                parts = line.split(": ")

            if parts and len(parts) >= 2:
                src, dst = parts[0].strip(), parts[1].strip()
                src_type = "ip" if RE_IPV4.match(src) else "domain"
                dst_type = "ip" if RE_IPV4.match(dst) else "subdomain"
                self.add_node(src, src, src_type)
                self.add_node(dst, dst, dst_type)
                self.add_edge(src, dst, "resolves_to", source_name)
                continue

            # Single item
            if RE_IPV4.match(line):
                self.add_node(line, line, "ip")
            elif line.startswith(("http://", "https://")):
                self.add_node(line, line, "url")
            else:
                self.add_node(line, line, "domain")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }

    def export_html(self, title: str = "TraceForge Asset Relationship Graph") -> str:
        nodes_count = len(self.nodes)
        edges_count = len(self.edges)

        rows = []
        for n in self.nodes.values():
            nid = n["id"]
            conns = [f"&rarr; {e['to']} ({e['relation']})" for e in self.edges if e["from"] == nid]
            conns += [f"&larr; {e['from']} ({e['relation']})" for e in self.edges if e["to"] == nid]
            conn_str = "<br>".join(conns) if conns else "<span style='color:#64748b'>Standalone</span>"
            rows.append(f"<tr><td><strong>{n['label']}</strong></td><td><span class='badge badge-{n['type']}'>{n['type']}</span></td><td>{conn_str}</td></tr>")

        table_html = "\n".join(rows)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
body {{ background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; padding: 24px; margin: 0; }}
h1 {{ color: #38bdf8; font-size: 20px; border-bottom: 1px solid #334155; padding-bottom: 12px; }}
.stats {{ display: flex; gap: 16px; margin: 16px 0; }}
.stat-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 12px 16px; min-width: 140px; }}
.stat-val {{ font-size: 20px; font-weight: bold; color: #38bdf8; }}
table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 6px; overflow: hidden; margin-top: 16px; }}
th {{ background: #0b132b; color: #94a3b8; text-align: left; padding: 10px 14px; font-size: 11px; text-transform: uppercase; }}
td {{ padding: 10px 14px; border-bottom: 1px solid #334155; font-size: 13px; }}
tr:hover {{ background: #273549; }}
.badge {{ display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
.badge-domain {{ background: #0369a1; color: #e0f2fe; }}
.badge-ip {{ background: #15803d; color: #dcfce7; }}
.badge-url {{ background: #a21caf; color: #fae8ff; }}
.badge-subdomain {{ background: #b45309; color: #fef3c7; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="stats">
  <div class="stat-card"><div>Entities</div><div class="stat-val">{nodes_count}</div></div>
  <div class="stat-card"><div>Relationships</div><div class="stat-val">{edges_count}</div></div>
</div>
<table>
<thead><tr><th>Entity Label</th><th>Type</th><th>Observed Relationships</th></tr></thead>
<tbody>
{table_html}
</tbody>
</table>
</body>
</html>"""

# -----------------------------------------------------------------------------
# 3. Snapshot Diff Engine
# -----------------------------------------------------------------------------
def diff_snapshots(domain: str, old_items: Union[List[str], Dict[str, Any]], new_items: Union[List[str], Dict[str, Any]]) -> Dict[str, Any]:
    old_map = {x: x for x in old_items} if isinstance(old_items, list) else old_items
    new_map = {x: x for x in new_items} if isinstance(new_items, list) else new_items

    all_keys = sorted(list(set(old_map.keys()) | set(new_map.keys())))
    diff_items = []
    added = removed = modified = unchanged = 0

    for k in all_keys:
        has_old = k in old_map
        has_new = k in new_map

        if has_old and not has_new:
            removed += 1
            diff_items.append({"key": k, "status": "removed", "old_value": old_map[k], "details": f"Removed: {old_map[k]}"})
        elif not has_old and has_new:
            added += 1
            diff_items.append({"key": k, "status": "added", "new_value": new_map[k], "details": f"Added: {new_map[k]}"})
        elif old_map[k] != new_map[k]:
            modified += 1
            diff_items.append({"key": k, "status": "modified", "old_value": old_map[k], "new_value": new_map[k], "details": f"Modified: {old_map[k]} -> {new_map[k]}"})
        else:
            unchanged += 1
            diff_items.append({"key": k, "status": "unchanged", "old_value": old_map[k], "new_value": new_map[k]})

    return {
        "domain": domain,
        "compared_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "added_count": added,
        "removed_count": removed,
        "modified_count": modified,
        "unchanged_count": unchanged,
        "items": diff_items,
    }

# -----------------------------------------------------------------------------
# 4. Evidence Indexer (Recursive with SHA-256 and Go Acceleration)
# -----------------------------------------------------------------------------
def index_evidence_directory(dir_path: Union[str, Path], follow_symlinks: bool = False, verbose: bool = False) -> List[Dict[str, Any]]:
    target = Path(dir_path).resolve()
    if not target.exists() or not target.is_dir():
        raise NotADirectoryError(f"Directory not found: {dir_path}")

    # Check adaptive runtime selection
    decision = select_runtime_for_feature("hash", verbose=verbose)
    if decision.selected_runtime == "go" and decision.binary_used:
        tool_args = ["hash", "--dir", str(target), "--json"] if "traceforge-native" in decision.binary_used else ["--dir", str(target), "--json"]
        res = ToolRunner.run(decision.binary_used, tool_args)
        if res.success and res.stdout.strip().startswith("["):
            try:
                return json.loads(res.stdout)
            except Exception:
                pass

    # Pure Python reference implementation
    evidence_list = []
    count = 0

    for root, dirs, files in os.walk(target, followlinks=follow_symlinks):
        if ".git" in dirs:
            dirs.remove(".git")
        if ".venv" in dirs:
            dirs.remove(".venv")

        for f in files:
            p = Path(root) / f
            is_symlink = p.is_symlink()
            if is_symlink and not follow_symlinks:
                continue

            try:
                stat = p.lstat() if is_symlink else p.stat()
                sha256_hex = "-"
                if not is_symlink:
                    h = hashlib.sha256()
                    with open(p, "rb") as fp:
                        while chunk := fp.read(65536):
                            h.update(chunk)
                    sha256_hex = h.hexdigest()

                mime, _ = mimetypes.guess_type(str(p))
                count += 1
                rel_path = str(p.relative_to(target))

                evidence_list.append({
                    "id": f"EVID-{count:03d}",
                    "relative_path": rel_path,
                    "filename": f,
                    "size_bytes": stat.st_size,
                    "mime_type": mime or "application/octet-stream",
                    "sha256": sha256_hex,
                    "mtime": datetime.datetime.fromtimestamp(stat.st_mtime, tz=datetime.timezone.utc).isoformat(),
                    "is_symlink": is_symlink,
                })
            except Exception:
                continue

    return evidence_list

# -----------------------------------------------------------------------------
# 5. Timeline Engine (UTC Normalizer, Sorter & Filter)
# -----------------------------------------------------------------------------
def parse_utc_timestamp(ts_str: str) -> Optional[datetime.datetime]:
    ts_str = ts_str.strip()
    formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S %z",
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.datetime.strptime(ts_str, fmt)
            if dt.year == 1900:  # Missing year in syslog format
                dt = dt.replace(year=datetime.datetime.now().year)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc)
        except Exception:
            continue
    return None

def normalize_timeline(events: List[Dict[str, Any]], min_severity: Optional[str] = None) -> List[Dict[str, Any]]:
    sev_rank = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    min_rank = sev_rank.get(min_severity.lower() if min_severity else "info", 1)

    normalized = []
    for idx, e in enumerate(events):
        raw_ts = str(e.get("timestamp_utc") or e.get("timestamp") or "")
        dt = parse_utc_timestamp(raw_ts) or datetime.datetime.now(datetime.timezone.utc)
        sev = str(e.get("severity", "info")).lower()
        if sev_rank.get(sev, 1) < min_rank:
            continue

        normalized.append({
            "id": e.get("id") or f"EVT-{idx+1:04d}",
            "timestamp_utc": dt.isoformat(),
            "original_timestamp": raw_ts,
            "source": e.get("source", "unknown"),
            "type": e.get("type", "event"),
            "severity": sev,
            "description": e.get("description") or e.get("title", ""),
            "_dt": dt,
        })

    normalized.sort(key=lambda x: x["_dt"])
    for n in normalized:
        del n["_dt"]
    return normalized

# -----------------------------------------------------------------------------
# 6. Log Triage Engine
# -----------------------------------------------------------------------------
RE_COMBINED_LOG = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*)" (\d{3}) (\d+|-)')
RE_SYSLOG = re.compile(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)$')
RE_AUTH_FAIL = re.compile(r"(?i)(failed password|authentication failure|auth fail|login fail|invalid user|unauthorized|access denied)")

def triage_log_stream(lines: List[str]) -> Dict[str, Any]:
    total_lines = len(lines)
    status_codes: Dict[str, int] = {}
    top_ips: Dict[str, int] = {}
    top_uris: Dict[str, int] = {}
    auth_failures = 0
    detected_format = "generic_text"
    anomalies: List[str] = []
    suspicious_events: List[Dict[str, Any]] = []

    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue

        # JSONL format
        if line_str.startswith("{") and line_str.endswith("}"):
            detected_format = "jsonl"
            try:
                rec = json.loads(line_str)
                cip = rec.get("client_ip") or rec.get("ip")
                if cip:
                    top_ips[cip] = top_ips.get(cip, 0) + 1
                st = str(rec.get("status", ""))
                if st:
                    status_codes[st] = status_codes.get(st, 0) + 1
                msg = str(rec.get("message", ""))
                if RE_AUTH_FAIL.search(msg):
                    auth_failures += 1
                    suspicious_events.append({"type": "auth_failure", "message": msg})
                continue
            except Exception:
                pass

        # Apache/Nginx combined access log
        match_http = RE_COMBINED_LOG.match(line_str)
        if match_http:
            detected_format = "http_access"
            cip, _, method, uri, st, _ = match_http.groups()
            top_ips[cip] = top_ips.get(cip, 0) + 1
            top_uris[uri] = top_uris.get(uri, 0) + 1
            status_codes[st] = status_codes.get(st, 0) + 1
            if int(st) in (401, 403):
                auth_failures += 1
            continue

        # Syslog format
        match_sys = RE_SYSLOG.match(line_str)
        if match_sys:
            detected_format = "syslog"
            _, _, _, msg = match_sys.groups()
            if RE_AUTH_FAIL.search(msg):
                auth_failures += 1
                suspicious_events.append({"type": "auth_failure", "message": msg})
            continue

        # Generic auth failure check
        if RE_AUTH_FAIL.search(line_str):
            auth_failures += 1
            suspicious_events.append({"type": "auth_failure", "message": line_str})

    if auth_failures >= 5:
        anomalies.append(f"High-volume authentication failures detected ({auth_failures} occurrences).")
    if status_codes.get("404", 0) > 30:
        anomalies.append(f"High rate of HTTP 404 responses ({status_codes['404']}) indicating path enumeration.")

    return {
        "total_lines": total_lines,
        "detected_format": detected_format,
        "auth_failures": auth_failures,
        "status_codes": status_codes,
        "top_ips": dict(sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
        "top_uris": dict(sorted(top_uris.items(), key=lambda x: x[1], reverse=True)[:10]),
        "anomalies": anomalies,
        "suspicious_events": suspicious_events[:50],
    }

# -----------------------------------------------------------------------------
# 7. Filesystem Baseline & Delta Comparator
# -----------------------------------------------------------------------------
def create_filesystem_baseline(dir_path: Union[str, Path]) -> Dict[str, Any]:
    items = index_evidence_directory(dir_path, follow_symlinks=False)
    file_map = {it["relative_path"]: it for it in items}
    return {
        "root_path": str(Path(dir_path).resolve()),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "files": file_map,
    }

def compare_filesystem_baselines(old_baseline: Dict[str, Any], new_baseline: Dict[str, Any]) -> Dict[str, Any]:
    old_files = old_baseline.get("files", {})
    new_files = new_baseline.get("files", {})

    old_map = {k: v.get("sha256", "") for k, v in old_files.items()}
    new_map = {k: v.get("sha256", "") for k, v in new_files.items()}

    return diff_snapshots("filesystem_baseline", old_map, new_map)

# -----------------------------------------------------------------------------
# 8. PCAP Summary (Native Python Fallback + TShark + Go native/tracepcap)
# -----------------------------------------------------------------------------
def summarize_pcap(pcap_path: Union[str, Path], verbose: bool = False) -> Dict[str, Any]:
    target = Path(pcap_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    filesize = target.stat().st_size
    decision = select_runtime_for_feature("pcap", verbose=verbose)

    # 1. Native Go acceleration if selected
    if decision.selected_runtime == "go" and decision.binary_used:
        tool_args = ["pcap", str(target), "--json"] if "traceforge-native" in decision.binary_used else [str(target), "--json"]
        res = ToolRunner.run(decision.binary_used, tool_args)
        if res.success and res.stdout.strip().startswith("{"):
            try:
                return json.loads(res.stdout)
            except Exception:
                pass

    # 2. TShark deep protocol dissection if installed
    if which_tool("tshark"):
        protocols: Dict[str, int] = {}
        top_ips: Dict[str, int] = {}
        dns_queries: Dict[str, int] = {}
        tls_snis: Dict[str, int] = {}

        res = ToolRunner.run("tshark", ["-r", str(target), "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol"])
        if res.success:
            for line in res.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 3:
                    src, dst, proto = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    if src:
                        top_ips[src] = top_ips.get(src, 0) + 1
                    if dst:
                        top_ips[dst] = top_ips.get(dst, 0) + 1
                    if proto:
                        protocols[proto] = protocols.get(proto, 0) + 1

        res_dns = ToolRunner.run("tshark", ["-r", str(target), "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name"])
        if res_dns.success:
            for line in res_dns.stdout.splitlines():
                q = line.strip()
                if q:
                    dns_queries[q] = dns_queries.get(q, 0) + 1

        res_tls = ToolRunner.run("tshark", ["-r", str(target), "-Y", "tls.handshake.extensions_server_name", "-T", "fields", "-e", "tls.handshake.extensions_server_name"])
        if res_tls.success:
            for line in res_tls.stdout.splitlines():
                s = line.strip()
                if s:
                    tls_snis[s] = tls_snis.get(s, 0) + 1

        return {
            "filepath": str(target),
            "filesize_bytes": filesize,
            "protocols": protocols,
            "top_ips": top_ips,
            "dns_queries": dns_queries,
            "tls_sni_hosts": tls_snis,
        }

    # 3. Pure Python PCAP header parsing fallback
    protocols = {"Ethernet": 1}
    with open(target, "rb") as f:
        magic_bytes = f.read(4)
        if magic_bytes in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\x0a\x0d\x0d\x0a"):
            protocols["PCAP-Valid-Container"] = 1

    return {
        "filepath": str(target),
        "filesize_bytes": filesize,
        "total_packets_estimated": max(1, filesize // 128),
        "protocols": protocols,
        "top_ips": {},
        "dns_queries": {},
        "tls_sni_hosts": {},
    }

# -----------------------------------------------------------------------------
# 9. Defensive Endpoint Inspector
# -----------------------------------------------------------------------------
def inspect_endpoint() -> Dict[str, Any]:
    hostname = socket.gethostname()
    os_name = os.name
    arch = os.uname().machine if hasattr(os, "uname") else "unknown"

    from traceforge.platform_detect import is_termux, get_termux_info

    if is_termux():
        termux_info = get_termux_info()
        battery_info = {}
        wifi_info = {}

        if termux_info["api_available"]:
            # Optional Termux:API queries with safe timeouts
            res_bat = ToolRunner.run("termux-battery-status", timeout=2)
            if res_bat.success and res_bat.stdout.strip().startswith("{"):
                try:
                    battery_info = json.loads(res_bat.stdout)
                except Exception:
                    pass
            res_wifi = ToolRunner.run("termux-wifi-connectioninfo", timeout=2)
            if res_wifi.success and res_wifi.stdout.strip().startswith("{"):
                try:
                    wifi_info = json.loads(res_wifi.stdout)
                except Exception:
                    pass

        # Android properties if available
        android_release = "unknown"
        res_prop = ToolRunner.run("getprop", ["ro.build.version.release"], timeout=2)
        if res_prop.success and res_prop.stdout.strip():
            android_release = res_prop.stdout.strip()

        return {
            "hostname": hostname,
            "os": "Termux (Android)",
            "android_version": android_release,
            "architecture": arch,
            "prefix": termux_info["prefix"],
            "shared_storage_mounted": termux_info["storage_mounted"],
            "termux_api_available": termux_info["api_available"],
            "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "battery": battery_info or "Termux:API not active",
            "wifi": wifi_info or "Termux:API not active",
            "active_users": ["termux_user"],
            "root_privileges": "unrooted_userland",
        }

    interfaces = []
    dns_resolvers = []
    active_users = []
    listening_ports = []
    total_processes = 0

    # DNS Resolvers
    if os.path.exists("/etc/resolv.conf"):
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            dns_resolvers.append(parts[1])
        except Exception:
            pass

    # Active Users
    res_who = ToolRunner.run("who")
    if res_who.success:
        active_users = [l.strip() for l in res_who.stdout.splitlines() if l.strip()]

    # Listening Ports
    res_net = ToolRunner.run("netstat", ["-an"])
    if res_net.success:
        for line in res_net.stdout.splitlines():
            if "LISTEN" in line:
                fields = line.strip().split()
                if len(fields) >= 4:
                    listening_ports.append(fields[3])

    # Process Count
    res_ps = ToolRunner.run("ps", ["-e"])
    if res_ps.success:
        total_processes = max(0, len(res_ps.stdout.splitlines()) - 1)

    return {
        "hostname": hostname,
        "os": os_name,
        "architecture": arch,
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dns_resolvers": dns_resolvers,
        "active_users": active_users,
        "listening_ports": listening_ports[:30],
        "total_processes": total_processes,
    }

# -----------------------------------------------------------------------------
# 10. Observation Correlation Engine
# -----------------------------------------------------------------------------
def correlate_observations(observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_val: Dict[str, List[Dict[str, Any]]] = {}
    for obs in observations:
        val = str(obs.get("object_value") or obs.get("value") or "").strip().lower()
        if val:
            by_val.setdefault(val, []).append(obs)

    relationships = []
    for val, list_obs in by_val.items():
        if len(list_obs) > 1:
            for i in range(len(list_obs)):
                for j in range(i + 1, len(list_obs)):
                    relationships.append({
                        "source": list_obs[i].get("source", "source_a"),
                        "target": list_obs[j].get("source", "source_b"),
                        "shared_indicator": val,
                        "type": "shared_observable",
                        "relation": f"Both sources observed shared value: {val}",
                    })
    return relationships

# -----------------------------------------------------------------------------
# 11. Case Deliverable Packager
# -----------------------------------------------------------------------------
def package_case(case_dir: Union[str, Path], format_type: str = "zip", out_path: Optional[Union[str, Path]] = None) -> Tuple[Path, str]:
    c_path = Path(case_dir).resolve()
    if not c_path.exists() or not c_path.is_dir():
        raise NotADirectoryError(f"Case directory not found: {case_dir}")

    case_name = c_path.name
    if not out_path:
        out_path = c_path / f"{case_name}-bundle.{format_type}"
    else:
        out_path = Path(out_path).resolve()

    if format_type == "zip":
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zw:
            for root, _, files in os.walk(c_path):
                for f in files:
                    if f.endswith((".zip", ".tar.gz", ".sha256")) or f.startswith("."):
                        continue
                    fp = Path(root) / f
                    rel = fp.relative_to(c_path)
                    zw.write(fp, arcname=str(rel))
    else:
        with tarfile.open(out_path, "w:gz") as tw:
            for root, _, files in os.walk(c_path):
                for f in files:
                    if f.endswith((".zip", ".tar.gz", ".sha256")) or f.startswith("."):
                        continue
                    fp = Path(root) / f
                    rel = fp.relative_to(c_path)
                    tw.add(fp, arcname=str(rel))

    # Calculate SHA-256
    sha256_hash = hashlib.sha256()
    with open(out_path, "rb") as f:
        while chunk := f.read(65536):
            sha256_hash.update(chunk)
    digest = sha256_hash.hexdigest()

    checksum_file = out_path.with_suffix(out_path.suffix + ".sha256")
    with open(checksum_file, "w", encoding="utf-8") as f:
        f.write(f"{digest}  {out_path.name}\n")

    return out_path, digest
