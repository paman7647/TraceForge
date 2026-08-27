import datetime
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from traceforge.config import get_workspace_dir, load_config, save_config


def hash_file(file_path: Path) -> Dict[str, str]:
    """Calculates SHA-256 and MD5 checksums for a given file."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
    }


class Case:
    """Manages an active forensic investigation case workspace."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.case_dir = get_workspace_dir() / case_id
        self.case_json = self.case_dir / "case.json"
        self.evidence_dir = self.case_dir / "evidence"
        self.reports_dir = self.case_dir / "reports"
        self.exports_dir = self.case_dir / "exports"
        self.logs_dir = self.case_dir / "logs"
        self.data: Dict[str, Any] = {}
        self.load()

    def exists(self) -> bool:
        return self.case_dir.exists() and self.case_json.exists()

    def load(self) -> None:
        if self.case_json.exists():
            try:
                with open(self.case_json, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception:
                self.data = {}
        else:
            self.data = {}

    def save(self) -> None:
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        with open(self.case_json, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def log_action(self, action: str, details: str, operator: str = "Analyst") -> None:
        """Appends an immutable entry to the chain of custody audit log."""
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry = {
            "timestamp": ts,
            "operator": operator,
            "action": action,
            "details": details,
        }
        if "chain_of_custody" not in self.data:
            self.data["chain_of_custody"] = []
        self.data["chain_of_custody"].append(entry)

        log_file = self.logs_dir / "chain_of_custody.log"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{operator}] {action} - {details}\n")
        self.save()

    def add_evidence(
        self,
        source_path: Union[str, Path],
        description: str = "",
        source_device: str = "Target System",
        analyst: str = "Analyst",
    ) -> Dict[str, Any]:
        src = Path(source_path).resolve()
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(f"Evidence file not found: {source_path}")

        evid_list = self.data.setdefault("evidence", [])
        evid_id = f"EVID-{len(evid_list) + 1:03d}"
        dest_filename = f"{evid_id}_{src.name}"
        dest_path = self.evidence_dir / dest_filename

        if dest_path.exists():
            try:
                os.chmod(dest_path, 0o644)
                dest_path.unlink()
            except Exception:
                pass

        shutil.copy2(src, dest_path)
        os.chmod(dest_path, 0o444)


        hashes = hash_file(dest_path)
        size_bytes = dest_path.stat().st_size
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        record = {
            "id": evid_id,
            "filename": src.name,
            "stored_filename": dest_filename,
            "relative_path": f"evidence/{dest_filename}",
            "size_bytes": size_bytes,
            "sha256": hashes["sha256"],
            "md5": hashes["md5"],
            "description": description,
            "source_device": source_device,
            "acquired_at": ts,
            "analyst": analyst,
        }

        evid_list.append(record)
        self.log_action("INGEST_EVIDENCE", f"Ingested {src.name} as {evid_id} (SHA-256: {hashes['sha256'][:16]}...)", analyst)
        return record

    ingest_evidence = add_evidence

    def add_finding(
        self,
        title: str,
        description: str = "",
        category: str = "General",
        severity: str = "medium",
        status: str = "open",
        evidence_refs: Optional[List[str]] = None,
        analyst: str = "Analyst",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        # Handle positional arg flexibility if callers pass (title, details/category)
        if "details" in kwargs and not description:
            description = kwargs["details"]

        findings = self.data.setdefault("findings", [])
        find_id = f"FIND-{len(findings) + 1:03d}"
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        rec = {
            "id": find_id,
            "title": title,
            "category": category,
            "severity": severity,
            "status": status,
            "description": description,
            "evidence": evidence_refs or [],
            "created_at": ts,
            "analyst": analyst,
        }
        findings.append(rec)
        self.log_action("RECORD_FINDING", f"Created finding {find_id}: {title} [{severity.upper()}]", analyst)
        return rec

    def add_ioc(
        self,
        value_or_type: str = "",
        ioc_type_or_value: str = "",
        value: Optional[str] = None,
        ioc_type: Optional[str] = None,
        context: str = "",
        source: str = "Manual Record",
        confidence: str = "high",
        analyst: str = "Analyst",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        if value is not None:
            actual_value = value.strip()
            actual_type = (ioc_type or value_or_type or "domain").lower().strip()
        else:
            KNOWN_TYPES = {"ip", "ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "cve", "btc", "asn"}
            first = value_or_type.strip()
            second = ioc_type_or_value.strip()

            if first.lower() in KNOWN_TYPES and second.lower() not in KNOWN_TYPES:
                actual_type = first.lower()
                actual_value = second
            else:
                actual_value = first
                actual_type = second.lower() if second.lower() in KNOWN_TYPES else "domain"

        from traceforge.tools import defang_ioc
        defanged = defang_ioc(actual_type, actual_value)

        iocs = self.data.setdefault("iocs", [])
        ioc_id = f"IOC-{len(iocs) + 1:03d}"
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        rec = {
            "id": ioc_id,
            "type": actual_type,
            "value": actual_value,
            "defanged": defanged,
            "context": context,
            "source": source,
            "confidence": confidence.lower(),
            "first_seen": ts,
            "last_seen": ts,
        }
        iocs.append(rec)
        self.log_action("ADD_IOC", f"Registered observable {ioc_id} ({actual_type}: {actual_value})", analyst)
        return rec

    def add_event(
        self,
        title_or_ts: str = "",
        title_or_desc: str = "",
        description: str = "",
        title: Optional[str] = None,
        timestamp: Optional[str] = None,
        source: str = "Manual Record",
        severity: str = "info",
        evidence_ref: str = "",
        analyst: str = "Analyst",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        events = self.data.setdefault("timeline", [])
        evt_id = f"EVT-{len(events) + 1:04d}"
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Resolve explicit kwargs first
        actual_title = title or kwargs.get("name") or ""
        actual_ts = timestamp or kwargs.get("time") or ""
        actual_desc = description or kwargs.get("details") or ""

        if not actual_title and title_or_ts:
            if title_or_desc:
                # First could be timestamp or title
                if any(c in title_or_ts for c in ("-", ":", "T", "Z")) and len(title_or_ts) >= 10:
                    actual_ts = title_or_ts
                    actual_title = title_or_desc
                else:
                    actual_title = title_or_ts
                    actual_desc = actual_desc or title_or_desc
            else:
                actual_title = title_or_ts

        if not actual_ts:
            actual_ts = now_ts
        if not actual_title:
            actual_title = "Timeline Event"


        rec = {
            "id": evt_id,
            "timestamp": actual_ts,
            "title": actual_title,
            "description": actual_desc,
            "source": source,
            "severity": severity.lower(),
            "evidence_ref": evidence_ref,
        }
        events.append(rec)
        self.log_action("ADD_TIMELINE_EVENT", f"Timeline event {evt_id} recorded ({actual_title})", analyst)
        return rec


    add_timeline_event = add_event

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verifies the cryptographic chain of custody for all ingested evidence.
        Recalculates SHA-256 and MD5 digests from disk and validates against recorded case manifest.
        """
        evidence_list = self.data.get("evidence", [])
        results = []
        intact_count = 0
        tampered_count = 0
        missing_count = 0

        for item in evidence_list:
            evid_id = item.get("id", "UNKNOWN")
            filename = item.get("filename", "")
            stored_filename = item.get("stored_filename", filename)
            rel_path = item.get("relative_path", f"evidence/{stored_filename}")
            target_path = self.case_dir / rel_path

            expected_sha256 = item.get("sha256", "")
            expected_md5 = item.get("md5", "")

            if not target_path.exists():
                missing_count += 1
                results.append({
                    "id": evid_id,
                    "filename": filename,
                    "status": "missing",
                    "path": str(target_path),
                    "expected_sha256": expected_sha256,
                    "actual_sha256": None,
                })
                continue

            current_hashes = hash_file(target_path)
            actual_sha256 = current_hashes["sha256"]
            actual_md5 = current_hashes["md5"]

            if actual_sha256 == expected_sha256 and (not expected_md5 or actual_md5 == expected_md5):
                intact_count += 1
                results.append({
                    "id": evid_id,
                    "filename": filename,
                    "status": "intact",
                    "sha256": actual_sha256,
                    "md5": actual_md5,
                })
            else:
                tampered_count += 1
                results.append({
                    "id": evid_id,
                    "filename": filename,
                    "status": "tampered",
                    "expected_sha256": expected_sha256,
                    "actual_sha256": actual_sha256,
                    "expected_md5": expected_md5,
                    "actual_md5": actual_md5,
                })

        all_intact = (tampered_count == 0 and missing_count == 0)
        return {
            "status": "intact" if all_intact else ("tampered" if tampered_count > 0 else "missing_evidence"),
            "intact": all_intact,
            "total_evidence": len(evidence_list),
            "intact_count": intact_count,
            "tampered_count": tampered_count,
            "missing_count": missing_count,
            "details": results,
        }


    def get_summary(self) -> Dict[str, Any]:
        evidence = self.data.get("evidence", [])
        findings = self.data.get("findings", [])
        iocs = self.data.get("iocs", [])
        timeline = self.data.get("timeline", [])

        high_sev = sum(1 for f in findings if f.get("severity") in ("high", "critical"))
        unique_ips = len({i["value"] for i in iocs if i.get("type") in ("ipv4", "ipv6", "ip")})
        unique_doms = len({i["value"] for i in iocs if i.get("type") == "domain"})
        unique_emails = len({i["value"] for i in iocs if i.get("type") == "email"})

        return {
            "case_id": self.case_id,
            "case_name": self.data.get("case_name", "Untitled Case"),
            "analyst": self.data.get("analyst", "Analyst"),
            "status": self.data.get("status", "active"),
            "created_at": self.data.get("created_at", "-"),
            "total_evidence": len(evidence),
            "total_findings": len(findings),
            "high_severity_findings": high_sev,
            "total_iocs": len(iocs),
            "unique_ips": unique_ips,
            "unique_domains": unique_doms,
            "unique_emails": unique_emails,
            "total_timeline_events": len(timeline),
        }

    summary = get_summary


def create_case(name: str = "Forensic Investigation", analyst: str = "Analyst", case_id: Optional[str] = None) -> Case:
    """Initializes a new case directory and case.json."""
    if not case_id:
        rand_suffix = hashlib.sha256(f"{name}{datetime.datetime.now()}".encode()).hexdigest()[:6].upper()
        date_str = datetime.datetime.now().strftime("%Y%m%d")
        case_id = f"CASE-{date_str}-{rand_suffix}"

    case = Case(case_id)
    case.case_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    case.data = {
        "case_id": case_id,
        "case_name": name,
        "analyst": analyst,
        "status": "active",
        "created_at": ts,
        "evidence": [],
        "findings": [],
        "iocs": [],
        "timeline": [],
        "chain_of_custody": [],
    }
    case.save()
    case.log_action("CREATE_CASE", f"Initialized new case: {name} ({case_id})", analyst)

    cfg = load_config()
    cfg["active_case"] = case_id
    save_config(cfg)

    return case


Case.create = staticmethod(create_case)


def get_active_case() -> Optional[Case]:
    cfg = load_config()
    cid = cfg.get("active_case", "")
    if cid:
        c = Case(cid)
        if c.exists():
            return c
    return None


def set_active_case(case_id: str) -> bool:
    c = Case(case_id)
    if c.exists():
        cfg = load_config()
        cfg["active_case"] = case_id
        save_config(cfg)
        return True
    return False


def list_all_cases() -> List[Dict[str, Any]]:
    ws = get_workspace_dir()
    results = []
    if not ws.exists():
        return results
    for entry in sorted(ws.iterdir()):
        if entry.is_dir() and (entry / "case.json").exists():
            c = Case(entry.name)
            results.append(c.get_summary())
    return results
