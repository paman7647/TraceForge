import datetime
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge.case import Case
from traceforge.config import get_workspace_dir, load_config, save_config


def list_cases() -> List[Dict[str, Any]]:
    """Lists all registered forensic cases with summary metadata."""
    ws = get_workspace_dir()
    cases: List[Dict[str, Any]] = []
    if not ws.exists():
        return cases

    for entry in ws.iterdir():
        if entry.is_dir():
            case_file = entry / "case.json"
            if case_file.exists():
                try:
                    c = Case(entry.name)
                    cases.append(c.summary())
                except Exception:
                    continue
    return sorted(cases, key=lambda x: x.get("created_at", ""), reverse=True)


def get_case(case_id: str) -> Optional[Case]:
    """Loads a case by ID with path validation."""
    clean_id = re.sub(r"[^a-zA-Z0-9_\-]", "", case_id)
    if not clean_id:
        return None
    ws = get_workspace_dir()
    if not (ws / clean_id / "case.json").exists():
        return None
    return Case(clean_id)


def create_case(name: str, analyst: str = "Analyst") -> Case:
    """Creates and initializes a new investigation case."""
    clean_name = name.strip() or "Untitled Investigation"
    clean_analyst = analyst.strip() or "Analyst"
    c = Case.create(clean_name, clean_analyst)
    set_active_case_id(c.case_id)
    return c


def delete_case(case_id: str) -> bool:
    """Deletes a case directory."""
    c = get_case(case_id)
    if not c:
        return False
    import shutil
    try:
        shutil.rmtree(c.case_dir)
        cfg = load_config()
        if cfg.get("active_case") == case_id:
            cfg["active_case"] = ""
            save_config(cfg)
        return True
    except Exception:
        return False


def get_active_case_id() -> str:
    """Returns active case ID."""
    cfg = load_config()
    return cfg.get("active_case", "")


def set_active_case_id(case_id: str) -> bool:
    """Sets active case ID."""
    c = get_case(case_id)
    if not c and case_id != "":
        return False
    cfg = load_config()
    cfg["active_case"] = case_id
    save_config(cfg)
    return True


def add_evidence(case_id: str, filename: str, content: bytes, description: str = "") -> Optional[Dict[str, Any]]:
    """Saves uploaded evidence specimen and computes SHA256 checksum."""
    c = get_case(case_id)
    if not c:
        return None

    safe_name = Path(filename).name.replace(" ", "_")
    safe_name = re.sub(r"[^a-zA-Z0-9._\-]", "", safe_name) or "evidence.bin"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / safe_name
        with open(tmp_path, "wb") as f:
            f.write(content)
        rec = c.add_evidence(tmp_path, description=description)

    c.add_timeline_event(f"Ingested evidence specimen '{safe_name}' (SHA256: {rec.get('sha256', '')[:12]}...).", source="web_upload")
    return rec


def list_evidence(case_id: str) -> List[Dict[str, Any]]:
    """Returns all evidence records for a case."""
    c = get_case(case_id)
    if not c:
        return []
    return c.data.get("evidence", [])


def list_case_iocs(case_id: str, ioc_type: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns IOCs for a case with optional type and search filtering."""
    c = get_case(case_id)
    if not c:
        return []
    iocs = c.data.get("iocs", [])
    if ioc_type and ioc_type.lower() != "all":
        iocs = [i for i in iocs if i.get("type", "").lower() == ioc_type.lower()]
    if search:
        q = search.lower()
        iocs = [i for i in iocs if q in i.get("value", "").lower() or q in i.get("defanged", "").lower()]
    return iocs


def add_case_ioc(case_id: str, ioc_type: str, value: str, confidence: str = "high") -> Optional[Dict[str, Any]]:
    """Adds an IOC to a case."""
    c = get_case(case_id)
    if not c:
        return None
    return c.add_ioc(value=value, ioc_type=ioc_type, confidence=confidence)


def list_case_findings(case_id: str, severity: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns findings for a case."""
    c = get_case(case_id)
    if not c:
        return []
    findings = c.data.get("findings", [])
    if severity and severity.lower() != "all":
        findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]
    return findings


def add_case_finding(case_id: str, title: str, details: str, severity: str = "Medium") -> Optional[Dict[str, Any]]:
    """Adds a finding to a case."""
    c = get_case(case_id)
    if not c:
        return None
    return c.add_finding(title=title, description=details, severity=severity)


def list_case_timeline(case_id: str) -> List[Dict[str, Any]]:
    """Returns chronological timeline events."""
    c = get_case(case_id)
    if not c:
        return []
    return c.data.get("timeline", [])


def add_case_timeline_event(case_id: str, description: str, source: str = "analyst") -> Optional[Dict[str, Any]]:
    """Adds a timeline event."""
    c = get_case(case_id)
    if not c:
        return None
    return c.add_timeline_event(title_or_desc=description, source=source)
