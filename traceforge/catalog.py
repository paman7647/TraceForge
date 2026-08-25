import csv
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge.config import get_project_root
from traceforge.platform_detect import is_tool_installed, which_tool

class ToolRecord:
    def __init__(
        self,
        tool_id: int,
        name: str,
        binary: str,
        category: str,
        subcategory: str,
        ecosystem: str,
        mac_install: str,
        linux_install: str,
        description: str,
        status: str,
        requires_root: bool,
        requires_api: bool,
        requires_hardware: bool,
        notes: str,
        source_url: str,
        termux_status: str = "supported",
        termux_package: str = "-",
        termux_install: str = "-",
        termux_notes: str = "",
        termux_root: bool = False,
        termux_api: bool = False,
        termux_hardware: bool = False,
    ):
        self.id = tool_id
        self.name = name
        self.binary = binary
        self.category = category
        self.subcategory = subcategory
        self.ecosystem = ecosystem
        self.mac_install = mac_install
        self.linux_install = linux_install
        self.description = description
        self.status = status
        self.requires_root = requires_root
        self.requires_api = requires_api
        self.requires_hardware = requires_hardware
        self.notes = notes
        self.source_url = source_url

        # Termux specific fields
        self.termux_status = termux_status
        self.termux_package = termux_package
        self.termux_install = termux_install
        self.termux_notes = termux_notes
        self.termux_root = termux_root
        self.termux_api = termux_api
        self.termux_hardware = termux_hardware

    @property
    def is_installed(self) -> bool:
        return is_tool_installed(self.binary)

    @property
    def binary_path(self) -> Optional[str]:
        return which_tool(self.binary)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "binary": self.binary,
            "category": self.category,
            "subcategory": self.subcategory,
            "ecosystem": self.ecosystem,
            "mac_install": self.mac_install,
            "linux_install": self.linux_install,
            "description": self.description,
            "status": self.status,
            "requires_root": self.requires_root,
            "requires_api": self.requires_api,
            "requires_hardware": self.requires_hardware,
            "notes": self.notes,
            "source_url": self.source_url,
            "termux_status": self.termux_status,
            "termux_package": self.termux_package,
            "termux_install": self.termux_install,
            "termux_notes": self.termux_notes,
            "termux_root": self.termux_root,
            "termux_api": self.termux_api,
            "termux_hardware": self.termux_hardware,
            "is_installed": self.is_installed,
            "binary_path": self.binary_path,
        }

def get_bundled_catalog_path() -> Path:
    """Resolves the canonical tools.tsv path from package data or repository root."""
    pkg_data = Path(__file__).resolve().parent / "data" / "tools.tsv"
    if pkg_data.exists():
        return pkg_data
    repo_data = get_project_root() / "catalog" / "tools.tsv"
    if repo_data.exists():
        return repo_data
    return pkg_data

Tool = ToolRecord

class Catalog:
    """Parses and indexes the canonical tool registry in catalog/tools.tsv."""

    def __init__(self, tsv_path: Optional[Path] = None):
        if tsv_path is None:
            tsv_path = get_bundled_catalog_path()
        self.tsv_path = Path(tsv_path)
        self.tools: List[ToolRecord] = []
        self._by_id: Dict[int, ToolRecord] = {}
        self._by_bin: Dict[str, ToolRecord] = {}
        self.load()

    def __len__(self) -> int:
        return len(self.tools)

    def load(self) -> None:
        if not self.tsv_path.exists():
            return
        self.tools.clear()
        self._by_id.clear()
        self._by_bin.clear()

        with open(self.tsv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for row in reader:
                try:
                    tid = int(row.get("id", "0"))
                    record = ToolRecord(
                        tool_id=tid,
                        name=row.get("name", ""),
                        binary=row.get("binary", ""),
                        category=row.get("category", ""),
                        subcategory=row.get("subcategory", ""),
                        ecosystem=row.get("ecosystem", "native"),
                        mac_install=row.get("mac_install", ""),
                        linux_install=row.get("linux_install", ""),
                        description=row.get("description", ""),
                        status=row.get("status", "verified"),
                        requires_root=row.get("requires_root", "no").lower() in ("yes", "true", "1"),
                        requires_api=row.get("requires_api", "no").lower() in ("yes", "true", "1"),
                        requires_hardware=row.get("requires_hardware", "no").lower() in ("yes", "true", "1"),
                        notes=row.get("notes", ""),
                        source_url=row.get("source_url", ""),
                        termux_status=row.get("termux_status", "supported"),
                        termux_package=row.get("termux_package", "-"),
                        termux_install=row.get("termux_install", "-"),
                        termux_notes=row.get("termux_notes", ""),
                        termux_root=row.get("termux_root", "no").lower() in ("yes", "true", "1"),
                        termux_api=row.get("termux_api", "no").lower() in ("yes", "true", "1"),
                        termux_hardware=row.get("termux_hardware", "no").lower() in ("yes", "true", "1"),
                    )
                    self.tools.append(record)
                    self._by_id[tid] = record
                    self._by_bin[record.binary.lower()] = record
                except Exception:
                    continue

    def get_by_id(self, tool_id: int) -> Optional[ToolRecord]:
        return self._by_id.get(tool_id)

    def get_by_binary(self, binary_name: str) -> Optional[ToolRecord]:
        return self._by_bin.get(binary_name.lower())

    def search(self, query: str) -> List[ToolRecord]:
        q = query.lower().strip()
        if not q:
            return self.tools.copy()
        results = []
        for t in self.tools:
            if (
                q in t.name.lower()
                or q in t.binary.lower()
                or q in t.category.lower()
                or q in t.subcategory.lower()
                or q in t.description.lower()
                or q in t.notes.lower()
                or q in t.termux_notes.lower()
                or q in t.termux_package.lower()
            ):
                results.append(t)
        return results

    def get_categories(self) -> List[str]:
        seen = set()
        cats = []
        for t in self.tools:
            if t.category and t.category not in seen:
                seen.add(t.category)
                cats.append(t.category)
        return cats

    def filter_by_category(self, category: str) -> List[ToolRecord]:
        return [t for t in self.tools if t.category == category]

    def filter_by_termux_status(self, termux_status: str) -> List[ToolRecord]:
        return [t for t in self.tools if t.termux_status == termux_status]
