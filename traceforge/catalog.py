import csv
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from traceforge.config import get_project_root
from traceforge.platform_detect import (
    detect_full_environment,
    detect_platform,
    is_termux,
    is_tool_installed,
    which_tool,
)

VALID_ECOSYSTEMS = ("native", "pipx", "go", "ruby_gem", "cargo", "manual", "api")

# Profiles defined by tool IDs or binary names
PROFILE_TOOL_MAPPINGS = {
    "minimal": [
        "exiftool", "binwalk", "xxd", "tshark", "tcpdump", "nmap",
        "subfinder", "dig", "whois", "sherlock", "holehe", "mat2",
        "pdfinfo", "pdftotext", "rg", "jq", "traceforge-native",
    ],
    "recommended": [
        "exiftool", "binwalk", "xxd", "zsteg", "steghide", "jhead", "pngcheck",
        "mediainfo", "ffmpeg", "ffprobe", "foremost", "yara", "tesseract",
        "sherlock", "maigret", "blackbird", "socialscan", "spiderfoot",
        "holehe", "h8mail", "theHarvester", "gitleaks", "trufflehog", "cewl", "john",
        "tshark", "tcpdump", "nmap", "masscan", "ngrep", "mitmproxy",
        "subfinder", "amass", "assetfinder", "dnsx", "httpx", "naabu", "nuclei", "gowitness",
        "dig", "whois", "dnsrecon", "dnstwist", "wafw00f",
        "pdfinfo", "pdftotext", "pdfimages", "qpdf", "rg", "fd", "jq", "olevba", "oleid", "docx2txt",
        "mat2", "proxychains4", "tor", "torsocks", "macchanger", "socat", "gpg", "age", "openssl",
        "traceforge-native",
    ],
}

class ToolRecord:
    """Represents an audited security tool definition with deterministic cross-platform capability evaluation."""

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
        self.name = name.strip()
        self.binary = binary.strip()
        self.category = category.strip()
        self.subcategory = subcategory.strip()
        self.ecosystem = ecosystem.strip().lower()
        self.mac_install = mac_install.strip()
        self.linux_install = linux_install.strip()
        self.description = description.strip()
        self.status = status.strip().lower()
        self.requires_root = requires_root
        self.requires_api = requires_api
        self.requires_hardware = requires_hardware
        self.notes = notes.strip()
        self.source_url = source_url.strip()

        # Termux specific fields
        self.termux_status = termux_status.strip().lower()
        self.termux_package = termux_package.strip()
        self.termux_install = termux_install.strip()
        self.termux_notes = termux_notes.strip()
        self.termux_root = termux_root
        self.termux_api = termux_api
        self.termux_hardware = termux_hardware

    @property
    def is_installed(self) -> bool:
        """Checks if the binary is present and executable on PATH or local bin."""
        return is_tool_installed(self.binary)

    @property
    def binary_path(self) -> Optional[str]:
        """Resolves the absolute path to the tool binary."""
        return which_tool(self.binary)

    def get_version(self) -> Optional[str]:
        """Attempts to retrieve the installed tool version safely."""
        path = self.binary_path
        if not path:
            return None

        flags = ["--version", "-version", "-V", "-v", "version"]
        if self.binary in ("nmap", "tcpdump", "openssl", "dig", "whois"):
            flags = ["-V", "-v", "--version", "version"]
        elif self.binary == "go":
            flags = ["version"]
        elif self.binary == "exiftool":
            flags = ["-ver", "--version"]

        for flag in flags:
            try:
                res = subprocess.run(
                    [path, flag],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                output = (res.stdout.strip() or res.stderr.strip()).splitlines()
                if output:
                    first_line = output[0].strip()
                    if len(first_line) > 120:
                        first_line = first_line[:117] + "..."
                    if any(c.isdigit() for c in first_line) or "version" in first_line.lower():
                        return first_line
            except Exception:
                continue

        return "installed"

    def get_supported_platforms_list(self) -> List[str]:
        """Returns the list of platform ecosystems where this tool is verifiable and available."""
        platforms = []
        # Check macOS
        if self.ecosystem in ("pipx", "go", "cargo", "ruby_gem") and self.linux_install not in ("-", "", "manual", "n/a"):
            platforms.append("macOS")
        elif self.ecosystem == "native" and self.mac_install not in ("-", "", "n/a", "manual", "none", "unsupported", "linux-only"):
            platforms.append("macOS (Homebrew)")
        elif self.ecosystem == "manual":
            platforms.append("macOS (Manual)")

        # Check Linux
        if self.ecosystem in ("pipx", "go", "cargo", "ruby_gem") and self.linux_install not in ("-", "", "manual", "n/a"):
            platforms.append("Linux (APT/Distro)")
        elif self.ecosystem == "native" and self.linux_install not in ("-", "", "n/a", "manual", "none", "unsupported"):
            platforms.append("Linux (Debian/Ubuntu/Kali)")
        elif self.ecosystem == "manual":
            platforms.append("Linux (Manual)")

        # Check Termux
        if self.termux_status in ("supported", "limited") and self.termux_package not in ("-", "none", "n/a"):
            platforms.append("Termux / Android")
        elif self.ecosystem in ("pipx", "go", "cargo") and self.linux_install not in ("-", "", "manual", "n/a"):
            platforms.append("Termux / Android (pip/Go)")
        elif self.termux_status == "manual":
            platforms.append("Termux (Manual)")

        return platforms

    def get_platform_capability(self, env: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Determines genuine platform capability for the specified host environment.
        Returns:
          - availability: 'SUPPORTED' | 'SUPPORTED_WITH_LIMITATIONS' | 'MANUAL_INSTALL' | 'NOT_AVAILABLE'
          - is_available: bool
          - is_installable: bool (True only if automated package installer recipe is executable)
          - install_command: Optional[str]
          - install_method: str ('Homebrew', 'APT', 'pkg', 'pipx', 'go', 'cargo', 'gem', 'Manual', 'Not applicable')
          - reason: str (Human-readable rationale)
          - status_label: 'installed' | 'missing' | 'unavailable' | 'manual' | 'api_required'
        """
        if env is None:
            env = detect_full_environment()

        is_inst = self.is_installed
        os_name = env.get("os_name", "").lower()
        distro = env.get("distro", "").lower()
        is_tmx = env.get("is_termux", False)
        arch = env.get("arch", "x86_64")

        # ---------------------------------------------------------------------
        # 1. Termux / Android Environment
        # ---------------------------------------------------------------------
        if is_tmx or "termux" in os_name or distro == "termux":
            if self.termux_status == "unsupported" or (self.termux_package in ("-", "n/a", "none") and self.termux_install in ("-", "n/a", "none")):
                # Check if pipx / go / cargo package works on Termux
                if self.ecosystem in ("pipx", "go", "cargo") and self.linux_install not in ("-", "manual", "n/a", ""):
                    cmd = f"pip install {self.linux_install}" if self.ecosystem == "pipx" else f"{self.ecosystem} install {self.linux_install}"
                    return {
                        "availability": "SUPPORTED",
                        "is_available": True,
                        "is_installable": True,
                        "install_command": cmd,
                        "install_method": f"Termux {self.ecosystem.upper()}",
                        "package_name": self.linux_install,
                        "reason": f"Available in Termux userland via {self.ecosystem}",
                        "status_label": "installed" if is_inst else "missing",
                    }
                else:
                    return {
                        "availability": "NOT_AVAILABLE",
                        "is_available": False,
                        "is_installable": False,
                        "install_command": None,
                        "install_method": "Not applicable",
                        "package_name": "-",
                        "reason": "Not available on Termux / Android",
                        "status_label": "installed" if is_inst else "unavailable",
                    }

            if self.termux_status == "manual" or self.termux_package == "manual":
                return {
                    "availability": "MANUAL_INSTALL",
                    "is_available": True,
                    "is_installable": False,
                    "install_command": None,
                    "install_method": "Manual",
                    "package_name": "manual",
                    "reason": "Manual build or clone required on Termux",
                    "status_label": "installed" if is_inst else "manual",
                }

            # Install command for Termux
            cmd = None
            if self.termux_install and self.termux_install not in ("-", "none", "manual"):
                cmd = self.termux_install
            elif self.termux_package and self.termux_package not in ("-", "none", "manual"):
                cmd = f"pkg install -y {self.termux_package}"

            avail = "SUPPORTED_WITH_LIMITATIONS" if (self.termux_status == "limited" or self.termux_root or self.termux_hardware) else "SUPPORTED"
            reason = f"Available on Termux with limitations: {self.termux_notes}" if avail == "SUPPORTED_WITH_LIMITATIONS" else "Available via Termux pkg"

            return {
                "availability": avail,
                "is_available": True,
                "is_installable": cmd is not None,
                "install_command": cmd,
                "install_method": "pkg",
                "package_name": self.termux_package,
                "reason": reason,
                "status_label": "installed" if is_inst else "missing",
            }

        # ---------------------------------------------------------------------
        # 2. macOS Environment (Darwin)
        # ---------------------------------------------------------------------
        if "darwin" in env.get("system", "").lower() or "macos" in os_name:
            if self.ecosystem == "manual":
                return {
                    "availability": "MANUAL_INSTALL",
                    "is_available": True,
                    "is_installable": False,
                    "install_command": None,
                    "install_method": "Manual",
                    "package_name": "manual",
                    "reason": "Manual installation required on macOS",
                    "status_label": "installed" if is_inst else "manual",
                }

            if self.ecosystem in ("pipx", "go", "cargo", "ruby_gem"):
                if self.linux_install in ("-", "manual", "n/a", "", "none"):
                    return {
                        "availability": "NOT_AVAILABLE",
                        "is_available": False,
                        "is_installable": False,
                        "install_command": None,
                        "install_method": "Not applicable",
                        "package_name": "-",
                        "reason": "Not available on macOS",
                        "status_label": "installed" if is_inst else "unavailable",
                    }
                else:
                    if self.ecosystem == "pipx":
                        cmd = f"pipx install {self.linux_install}"
                    elif self.ecosystem == "go":
                        cmd = f"go install {self.linux_install}@latest"
                    elif self.ecosystem == "cargo":
                        cmd = f"cargo install {self.linux_install}"
                    else:
                        cmd = f"gem install --user-install {self.linux_install}"

                    return {
                        "availability": "SUPPORTED",
                        "is_available": True,
                        "is_installable": True,
                        "install_command": cmd,
                        "install_method": self.ecosystem.upper(),
                        "package_name": self.linux_install,
                        "reason": f"Available via {self.ecosystem.upper()} on macOS",
                        "status_label": "installed" if is_inst else "missing",
                    }

            if self.ecosystem == "native":
                if not self.mac_install or self.mac_install in ("-", "n/a", "none", "unsupported", "linux-only", "linux_only"):
                    return {
                        "availability": "NOT_AVAILABLE",
                        "is_available": False,
                        "is_installable": False,
                        "install_command": None,
                        "install_method": "Not applicable",
                        "package_name": "-",
                        "reason": "Not available on macOS - Linux only",
                        "status_label": "installed" if is_inst else "unavailable",
                    }
                elif self.mac_install == "manual":
                    return {
                        "availability": "MANUAL_INSTALL",
                        "is_available": True,
                        "is_installable": False,
                        "install_command": None,
                        "install_method": "Manual",
                        "package_name": "manual",
                        "reason": "Manual installation required on macOS",
                        "status_label": "installed" if is_inst else "manual",
                    }
                else:
                    return {
                        "availability": "SUPPORTED",
                        "is_available": True,
                        "is_installable": True,
                        "install_command": f"brew install {self.mac_install}",
                        "install_method": "Homebrew",
                        "package_name": self.mac_install,
                        "reason": "Available via Homebrew on macOS",
                        "status_label": "installed" if is_inst else "missing",
                    }

        # ---------------------------------------------------------------------
        # 3. Linux Environment (Debian, Ubuntu, Kali, Arch, Fedora)
        # ---------------------------------------------------------------------
        if "linux" in env.get("system", "").lower() or "linux" in os_name:
            if self.ecosystem == "manual":
                return {
                    "availability": "MANUAL_INSTALL",
                    "is_available": True,
                    "is_installable": False,
                    "install_command": None,
                    "install_method": "Manual",
                    "package_name": "manual",
                    "reason": "Manual installation required on Linux",
                    "status_label": "installed" if is_inst else "manual",
                }

            if self.ecosystem in ("pipx", "go", "cargo", "ruby_gem"):
                if self.linux_install in ("-", "manual", "n/a", "", "none"):
                    return {
                        "availability": "NOT_AVAILABLE",
                        "is_available": False,
                        "is_installable": False,
                        "install_command": None,
                        "install_method": "Not applicable",
                        "package_name": "-",
                        "reason": "Not available on Linux",
                        "status_label": "installed" if is_inst else "unavailable",
                    }
                else:
                    if self.ecosystem == "pipx":
                        cmd = f"pipx install {self.linux_install}"
                    elif self.ecosystem == "go":
                        cmd = f"go install {self.linux_install}@latest"
                    elif self.ecosystem == "cargo":
                        cmd = f"cargo install {self.linux_install}"
                    else:
                        cmd = f"gem install --user-install {self.linux_install}"

                    return {
                        "availability": "SUPPORTED",
                        "is_available": True,
                        "is_installable": True,
                        "install_command": cmd,
                        "install_method": self.ecosystem.upper(),
                        "package_name": self.linux_install,
                        "reason": f"Available via {self.ecosystem.upper()} on Linux",
                        "status_label": "installed" if is_inst else "missing",
                    }

            if self.ecosystem == "native":
                if not self.linux_install or self.linux_install in ("-", "n/a", "none", "unsupported"):
                    return {
                        "availability": "NOT_AVAILABLE",
                        "is_available": False,
                        "is_installable": False,
                        "install_command": None,
                        "install_method": "Not applicable",
                        "package_name": "-",
                        "reason": "Not available on Linux",
                        "status_label": "installed" if is_inst else "unavailable",
                    }
                elif self.linux_install == "manual":
                    return {
                        "availability": "MANUAL_INSTALL",
                        "is_available": True,
                        "is_installable": False,
                        "install_command": None,
                        "install_method": "Manual",
                        "package_name": "manual",
                        "reason": "Manual installation required on Linux",
                        "status_label": "installed" if is_inst else "manual",
                    }
                else:
                    # Check distro capability
                    distro_fam = env.get("distro_family", "").lower()
                    if any(x in distro for x in ("debian", "ubuntu", "kali", "mint", "pop")) or distro_fam == "debian" or distro in ("linux", ""):
                        cmd = f"sudo apt-get install -y {self.linux_install}"
                        method = "APT"
                        reason = f"Available via APT on {distro.capitalize() or 'Debian/Ubuntu/Kali'}"
                    elif "arch" in distro or distro_fam == "arch" or "manjaro" in distro:
                        cmd = f"sudo pacman -S --noconfirm {self.linux_install}"
                        method = "Pacman"
                        reason = "Available via Pacman on Arch Linux"
                    elif any(x in distro for x in ("fedora", "rhel", "centos", "rocky", "alma")) or distro_fam == "fedora":
                        cmd = f"sudo dnf install -y {self.linux_install}"
                        method = "DNF"
                        reason = f"Available via DNF on {distro.capitalize()}"
                    else:
                        cmd = None
                        method = f"Manual ({distro})"
                        reason = f"Distribution '{distro}' detected; manual package install needed"

                    return {
                        "availability": "SUPPORTED" if cmd else "SUPPORTED_WITH_LIMITATIONS",
                        "is_available": True,
                        "is_installable": cmd is not None,
                        "install_command": cmd,
                        "install_method": method,
                        "package_name": self.linux_install,
                        "reason": reason,
                        "status_label": "installed" if is_inst else "missing",
                    }

        # ---------------------------------------------------------------------
        # 4. Unknown / Unsupported Environment
        # ---------------------------------------------------------------------
        return {
            "availability": "NOT_AVAILABLE",
            "is_available": False,
            "is_installable": False,
            "install_command": None,
            "install_method": "Not applicable",
            "package_name": "-",
            "reason": f"Platform '{os_name}' is not supported",
            "status_label": "installed" if is_inst else "unavailable",
        }

    def is_supported_on_platform(self, env: Optional[Dict[str, Any]] = None) -> bool:
        """Determines if the tool is available (supported or manual) on the target host."""
        cap = self.get_platform_capability(env)
        return cap["is_available"]

    def get_install_command(self, env: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Returns the automated installation command for the target host environment."""
        cap = self.get_platform_capability(env)
        return cap.get("install_command")

    @property
    def is_installable(self) -> bool:
        """Checks if TraceForge provides an automated installer for this tool on host."""
        return self.get_install_command() is not None

    @property
    def status_label(self) -> str:
        """Returns the canonical operational status string."""
        cap = self.get_platform_capability()
        return cap["status_label"]

    def to_dict(self, env: Optional[Dict[str, Any]] = None, include_version: bool = False) -> Dict[str, Any]:
        """Serializes tool metadata with full platform capability context."""
        if env is None:
            env = detect_full_environment()

        inst = self.is_installed
        ver = self.get_version() if (inst and include_version) else ("installed" if inst else None)
        cap = self.get_platform_capability(env)


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
            "supported_platforms": self.get_supported_platforms_list(),
            # Platform capability evaluation
            "is_installed": inst,
            "binary_path": self.binary_path,
            "version": ver,
            "is_supported": cap["is_available"],
            "availability": cap["availability"],
            "install_command": cap["install_command"],
            "install_method": cap["install_method"],
            "package_name": cap["package_name"],
            "platform_reason": cap["reason"],
            "is_installable": cap["is_installable"],
            "status_label": cap["status_label"],
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
    """Canonical loader, indexer, search, audit, and platform capability engine for TraceForge tools."""

    def __init__(self, tsv_path: Optional[Path] = None):
        if tsv_path is None:
            tsv_path = get_bundled_catalog_path()
        self.tsv_path = Path(tsv_path)
        self.tools: List[ToolRecord] = []
        self._by_id: Dict[int, ToolRecord] = {}
        self._by_bin: Dict[str, ToolRecord] = {}
        self._by_name: Dict[str, ToolRecord] = {}
        self.load()

    def __len__(self) -> int:
        return len(self.tools)

    def __iter__(self):
        return iter(self.tools)

    def load(self) -> None:
        if not self.tsv_path.exists():
            return
        self.tools.clear()
        self._by_id.clear()
        self._by_bin.clear()
        self._by_name.clear()

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
                    self._by_name[record.name.lower()] = record
                except Exception:
                    continue

    def get_by_id(self, tool_id: int) -> Optional[ToolRecord]:
        return self._by_id.get(tool_id)

    def get_by_binary(self, binary_name: str) -> Optional[ToolRecord]:
        return self._by_bin.get(binary_name.lower().strip())

    def get_by_name(self, name: str) -> Optional[ToolRecord]:
        return self._by_name.get(name.lower().strip())

    def find_tool(self, query: str) -> Optional[ToolRecord]:
        """Resolves tool by ID, exact binary name, or exact name."""
        q = query.strip()
        if q.isdigit():
            return self.get_by_id(int(q))
        return self.get_by_binary(q) or self.get_by_name(q)

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
                or q in t.ecosystem.lower()
                or q in t.termux_package.lower()
                or q in t.termux_notes.lower()
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

    def get_ecosystems(self) -> List[str]:
        seen = set()
        ecos = []
        for t in self.tools:
            if t.ecosystem and t.ecosystem not in seen:
                seen.add(t.ecosystem)
                ecos.append(t.ecosystem)
        return ecos

    def filter_tools(
        self,
        category: Optional[str] = None,
        subcategory: Optional[str] = None,
        ecosystem: Optional[str] = None,
        installed_only: bool = False,
        missing_only: bool = False,
        available_only: bool = False,
        unavailable_only: bool = False,
        manual_only: bool = False,
        env: Optional[Dict[str, Any]] = None,
    ) -> List[ToolRecord]:
        if env is None:
            env = detect_full_environment()

        results = self.tools.copy()

        if category:
            results = [t for t in results if t.category.lower() == category.lower().strip()]
        if subcategory:
            results = [t for t in results if t.subcategory.lower() == subcategory.lower().strip()]
        if ecosystem:
            results = [t for t in results if t.ecosystem.lower() == ecosystem.lower().strip()]

        if installed_only:
            results = [t for t in results if t.is_installed]
        elif missing_only:
            results = [t for t in results if not t.is_installed and t.is_supported_on_platform(env)]

        if available_only:
            results = [t for t in results if t.is_supported_on_platform(env)]
        elif unavailable_only:
            results = [t for t in results if not t.is_supported_on_platform(env)]

        if manual_only:
            results = [t for t in results if t.get_platform_capability(env)["availability"] == "MANUAL_INSTALL"]

        return results

    def get_tools_for_profile(self, profile: str) -> List[ToolRecord]:
        """Resolves concrete tool records for a designated installation profile."""
        prof_key = profile.lower().strip()
        if prof_key == "full":
            return self.tools.copy()

        targets = PROFILE_TOOL_MAPPINGS.get(prof_key, PROFILE_TOOL_MAPPINGS["recommended"])
        matched: List[ToolRecord] = []
        for t in targets:
            rec = self.find_tool(t)
            if rec and rec not in matched:
                matched.append(rec)
        return matched

    def get_install_plan_for_profile(self, profile: str, env: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calculates a deterministic installation plan for a profile on the target host.
        Separates tools to install, already installed, skipped (unavailable on platform), and skipped (manual).
        """
        if env is None:
            env = detect_full_environment()

        raw_targets = self.get_tools_for_profile(profile)
        to_install: List[ToolRecord] = []
        already_installed: List[ToolRecord] = []
        skipped_unavailable: List[Tuple[ToolRecord, str]] = []
        skipped_manual: List[Tuple[ToolRecord, str]] = []

        for t in raw_targets:
            cap = t.get_platform_capability(env)
            if t.is_installed:
                already_installed.append(t)
            elif cap["availability"] == "NOT_AVAILABLE":
                skipped_unavailable.append((t, cap["reason"]))
            elif cap["availability"] == "MANUAL_INSTALL" or not cap["is_installable"]:
                skipped_manual.append((t, cap["reason"]))
            else:
                to_install.append(t)

        return {
            "profile": profile.lower(),
            "platform": env.get("display_name", env.get("os_name")),
            "package_manager": env.get("pkg_manager"),
            "total_profile_tools": len(raw_targets),
            "installable_count": len(to_install),
            "already_installed_count": len(already_installed),
            "unavailable_count": len(skipped_unavailable),
            "manual_count": len(skipped_manual),
            "installable": to_install,
            "to_install": to_install,
            "already_installed": already_installed,
            "skipped_unavailable": skipped_unavailable,
            "skipped_manual": skipped_manual,
        }

    def audit(self) -> Dict[str, Any]:
        """Performs a comprehensive integrity and schema audit across all catalog entries."""
        seen_ids = set()
        seen_bins = set()
        duplicate_ids = []
        duplicate_bins = []
        invalid_ecosystems = []
        missing_recipes = []
        manual_tools = []
        root_tools = []
        api_tools = []
        hardware_tools = []

        for t in self.tools:
            if t.id in seen_ids:
                duplicate_ids.append(t.id)
            seen_ids.add(t.id)

            if t.binary.lower() in seen_bins:
                duplicate_bins.append(t.binary)
            seen_bins.add(t.binary.lower())

            if t.ecosystem not in VALID_ECOSYSTEMS:
                invalid_ecosystems.append((t.id, t.binary, t.ecosystem))

            if t.ecosystem != "manual" and not t.mac_install and not t.linux_install:
                missing_recipes.append((t.id, t.binary))

            if t.ecosystem == "manual":
                manual_tools.append((t.id, t.binary))

            if t.requires_root:
                root_tools.append((t.id, t.binary))

            if t.requires_api:
                api_tools.append((t.id, t.binary))

            if t.requires_hardware:
                hardware_tools.append((t.id, t.binary))

        is_clean = len(duplicate_ids) == 0 and len(duplicate_bins) == 0 and len(invalid_ecosystems) == 0

        return {
            "total_tools": len(self.tools),
            "is_clean": is_clean,
            "duplicate_ids": duplicate_ids,
            "duplicate_binaries": duplicate_bins,
            "invalid_ecosystems": invalid_ecosystems,
            "missing_recipes": missing_recipes,
            "manual_tools": manual_tools,
            "root_required_tools": root_tools,
            "api_required_tools": api_tools,
            "hardware_tools": hardware_tools,
            "hardware_required_tools": hardware_tools,
        }

    def audit_platform(self, env: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Audits all 152 tools against a target platform environment.
        Categorizes every tool into supported, manual, limited, or not available.
        """
        if env is None:
            env = detect_full_environment()

        total = len(self.tools)
        available = []
        installed = []
        missing = []
        unavailable = []
        manual = []
        limited = []

        for t in self.tools:
            cap = t.get_platform_capability(env)
            avail = cap["availability"]

            if t.is_installed:
                installed.append(t)
            elif avail in ("SUPPORTED", "SUPPORTED_WITH_LIMITATIONS"):
                missing.append(t)

            if cap["is_available"]:
                available.append(t)

            if avail == "NOT_AVAILABLE":
                unavailable.append((t, cap["reason"]))
            elif avail == "MANUAL_INSTALL":
                manual.append((t, cap["reason"]))
            elif avail == "SUPPORTED_WITH_LIMITATIONS":
                limited.append((t, cap["reason"]))

        return {
            "platform_name": env.get("display_name", env.get("os_name", "Unknown Platform")),
            "platform": {
                "os": env.get("os_name"),
                "distro": env.get("distro"),
                "arch": env.get("arch"),
                "hardware": env.get("hardware"),
                "display_name": env.get("display_name"),
                "pkg_manager": env.get("pkg_manager"),
                "has_root": env.get("has_root", False),
                "is_termux": env.get("is_termux", False),
            },
            "total_catalog": total,
            "total_tools": total,
            "available_count": len(available),
            "installed_count": len(installed),
            "missing_count": len(missing),
            "unavailable_count": len(unavailable),
            "manual_count": len(manual),
            "limited_count": len(limited),
            "unavailable_tools": [{"id": t.id, "name": t.name, "binary": t.binary, "reason": reason} for t, reason in unavailable],
            "manual_tools": [{"id": t.id, "name": t.name, "binary": t.binary, "reason": reason} for t, reason in manual],
            "limited_tools": [{"id": t.id, "name": t.name, "binary": t.binary, "reason": reason} for t, reason in limited],
        }

    def get_coverage_report(self, env: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Calculates dynamic tool coverage statistics for the host environment."""
        if env is None:
            env = detect_full_environment()

        audit_pf = self.audit_platform(env)
        total = len(self.tools)

        categories_breakdown: Dict[str, Dict[str, int]] = {}
        ecosystems_breakdown: Dict[str, int] = {}

        for t in self.tools:
            is_inst = t.is_installed
            is_supp = t.is_supported_on_platform(env)

            # Category tracking
            cat_entry = categories_breakdown.setdefault(t.category, {"total": 0, "available": 0, "installed": 0})
            cat_entry["total"] += 1
            if is_supp:
                cat_entry["available"] += 1
            if is_inst:
                cat_entry["installed"] += 1

            # Ecosystem tracking
            ecosystems_breakdown[t.ecosystem] = ecosystems_breakdown.get(t.ecosystem, 0) + 1

        return {
            "total_catalog": total,
            "cli_accessible": total,
            "web_exposed": total,
            "platform_supported": audit_pf["available_count"],
            "installed_locally": audit_pf["installed_count"],
            "missing_locally": audit_pf["missing_count"],
            "unavailable_on_platform": audit_pf["unavailable_count"],
            "manual_only": audit_pf["manual_count"],
            "platform": audit_pf["platform"],
            "categories": categories_breakdown,
            "ecosystems": ecosystems_breakdown,
        }

    def integration_audit(self, env: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Per-tool integration depth audit.

        Classifies every catalog tool into one of four states:
          FULLY_INTEGRATED  — tool is called directly in a module, workflow, or tools.py
          RUNNABLE          — tool works via the generic ToolRunner path; no dedicated module call
          MANUAL_ONLY       — requires manual setup; cannot be auto-installed or run without user config
          UNSUPPORTED       — not available on the host platform

        All tools in every state are CLI/web-discoverable.
        RUNNABLE tools can still be executed via `traceforge tools run <tool>`.
        """
        if env is None:
            env = detect_full_environment()

        # Binaries that are explicitly invoked in module handlers, tools.py, or batch workflows.
        # Updated when module coverage expands — ground truth of what has a dedicated code path.
        module_integrated = {
            # image module
            "exiftool", "binwalk", "strings", "zsteg", "steghide", "ffmpeg", "ffprobe",
            "mediainfo", "pngcheck", "jhead", "yara", "tesseract", "foremost", "mat2",
            # document module
            "pdftotext", "pdfinfo", "pdfimages", "olevba", "oleid", "docx2txt",
            "antiword", "mutool", "rg",
            # network module
            "tshark", "tcpdump", "capinfos", "zeek", "nmap", "dig", "whois",
            # identity module
            "sherlock", "maigret", "blackbird", "socialscan",
            # email module
            "holehe", "h8mail", "emailrep", "theHarvester", "checkdmarc",
            # domain module
            "subfinder", "assetfinder", "dnsrecon", "dnstwist", "wafw00f", "httpx",
            "dnsx", "naabu", "gowitness",
            # opsec module
            "tor", "torsocks", "proxychains4", "macchanger", "gpg", "age", "openssl", "socat",
            # batch workflows + tools.py core
            "traceforge-native", "tracehash", "tracepcap",
        }

        fully_integrated = []
        runnable = []
        manual_only = []
        unsupported = []

        for t in self.tools:
            cap = t.get_platform_capability(env)

            if t.ecosystem == "manual" or t.status == "manual":
                manual_only.append(t)
            elif cap["availability"] == "NOT_AVAILABLE":
                unsupported.append(t)
            elif t.binary in module_integrated:
                fully_integrated.append(t)
            else:
                runnable.append(t)

        def _serialize(tool_list: List[ToolRecord]) -> List[Dict[str, str]]:
            return [{"id": t.id, "name": t.name, "binary": t.binary, "category": t.category} for t in tool_list]

        return {
            "total_catalog": len(self.tools),
            "fully_integrated": len(fully_integrated),
            "runnable": len(runnable),
            "manual_only": len(manual_only),
            "unsupported_on_platform": len(unsupported),
            "fully_integrated_tools": _serialize(fully_integrated),
            "runnable_tools": _serialize(runnable),
            "manual_tools": _serialize(manual_only),
            "unsupported_tools": _serialize(unsupported),
            "note": (
                "RUNNABLE tools work via 'traceforge tools run <tool>' and appear in CLI/web catalog. "
                "They have no dedicated module handler by design — the generic runner is sufficient."
            ),
        }

