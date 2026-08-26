import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from traceforge.config import get_project_root

def is_termux() -> bool:
    """Multi-indicator detector for Termux Android runtime environment."""
    if "TERMUX_VERSION" in os.environ:
        return True
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix and os.path.isdir(prefix):
        return True
    if os.path.isdir("/data/data/com.termux/files/usr"):
        return True
    return False

def get_termux_info() -> Dict[str, Any]:
    """Inspects Termux specific prefix, shared storage mount, and optional API availability."""
    if not is_termux():
        return {
            "is_termux": False,
            "prefix": "",
            "version": "",
            "storage_mounted": False,
            "api_available": False,
            "boot_available": False,
            "widget_available": False,
        }

    prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    storage_dir = Path.home() / "storage"
    boot_dir = Path.home() / ".termux" / "boot"
    shortcuts_dir = Path.home() / ".shortcuts"

    api_installed = (
        shutil.which("termux-battery-status") is not None
        or shutil.which("termux-wifi-connectioninfo") is not None
        or shutil.which("termux-location") is not None
    )

    return {
        "is_termux": True,
        "prefix": prefix,
        "version": os.environ.get("TERMUX_VERSION", "termux-env"),
        "storage_mounted": storage_dir.is_dir() and os.access(str(storage_dir), os.R_OK),
        "api_available": api_installed,
        "boot_available": boot_dir.is_dir(),
        "widget_available": shortcuts_dir.is_dir(),
    }

def detect_platform() -> Dict[str, Any]:
    """Detects exact operating system, distribution, architecture, and display identity."""
    arch = platform.machine().lower()
    if arch in ("x86_64", "amd64"):
        norm_arch = "x86_64"
    elif arch in ("arm64", "aarch64"):
        norm_arch = "arm64"
    elif "arm" in arch:
        norm_arch = "arm"
    else:
        norm_arch = arch

    if is_termux():
        return {
            "system": "android",
            "os_name": "Termux",
            "distro": "termux",
            "version": os.environ.get("TERMUX_VERSION", "termux-env"),
            "arch": norm_arch,
            "raw_arch": arch,
            "hardware": "Android ARM" if "arm" in norm_arch else "Android",
            "display_name": f"Termux / Android ({norm_arch})",
            "python_version": platform.python_version(),
        }

    system = platform.system().lower()
    os_name = "Unknown"
    distro = "unknown"
    version = "unknown"
    hardware = "Generic"
    display_name = f"Unknown OS ({norm_arch})"

    if system == "darwin":
        os_name = "macOS"
        distro = "macos"
        version = platform.mac_ver()[0]
        hardware = "Apple Silicon" if norm_arch == "arm64" else "Intel"
        display_name = f"macOS {hardware} ({norm_arch})"
    elif system == "linux":
        os_name = "Linux"
        distro_name = "Linux"
        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("ID="):
                            distro = line.strip().split("=")[1].strip('"').lower()
                        elif line.startswith("NAME="):
                            distro_name = line.strip().split("=")[1].strip('"')
                        elif line.startswith("VERSION_ID="):
                            version = line.strip().split("=")[1].strip('"')
            except Exception:
                pass
        elif os.path.exists("/etc/debian_version"):
            distro = "debian"
            distro_name = "Debian"
            try:
                with open("/etc/debian_version", "r", encoding="utf-8") as f:
                    version = f.read().strip()
            except Exception:
                pass

        if distro == "kali":
            display_name = f"Kali Linux ({norm_arch})"
        elif distro == "ubuntu":
            display_name = f"Ubuntu {version} ({norm_arch})"
        elif distro == "debian":
            display_name = f"Debian {version} ({norm_arch})"
        elif distro == "arch":
            display_name = f"Arch Linux ({norm_arch})"
        elif distro == "fedora":
            display_name = f"Fedora {version} ({norm_arch})"
        else:
            display_name = f"{distro_name} ({norm_arch})"

    elif system == "windows":
        os_name = "Windows"
        distro = "windows"
        version = platform.version()
        display_name = f"Windows {version} ({norm_arch})"

    return {
        "system": system,
        "os_name": os_name,
        "distro": distro,
        "version": version,
        "arch": norm_arch,
        "raw_arch": arch,
        "hardware": hardware,
        "display_name": display_name,
        "python_version": platform.python_version(),
    }

def which_tool(tool_name: str) -> Optional[str]:
    """Finds binary path across PATH, local project bin, Termux prefix, and user locations."""
    # 0. Termux prefix bin
    if is_termux():
        prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
        termux_bin = Path(prefix) / "bin" / tool_name
        if termux_bin.exists() and os.access(termux_bin, os.X_OK):
            return str(termux_bin)

    # 1. Project bin directory
    project_bin = get_project_root() / "bin" / tool_name
    if project_bin.exists() and os.access(project_bin, os.X_OK):
        return str(project_bin)

    # 2. System PATH
    found = shutil.which(tool_name)
    if found:
        return found

    # 3. User local bin
    user_bin = Path.home() / ".local" / "bin" / tool_name
    if user_bin.exists() and os.access(user_bin, os.X_OK):
        return str(user_bin)

    # 4. Go bin
    go_bin = Path.home() / "go" / "bin" / tool_name
    if go_bin.exists() and os.access(go_bin, os.X_OK):
        return str(go_bin)

    # 5. Cargo bin
    cargo_bin = Path.home() / ".cargo" / "bin" / tool_name
    if cargo_bin.exists() and os.access(cargo_bin, os.X_OK):
        return str(cargo_bin)

    # 6. Homebrew specific locations
    for hb_dir in ("/opt/homebrew/bin", "/usr/local/bin"):
        hb_bin = Path(hb_dir) / tool_name
        if hb_bin.exists() and os.access(hb_bin, os.X_OK):
            return str(hb_bin)

    return None

def is_tool_installed(tool_name: str) -> bool:
    return which_tool(tool_name) is not None

def get_installed_version(tool_name: str) -> Optional[str]:
    path = which_tool(tool_name)
    if not path:
        return None
    try:
        res = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=2
        )
        out = res.stdout.strip() or res.stderr.strip()
        return out.splitlines()[0] if out else "installed"
    except Exception:
        return "installed"

def detect_full_environment() -> Dict[str, Any]:
    """Inspects complete runtime toolchains, package managers, privileges, and system resources."""
    base = detect_platform()
    termux_info = get_termux_info()

    # Package Managers
    pkg_mgr = "none"
    if termux_info["is_termux"] and shutil.which("pkg"):
        pkg_mgr = "pkg"
    elif shutil.which("brew"):
        pkg_mgr = "homebrew"
    elif shutil.which("apt-get"):
        pkg_mgr = "apt"
    elif shutil.which("pacman"):
        pkg_mgr = "pacman"
    elif shutil.which("dnf"):
        pkg_mgr = "dnf"

    # Privileges & Root
    has_root = False
    sudo_available = False
    try:
        if hasattr(os, "geteuid"):
            has_root = os.geteuid() == 0
        sudo_available = shutil.which("sudo") is not None
    except Exception:
        pass

    # Go toolchain
    go_path = shutil.which("go")
    go_version = None
    if go_path:
        try:
            res = subprocess.run([go_path, "version"], capture_output=True, text=True, timeout=2)
            go_version = res.stdout.strip()
        except Exception:
            go_version = "go (detected)"

    # Rust toolchain
    rustc_path = shutil.which("rustc")
    rust_version = None
    if rustc_path:
        try:
            res = subprocess.run([rustc_path, "--version"], capture_output=True, text=True, timeout=2)
            rust_version = res.stdout.strip()
        except Exception:
            rust_version = "rustc (detected)"

    # Python pipx
    pipx_path = shutil.which("pipx")

    # Native Go engine compiled
    native_bin = which_tool("traceforge-native")

    # Disk Space in GB
    try:
        usage = shutil.disk_usage(str(get_project_root()))
        free_gb = round(usage.free / (1024 ** 3), 1)
        total_gb = round(usage.total / (1024 ** 3), 1)
    except Exception:
        free_gb = 0.0
        total_gb = 0.0

    # Memory in GB
    ram_gb = 0.0
    try:
        if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names and "SC_PHYS_PAGES" in os.sysconf_names:
            ram_bytes = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
            ram_gb = round(ram_bytes / (1024 ** 3), 1)
    except Exception:
        pass

    return {
        "os_name": base["os_name"],
        "system": base["system"],
        "distro": base["distro"],
        "os_version": base["version"],
        "arch": base["arch"],
        "hardware": base["hardware"],
        "display_name": base["display_name"],
        "python_version": base["python_version"],
        "is_termux": termux_info["is_termux"],
        "termux": termux_info,
        "in_venv": sys.prefix != sys.base_prefix,
        "has_root": has_root,
        "sudo_available": sudo_available,
        "pipx_available": pipx_path is not None,
        "pkg_manager": pkg_mgr,
        "go_available": go_path is not None,
        "go_version": go_version,
        "rust_available": rustc_path is not None,
        "rust_version": rust_version,
        "native_engine_built": native_bin is not None,
        "disk_free_gb": free_gb,
        "disk_total_gb": total_gb,
        "ram_gb": ram_gb,
        "has_exiftool": is_tool_installed("exiftool"),
        "has_tshark": is_tool_installed("tshark"),
        "has_nmap": is_tool_installed("nmap"),
    }

def recommend_runtime_profile(env: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Deterministically evaluates host capabilities and recommends the optimal profile."""
    if env is None:
        env = detect_full_environment()

    # If low disk space (< 2 GB), recommend minimal
    if 0 < env.get("disk_free_gb", 10.0) < 2.0:
        return {
            "profile": "minimal",
            "reason": "Host has constrained disk space (<2 GB). Minimal installation runs core functionality with zero optional dependencies.",
            "summary": "Core Python runtime + essential built-ins only",
        }

    # Termux environment optimizations
    if env.get("is_termux"):
        if env.get("go_available"):
            return {
                "profile": "python-go",
                "reason": "Termux Android environment with Go toolchain detected. Python handles core workflows and reporting while Go provides high-speed streaming and hashing.",
                "summary": "Termux Python core + native Go acceleration",
            }
        return {
            "profile": "python",
            "reason": "Termux Android environment detected. Pure Python reference engine executes all investigation modules, IOC extraction, and case reporting without requiring root or external compilers.",
            "summary": "Pure Python runtime optimized for Termux userland",
        }

    # If Go is installed and available
    if env.get("go_available"):
        return {
            "profile": "python-go",
            "reason": "Python is available for core CLI logic and reporting; Go toolchain detected for high-throughput streaming and fast hashing.",
            "summary": "Python for application logic + Go for high-throughput acceleration",
        }

    # Standard Python environment
    return {
        "profile": "python",
        "reason": "Python environment detected. All forensics, extraction, graph analysis, and multi-format exports run natively in pure Python.",
        "summary": "Pure Python runtime with full document and export support",
    }
