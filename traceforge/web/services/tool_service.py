import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from traceforge.catalog import Catalog, ToolRecord
from traceforge.platform_detect import detect_full_environment, which_tool
from traceforge.runners import ToolRunner


def get_catalog() -> Catalog:
    return Catalog()


def list_catalog_tools(
    category: Optional[str] = None,
    subcategory: Optional[str] = None,
    search: Optional[str] = None,
    installed_only: bool = False,
    available_only: bool = False,
) -> List[Dict[str, Any]]:
    """Returns catalog tools with platform capabilities and real-time installation status."""
    cat = get_catalog()
    env = detect_full_environment()
    res: List[Dict[str, Any]] = []

    for tool in cat.tools:
        if category and category.lower() != "all" and tool.category.lower() != category.lower():
            continue
        if subcategory and subcategory.lower() != "all" and tool.subcategory.lower() != subcategory.lower():
            continue
        if search:
            q = search.lower()
            if q not in tool.name.lower() and q not in tool.binary.lower() and q not in tool.description.lower():
                continue

        d = tool.to_dict(env)
        if installed_only and not d["is_installed"]:
            continue
        if available_only and not d["is_supported"]:
            continue

        res.append(d)

    return res


def get_tool_details(tool_identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a tool by ID or binary name and returns complete dictionary."""
    cat = get_catalog()
    env = detect_full_environment()
    tool = cat.find_tool(tool_identifier)
    if not tool:
        return None
    return tool.to_dict(env, include_version=True)



def get_platform_audit() -> Dict[str, Any]:
    """Audits entire catalog against active host environment."""
    cat = get_catalog()
    env = detect_full_environment()
    return cat.audit_platform(env)


def get_integration_audit() -> Dict[str, Any]:
    """Returns per-tool integration depth classification for all catalog tools."""
    cat = get_catalog()
    env = detect_full_environment()
    return cat.integration_audit(env)


def run_catalog_tool(tool_identifier: str, target: str = "", extra_args: Optional[List[str]] = None, timeout: int = 60) -> Dict[str, Any]:
    """Executes a catalog tool defensively via ToolRunner structured binary arguments (no shell=True)."""
    cat = get_catalog()
    tool = cat.find_tool(tool_identifier)
    if not tool:
        return {"error": f"Tool '{tool_identifier}' not found in catalog", "exit_code": 127}

    bin_path = which_tool(tool.binary)
    if not bin_path:
        return {"error": f"Binary '{tool.binary}' is not installed on this system.", "exit_code": 127}

    args = list(extra_args or [])
    if target and target not in args:
        args.append(target)

    res = ToolRunner.run_catalog_tool(tool.binary, args, timeout=timeout)
    return res.to_dict()


def install_catalog_tool(tool_identifier: str) -> Dict[str, Any]:
    """Executes platform-aware installer for a catalog tool."""
    cat = get_catalog()
    env = detect_full_environment()
    tool = cat.find_tool(tool_identifier)
    if not tool:
        return {"success": False, "error": f"Tool '{tool_identifier}' not found in catalog"}

    cap = tool.get_platform_capability(env)
    if not cap["is_available"]:
        return {"success": False, "error": f"Tool '{tool.name}' is not supported on {env['display_name']}: {cap['status_label']}"}

    if cap.get("availability") == "MANUAL_INSTALL":
        return {"success": False, "error": f"Tool '{tool.name}' requires manual installation: {tool.source_url}"}

    install_cmd = cap["install_command"]
    if not install_cmd or install_cmd == "-":
        return {"success": False, "error": f"No automatic install command available for {tool.name} on {env['display_name']}"}

    # Execute installation via scripts/install_tool.sh or native package manager safely
    try:
        proc = subprocess.run(
            ["bash", "scripts/install_tool.sh", tool.binary],
            capture_output=True,
            text=True,
            timeout=180,
        )
        is_installed = bool(which_tool(tool.binary))
        return {
            "success": proc.returncode == 0 or is_installed,
            "installed": is_installed,
            "binary_path": which_tool(tool.binary) or "",
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "command": install_cmd,
        }
    except Exception as e:
        return {"success": False, "error": f"Installation failed: {str(e)}"}
