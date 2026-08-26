from typing import Any, Dict

from traceforge.catalog import Catalog, get_bundled_catalog_path
from traceforge.config import (
    get_cache_dir,
    get_config_dir,
    get_config_path,
    get_logs_dir,
    get_project_root,
    get_runtime_profile,
    get_user_data_dir,
    get_workspace_dir,
    load_config,
    set_runtime_profile,
)
from traceforge.platform_detect import detect_full_environment
from traceforge.runners import CAPABILITY_MATRIX, select_runtime_for_feature


def get_runtime_status() -> Dict[str, Any]:
    """Returns platform diagnostic data, active profile, and fast-path selections."""
    env = detect_full_environment()
    profile = get_runtime_profile()
    cat = Catalog()
    pf_audit = cat.audit_platform(env)

    capabilities: Dict[str, Dict[str, Any]] = {}
    for feat, spec in CAPABILITY_MATRIX.items():
        dec = select_runtime_for_feature(feat)
        capabilities[feat] = {
            "selected_runtime": dec.selected_runtime,
            "binary_used": dec.binary_used,
            "preferred": spec.get("preferred", "python"),
            "description": spec.get("description", spec.get("reason", "")),
        }

    return {
        "host": env,
        "active_profile": profile,
        "capabilities": capabilities,
        "tool_breakdown": pf_audit,
    }


def set_profile(profile_name: str) -> bool:
    return set_runtime_profile(profile_name)


def get_paths() -> Dict[str, str]:
    return {
        "config_file": str(get_config_path()),
        "config_dir": str(get_config_dir()),
        "user_data_dir": str(get_user_data_dir()),
        "workspace_dir": str(get_workspace_dir()),
        "cache_dir": str(get_cache_dir()),
        "logs_dir": str(get_logs_dir()),
        "project_root": str(get_project_root()),
        "bundled_catalog": str(get_bundled_catalog_path()),
    }


def execute_repair() -> Dict[str, Any]:
    """Executes automated repair routines and returns action log."""
    actions = []
    try:
        get_config_dir().mkdir(parents=True, exist_ok=True)
        get_user_data_dir().mkdir(parents=True, exist_ok=True)
        get_workspace_dir().mkdir(parents=True, exist_ok=True)
        get_cache_dir().mkdir(parents=True, exist_ok=True)
        get_logs_dir().mkdir(parents=True, exist_ok=True)
        actions.append("Verified and created directory hierarchy (Config, Workspace, Cache, Logs).")

        cfg = load_config()
        actions.append("Configuration verified and synchronized.")

        cat = Catalog()
        actions.append(f"Tool catalog verified ({len(cat.tools)} definitions loaded).")

        return {"success": True, "actions": actions}
    except Exception as e:
        return {"success": False, "error": str(e), "actions": actions}
