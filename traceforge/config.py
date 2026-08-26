import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

VALID_PROFILES: Tuple[str, ...] = (
    "recommended",
    "minimal",
    "python",
    "go",
    "python-go",
    "full",
    "custom",
)

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "1.0.1",
    "workspace_dir": "workspace",
    "active_case": "",
    "default_format": "html",
    "redaction_enabled": False,
    "native_bin_dir": "bin",
    "runtime_profile": "python-go",
    "feature_runtimes": {},
    "custom_components": {
        "python": True,
        "go": True,
        "rust": False,
        "reporting": True,
        "network": True,
        "image": True,
        "domain": True,
        "identity": True,
        "document": True,
        "opsec": True,
        "catalog_tools": True,
    },
}

def get_project_root() -> Path:
    """Returns the project root directory."""
    src_path = Path(__file__).resolve().parent.parent
    if (src_path / "catalog" / "tools.tsv").exists() or (src_path / "VERSION").exists():
        return src_path
    return Path.cwd()

def get_config_dir() -> Path:
    """Returns the TraceForge user configuration directory."""
    config_home = os.environ.get("XDG_CONFIG_HOME")
    if config_home:
        path = Path(config_home) / "traceforge"
    else:
        path = Path.home() / ".config" / "traceforge"
    path.mkdir(parents=True, exist_ok=True)
    return path

def get_config_path() -> Path:
    return get_config_dir() / "config.json"

def load_config() -> Dict[str, Any]:
    cfg_file = get_config_path()
    if not cfg_file.exists():
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()
    try:
        with open(cfg_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            merged = DEFAULT_CONFIG.copy()
            merged.update(data)
            return merged
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(cfg: Dict[str, Any]) -> None:
    cfg_file = get_config_path()
    try:
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass

def get_user_data_dir() -> Path:
    """Returns the platform-aware user data directory (cases, evidence, exports)."""
    # 1. Environment override
    env_dir = os.environ.get("TRACEFORGE_DATA_DIR")
    if env_dir:
        p = Path(env_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    # 2. Project local override if running in git repo workspace
    src_path = Path(__file__).resolve().parent.parent
    if (src_path / ".git").exists() or (src_path / "catalog" / "tools.tsv").exists():
        ws = src_path / "workspace"
        ws.mkdir(parents=True, exist_ok=True)
        return ws

    # 3. System XDG / macOS standard data directory
    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        p = Path(xdg_data) / "traceforge"
    elif sys.platform == "darwin":
        p = Path.home() / "Library" / "Application Support" / "TraceForge"
    else:
        p = Path.home() / ".local" / "share" / "traceforge"

    p.mkdir(parents=True, exist_ok=True)
    return p

def get_workspace_dir() -> Path:
    cfg = load_config()
    configured = cfg.get("workspace_dir", "")
    if configured:
        ws_path = Path(configured)
        if not ws_path.is_absolute():
            user_data = get_user_data_dir()
            if user_data.name == ws_path.name:
                ws_path = user_data
            else:
                ws_path = user_data / ws_path
    else:
        ws_path = get_user_data_dir()
    ws_path.mkdir(parents=True, exist_ok=True)
    return ws_path

def get_cache_dir() -> Path:
    """Returns the platform-aware application cache directory."""
    env_cache = os.environ.get("TRACEFORGE_CACHE_DIR")
    if env_cache:
        p = Path(env_cache)
    else:
        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        if xdg_cache:
            p = Path(xdg_cache) / "traceforge"
        elif sys.platform == "darwin":
            p = Path.home() / "Library" / "Caches" / "TraceForge"
        else:
            p = Path.home() / ".cache" / "traceforge"
    p.mkdir(parents=True, exist_ok=True)
    return p

def get_logs_dir() -> Path:
    """Returns the user logs directory."""
    p = get_user_data_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p

def get_runtime_profile() -> str:
    """Returns the active runtime profile."""
    cfg = load_config()
    prof = str(cfg.get("runtime_profile", "python-go")).lower().strip()
    return prof if prof in VALID_PROFILES else "python-go"

def set_runtime_profile(profile: str) -> bool:
    """Sets and persists the active runtime profile."""
    norm = profile.lower().strip()
    if norm not in VALID_PROFILES:
        return False
    cfg = load_config()
    cfg["runtime_profile"] = norm
    save_config(cfg)
    return True

def get_feature_runtime(feature: str, default: Optional[str] = None) -> Optional[str]:
    """Retrieves tool/feature runtime override if configured."""
    cfg = load_config()
    overrides = cfg.get("feature_runtimes", {})
    return overrides.get(feature, default)

def set_feature_runtime(feature: str, runtime: str) -> bool:
    """Sets a feature-level runtime override."""
    norm_rt = runtime.lower().strip()
    if norm_rt not in ("python", "go", "native", "auto", "rust"):
        return False
    cfg = load_config()
    if "feature_runtimes" not in cfg or not isinstance(cfg["feature_runtimes"], dict):
        cfg["feature_runtimes"] = {}
    if norm_rt == "auto":
        cfg["feature_runtimes"].pop(feature, None)
    else:
        cfg["feature_runtimes"][feature] = norm_rt
    save_config(cfg)
    return True

def get_custom_components() -> Dict[str, bool]:
    cfg = load_config()
    defaults = DEFAULT_CONFIG["custom_components"].copy()
    user_comps = cfg.get("custom_components", {})
    if isinstance(user_comps, dict):
        defaults.update(user_comps)
    return defaults

def set_custom_components(components: Dict[str, bool]) -> None:
    cfg = load_config()
    cfg["custom_components"] = components
    save_config(cfg)
