"""TraceForge API Key & OSINT Credentials Management Vault.

Provides secure local storage, environment injection, masking, and validation
for third-party OSINT data providers, threat intelligence feeds, and search APIs.
"""

import os
import stat
import urllib.request
import urllib.error
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

KEY_REGISTRY: Dict[str, Dict[str, Any]] = {
    "SHODAN_API_KEY": {
        "name": "Shodan API",
        "category": "Infrastructure & IoT",
        "description": "Port scanning, passive banners, SSL certificates, and vulnerability exposure.",
        "test_url": "https://api.shodan.io/api-info?key={KEY}",
        "docs_url": "https://account.shodan.io/",
    },
    "VIRUSTOTAL_API_KEY": {
        "name": "VirusTotal v3 API",
        "category": "Threat Intelligence",
        "description": "File hash analysis, malicious domain/IP scoring, and URL threat triage.",
        "test_url": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        "headers": {"x-apikey": "{KEY}"},
        "docs_url": "https://www.virustotal.com/gui/user/api-key",
    },
    "SECURITYTRAILS_API_KEY": {
        "name": "SecurityTrails API",
        "category": "Domain & Passive DNS",
        "description": "Historical DNS records, subdomains, and WHOIS change intelligence.",
        "test_url": "https://api.securitytrails.com/v1/ping",
        "headers": {"apikey": "{KEY}"},
        "docs_url": "https://securitytrails.com/app/account/credentials",
    },
    "CENSYS_API_ID": {
        "name": "Censys API ID",
        "category": "Infrastructure & Certificates",
        "description": "Internet-wide scan dataset and certificate transparency logs (API ID component).",
        "docs_url": "https://search.censys.io/account/api",
    },
    "CENSYS_API_SECRET": {
        "name": "Censys API Secret",
        "category": "Infrastructure & Certificates",
        "description": "Internet-wide scan dataset and certificate transparency logs (Secret component).",
        "docs_url": "https://search.censys.io/account/api",
    },
    "HUNTER_API_KEY": {
        "name": "Hunter.io API",
        "category": "Email & Corporate Discovery",
        "description": "Corporate domain email pattern discovery, verification, and lead harvesting.",
        "test_url": "https://api.hunter.io/v2/account?api_key={KEY}",
        "docs_url": "https://hunter.io/api_keys",
    },
    "HIBP_API_KEY": {
        "name": "HaveIBeenPwned API",
        "category": "Breach & Exposure",
        "description": "Authorized HaveIBeenPwned API v3 for deep email account breach searches.",
        "test_url": "https://haveibeenpwned.com/api/v3/breaches",
        "headers": {"hibp-api-key": "{KEY}", "user-agent": "TraceForge-OSINT-Suite"},
        "docs_url": "https://haveibeenpwned.com/API/Key",
    },
    "INTELX_API_KEY": {
        "name": "Intelligence X API",
        "category": "Darknet & Leak Search",
        "description": "Searches data leaks, darknet pastes, and archival breaches via IntelX.",
        "docs_url": "https://intelx.io/account?tab=developer",
    },
    "DEHASHED_API_KEY": {
        "name": "DeHashed API Key",
        "category": "Breach & Leak Repositories",
        "description": "DeHashed database query token for credential leak lookups.",
        "docs_url": "https://dehashed.com/",
    },
    "DEHASHED_EMAIL": {
        "name": "DeHashed User Email",
        "category": "Breach & Leak Repositories",
        "description": "Registered account email used in conjunction with DeHashed API key.",
        "docs_url": "https://dehashed.com/",
    },
    "LEAKCHECK_API_KEY": {
        "name": "LeakCheck API",
        "category": "Breach & Leak Repositories",
        "description": "Direct breach database queries for exposed credentials and hashes.",
        "docs_url": "https://leakcheck.io/api",
    },
    "ALIENVAULT_OTX_KEY": {
        "name": "AlienVault OTX Key",
        "category": "Threat Intelligence",
        "description": "Open Threat Exchange IOC feeds, malicious pulses, and adversary tracking.",
        "docs_url": "https://otx.alienvault.com/api",
    },
    "CHAOS_KEY": {
        "name": "ProjectDiscovery Chaos API",
        "category": "Domain & Passive Recon",
        "description": "ProjectDiscovery internet-wide passive DNS and subdomain dataset access.",
        "docs_url": "https://chaos.projectdiscovery.io/#/",
    },
    "IPINFO_API_KEY": {
        "name": "IPinfo API Token",
        "category": "Geolocation & ASN",
        "description": "High-accuracy IP geolocation, ASN routing, and hosting provider metadata.",
        "test_url": "https://ipinfo.io/json?token={KEY}",
        "docs_url": "https://ipinfo.io/account/token",
    },
    "GITHUB_TOKEN": {
        "name": "GitHub Personal Access Token",
        "category": "Code & Developer OSINT",
        "description": "Bypasses strict anonymous rate-limits during public repo and commit harvesting.",
        "test_url": "https://api.github.com/user",
        "headers": {"Authorization": "Bearer {KEY}", "User-Agent": "TraceForge-OSINT-Suite"},
        "docs_url": "https://github.com/settings/tokens",
    },
    "WIGLE_API_KEY": {
        "name": "WiGLE API Token",
        "category": "Wireless & RF Intelligence",
        "description": "Wireless network BSSID/SSID geolocation mapping and cellular tower queries.",
        "docs_url": "https://wigle.net/account",
    },
    "WIGLE_NAME": {
        "name": "WiGLE API Name",
        "category": "Wireless & RF Intelligence",
        "description": "WiGLE API encoded user identifier.",
        "docs_url": "https://wigle.net/account",
    },
    "ETHERSCAN_API_KEY": {
        "name": "Etherscan API",
        "category": "Blockchain & Financial OSINT",
        "description": "Ethereum wallet balance, transaction ledger, and smart contract analysis.",
        "docs_url": "https://etherscan.io/myapikey",
    },
    "OPENAI_API_KEY": {
        "name": "OpenAI API Key",
        "category": "AI Correlation & Analysis",
        "description": "AI analysis and IOC entity relationship summarization via OpenAI models.",
        "docs_url": "https://platform.openai.com/api-keys",
    },
    "GEMINI_API_KEY": {
        "name": "Google Gemini API Key",
        "category": "AI Correlation & Analysis",
        "description": "Multimodal investigation synthesis and threat intelligence parsing via Gemini.",
        "docs_url": "https://aistudio.google.com/app/apikey",
    },
}

def get_credentials_path() -> Path:
    """Returns the path to ~/.traceforge/credentials.env with secure permissions."""
    override = os.environ.get("TRACEFORGE_CREDENTIALS_PATH")
    if override:
        cred_file = Path(override)
        cred_file.parent.mkdir(parents=True, exist_ok=True)
        if not cred_file.exists():
            cred_file.touch(mode=0o600)
        else:
            try:
                cred_file.chmod(0o600)
            except OSError:
                pass
        return cred_file

    home_dir = Path.home() / ".traceforge"
    home_dir.mkdir(parents=True, exist_ok=True)
    cred_file = home_dir / "credentials.env"
    if not cred_file.exists():
        cred_file.touch(mode=0o600)
    else:
        # Enforce 0600 permissions
        try:
            cred_file.chmod(0o600)
        except OSError:
            pass
    return cred_file


def load_credentials() -> Dict[str, str]:
    """Loads all credentials from ~/.traceforge/credentials.env, project .env, and os.environ."""
    creds: Dict[str, str] = {}
    
    # 1. Project-local .env
    local_env = Path(".env")
    if local_env.exists() and local_env.is_file():
        try:
            for line in local_env.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    creds[k.strip()] = v.strip().strip("\"'")
        except Exception:
            pass

    # 2. User vault ~/.traceforge/credentials.env
    vault_file = get_credentials_path()
    if vault_file.exists():
        try:
            for line in vault_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    creds[k.strip()] = v.strip().strip("\"'")
        except Exception:
            pass

    # 3. Active environment variables (highest priority)
    for k in KEY_REGISTRY:
        if k in os.environ and os.environ[k].strip():
            creds[k] = os.environ[k].strip()

    return creds

def save_credential(key_name: str, value: str) -> None:
    """Saves or updates a credential in ~/.traceforge/credentials.env."""
    key_name = key_name.strip().upper()
    value = value.strip()
    vault_file = get_credentials_path()
    
    lines: List[str] = []
    found = False
    if vault_file.exists():
        for line in vault_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped.startswith(f"{key_name}=") or stripped.startswith(f"export {key_name}="):
                lines.append(f"{key_name}={value}")
                found = True
            else:
                lines.append(line)
                
    if not found:
        lines.append(f"{key_name}={value}")

    vault_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        vault_file.chmod(0o600)
    except OSError:
        pass

    # Export to active Python process environment
    os.environ[key_name] = value

def remove_credential(key_name: str) -> bool:
    """Removes a credential from ~/.traceforge/credentials.env and process environment."""
    key_name = key_name.strip().upper()
    vault_file = get_credentials_path()
    if not vault_file.exists():
        return False
        
    lines = []
    removed = False
    for line in vault_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{key_name}=") or stripped.startswith(f"export {key_name}="):
            removed = True
        else:
            lines.append(line)

    if removed:
        vault_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            vault_file.chmod(0o600)
        except OSError:
            pass

    if key_name in os.environ:
        del os.environ[key_name]

    return removed

def mask_key(val: Optional[str]) -> str:
    """Masks secret key value showing only initial characters and final 4 characters."""
    if not val:
        return "<NOT CONFIGURED>"
    if len(val) <= 8:
        return "••••••••"
    return f"{val[:3]}••••••••{val[-4:]}"

def test_credential(key_name: str) -> Dict[str, Any]:
    """Tests if a configured API key connects successfully against public provider endpoints."""
    creds = load_credentials()
    val = creds.get(key_name, "").strip()
    if not val:
        return {"status": "missing", "message": f"API key {key_name} is not set"}

    reg = KEY_REGISTRY.get(key_name)
    if not reg or "test_url" not in reg:
        return {"status": "unsupported", "message": f"Online automated validation is not available for {key_name}. Key is stored."}

    test_url = reg["test_url"].replace("{KEY}", val)
    headers = {k: v.replace("{KEY}", val) for k, v in reg.get("headers", {}).items()}
    if "User-Agent" not in headers and "user-agent" not in headers:
        headers["User-Agent"] = "TraceForge-OSINT-Auditor/1.0"

    try:
        req = urllib.request.Request(test_url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status in (200, 201, 204):
                return {"status": "valid", "code": resp.status, "message": "API key successfully verified with remote provider."}
            return {"status": "unknown", "code": resp.status, "message": f"Received HTTP {resp.status}"}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"status": "invalid", "code": e.code, "message": f"Authentication failed (HTTP {e.code}: Invalid API Key or Unauthorized)"}
        return {"status": "error", "code": e.code, "message": f"Provider returned HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"status": "network_error", "message": f"Connection check failed: {str(e)}"}

def generate_env_template() -> str:
    """Generates an annotated .env template for all supported OSINT services."""
    lines = [
        "# ==============================================================================",
        "# TraceForge OSINT Suite — Provider API Keys & Credentials Configuration",
        "# Save this file to ~/.traceforge/credentials.env or .env (chmod 600)",
        "# ==============================================================================",
        "",
    ]
    current_cat = None
    for k, info in sorted(KEY_REGISTRY.items(), key=lambda item: item[1]["category"]):
        if info["category"] != current_cat:
            current_cat = info["category"]
            lines.append(f"\n# --- {current_cat} ---")
        lines.append(f"# {info['name']}: {info['description']}")
        lines.append(f"# Docs: {info.get('docs_url', 'N/A')}")
        lines.append(f"{k}=")
    return "\n".join(lines) + "\n"
