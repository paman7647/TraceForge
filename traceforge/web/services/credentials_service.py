"""TraceForge Web Service for API Key & Credentials Vault.

Provides backend API integration for listing, configuring, removing, and validating
third-party OSINT data provider tokens and API keys.
"""

from typing import Any, Dict, List, Optional
from traceforge.credentials import (
    KEY_REGISTRY,
    generate_env_template,
    get_credentials_path,
    load_credentials,
    mask_key,
    remove_credential,
    save_credential,
    test_credential,
)


def list_credentials() -> Dict[str, Any]:
    """Returns all registered providers with current vault configuration status."""
    creds = load_credentials()
    vault_path = str(get_credentials_path())
    providers: List[Dict[str, Any]] = []

    configured_count = 0
    for key, info in KEY_REGISTRY.items():
        val = creds.get(key, "")
        is_set = bool(val and val.strip())
        if is_set:
            configured_count += 1
        providers.append({
            "key": key,
            "name": info.get("name", key),
            "category": info.get("category", "General"),
            "description": info.get("description", ""),
            "docs_url": info.get("docs_url", ""),
            "is_configured": is_set,
            "masked_value": mask_key(val) if is_set else "<NOT CONFIGURED>",
        })

    return {
        "vault_path": vault_path,
        "total_providers": len(KEY_REGISTRY),
        "configured_count": configured_count,
        "providers": providers,
    }


def set_credential(key: str, value: str) -> Dict[str, Any]:
    """Saves a credential in the secure vault."""
    norm_key = key.strip().upper()
    norm_val = value.strip()
    if not norm_key:
        raise ValueError("Key name is required")
    if not norm_val:
        raise ValueError("Key value is required")

    save_credential(norm_key, norm_val)
    return {
        "success": True,
        "key": norm_key,
        "masked_value": mask_key(norm_val),
        "message": f"Credential for {norm_key} saved securely.",
    }


def delete_credential(key: str) -> Dict[str, Any]:
    """Removes a credential from the secure vault."""
    norm_key = key.strip().upper()
    if not norm_key:
        raise ValueError("Key name is required")

    success = remove_credential(norm_key)
    return {
        "success": success,
        "key": norm_key,
        "message": f"Removed {norm_key} from vault" if success else f"{norm_key} was not found in vault",
    }


def validate_credential(key: str) -> Dict[str, Any]:
    """Tests connectivity and verifies credential against provider API."""
    norm_key = key.strip().upper()
    if not norm_key:
        raise ValueError("Key name is required")

    res = test_credential(norm_key)
    return {
        "key": norm_key,
        "status": res.get("status", "unknown"),
        "message": res.get("message", ""),
    }


def get_template() -> str:
    """Generates the annotated .env template."""
    return generate_env_template()
