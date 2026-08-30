#!/usr/bin/env bash
# ==============================================================================
# TraceForge — Shell API Key & OSINT Credentials Management Vault
# ==============================================================================

CRED_VAULT_DIR="${HOME}/.traceforge"
CRED_VAULT_FILE="${CRED_VAULT_DIR}/credentials.env"

# Ensure secure directory and file permissions (0700 / 0600)
ensure_vault_file() {
    if [[ ! -d "$CRED_VAULT_DIR" ]]; then
        mkdir -p "$CRED_VAULT_DIR" 2>/dev/null || true
        chmod 700 "$CRED_VAULT_DIR" 2>/dev/null || true
    fi
    if [[ ! -f "$CRED_VAULT_FILE" ]]; then
        touch "$CRED_VAULT_FILE" 2>/dev/null || true
        chmod 600 "$CRED_VAULT_FILE" 2>/dev/null || true
    else
        chmod 600 "$CRED_VAULT_FILE" 2>/dev/null || true
    fi
}

# Load and export all credentials into current shell environment
load_credentials_env() {
    ensure_vault_file
    
    # 1. Load project-local .env if present
    if [[ -f ".env" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            [[ -z "$line" || "$line" == \#* ]] && continue
            if [[ "$line" == *"="* ]]; then
                key="${line%%=*}"
                val="${line#*=}"
                key="$(printf '%s' "$key" | tr -cd '[:alnum:]_')"
                val="$(printf '%s' "$val" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
                if [[ -n "$key" && -z "${!key:-}" ]]; then
                    export "$key=$val"
                fi
            fi
        done < ".env"
    fi

    # 2. Load ~/.traceforge/credentials.env
    if [[ -f "$CRED_VAULT_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            [[ -z "$line" || "$line" == \#* ]] && continue
            if [[ "$line" == *"="* ]]; then
                key="${line%%=*}"
                val="${line#*=}"
                key="$(printf '%s' "$key" | tr -cd '[:alnum:]_')"
                val="$(printf '%s' "$val" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
                if [[ -n "$key" ]]; then
                    export "$key=$val"
                fi
            fi
        done < "$CRED_VAULT_FILE"
    fi
}

# Mask key representation
mask_key_val() {
    local val="$1"
    if [[ -z "$val" ]]; then
        printf '<NOT CONFIGURED>'
        return
    fi
    local len="${#val}"
    if [[ $len -le 8 ]]; then
        printf '••••••••'
    else
        local prefix="${val:0:3}"
        local suffix="${val: -4}"
        printf '%s••••••••%s' "$prefix" "$suffix"
    fi
}

# Save a credential to vault
save_vault_key() {
    local key_name="$1"
    local key_val="$2"
    ensure_vault_file

    key_name="$(printf '%s' "$key_name" | tr '[:lower:]' '[:upper:]' | tr -cd '[:alnum:]_')"
    [[ -z "$key_name" ]] && return 1

    local temp_file="${CRED_VAULT_FILE}.tmp.$$"
    local found=0

    if [[ -f "$CRED_VAULT_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" == "${key_name}="* || "$line" == "export ${key_name}="* ]]; then
                printf '%s=%s\n' "$key_name" "$key_val" >> "$temp_file"
                found=1
            else
                printf '%s\n' "$line" >> "$temp_file"
            fi
        done < "$CRED_VAULT_FILE"
    fi

    if [[ $found -eq 0 ]]; then
        printf '%s=%s\n' "$key_name" "$key_val" >> "$temp_file"
    fi

    mv -f "$temp_file" "$CRED_VAULT_FILE"
    chmod 600 "$CRED_VAULT_FILE"
    export "$key_name=$key_val"
}

# Delete a credential from vault
remove_vault_key() {
    local key_name="$1"
    ensure_vault_file

    key_name="$(printf '%s' "$key_name" | tr '[:lower:]' '[:upper:]' | tr -cd '[:alnum:]_')"
    [[ -z "$key_name" ]] && return 1

    local temp_file="${CRED_VAULT_FILE}.tmp.$$"
    if [[ -f "$CRED_VAULT_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" != "${key_name}="* && "$line" != "export ${key_name}="* ]]; then
                printf '%s\n' "$line" >> "$temp_file"
            fi
        done < "$CRED_VAULT_FILE"
        mv -f "$temp_file" "$CRED_VAULT_FILE" 2>/dev/null || true
        chmod 600 "$CRED_VAULT_FILE" 2>/dev/null || true
    fi
    unset "$key_name" 2>/dev/null || true
}
