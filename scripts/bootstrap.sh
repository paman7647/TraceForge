#!/usr/bin/env bash
# TraceForge 1.0.0 — One-Command Remote Bootstrap Installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/paman7647/TraceForge/master/scripts/bootstrap.sh | bash
#   wget -qO- https://raw.githubusercontent.com/paman7647/TraceForge/master/scripts/bootstrap.sh | bash
# Or with arguments:
#   curl -fsSL https://raw.githubusercontent.com/paman7647/TraceForge/master/scripts/bootstrap.sh | bash -s -- --profile recommended

set -Eeuo pipefail
IFS=$'\n\t'

REPO_URL="https://github.com/paman7647/TraceForge.git"
TARGET_DIR="${TRACEFORGE_DIR:-$HOME/TraceForge}"

echo "======================================================================"
echo "               TRACEFORGE 1.0.0 — REMOTE BOOTSTRAP"
echo "======================================================================"
echo "[*] Source Repository : $REPO_URL"
echo "[*] Target Directory  : $TARGET_DIR"

if [[ "$(id -u)" -eq 0 ]] && [[ -z "${ALLOW_ROOT:-}" ]] && [[ ! -d "/data/data/com.termux" ]]; then
    echo "[!] Warning: Running installer as root is not recommended." >&2
    echo "    Please run as a standard non-root user." >&2
    echo "    To override, export ALLOW_ROOT=1" >&2
fi

# Ensure git or curl/tar are available
if ! command -v git >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
    if [[ -d "/data/data/com.termux" ]]; then
        pkg update -y 2>/dev/null || true
        pkg install -y git curl tar 2>/dev/null || true
    elif command -v apt-get >/dev/null 2>&1; then
        if [[ "$(id -u)" -eq 0 ]]; then
            apt-get update -y 2>/dev/null || true
            apt-get install -y git curl tar 2>/dev/null || true
        elif command -v sudo >/dev/null 2>&1; then
            sudo apt-get update -y 2>/dev/null || true
            sudo apt-get install -y git curl tar 2>/dev/null || true
        fi
    fi
fi

if [[ -d "$TARGET_DIR/.git" ]]; then
    echo "[*] Existing TraceForge repository detected. Pulling latest updates..."
    (cd "$TARGET_DIR" && git pull --ff-only origin master 2>/dev/null) || true
elif [[ -d "$TARGET_DIR" ]]; then
    echo "[*] Target directory $TARGET_DIR already exists."
else
    echo "[*] Cloning TraceForge repository..."
    if command -v git >/dev/null 2>&1; then
        git clone "$REPO_URL" "$TARGET_DIR"
    else
        echo "[*] Git not found, downloading archive via curl/tar..."
        mkdir -p "$TARGET_DIR"
        curl -fsSL "https://github.com/paman7647/TraceForge/archive/refs/heads/master.tar.gz" | tar -xz -C "$TARGET_DIR" --strip-components=1
    fi
fi

cd "$TARGET_DIR"
chmod +x setup.sh run.sh main.sh install_all.sh 2>/dev/null || true

echo "[*] Launching TraceForge setup..."
./setup.sh "$@"
