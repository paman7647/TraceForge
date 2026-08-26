#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# TraceForge — lib/common.sh
# Core terminal helpers, safe logging, path resolution, and string utilities.

# Guard against multiple inclusion
[[ -n "${_TRACEFORGE_LIB_COMMON_LOADED:-}" ]] && return 0
readonly _TRACEFORGE_LIB_COMMON_LOADED=1

# Strict execution defaults when invoked
set -o pipefail

# Terminal colors and styling with TTY auto-detection
if [[ -t 1 && -n "${TERM:-}" && "${TERM:-}" != "dumb" ]]; then
    readonly C_RED=$'\033[0;31m'
    readonly C_GREEN=$'\033[0;32m'
    readonly C_YELLOW=$'\033[1;33m'
    readonly C_BLUE=$'\033[0;34m'
    readonly C_CYAN=$'\033[0;36m'
    readonly C_MAGENTA=$'\033[0;35m'
    readonly C_BOLD=$'\033[1m'
    readonly C_DIM=$'\033[2m'
    readonly C_RESET=$'\033[0m'
else
    readonly C_RED=''
    readonly C_GREEN=''
    readonly C_YELLOW=''
    readonly C_BLUE=''
    readonly C_CYAN=''
    readonly C_MAGENTA=''
    readonly C_BOLD=''
    readonly C_DIM=''
    readonly C_RESET=''
fi

# Standardized Logging functions
log_info() {
    printf '%b[INFO]%b %s\n' "$C_BLUE" "$C_RESET" "$*" >&2
}

log_ok() {
    printf '%b[OK]%b   %s\n' "$C_GREEN" "$C_RESET" "$*" >&2
}

log_warn() {
    printf '%b[WARN]%b %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2
}

log_err() {
    printf '%b[ERROR]%b %s\n' "$C_RED" "$C_RESET" "$*" >&2
}

log_skip() {
    printf '%b[SKIP]%b %s\n' "$C_DIM" "$C_RESET" "$*" >&2
}

log_step() {
    printf '%b[*]%b %s\n' "$C_CYAN" "$C_RESET" "$*" >&2
}

# Compatibility aliases
info() {
    log_info "$*"
}

warn() {
    log_warn "$*"
}

err() {
    log_err "$*"
}

step() {
    log_step "$*"
}

die() {
    printf '%b[ERROR] FATAL:%b %s\n' "$C_RED" "$C_RESET" "$*" >&2
    exit 1
}

# Command existence check
need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Project root canonical resolution
project_root() {
    CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P
}

# Clean string sanitizer for file and directory names
sanitize_name() {
    local input=${1:-unnamed_target}
    input="${input// /_}"
    input="$(printf '%s' "$input" | tr -cd '[:alnum:]._-')"
    [[ -n "$input" ]] || input="unnamed_target"
    printf '%s' "$input"
}

# Safe workspace timestamped directory generator
make_run_dir() {
    local base_root=$1
    local label=$2
    local timestamp safe_label target_dir

    timestamp="$(date '+%Y%m%d_%H%M%S')"
    safe_label="$(sanitize_name "$label")"
    target_dir="$base_root/workspace/${timestamp}_${safe_label}"

    mkdir -p -- "$target_dir"
    printf '%s' "$target_dir"
}

# Cryptographic file hashing with fallback
hash_file() {
    local target_file=$1
    if [[ ! -f "$target_file" ]]; then
        printf 'Error: File does not exist: %s\n' "$target_file" >&2
        return 1
    fi

    if need_cmd sha256sum; then
        sha256sum "$target_file" | awk '{print $1}'
    elif need_cmd shasum; then
        shasum -a 256 "$target_file" | awk '{print $1}'
    elif need_cmd openssl; then
        openssl dgst -sha256 "$target_file" | awk '{print $NF}'
    else
        printf 'unavailable'
    fi
}

# Prompt user for single line input
read_input() {
    local prompt_msg=${1:-"Input: "}
    local default_val=${2:-""}
    local user_val=""

    if [[ -n "$default_val" ]]; then
        printf '%b%s%b [%s]: ' "$C_CYAN" "$prompt_msg" "$C_RESET" "$default_val" >&2
    else
        printf '%b%s%b: ' "$C_CYAN" "$prompt_msg" "$C_RESET" >&2
    fi

    IFS= read -r user_val || true
    if [[ -z "$user_val" && -n "$default_val" ]]; then
        user_val="$default_val"
    fi
    printf '%s' "$user_val"
}

# Pause prompt for operator menus
pause_menu() {
    if [[ -t 0 ]]; then
        local dummy
        printf '\n%bPress [Enter] to continue...%b ' "$C_DIM" "$C_RESET" >&2
        IFS= read -r dummy || true
    fi
}

# Safe command runner using Bash arrays (never eval)
safe_run_cmd() {
    local cmd_binary=$1
    shift
    local -a cmd_args=("$@")

    if ! need_cmd "$cmd_binary"; then
        log_warn "Command '$cmd_binary' is not installed or not found on PATH."
        return 127
    fi

    "$cmd_binary" "${cmd_args[@]}"
}

# Clear screen if interactive and supported
clear_screen() {
    if [[ -t 1 && -n "${TERM:-}" && "${TERM:-}" != "dumb" ]] && need_cmd clear; then
        clear
    fi
}

# Standard banner
print_banner() {
    local subtitle=${1:-""}
    clear_screen
    printf '%b' "$C_MAGENTA"
    printf '%s\n' '╔══════════════════════════════════════════════════════════════════════╗'
    printf '%s\n' '║                           TRACEFORGE                                 ║'
    printf '%s\n' '║               OSINT · DFIR · Security Investigation                  ║'
    printf '%s\n' '╠══════════════════════════════════════════════════════════════════════╣'
    printf '%s\n' '║ Lead: Aman Kumar Pandey                                 v1.0.0       ║'
    printf '%s\n' '╚══════════════════════════════════════════════════════════════════════╝'
    printf '%b\n' "$C_RESET"
    if [[ -n "$subtitle" ]]; then
        printf '%b[ %s ]%b\n\n' "$C_CYAN" "$subtitle" "$C_RESET"
    fi
}
