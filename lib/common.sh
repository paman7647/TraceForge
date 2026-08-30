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

# Real-time animated command execution spinner with live elapsed timer
run_spinner_cmd() {
    local label=$1
    local outfile=$2
    shift 2
    local -a cmd_to_run=("$@")

    if [[ ${#cmd_to_run[@]} -eq 0 ]]; then
        return 0
    fi

    # Ensure parent output directory exists
    mkdir -p -- "$(dirname -- "$outfile")" 2>/dev/null || true

    # If non-interactive (CI / piped stream), run synchronously with simple clean log output
    if [[ ! -t 1 && ! -t 2 ]]; then
        log_step "$label..."
        "${cmd_to_run[@]}" > "$outfile" 2>&1 || true
        log_ok "$label (done)"
        return 0
    fi

    local spinner_frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local frame_count=${#spinner_frames[@]}
    local i=0
    local start_time
    start_time="$(date +%s 2>/dev/null || echo 0)"

    # Hide cursor
    printf '\033[?25l' >&2

    # Launch process in background
    "${cmd_to_run[@]}" > "$outfile" 2>&1 &
    local cmd_pid=$!

    while kill -0 "$cmd_pid" 2>/dev/null; do
        local now
        now="$(date +%s 2>/dev/null || echo 0)"
        local elapsed=$(( now - start_time ))
        local frame="${spinner_frames[i]}"
        printf '\r\033[K%b[*]%b %-52s %b[%s]%b %b(%ds)%b' \
            "$C_CYAN" "$C_RESET" "$label" "$C_YELLOW" "$frame" "$C_RESET" "$C_DIM" "$elapsed" "$C_RESET" >&2
        i=$(( (i + 1) % frame_count ))
        sleep 0.1
    done

    wait "$cmd_pid" 2>/dev/null || true
    local exit_status=$?

    local end_time
    end_time="$(date +%s 2>/dev/null || echo 0)"
    local total_elapsed=$(( end_time - start_time ))

    # Restore cursor
    printf '\033[?25h' >&2

    if [[ -s "$outfile" ]]; then
        printf '\r\033[K%b[OK]%b   %-52s %b(done in %ds)%b\n' \
            "$C_GREEN" "$C_RESET" "$label" "$C_DIM" "$total_elapsed" "$C_RESET" >&2
    else
        printf '\r\033[K%b[SKIP]%b %-52s %b(no records / %ds)%b\n' \
            "$C_DIM" "$C_RESET" "$label" "$C_DIM" "$total_elapsed" "$C_RESET" >&2
    fi
}


# Scan depth mode selector (Quick vs Full Deep Scan)
prompt_scan_mode() {
    local default_mode=${1:-"quick"}
    local user_override=${2:-""}

    if [[ "$user_override" == "full" || "$user_override" == "deep" || "$user_override" == "--full" || "$user_override" == "--deep" ]]; then
        printf 'full'
        return 0
    elif [[ "$user_override" == "quick" || "$user_override" == "--quick" ]]; then
        printf 'quick'
        return 0
    fi

    if [[ -t 0 && -t 1 ]]; then
        printf '\n%bSelect Scan Depth Profile:%b\n' "$C_BOLD" "$C_RESET" >&2
        printf '  %b[1]%b Quick Scan     (Default essential tools for rapid triage)\n' "$C_CYAN" "$C_RESET" >&2
        printf '  %b[2]%b Full Deep Scan (Exhaustively run all available catalog domain tools)\n' "$C_CYAN" "$C_RESET" >&2
        local choice
        choice="$(read_input "Select Scan Depth [1 or 2]" "1")"
        case "$choice" in
            2|full|deep|FULL|DEEP) printf 'full' ;;
            *) printf 'quick' ;;
        esac
    else
        printf '%s' "$default_mode"
    fi
}

# Finalizes module runs: generates TXT, MD, HTML, JSON, IOCs and SHA-256 manifest
finalize_module_run() {
    local module_id=$1
    local module_title=$2
    local target=$3
    local scan_mode=$4
    local run_dir=$5
    local root_base="${ROOT_DIR:-}"
    if [[ -z "$root_base" ]] && command -v project_root >/dev/null 2>&1; then
        root_base="$(project_root 2>/dev/null || pwd -P)"
    fi
    [[ -z "$root_base" ]] && root_base="$(pwd -P)"

    # 1. Run Python reporter if available
    local py_bin="python3"
    if [[ -x "$root_base/.venv/bin/python3" ]]; then
        py_bin="$root_base/.venv/bin/python3"
    elif [[ -x "$root_base/.venv/bin/python" ]]; then
        py_bin="$root_base/.venv/bin/python"
    elif [[ -x "$root_base/.osint_venv/bin/python" ]]; then
        py_bin="$root_base/.osint_venv/bin/python"
    fi

    if command -v "$py_bin" >/dev/null 2>&1; then
        "$py_bin" -c "
import sys
from pathlib import Path
from traceforge.modules.reporting import generate_module_reports

out_dir = Path('$run_dir')
report_txt = out_dir / 'report.txt'
sections = []
if report_txt.exists():
    current_sec = None
    current_lines = []
    with open(report_txt, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line_str = line.rstrip()
            if line_str.startswith('[') and line_str.endswith(']') and len(line_str) > 2:
                if current_sec:
                    sections.append({'title': current_sec, 'content': '\n'.join(current_lines).strip()})
                current_sec = line_str[1:-1]
                current_lines = []
            elif current_sec:
                current_lines.append(line_str)
        if current_sec:
            sections.append({'title': current_sec, 'content': '\n'.join(current_lines).strip()})

generate_module_reports(
    module_id='$module_id',
    module_title='$module_title',
    target='$target',
    scan_mode='$scan_mode',
    out_dir=out_dir,
    sections=sections,
)
" 2>/dev/null || true
    fi

    # 2. Build SHA-256 integrity manifest
    if need_cmd sha256sum; then
        (cd "$run_dir" && find . -maxdepth 3 -type f ! -name "manifest.txt" ! -name "SHA256SUMS" -exec sha256sum {} + | sort > manifest.txt) 2>/dev/null || true
    elif need_cmd shasum; then
        (cd "$run_dir" && find . -maxdepth 3 -type f ! -name "manifest.txt" ! -name "SHA256SUMS" -exec shasum -a 256 {} + | sort > manifest.txt) 2>/dev/null || true
    else
        find "$run_dir" -maxdepth 3 -type f | sort > "$run_dir/manifest.txt" 2>/dev/null || true
    fi

    printf '\n%b' "$C_GREEN"
    printf '%s\n' '----------------------------------------------------------------------'
    printf '✓ %s (%s SCAN) COMPLETED\n' "$module_title" "$(echo "$scan_mode" | tr '[:lower:]' '[:upper:]')"
    printf '%s\n' '----------------------------------------------------------------------'
    printf '%b' "$C_RESET"
    printf 'Evidence & Structured Reports:\n'
    printf '  • Text Report     : %s/report.txt\n' "$run_dir"
    printf '  • Markdown Report : %s/report.md\n' "$run_dir"
    printf '  • HTML Dashboard  : %s/report.html\n' "$run_dir"
    printf '  • JSON Dataset    : %s/report.json\n' "$run_dir"
    printf '  • Extracted IOCs  : %s/iocs.json\n' "$run_dir"
    printf '  • SHA256 Manifest : %s/manifest.txt\n\n' "$run_dir"
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

# Load credentials vault
if [[ -f "${ROOT_DIR:-.}/lib/credentials.sh" ]]; then
    source "${ROOT_DIR:-.}/lib/credentials.sh"
    load_credentials_env
fi

