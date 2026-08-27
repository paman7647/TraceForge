#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295,SC2119,SC2120
# =============================================================================
# TraceForge — lib/doctor.sh
# Pure-Bash System, Environment, Toolchain, and Workspace Diagnostic Engine
# Works in zero-dependency environments before or after Python setup.
# =============================================================================

[[ -n "${_TRACEFORGE_LIB_DOCTOR_LOADED:-}" ]] && return 0
readonly _TRACEFORGE_LIB_DOCTOR_LOADED=1

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/common.sh"
# shellcheck source=lib/platform.sh
source "$SCRIPT_DIR/platform.sh"

run_system_diagnostics() {
    local repair_mode=0
    for arg in "$@"; do
        case "$arg" in
            --help|-h)
                printf 'TraceForge Environment & Runtime Diagnostics\n\nUsage:\n  ./scripts/doctor.sh [options]\n\nOptions:\n  --repair, -r    Attempt automated directory and toolchain repair\n  --help, -h      Show this help message\n'
                exit 0
                ;;
            --repair|-r)
                repair_mode=1
                ;;
            *)
                log_err "Unknown option: $arg"
                printf 'Usage: ./scripts/doctor.sh [--repair] [--help]\n' >&2
                exit 1
                ;;
        esac
    done


    if [[ "$repair_mode" -eq 1 ]]; then
        printf '%b[+] Initiating Environment & Toolchain Repair...%b\n' "$C_CYAN" "$C_RESET"
        mkdir -p "$ROOT_DIR/workspace" "$ROOT_DIR/bin" "$ROOT_DIR/docs" "$ROOT_DIR/catalog" 2>/dev/null || true
        if [[ -f "$ROOT_DIR/scripts/build_native.sh" ]]; then
            bash "$ROOT_DIR/scripts/build_native.sh" 2>/dev/null || true
        fi
        if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
            "$ROOT_DIR/.venv/bin/python" -m traceforge doctor --repair 2>/dev/null || true
        fi
        printf '%b[✓] Environment repair actions finished.%b\n\n' "$C_GREEN" "$C_RESET"
    fi

    local ok_count=0
    local warn_count=0
    local err_count=0
    local miss_count=0
    local opt_count=0

    printf '%b' "$C_MAGENTA"
    printf '%s\n' '======================================================================'
    printf '%s\n' '              TRACEFORGE ENVIRONMENT & RUNTIME DIAGNOSTICS            '
    printf '%s\n' '======================================================================'
    printf '%b\n' "$C_RESET"

    # 1. Host Architecture & Kernel
    printf '%b[ HOST PLATFORM ]%b\n' "$C_BOLD" "$C_RESET"
    printf '  %-24s : %s\n' "Operating System" "$OS_NAME ($OS_TYPE)"
    printf '  %-24s : %s\n' "Kernel Architecture" "$OS_ARCH"
    if [[ "$OS_TYPE" == "linux" ]]; then
        printf '  %-24s : %s (v%s)\n' "Linux Distribution" "$LINUX_DISTRO" "$LINUX_VERSION"
    fi
    printf '  %-24s : %s\n' "Bash Shell Version" "$BASH_VERSION"
    printf '  %-24s : %s\n' "Execution User" "${USER:-$(id -un 2>/dev/null || echo "unknown")} (UID: $(id -u 2>/dev/null || echo "-"))"
    printf '\n'

    # 2. Base Runtime Toolchains
    printf '%b[ CORE RUNTIME TOOLCHAINS ]%b\n' "$C_BOLD" "$C_RESET"

    # Python
    local py_bin=""
    local py_ver=""
    for cand in "$ROOT_DIR/.venv/bin/python" "$ROOT_DIR/.osint_venv/bin/python" python3 python; do
        if command -v "$cand" >/dev/null 2>&1; then
            if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
                py_bin="$(command -v "$cand")"
                py_ver="$("$py_bin" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo "unknown")"
                break
            fi
        fi
    done

    if [[ -n "$py_bin" ]]; then
        printf '  %-24s : %b[OK]%b   v%s (%s)\n' "Python (>=3.9)" "$C_GREEN" "$C_RESET" "$py_ver" "$py_bin"
        ok_count=$((ok_count + 1))
    else
        printf '  %-24s : %b[ERROR]%b Python 3.9+ is missing or not detected on PATH\n' "Python (>=3.9)" "$C_RED" "$C_RESET"
        err_count=$((err_count + 1))
    fi

    # Go compiler
    if need_cmd go; then
        local go_ver
        go_ver="$(go version 2>/dev/null | awk '{print $3}' || echo "available")"
        printf '  %-24s : %b[OK]%b   %s (%s)\n' "Go Toolchain" "$C_GREEN" "$C_RESET" "$go_ver" "$(command -v go)"
        ok_count=$((ok_count + 1))
    else
        printf '  %-24s : %b[OPTIONAL]%b Go compiler not found (Python fallbacks will be used)\n' "Go Toolchain" "$C_DIM" "$C_RESET"
        opt_count=$((opt_count + 1))
    fi

    # Git
    if need_cmd git; then
        local git_ver
        git_ver="$(git --version 2>/dev/null | awk '{print $3}' || echo "available")"
        printf '  %-24s : %b[OK]%b   v%s (%s)\n' "Git VCS" "$C_GREEN" "$C_RESET" "$git_ver" "$(command -v git)"
        ok_count=$((ok_count + 1))
    else
        printf '  %-24s : %b[WARN]%b Git is missing (Repo updates will not be available)\n' "Git VCS" "$C_YELLOW" "$C_RESET"
        warn_count=$((warn_count + 1))
    fi

    # Network fetchers (curl / wget)
    if need_cmd curl; then
        printf '  %-24s : %b[OK]%b   %s\n' "cURL Utility" "$C_GREEN" "$C_RESET" "$(command -v curl)"
        ok_count=$((ok_count + 1))
    elif need_cmd wget; then
        printf '  %-24s : %b[OK]%b   %s\n' "Wget Utility" "$C_GREEN" "$C_RESET" "$(command -v wget)"
        ok_count=$((ok_count + 1))
    else
        printf '  %-24s : %b[WARN]%b Neither curl nor wget was found\n' "HTTP Fetcher" "$C_YELLOW" "$C_RESET"
        warn_count=$((warn_count + 1))
    fi
    printf '\n'

    # 3. Virtual Environment & TraceForge Installation Status
    printf '%b[ TRACEFORGE ENVIRONMENT & WORKSPACE ]%b\n' "$C_BOLD" "$C_RESET"
    local venv_path="$ROOT_DIR/.venv"
    if [[ ! -d "$venv_path" && -d "$ROOT_DIR/.osint_venv" ]]; then
        venv_path="$ROOT_DIR/.osint_venv"
    fi

    if [[ -d "$venv_path" && -x "$venv_path/bin/python" ]]; then
        if "$venv_path/bin/python" -c 'import traceforge' 2>/dev/null; then
            printf '  %-24s : %b[OK]%b   Configured at %s\n' "Virtual Environment" "$C_GREEN" "$C_RESET" "$venv_path"
            ok_count=$((ok_count + 1))
        else
            printf '  %-24s : %b[WARN]%b Virtualenv exists but traceforge package is not installed in it\n' "Virtual Environment" "$C_YELLOW" "$C_RESET"
            warn_count=$((warn_count + 1))
        fi
    else
        printf '  %-24s : %b[MISSING]%b Virtualenv not initialized (Run ./setup.sh)\n' "Virtual Environment" "$C_YELLOW" "$C_RESET"
        miss_count=$((miss_count + 1))
    fi

    # Native Go acceleration binary
    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
        printf '  %-24s : %b[OK]%b   %s\n' "Native Fast-Path" "$C_GREEN" "$C_RESET" "bin/traceforge-native"
        ok_count=$((ok_count + 1))
    else
        printf '  %-24s : %b[OPTIONAL]%b bin/traceforge-native not compiled (Python reference will run)\n' "Native Fast-Path" "$C_DIM" "$C_RESET"
        opt_count=$((opt_count + 1))
    fi

    # Workspace directory write permissions
    local ws_dir="$ROOT_DIR/workspace"
    if [[ -d "$ws_dir" && -w "$ws_dir" ]]; then
        printf '  %-24s : %b[OK]%b   Writable (%s)\n' "Workspace Directory" "$C_GREEN" "$C_RESET" "$ws_dir"
        ok_count=$((ok_count + 1))
    else
        mkdir -p "$ws_dir" 2>/dev/null || true
        if [[ -w "$ws_dir" ]]; then
            printf '  %-24s : %b[OK]%b   Created and writable\n' "Workspace Directory" "$C_GREEN" "$C_RESET"
            ok_count=$((ok_count + 1))
        else
            printf '  %-24s : %b[ERROR]%b Workspace directory is not writable: %s\n' "Workspace Directory" "$C_RED" "$C_RESET" "$ws_dir"
            err_count=$((err_count + 1))
        fi
    fi

    # Central tool catalog
    local cat_tsv="$ROOT_DIR/catalog/tools.tsv"
    if [[ -f "$cat_tsv" ]]; then
        local cat_c
        cat_c="$(awk 'NR>1 {c++} END {print c+0}' "$cat_tsv")"
        printf '  %-24s : %b[OK]%b   %s tools cataloged (%s)\n' "Tool Catalog TSV" "$C_GREEN" "$C_RESET" "$cat_c" "$cat_tsv"
        ok_count=$((ok_count + 1))
    else
        printf '  %-24s : %b[ERROR]%b Missing central catalog: %s\n' "Tool Catalog TSV" "$C_RED" "$C_RESET" "$cat_tsv"
        err_count=$((err_count + 1))
    fi
    printf '\n'

    # 4. Platform Specific Integrations
    if [[ "$OS_TYPE" == "termux" ]]; then
        printf '%b[ TERMUX / ANDROID INTEGRATION ]%b\n' "$C_BOLD" "$C_RESET"
        printf '  %-24s : %s\n' "Termux Prefix" "$TERMUX_PREFIX"
        if [[ "$TERMUX_STORAGE_AVAILABLE" -eq 1 ]]; then
            printf '  %-24s : %b[OK]%b   Mounted ($HOME/storage)\n' "Shared Storage" "$C_GREEN" "$C_RESET"
            ok_count=$((ok_count + 1))
        else
            printf '  %-24s : %b[WARN]%b Not mounted (Run: termux-setup-storage)\n' "Shared Storage" "$C_YELLOW" "$C_RESET"
            warn_count=$((warn_count + 1))
        fi
        if [[ "$TERMUX_API_AVAILABLE" -eq 1 ]]; then
            printf '  %-24s : %b[OK]%b   Active\n' "Termux:API" "$C_GREEN" "$C_RESET"
            ok_count=$((ok_count + 1))
        else
            printf '  %-24s : %b[OPTIONAL]%b Optional package (pkg install termux-api)\n' "Termux:API" "$C_DIM" "$C_RESET"
            opt_count=$((opt_count + 1))
        fi
        printf '\n'
    elif [[ "$OS_TYPE" == "darwin" ]]; then
        printf '%b[ MACOS INTEGRATION ]%b\n' "$C_BOLD" "$C_RESET"
        if [[ -n "$BREW_PREFIX" ]]; then
            printf '  %-24s : %b[OK]%b   Prefix at %s\n' "Homebrew" "$C_GREEN" "$C_RESET" "$BREW_PREFIX"
            ok_count=$((ok_count + 1))
        else
            printf '  %-24s : %b[WARN]%b Homebrew not found (Install via https://brew.sh)\n' "Homebrew" "$C_YELLOW" "$C_RESET"
            warn_count=$((warn_count + 1))
        fi
        printf '\n'
    fi

    # 5. External Forensic Utilities Audit
    printf '%b[ AUDITED EXTERNAL UTILITIES ]%b\n' "$C_BOLD" "$C_RESET"
    local -a key_tools=(
        "exiftool:Image & Document EXIF Extraction"
        "tshark:Network Packet Dissection"
        "binwalk:Firmware & File Carving"
        "strings:ASCII/Unicode String Extraction"
        "dig:DNS Name Resolution"
        "whois:Domain & IP Registration Lookup"
        "sherlock:Social Media Identity Search"
        "holehe:Email Account Registration Recon"
        "subfinder:Passive Subdomain Discovery"
        "mat2:OPSEC Metadata Sanitization"
        "jq:JSON Stream Processing"
        "ripgrep:High-Speed Pattern Search (rg)"
    )

    for item in "${key_tools[@]}"; do
        local b="${item%%:*}"
        local d="${item#*:}"
        local b_cmd="$b"
        [[ "$b" == "ripgrep" ]] && b_cmd="rg"

        if need_cmd "$b_cmd"; then
            printf '  %-14s : %b[OK]%b       %s (%s)\n' "$b" "$C_GREEN" "$C_RESET" "$d" "$(command -v "$b_cmd")"
            ok_count=$((ok_count + 1))
        else
            printf '  %-14s : %b[OPTIONAL]%b %s\n' "$b" "$C_DIM" "$C_RESET" "$d (Optional / Fallback Active)"
            opt_count=$((opt_count + 1))
        fi
    done
    printf '\n'

    # Summary
    printf '%s\n' '----------------------------------------------------------------------'
    printf 'DIAGNOSTIC SUMMARY: '
    printf '%b%d OK%b | ' "$C_GREEN" "$ok_count" "$C_RESET"
    printf '%b%d WARN%b | ' "$C_YELLOW" "$warn_count" "$C_RESET"
    printf '%b%d ERROR%b | ' "$C_RED" "$err_count" "$C_RESET"
    printf '%b%d MISSING%b | ' "$C_YELLOW" "$miss_count" "$C_RESET"
    printf '%b%d OPTIONAL%b\n' "$C_DIM" "$opt_count" "$C_RESET"

    if [[ "$err_count" -gt 0 ]]; then
        printf '%b[ERROR] Critical issues detected. Please run ./setup.sh to resolve requirements.%b\n' "$C_RED" "$C_RESET"
        return 1
    elif [[ "$warn_count" -gt 0 || "$miss_count" -gt 0 ]]; then
        printf '%b[WARN] TraceForge is operable, but optional dependencies can be installed with ./install_all.sh%b\n' "$C_YELLOW" "$C_RESET"
        return 0
    else
        printf '%b[OK] System environment is fully configured and healthy.%b\n' "$C_GREEN" "$C_RESET"
        return 0
    fi
}
