#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# TraceForge 1.0.0 — Primary Setup & Environment Installer
# Supports macOS (Homebrew), Linux (Debian/Ubuntu/Kali/Arch/Fedora), and Termux (Android).

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
cd "$ROOT_DIR"

# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"

PROFILE="recommended"
DRY_RUN=0
NON_INTERACTIVE=0
AUTO_INSTALL_DEPS=1
REPAIR_MODE=0
VERBOSE_MODE=0
OFFLINE_MODE=0

show_help() {
    local exit_code="${1:-0}"
    cat << 'EOF'
TraceForge 1.0.0 — First-Time Setup & Installer

Usage:
  ./setup.sh [options]

Options:
  --profile <name>       Setup profile: minimal | recommended | full | custom
  --no-system-deps       Skip automatic installation of system packages (git, python, etc.)
  --dry-run              Preview planned setup actions without modifying system
  --repair               Verify and repair existing virtualenv / toolchain installation
  --offline              Offline mode: skip package manager updates and network downloads
  --verbose, -v          Show detailed command output during installation
  --non-interactive, -y  Run without prompting for confirmations
  --help, -h             Show this help message

Profiles:
  minimal                Install only TraceForge and core Python runtime (<250MB)
  recommended            TraceForge + Go native fast-paths + core OSINT tools (~1.2GB)
  full                   Comprehensive suite including all installable catalog utilities (~3.5GB)
  custom                 Interactive selection of components and tools

Examples:
  ./setup.sh                          # Interactive friendly setup
  ./setup.sh --profile recommended    # Direct recommended installation
  ./setup.sh -y                       # Non-interactive automated install
  ./setup.sh --dry-run                # Preview installation steps
  ./setup.sh --repair                 # Repair an existing installation
  ./setup.sh --offline                # Setup with existing local tools without network calls
EOF
    exit "$exit_code"
}

# Parse CLI flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="${2:-}"
            NON_INTERACTIVE=1
            shift 2
            ;;
        --no-system-deps)
            AUTO_INSTALL_DEPS=0
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --repair)
            REPAIR_MODE=1
            shift
            ;;
        --offline)
            OFFLINE_MODE=1
            AUTO_INSTALL_DEPS=0
            shift
            ;;
        --verbose|-v)
            VERBOSE_MODE=1
            shift
            ;;
        --non-interactive|-y)
            NON_INTERACTIVE=1
            shift
            ;;
        --help|-h)
            show_help 0
            ;;
        *)
            log_err "Unknown option: $1"
            show_help 1
            ;;
    esac
done


printf '%b' "$C_MAGENTA"
printf '%s\n' '======================================================================'
printf '%s\n' '                   TRACEFORGE 1.0.0 — SETUP                           '
printf '%s\n' '        Open-Source Intelligence & Digital Forensics Suite            '
printf '%s\n' '======================================================================'
printf '%b\n' "$C_RESET"

# Privilege execution helper
run_as_root() {
    if [[ "$IS_TERMUX" -eq 1 ]]; then
        "$@"
    elif [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        "$@"
    fi
}

# 1. Platform Detection
detect_platform
init_environment_paths

PKG_MGR="none"
if [[ "$IS_TERMUX" -eq 1 ]]; then
    PKG_MGR="pkg"
elif [[ "$OS_TYPE" == "darwin" ]]; then
    if command -v brew >/dev/null 2>&1 || [[ -x "/opt/homebrew/bin/brew" ]] || [[ -x "/usr/local/bin/brew" ]]; then
        PKG_MGR="brew"
    fi
elif [[ "$OS_TYPE" == "linux" ]]; then
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MGR="apt"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MGR="pacman"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
    elif command -v zypper >/dev/null 2>&1; then
        PKG_MGR="zypper"
    elif command -v apk >/dev/null 2>&1; then
        PKG_MGR="apk"
    fi
fi

log_info "Detected Platform : $OS_NAME ($OS_ARCH)"
log_info "Package Manager   : $PKG_MGR"
if [[ "$OFFLINE_MODE" -eq 1 ]]; then
    log_info "Operating Mode    : OFFLINE (Network updates bypassed)"
fi

# 2. Automated Base System Dependencies Installation
install_system_base_packages() {
    [[ "$AUTO_INSTALL_DEPS" -eq 1 ]] || return 0
    [[ "$OFFLINE_MODE" -eq 0 ]] || return 0

    log_step "Checking base system requirements (git, python3, curl, build tools)..."

    if [[ "$IS_TERMUX" -eq 1 ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_info "[DRY-RUN] pkg update && pkg install -y git python python-pip curl wget ffmpeg ca-certificates tar gzip unzip gnupg clang make"
            return 0
        fi
        log_info "Updating Termux package repositories..."
        pkg update -y 2>/dev/null || apt-get update -y 2>/dev/null || true
        log_info "Installing Termux base toolchain..."
        pkg install -y git python python-pip curl wget ffmpeg ca-certificates tar gzip unzip gnupg clang make 2>/dev/null || true

    elif [[ "$PKG_MGR" == "apt" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_info "[DRY-RUN] apt-get update && apt-get install -y git python3 python3-pip python3-venv python3-dev curl wget gnupg ca-certificates ffmpeg build-essential..."
            return 0
        fi
        log_info "Updating APT package cache..."
        DEBIAN_FRONTEND=noninteractive run_as_root apt-get update -y -qq || true

        log_info "Installing core runtime packages via APT..."
        DEBIAN_FRONTEND=noninteractive run_as_root apt-get install -y --no-install-recommends \
            git python3 python3-pip python3-venv python3-dev curl wget gnupg ca-certificates \
            tar gzip unzip build-essential ffmpeg xdg-utils lsb-release 2>/dev/null || true

    elif [[ "$PKG_MGR" == "pacman" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_info "[DRY-RUN] pacman -Sy --noconfirm git python python-pip curl wget ffmpeg ca-certificates base-devel"
            return 0
        fi
        log_info "Installing base packages via pacman..."
        run_as_root pacman -Sy --noconfirm git python python-pip curl wget ffmpeg ca-certificates base-devel 2>/dev/null || true

    elif [[ "$PKG_MGR" == "dnf" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_info "[DRY-RUN] dnf install -y git python3 python3-pip python3-devel curl wget ffmpeg ca-certificates gcc gcc-c++ make"
            return 0
        fi
        log_info "Installing base packages via dnf..."
        run_as_root dnf install -y git python3 python3-pip python3-devel curl wget ffmpeg ca-certificates gcc gcc-c++ make 2>/dev/null || true

    elif [[ "$OS_TYPE" == "darwin" ]]; then
        if ! command -v brew >/dev/null 2>&1; then
            log_info "Homebrew not detected. Installing Homebrew..."
            if [[ "$DRY_RUN" -eq 1 ]]; then
                log_info "[DRY-RUN] Install Homebrew via official shell script"
            else
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" 2>/dev/null || true
                init_environment_paths
            fi
        fi

        if command -v brew >/dev/null 2>&1; then
            if [[ "$DRY_RUN" -eq 1 ]]; then
                log_info "[DRY-RUN] brew install python@3.11 git curl wget ffmpeg ca-certificates"
            else
                log_info "Checking Homebrew base formulas (python, git, curl, ffmpeg)..."
                brew install python@3.11 git curl wget ffmpeg ca-certificates 2>/dev/null || true
            fi
        fi
    fi
}

install_system_base_packages

# 3. Locate Python Interpreter (>= 3.9)
find_python_interpreter() {
    local py_cand=""
    for cand in python3.13 python3.12 python3.11 python3.10 python3.9 python3 python; do
        if command -v "$cand" >/dev/null 2>&1; then
            if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
                py_cand=$(command -v "$cand")
                echo "$py_cand"
                return 0
            fi
        fi
    done
    echo ""
    return 1
}

PYTHON_BIN=$(find_python_interpreter || true)

if [[ -z "$PYTHON_BIN" && "$OFFLINE_MODE" -eq 0 ]]; then
    log_warn "Python 3.9+ was not found in PATH. Attempting automatic provisioning..."
    if [[ "$PKG_MGR" == "apt" ]]; then
        DEBIAN_FRONTEND=noninteractive run_as_root apt-get update -y && DEBIAN_FRONTEND=noninteractive run_as_root apt-get install -y python3 python3-venv python3-pip python3-dev
    elif [[ "$IS_TERMUX" -eq 1 ]]; then
        pkg install -y python python-pip
    elif [[ "$PKG_MGR" == "brew" ]]; then
        brew install python@3.11
    fi
    PYTHON_BIN=$(find_python_interpreter || true)
fi

if [[ -z "$PYTHON_BIN" ]]; then
    log_err "Python 3.9 or higher is required but could not be detected."
    if [[ "$OS_TYPE" == "darwin" ]]; then
        echo "    Install with: brew install python@3.11" >&2
    elif [[ "$IS_TERMUX" -eq 1 ]]; then
        echo "    Install with: pkg install python" >&2
    else
        echo "    Install with: sudo apt-get install python3 python3-venv python3-pip" >&2
    fi
    exit 1
fi

PY_VER=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo "unknown")
log_ok "Detected Python   : $PYTHON_BIN (v$PY_VER)"

# 4. Interactive Profile Selection if not specified
if [[ "$NON_INTERACTIVE" -eq 0 ]] && [[ -t 0 ]]; then
    echo ""
    echo "Select an installation profile:"
    echo "  [1] Recommended (Python + Go fast-paths + Core tools ~1.2GB) [Default]"
    echo "  [2] Minimal     (TraceForge core engine + Python only <250MB)"
    echo "  [3] Full        (Complete installable catalog suite ~3.5GB)"
    echo "  [4] Custom      (Manual component selection)"
    read -r -p "Enter choice [1-4, Default: 1]: " prof_choice
    case "$prof_choice" in
        2|"minimal"|"m")
            PROFILE="minimal"
            ;;
        3|"full"|"f")
            PROFILE="full"
            ;;
        4|"custom"|"c")
            PROFILE="custom"
            ;;
        *)
            PROFILE="recommended"
            ;;
    esac
fi

# Normalize profile names
case "$PROFILE" in
    recommended|python-go)
        INSTALL_PROFILE="python-go"
        ;;
    minimal|min)
        INSTALL_PROFILE="minimal"
        ;;
    full)
        INSTALL_PROFILE="full"
        ;;
    custom)
        INSTALL_PROFILE="custom"
        ;;
    *)
        INSTALL_PROFILE="python-go"
        ;;
esac

log_info "Selected Profile  : $INSTALL_PROFILE"

# 5. Dry Run Mode
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo ""
    echo "=== TraceForge Setup (DRY-RUN PREVIEW) ==="
    echo "Target Directory     : $ROOT_DIR"
    echo "Virtual Environment  : $ROOT_DIR/.venv"
    echo "Python Interpreter   : $PYTHON_BIN ($PY_VER)"
    echo "Installation Profile : $INSTALL_PROFILE"
    echo "Offline Mode         : $OFFLINE_MODE"
    echo "Native Provisioning  : Will invoke ./install_all.sh --profile $INSTALL_PROFILE --dry-run"
    echo ""
    if [[ -f "$ROOT_DIR/install_all.sh" ]]; then
        bash "$ROOT_DIR/install_all.sh" --profile "$INSTALL_PROFILE" --dry-run
    fi
    log_ok "Dry-run simulation completed. No changes were made."
    exit 0
fi

# 6. Virtual Environment Setup & Auto-Healing
VENV_DIR="$ROOT_DIR/.venv"
if [[ "$REPAIR_MODE" -eq 1 ]] && [[ -d "$VENV_DIR" ]]; then
    log_step "Repair mode: validating virtual environment integrity..."
    if [[ ! -x "$VENV_DIR/bin/python" ]]; then
        log_warn "Corrupted virtual environment detected. Removing and recreating..."
        rm -rf "$VENV_DIR"
    fi
fi

if [[ ! -d "$VENV_DIR" ]]; then
    log_step "Creating virtual environment at .venv..."
    if ! "$PYTHON_BIN" -m venv "$VENV_DIR" 2>/dev/null; then
        log_warn "Standard venv module creation failed. Attempting fallback..."
        if [[ "$PKG_MGR" == "apt" && "$OFFLINE_MODE" -eq 0 ]]; then
            DEBIAN_FRONTEND=noninteractive run_as_root apt-get install -y python3-venv python3-virtualenv 2>/dev/null || true
        elif [[ "$IS_TERMUX" -eq 1 && "$OFFLINE_MODE" -eq 0 ]]; then
            pkg install -y python-pip 2>/dev/null || true
        fi
        "$PYTHON_BIN" -m venv "$VENV_DIR" || "$PYTHON_BIN" -m virtualenv "$VENV_DIR"
    fi
fi

VENV_PY="$VENV_DIR/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
    log_err "Virtual environment Python not found at $VENV_PY"
    exit 1
fi

if [[ "$OFFLINE_MODE" -eq 0 ]]; then
    log_step "Upgrading pip and build tools in virtual environment..."
    if [[ "$VERBOSE_MODE" -eq 1 ]]; then
        "$VENV_PY" -m pip install --upgrade pip setuptools wheel
    else
        "$VENV_PY" -m pip install --quiet --upgrade pip setuptools wheel 2>/dev/null || "$VENV_PY" -m pip install --upgrade pip setuptools wheel
    fi
fi

# 7. Install TraceForge in Editable Mode
log_step "Installing TraceForge into virtual environment..."
PIP_INSTALL_FLAGS=("-e" ".")
if [[ "$OFFLINE_MODE" -eq 1 ]]; then
    PIP_INSTALL_FLAGS+=("--no-build-isolation")
fi

if [[ "$VERBOSE_MODE" -eq 1 ]]; then
    "$VENV_PY" -m pip install "${PIP_INSTALL_FLAGS[@]}"
else
    "$VENV_PY" -m pip install --quiet "${PIP_INSTALL_FLAGS[@]}" 2>/dev/null || "$VENV_PY" -m pip install "${PIP_INSTALL_FLAGS[@]}"
fi

# 8. Optional Native Helpers & Tools Provisioning
if [[ "$INSTALL_PROFILE" != "minimal" ]] && [[ -f "$ROOT_DIR/install_all.sh" ]]; then
    log_step "Provisioning profile dependencies ($INSTALL_PROFILE)..."
    INSTALL_ALL_ARGS=("--profile" "$INSTALL_PROFILE")
    if [[ "$OFFLINE_MODE" -eq 1 ]]; then
        INSTALL_ALL_ARGS+=("--offline")
    fi
    bash "$ROOT_DIR/install_all.sh" "${INSTALL_ALL_ARGS[@]}"
fi

# 9. Build Go Fast-Path Binary using scripts/build_native.sh
if [[ -f "$ROOT_DIR/scripts/build_native.sh" ]]; then
    log_step "Checking / building Go native helpers..."
    if [[ "$REPAIR_MODE" -eq 1 ]]; then
        bash "$ROOT_DIR/scripts/build_native.sh" --force
    else
        bash "$ROOT_DIR/scripts/build_native.sh"
    fi
fi

# 10. Set executable permissions safely
chmod +x "$ROOT_DIR/run.sh" "$ROOT_DIR/main.sh" "$ROOT_DIR/setup.sh" "$ROOT_DIR/install_all.sh" \
    "$ROOT_DIR/modules"/*.sh "$ROOT_DIR/scripts"/*.sh 2>/dev/null || true

# 11. Ensure global shell PATH exports are configured (~/.zshrc, ~/.bashrc)
if command -v persist_user_shell_paths >/dev/null 2>&1; then
    persist_user_shell_paths || true
fi

# 12. Run repair diagnostics if requested
if [[ "$REPAIR_MODE" -eq 1 ]]; then
    log_step "Executing automated system repair routines..."
    "$VENV_PY" -m traceforge doctor --repair 2>/dev/null || true
fi

# 13. Dynamic Installation Summary

printf '\n%b' "$C_MAGENTA"
printf '%s\n' '======================================================================'
printf '%s\n' '                  TRACEFORGE INSTALLATION COMPLETE                    '
printf '%s\n' '======================================================================'
printf '%b\n' "$C_RESET"

"$VENV_PY" -m traceforge --version 2>/dev/null || log_ok "TraceForge core installed."

echo ""
echo "You can now run TraceForge globally from any directory:"
echo "  traceforge"
echo ""
echo "Common Commands:"
echo "  traceforge doctor              Run system & toolchain diagnostics"
echo "  traceforge cases               List investigation cases"
echo "  traceforge web                 Launch interactive web console"
echo "  traceforge investigate <mod>   Run forensics & reconnaissance modules"
echo "  traceforge batch plan <target> Create multi-tool batch execution plan"
echo "  traceforge config paths        Show configuration and user data directories"
echo "  traceforge --help              View full CLI manual"
echo ""
echo "Development / Repository Launchers:"
echo "  ./main.sh                      Launch interactive operator console"
echo "  ./run.sh                       Thin CLI runner"
echo "======================================================================"
