#!/usr/bin/env bash
# TraceForge 1.0.0 — Primary Setup & Environment Installer
# Supports macOS (Homebrew), Linux (Debian/Ubuntu/Kali/Arch/Fedora), and Termux (Android).

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
cd "$ROOT_DIR"

PROFILE="recommended"
DRY_RUN=0
NON_INTERACTIVE=0
AUTO_INSTALL_DEPS=1

show_help() {
    cat << 'EOF'
TraceForge 1.0.0 — First-Time Setup & Installer

Usage:
  ./setup.sh [options]

Options:
  --profile <name>       Setup profile: minimal | recommended | full | custom
  --no-system-deps       Skip automatic installation of system packages (git, python, etc.)
  --dry-run              Preview planned setup actions without modifying system
  --non-interactive, -y  Run without prompting for confirmations
  --help, -h             Show this help message

Profiles:
  minimal                Install only TraceForge and core Python requirements (<250MB)
  recommended            TraceForge + Go native fast-paths + core OSINT tools (~1.2GB)
  full                   Comprehensive suite including all 152 catalog utilities (~3.5GB)
  custom                 Interactive selection of components and tools

Examples:
  ./setup.sh                          # Interactive friendly setup
  ./setup.sh --profile recommended    # Direct recommended installation
  ./setup.sh -y                       # Non-interactive automated install
  ./setup.sh --dry-run                # Preview installation steps
EOF
    exit 0
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
        --non-interactive|-y)
            NON_INTERACTIVE=1
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            echo "[-] Unknown option: $1" >&2
            show_help
            ;;
    esac
done

echo "======================================================================"
echo "                   TRACEFORGE 1.0.0 — SETUP"
echo "        Open-Source Intelligence & Digital Forensics Suite"
echo "======================================================================"

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
OS_NAME="unknown"
ARCH_NAME=$(uname -m 2>/dev/null || echo "unknown")
IS_TERMUX=0
PKG_MGR="none"

if [[ -n "${TERMUX_VERSION:-}" ]] || [[ -d "/data/data/com.termux" ]] || [[ "${PREFIX:-}" == *com.termux* ]]; then
    IS_TERMUX=1
    OS_NAME="termux"
    PKG_MGR="pkg"
elif [[ "$(uname -s 2>/dev/null)" == "Darwin" ]]; then
    OS_NAME="darwin"
    if command -v brew >/dev/null 2>&1; then
        PKG_MGR="brew"
    elif [[ -x "/opt/homebrew/bin/brew" ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
        PKG_MGR="brew"
    elif [[ -x "/usr/local/bin/brew" ]]; then
        eval "$(/usr/local/bin/brew shellenv)"
        PKG_MGR="brew"
    fi
elif [[ "$(uname -s 2>/dev/null)" == "Linux" ]]; then
    OS_NAME="linux"
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

echo "[+] Detected Platform : $OS_NAME ($ARCH_NAME)"
echo "[+] Package Manager   : $PKG_MGR"

# 2. Automated Base System Dependencies Installation
install_system_base_packages() {
    [[ "$AUTO_INSTALL_DEPS" -eq 1 ]] || return 0

    echo "[*] Checking base system requirements (git, python3, curl, ffmpeg, build tools)..."

    if [[ "$IS_TERMUX" -eq 1 ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "    [dry-run] pkg update && pkg install -y git python python-pip curl wget ffmpeg ca-certificates tar gzip unzip gnupg clang make"
            return 0
        fi
        echo "[*] Updating Termux package repositories..."
        pkg update -y 2>/dev/null || apt-get update -y 2>/dev/null || true
        echo "[*] Installing Termux base toolchain..."
        pkg install -y git python python-pip curl wget ffmpeg ca-certificates tar gzip unzip gnupg clang make 2>/dev/null || true

    elif [[ "$PKG_MGR" == "apt" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "    [dry-run] apt-get update && apt-get install -y git python3 python3-pip python3-venv python3-dev curl wget gnupg ca-certificates ffmpeg build-essential..."
            return 0
        fi
        echo "[*] Updating APT package cache..."
        DEBIAN_FRONTEND=noninteractive run_as_root apt-get update -y -qq || true

        echo "[*] Installing core runtime packages via APT..."
        DEBIAN_FRONTEND=noninteractive run_as_root apt-get install -y --no-install-recommends \
            git \
            python3 \
            python3-pip \
            python3-venv \
            python3-dev \
            curl \
            wget \
            gnupg \
            ca-certificates \
            tar \
            gzip \
            unzip \
            build-essential \
            ffmpeg \
            xdg-utils \
            lsb-release 2>/dev/null || true

        # Optional GUI / headless browser / rendering support libraries
        echo "[*] Ensuring graphical & document rendering dependencies..."
        DEBIAN_FRONTEND=noninteractive run_as_root apt-get install -y --no-install-recommends \
            fonts-liberation \
            libnss3 \
            libatk-bridge2.0-0 \
            libatk1.0-0 \
            libxcomposite1 \
            libxdamage1 \
            libxrandr2 \
            libgbm1 \
            libasound2 \
            libpangocairo-1.0-0 \
            libx11-xcb1 \
            libxext6 \
            libxrender1 \
            libxtst6 \
            libxshmfence1 \
            libglib2.0-0 \
            libdrm2 \
            libxfixes3 \
            libxcb1 \
            libxi6 \
            libpango-1.0-0 2>/dev/null || true

    elif [[ "$PKG_MGR" == "pacman" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "    [dry-run] pacman -Sy --noconfirm git python python-pip curl wget ffmpeg ca-certificates base-devel"
            return 0
        fi
        echo "[*] Installing base packages via pacman..."
        run_as_root pacman -Sy --noconfirm git python python-pip curl wget ffmpeg ca-certificates base-devel 2>/dev/null || true

    elif [[ "$PKG_MGR" == "dnf" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "    [dry-run] dnf install -y git python3 python3-pip python3-devel curl wget ffmpeg ca-certificates gcc gcc-c++ make"
            return 0
        fi
        echo "[*] Installing base packages via dnf..."
        run_as_root dnf install -y git python3 python3-pip python3-devel curl wget ffmpeg ca-certificates gcc gcc-c++ make 2>/dev/null || true

    elif [[ "$OS_NAME" == "darwin" ]]; then
        if ! command -v brew >/dev/null 2>&1; then
            echo "[*] Homebrew not detected. Installing Homebrew..."
            if [[ "$DRY_RUN" -eq 1 ]]; then
                echo "    [dry-run] Install Homebrew via official shell script"
            else
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" 2>/dev/null || true
                if [[ -x "/opt/homebrew/bin/brew" ]]; then
                    eval "$(/opt/homebrew/bin/brew shellenv)"
                    PKG_MGR="brew"
                elif [[ -x "/usr/local/bin/brew" ]]; then
                    eval "$(/usr/local/bin/brew shellenv)"
                    PKG_MGR="brew"
                fi
            fi
        fi

        if command -v brew >/dev/null 2>&1; then
            if [[ "$DRY_RUN" -eq 1 ]]; then
                echo "    [dry-run] brew install python@3.11 git curl wget ffmpeg ca-certificates"
            else
                echo "[*] Checking Homebrew base formulas (python, git, curl, ffmpeg)..."
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

# If python is still missing, attempt emergency install on supported systems
if [[ -z "$PYTHON_BIN" ]]; then
    echo "[!] Python 3.9+ was not found in PATH. Attempting automatic provisioning..."
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
    echo "[-] Error: Python 3.9 or higher is required but could not be detected or installed." >&2
    if [[ "$OS_NAME" == "darwin" ]]; then
        echo "    Install with: brew install python@3.11" >&2
    elif [[ "$IS_TERMUX" -eq 1 ]]; then
        echo "    Install with: pkg install python" >&2
    else
        echo "    Install with: sudo apt-get install python3 python3-venv python3-pip" >&2
    fi
    exit 1
fi

PY_VER=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo "unknown")
echo "[+] Detected Python   : $PYTHON_BIN (v$PY_VER)"

# 4. Interactive Profile Selection if not specified
if [[ "$NON_INTERACTIVE" -eq 0 ]] && [[ -t 0 ]]; then
    echo ""
    echo "Select an installation profile:"
    echo "  [1] Recommended (Python + Go fast-paths + Core tools ~1.2GB) [Default]"
    echo "  [2] Minimal     (TraceForge core engine + Python only <250MB)"
    echo "  [3] Full        (Complete 152-tool suite ~3.5GB)"
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

echo "[+] Selected Profile  : $INSTALL_PROFILE"

# 5. Dry Run Mode
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo ""
    echo "=== TraceForge Setup (DRY-RUN PREVIEW) ==="
    echo "Target Directory     : $ROOT_DIR"
    echo "Virtual Environment  : $ROOT_DIR/.venv"
    echo "Python Interpreter   : $PYTHON_BIN ($PY_VER)"
    echo "Installation Profile : $INSTALL_PROFILE"
    echo "Native Provisioning  : Will invoke ./install_all.sh --profile $INSTALL_PROFILE --dry-run"
    echo ""
    if [[ -f "$ROOT_DIR/install_all.sh" ]]; then
        "$ROOT_DIR/install_all.sh" --profile "$INSTALL_PROFILE" --dry-run
    fi
    echo "[+] Dry-run simulation completed. No changes were made."
    exit 0
fi

# 6. Virtual Environment Setup & Auto-Healing
VENV_DIR="$ROOT_DIR/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
    echo "[*] Creating virtual environment at .venv..."
    if ! "$PYTHON_BIN" -m venv "$VENV_DIR" 2>/dev/null; then
        echo "[!] Standard venv module creation failed. Attempting to install python3-venv / virtualenv..."
        if [[ "$PKG_MGR" == "apt" ]]; then
            DEBIAN_FRONTEND=noninteractive run_as_root apt-get install -y python3-venv python3-virtualenv 2>/dev/null || true
        elif [[ "$IS_TERMUX" -eq 1 ]]; then
            pkg install -y python-pip 2>/dev/null || true
        fi
        "$PYTHON_BIN" -m venv "$VENV_DIR" || "$PYTHON_BIN" -m virtualenv "$VENV_DIR"
    fi
fi

# Locate venv python
VENV_PY="$VENV_DIR/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
    echo "[-] Error: Virtual environment Python not found at $VENV_PY" >&2
    exit 1
fi

echo "[*] Upgrading pip and build tools in virtual environment..."
"$VENV_PY" -m pip install --quiet --upgrade pip setuptools wheel 2>/dev/null || "$VENV_PY" -m pip install --upgrade pip setuptools wheel

# 7. Install TraceForge in Editable Mode
echo "[*] Installing TraceForge into virtual environment..."
"$VENV_PY" -m pip install --quiet -e . 2>/dev/null || "$VENV_PY" -m pip install -e .

# 8. Optional Native Helpers & Tools Provisioning
if [[ "$INSTALL_PROFILE" != "minimal" ]] && [[ -f "$ROOT_DIR/install_all.sh" ]]; then
    echo "[*] Provisioning profile dependencies ($INSTALL_PROFILE)..."
    bash "$ROOT_DIR/install_all.sh" --profile "$INSTALL_PROFILE"
fi

# 9. Build Go Fast-Path Binary if Go is installed
if command -v go >/dev/null 2>&1 && [[ -d "$ROOT_DIR/go" ]]; then
    echo "[*] Compiling Go fast-path acceleration binary..."
    mkdir -p "$ROOT_DIR/bin"
    (cd "$ROOT_DIR/go" && go build -trimpath -ldflags="-s -w" -o "$ROOT_DIR/bin/traceforge-native" .) 2>/dev/null || true
    if [[ -x "$ROOT_DIR/bin/traceforge-native" ]]; then
        echo "[+] Go acceleration binary built: bin/traceforge-native"
    fi
fi

# 10. Set executable permissions
chmod +x "$ROOT_DIR/run.sh" "$ROOT_DIR/main.sh" "$ROOT_DIR/setup.sh" "$ROOT_DIR/install_all.sh" "$ROOT_DIR/modules"/*.sh "$ROOT_DIR/scripts"/*.sh 2>/dev/null || true

# 11. Verify Installation
echo ""
echo "======================================================================"
echo "                  TRACEFORGE INSTALLATION COMPLETE"
echo "======================================================================"
"$VENV_PY" -m traceforge --version || true

echo ""
echo "Launch TraceForge with:"
echo "  ./run.sh"
echo ""
echo "Or activate the virtual environment:"
echo "  source .venv/bin/activate"
echo "  traceforge"
echo ""
echo "Run diagnostics any time with:"
echo "  ./run.sh doctor"
echo "======================================================================"
