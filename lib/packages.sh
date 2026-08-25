#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — lib/packages.sh
# Ecosystem package managers: Homebrew, APT, Termux (pkg), pipx, Go, Gem, Cargo.
# =============================================================================

[[ -n "${_TRACEFORGE_LIB_PACKAGES_LOADED:-}" ]] && return 0
readonly _TRACEFORGE_LIB_PACKAGES_LOADED=1

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/common.sh"
# shellcheck source=lib/platform.sh
source "$SCRIPT_DIR/platform.sh"

APT_UPDATED_FLAG=0
TERMUX_UPDATED_FLAG=0
VENV_PATH="$(project_root)/.osint_venv"

# Execute with appropriate privileges depending on platform
sudo_exec() {
    if [[ "$OS_TYPE" == "termux" ]]; then
        # Termux operates in userland prefix ($PREFIX); never invoke sudo/root blindly
        "$@"
    elif [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die "Root permissions are required for this action, but 'sudo' is not available."
    fi
}

# Update Termux package metadata cache
termux_update_cached() {
    if [[ "$TERMUX_UPDATED_FLAG" -eq 1 ]]; then
        return 0
    fi
    info "Updating Termux package repository metadata..."
    if need_cmd pkg; then
        pkg update -y || warn "Termux 'pkg update' returned non-zero; continuing."
    else
        apt-get update -y || warn "Termux 'apt-get update' returned non-zero; continuing."
    fi
    TERMUX_UPDATED_FLAG=1
}

# Install Termux native package
install_termux_package() {
    local package=$1
    local binary_check=${2:-""}
    [[ -n "$package" && "$package" != "manual" && "$package" != "n/a" && "$package" != "-" ]] || return 0

    if [[ -n "$binary_check" ]] && need_cmd "$binary_check"; then
        info "Binary already available: $binary_check"
        return 0
    fi

    termux_update_cached
    info "Installing Termux package: $package"
    if need_cmd pkg; then
        pkg install -y "$package" || {
            warn "Termux 'pkg' failed to install package '$package'."
            return 1
        }
    else
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" || {
            warn "Termux 'apt-get' failed to install package '$package'."
            return 1
        }
    fi
}

# Check and guide Termux shared storage setup
ensure_termux_storage() {
    if [[ "$OS_TYPE" != "termux" ]]; then
        return 0
    fi
    if [[ -d "$HOME/storage" && -r "$HOME/storage" ]]; then
        return 0
    fi

    warn "Shared Android storage is not available yet."
    printf '\n%bTo grant TraceForge access to Android shared files (/sdcard, Downloads, DCIM), run:%b\n' "$C_YELLOW" "$C_RESET"
    printf '  %btermux-setup-storage%b\n\n' "$C_BOLD" "$C_RESET"
    printf 'Then restart or retry your investigation.\n\n'
    return 1
}

# Update APT metadata once per session only when an installation is actually required
apt_update_cached() {
    if [[ "$APT_UPDATED_FLAG" -eq 1 ]]; then
        return 0
    fi
    info "Updating APT package cache..."
    sudo_exec apt-get update -y
    APT_UPDATED_FLAG=1
}

# Install Homebrew if absent on macOS
ensure_homebrew_installed() {
    if need_cmd brew; then
        init_environment_paths
        return 0
    fi

    if [[ "$OS_TYPE" != "darwin" ]]; then
        warn "Homebrew auto-installer is primarily for macOS."
        return 1
    fi

    info "Homebrew not detected. Launching official Homebrew installation script..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    init_environment_paths

    if ! need_cmd brew; then
        die "Homebrew installation completed but 'brew' command is still not found in PATH."
    fi
}

# Install a formula via Homebrew
install_brew_formula() {
    local formula=$1
    [[ -n "$formula" && "$formula" != "manual" && "$formula" != "n/a" && "$formula" != "-" ]] || return 0

    ensure_homebrew_installed

    if brew list --formula "$formula" >/dev/null 2>&1; then
        info "Homebrew formula already installed: $formula"
        return 0
    fi

    info "Installing Homebrew formula: $formula"
    brew install "$formula" || {
        warn "Failed to install Homebrew formula '$formula'. Please check manual installation."
        return 1
    }
}

# Install packages via APT (Debian/Ubuntu/Kali)
install_apt_package() {
    local package=$1
    local binary_check=${2:-""}
    [[ -n "$package" && "$package" != "manual" && "$package" != "n/a" && "$package" != "-" ]] || return 0

    if [[ -n "$binary_check" ]] && need_cmd "$binary_check"; then
        info "Binary already available: $binary_check"
        return 0
    fi

    apt_update_cached
    info "Installing APT package: $package"
    DEBIAN_FRONTEND=noninteractive sudo_exec apt-get install -y "$package" || {
        warn "APT failed to install package '$package'."
        return 1
    }
}

# Ensure pipx exists and complies with PEP 668
ensure_pipx() {
    init_environment_paths
    if need_cmd pipx; then
        return 0
    fi

    info "Setting up isolated pipx environment (PEP 668 compliant)..."

    if [[ "$OS_TYPE" == "darwin" ]]; then
        install_brew_formula pipx
        init_environment_paths
        pipx ensurepath >/dev/null 2>&1 || true
        return 0
    fi

    if [[ "$OS_TYPE" == "termux" ]]; then
        install_termux_package "python" "python3"
        python3 -m pip install --user --upgrade pip pipx 2>/dev/null || {
            info "Creating isolated virtualenv for pipx under Termux..."
            python3 -m venv "$VENV_PATH"
            "$VENV_PATH/bin/pip" install pipx
            mkdir -p "$HOME/.local/bin"
            ln -sf "$VENV_PATH/bin/pipx" "$HOME/.local/bin/pipx"
        }
        init_environment_paths
        return 0
    fi

    # Linux flow: Try system pipx first
    if [[ "$OS_TYPE" == "linux" ]]; then
        apt_update_cached
        if apt-cache show pipx >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive sudo_exec apt-get install -y pipx
            init_environment_paths
            pipx ensurepath >/dev/null 2>&1 || true
            return 0
        fi
    fi

    # Fallback: Create dedicated project virtualenv for pipx
    if ! need_cmd python3; then
        install_apt_package "python3" "python3"
        install_apt_package "python3-venv" ""
    fi

    if [[ ! -d "$VENV_PATH" ]]; then
        info "Creating isolated Python environment at $VENV_PATH..."
        python3 -m venv "$VENV_PATH"
    fi

    "$VENV_PATH/bin/python" -m pip install --upgrade pip pipx
    mkdir -p "$HOME/.local/bin"
    ln -sf "$VENV_PATH/bin/pipx" "$HOME/.local/bin/pipx"
    init_environment_paths
}

# Install isolated Python CLI tool via pipx
install_pipx_app() {
    local package=$1
    local binary_name=${2:-"$package"}
    [[ -n "$package" && "$package" != "manual" && "$package" != "n/a" && "$package" != "-" ]] || return 0

    ensure_pipx

    if need_cmd "$binary_name"; then
        info "Python tool already installed: $binary_name"
        return 0
    fi

    info "Installing Python application via pipx: $package"
    pipx install "$package" || {
        warn "pipx failed to install '$package'."
        return 1
    }
    init_environment_paths
}

# Ensure Go toolchain is available
ensure_go() {
    init_environment_paths
    if need_cmd go; then
        return 0
    fi

    info "Installing Go toolchain..."
    if [[ "$OS_TYPE" == "darwin" ]]; then
        install_brew_formula go
    elif [[ "$OS_TYPE" == "termux" ]]; then
        install_termux_package "golang" "go"
    else
        install_apt_package "golang-go" "go"
    fi
    init_environment_paths
}

# Install a Go binary via `go install`
install_go_tool() {
    local binary_name=$1
    local module_path=$2
    [[ -n "$binary_name" && -n "$module_path" && "$module_path" != "manual" ]] || return 0

    ensure_go
    if ! need_cmd go; then
        warn "Go compiler not available; skipping Go tool $binary_name."
        return 1
    fi

    if need_cmd "$binary_name"; then
        info "Go tool already installed: $binary_name"
        return 0
    fi

    info "Compiling and installing Go tool: $binary_name ($module_path)..."
    mkdir -p "${GOPATH:-$HOME/go}/bin"
    go install "$module_path" || {
        warn "Failed to install Go tool $binary_name ($module_path)."
        return 1
    }
    init_environment_paths
}

# Ensure Ruby and Gem toolchain is available
ensure_ruby() {
    init_environment_paths
    if need_cmd ruby && need_cmd gem; then
        return 0
    fi

    info "Installing Ruby environment..."
    if [[ "$OS_TYPE" == "darwin" ]]; then
        install_brew_formula ruby
    elif [[ "$OS_TYPE" == "termux" ]]; then
        install_termux_package "ruby" "ruby"
        install_termux_package "make" "make"
        install_termux_package "clang" "clang"
    else
        install_apt_package "ruby-full" "ruby"
        install_apt_package "make" "make"
        install_apt_package "gcc" "gcc"
        install_apt_package "zlib1g-dev" ""
    fi
    init_environment_paths
}

# Install Ruby Gem tool
install_gem_tool() {
    local gem_name=$1
    local binary_name=${2:-"$gem_name"}
    [[ -n "$gem_name" && "$gem_name" != "manual" && "$gem_name" != "n/a" ]] || return 0

    ensure_ruby
    if ! need_cmd gem; then
        warn "RubyGems unavailable; skipping $gem_name."
        return 1
    fi

    if need_cmd "$binary_name"; then
        info "Ruby gem already installed: $binary_name"
        return 0
    fi

    info "Installing Ruby gem: $gem_name"
    if [[ "$OS_TYPE" == "darwin" || "$OS_TYPE" == "termux" ]]; then
        gem install --user-install "$gem_name" || {
            warn "Failed to install gem '$gem_name'."
            return 1
        }
    else
        sudo_exec gem install "$gem_name" || {
            warn "Failed to install gem '$gem_name'."
            return 1
        }
    fi
    init_environment_paths
}

# Ensure Rust / Cargo toolchain is available
ensure_cargo() {
    init_environment_paths
    if need_cmd cargo; then
        return 0
    fi

    info "Installing Rust/Cargo toolchain..."
    if [[ "$OS_TYPE" == "darwin" ]]; then
        install_brew_formula rust
    elif [[ "$OS_TYPE" == "termux" ]]; then
        install_termux_package "rust" "cargo"
    else
        install_apt_package "cargo" "cargo"
    fi
    init_environment_paths
}

# Install Cargo crate binary
install_cargo_tool() {
    local crate_name=$1
    local binary_name=${2:-"$crate_name"}
    [[ -n "$crate_name" && "$crate_name" != "manual" && "$crate_name" != "n/a" ]] || return 0

    ensure_cargo
    if ! need_cmd cargo; then
        warn "Cargo unavailable; skipping crate $crate_name."
        return 1
    fi

    if need_cmd "$binary_name"; then
        info "Cargo binary already installed: $binary_name"
        return 0
    fi

    info "Building and installing Cargo crate: $crate_name..."
    cargo install "$crate_name" || {
        warn "Failed to install Cargo crate '$crate_name'."
        return 1
    }
    init_environment_paths
}
