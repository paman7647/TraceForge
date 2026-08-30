#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# TraceForge — lib/platform.sh
# Cross-platform host identification, Termux/Android detection & path discovery.

[[ -n "${_TRACEFORGE_LIB_PLATFORM_LOADED:-}" ]] && return 0
readonly _TRACEFORGE_LIB_PLATFORM_LOADED=1

export OS_TYPE="unknown"
export OS_NAME="Unknown"
export OS_ARCH="$(uname -m 2>/dev/null || echo "unknown")"
export LINUX_DISTRO="unknown"
export LINUX_VERSION="unknown"
export BREW_PREFIX=""
export HOMEBREW_BIN=""
export IS_TERMUX=0
export TERMUX_PREFIX=""
export TERMUX_STORAGE_DIR="$HOME/storage"
export TERMUX_STORAGE_AVAILABLE=0
export TERMUX_API_AVAILABLE=0

detect_platform() {
    # 1. First-class Termux / Android Detection (multi-indicator verification)
    if [[ -n "${TERMUX_VERSION:-}" ]] || \
       [[ -n "${PREFIX:-}" && "$PREFIX" == *"/com.termux/"* && -d "$PREFIX" ]] || \
       [[ -d "/data/data/com.termux/files/usr" ]]; then
        OS_TYPE="termux"
        OS_NAME="Termux"
        LINUX_DISTRO="termux"
        LINUX_VERSION="${TERMUX_VERSION:-1.0}"
        IS_TERMUX=1
        TERMUX_PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

        # Check Android shared storage mount status
        if [[ -d "$TERMUX_STORAGE_DIR" && -r "$TERMUX_STORAGE_DIR" ]]; then
            TERMUX_STORAGE_AVAILABLE=1
        else
            TERMUX_STORAGE_AVAILABLE=0
        fi

        # Check Termux:API command availability
        if command -v termux-battery-status >/dev/null 2>&1 || \
           command -v termux-wifi-connectioninfo >/dev/null 2>&1; then
            TERMUX_API_AVAILABLE=1
        else
            TERMUX_API_AVAILABLE=0
        fi
        return 0
    fi

    local raw_os="${OSTYPE:-}"
    raw_os="$(echo "$raw_os" | tr '[:upper:]' '[:lower:]')"

    case "$raw_os" in
        darwin*)
            OS_TYPE="darwin"
            OS_NAME="macOS"
            ;;
        linux*)
            OS_TYPE="linux"
            OS_NAME="Linux"
            if [[ -r /etc/os-release ]]; then
                LINUX_DISTRO="$(awk -F= '$1=="ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)"
                LINUX_VERSION="$(awk -F= '$1=="VERSION_ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)"
            elif command -v lsb_release >/dev/null 2>&1; then
                LINUX_DISTRO="$(lsb_release -si 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "linux")"
                LINUX_VERSION="$(lsb_release -sr 2>/dev/null || echo "unknown")"
            elif [[ -r /etc/debian_version ]]; then
                LINUX_DISTRO="debian"
                LINUX_VERSION="$(cat /etc/debian_version)"
            elif [[ -r /etc/arch-release ]]; then
                LINUX_DISTRO="arch"
                LINUX_VERSION="rolling"
            elif [[ -r /etc/fedora-release ]]; then
                LINUX_DISTRO="fedora"
                LINUX_VERSION="$(awk '{print $3}' /etc/fedora-release 2>/dev/null || echo "unknown")"
            fi
            ;;
        *)
            OS_TYPE="unknown"
            OS_NAME="Unknown OS ($raw_os)"
            ;;
    esac
}

init_environment_paths() {
    # 0. Suite native binaries ($ROOT_DIR/bin or current directory bin)
    local root_base="${ROOT_DIR:-}"
    if [[ -z "$root_base" ]] && command -v project_root >/dev/null 2>&1; then
        root_base="$(project_root 2>/dev/null || pwd -P)"
    fi
    [[ -z "$root_base" ]] && root_base="$(pwd -P)"
    local suite_bin="$root_base/bin"
    if [[ -d "$suite_bin" ]]; then
        case ":$PATH:" in
            *":$suite_bin:"*) ;;
            *) export PATH="$suite_bin:$PATH" ;;
        esac
    fi

    # 1. Termux environment binaries ($PREFIX/bin)
    if [[ "$OS_TYPE" == "termux" && -n "$TERMUX_PREFIX" && -d "$TERMUX_PREFIX/bin" ]]; then
        case ":$PATH:" in
            *":$TERMUX_PREFIX/bin:"*) ;;
            *) export PATH="$TERMUX_PREFIX/bin:$PATH" ;;
        esac
    fi

    # 2. Standard user local binary path (pipx, pip --user)
    if [[ -d "$HOME/.local/bin" ]]; then
        case ":$PATH:" in
            *":$HOME/.local/bin:"*) ;;
            *) export PATH="$HOME/.local/bin:$PATH" ;;
        esac
    fi

    # 2b. Python user base binary path (pip install --user)
    local py_user_base=""
    if command -v python3 >/dev/null 2>&1; then
        py_user_base="$(python3 -m site --user-base 2>/dev/null || echo "")"
        if [[ -n "$py_user_base" && -d "$py_user_base/bin" ]]; then
            case ":$PATH:" in
                *":$py_user_base/bin:"*) ;;
                *) export PATH="$py_user_base/bin:$PATH" ;;
            esac
        fi
    fi

    # 2c. macOS Framework Python user binary paths (~/Library/Python/*/bin)
    if [[ "$OS_TYPE" == "darwin" && -d "$HOME/Library/Python" ]]; then
        for py_dir in "$HOME/Library/Python"/*/bin; do
            if [[ -d "$py_dir" ]]; then
                case ":$PATH:" in
                    *":$py_dir:"*) ;;
                    *) export PATH="$py_dir:$PATH" ;;
                esac
            fi
        done
    fi

    # 2d. ProjectDiscovery Tool Manager (pdtm) Go binary path
    if [[ -d "$HOME/.pdtm/go/bin" ]]; then
        case ":$PATH:" in
            *":$HOME/.pdtm/go/bin:"*) ;;
            *) export PATH="$HOME/.pdtm/go/bin:$PATH" ;;
        esac
    fi

    # 3. Go binaries ($HOME/go/bin or $GOPATH/bin)
    local go_bin="${GOPATH:-$HOME/go}/bin"
    if [[ -d "$go_bin" ]]; then
        case ":$PATH:" in
            *":$go_bin:"*) ;;
            *) export PATH="$go_bin:$PATH" ;;
        esac
    fi

    # 4. Rust / Cargo binaries ($HOME/.cargo/bin)
    if [[ -d "$HOME/.cargo/bin" ]]; then
        case ":$PATH:" in
            *":$HOME/.cargo/bin:"*) ;;
            *) export PATH="$HOME/.cargo/bin:$PATH" ;;
        esac
    fi

    # 5. macOS Homebrew environment initialization
    if [[ "$OS_TYPE" == "darwin" ]]; then
        if [[ -x /opt/homebrew/bin/brew ]]; then
            HOMEBREW_BIN="/opt/homebrew/bin/brew"
            BREW_PREFIX="/opt/homebrew"
        elif [[ -x /usr/local/bin/brew ]]; then
            HOMEBREW_BIN="/usr/local/bin/brew"
            BREW_PREFIX="/usr/local"
        elif command -v brew >/dev/null 2>&1; then
            HOMEBREW_BIN="$(command -v brew)"
            BREW_PREFIX="$("$HOMEBREW_BIN" --prefix 2>/dev/null || echo "")"
        fi

        if [[ -n "$HOMEBREW_BIN" && -x "$HOMEBREW_BIN" ]]; then
            eval "$("$HOMEBREW_BIN" shellenv 2>/dev/null || true)"
        fi

        # Homebrew Ruby / Python opt paths if present
        if [[ -n "$BREW_PREFIX" ]]; then
            [[ -d "$BREW_PREFIX/opt/ruby/bin" ]] && export PATH="$BREW_PREFIX/opt/ruby/bin:$PATH"
            [[ -d "$BREW_PREFIX/opt/python/libexec/bin" ]] && export PATH="$BREW_PREFIX/opt/python/libexec/bin:$PATH"
        fi
    fi

    # 6. Ruby Gem user directories
    if command -v ruby >/dev/null 2>&1; then
        local gem_user_dir
        gem_user_dir="$(ruby -e 'puts Gem.user_dir' 2>/dev/null || echo "")"
        if [[ -n "$gem_user_dir" && -d "$gem_user_dir/bin" ]]; then
            case ":$PATH:" in
                *":$gem_user_dir/bin:"*) ;;
                *) export PATH="$gem_user_dir/bin:$PATH" ;;
            esac
        fi
    fi

    hash -r 2>/dev/null || true
}

# Detects and configures shell rc files (~/.zshrc, ~/.bashrc) with global CLI paths
persist_user_shell_paths() {
    local target_rc=""
    local user_shell="${SHELL:-}"

    if [[ "$user_shell" == *"zsh"* || -f "$HOME/.zshrc" ]]; then
        target_rc="$HOME/.zshrc"
    elif [[ "$user_shell" == *"bash"* ]]; then
        if [[ "$OS_TYPE" == "darwin" && -f "$HOME/.bash_profile" ]]; then
            target_rc="$HOME/.bash_profile"
        else
            target_rc="$HOME/.bashrc"
        fi
    elif [[ -f "$HOME/.profile" ]]; then
        target_rc="$HOME/.profile"
    fi

    [[ -z "$target_rc" ]] && return 0

    local -a needed_paths=()

    # Check ~/.local/bin
    if [[ -d "$HOME/.local/bin" ]]; then
        needed_paths+=('$HOME/.local/bin')
    fi

    # Check Python user base
    if command -v python3 >/dev/null 2>&1; then
        local pbase
        pbase="$(python3 -m site --user-base 2>/dev/null || echo "")"
        if [[ -n "$pbase" && -d "$pbase/bin" ]]; then
            # Format nicely with $HOME
            local rel_pbase="${pbase/#$HOME/\$HOME}"
            needed_paths+=("$rel_pbase/bin")
        fi
    fi

    # Check macOS Library Python paths
    if [[ "$OS_TYPE" == "darwin" && -d "$HOME/Library/Python" ]]; then
        for pdir in "$HOME/Library/Python"/*/bin; do
            if [[ -d "$pdir" ]]; then
                local rel_pdir="${pdir/#$HOME/\$HOME}"
                needed_paths+=("$rel_pdir")
            fi
        done
    fi

    # Check Go bin
    if [[ -d "$HOME/go/bin" ]]; then
        needed_paths+=('$HOME/go/bin')
    fi

    # Check Cargo bin
    if [[ -d "$HOME/.cargo/bin" ]]; then
        needed_paths+=('$HOME/.cargo/bin')
    fi

    # Deduplicate paths
    local -a unique_paths=()
    for p in "${needed_paths[@]}"; do
        local already=0
        for u in "${unique_paths[@]}"; do
            if [[ "$u" == "$p" ]]; then
                already=1
                break
            fi
        done
        if [[ "$already" -eq 0 ]]; then
            unique_paths+=("$p")
        fi
    done

    # Check if target_rc already has these paths
    local missing_paths=()
    for p in "${unique_paths[@]}"; do
        local check_str="${p//\$HOME/$HOME}"
        if [[ -f "$target_rc" ]] && grep -Fq "$check_str" "$target_rc" 2>/dev/null; then
            continue
        elif [[ -f "$target_rc" ]] && grep -Fq "$p" "$target_rc" 2>/dev/null; then
            continue
        else
            missing_paths+=("$p")
        fi
    done

    if [[ ${#missing_paths[@]} -gt 0 ]]; then
        {
            echo ""
            echo "# >>> TraceForge global CLI environment path >>>"
            for mp in "${missing_paths[@]}"; do
                echo "export PATH=\"$mp:\$PATH\""
            done
            echo "# <<< TraceForge global CLI environment path <<<"
        } >> "$target_rc" 2>/dev/null || return 1
        return 0
    fi
    return 0
}

detect_platform
init_environment_paths

