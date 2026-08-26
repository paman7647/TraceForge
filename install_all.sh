#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# TraceForge — Multi-Ecosystem Dependency Provisioner
# Supports profiles: minimal, python, go, python-go (recommended), full, and custom.

set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$ROOT_DIR/lib/common.sh"
source "$ROOT_DIR/lib/platform.sh"
source "$ROOT_DIR/lib/packages.sh"
source "$ROOT_DIR/lib/catalog.sh"

WORKSPACE_DIR="$ROOT_DIR/workspace"
CATALOG_PATH="$(catalog_file)"
PROFILE="python-go"
PROFILE_EXPLICIT=0
DRY_RUN=0
NON_INTERACTIVE=0

usage() {
    cat << EOF
TraceForge Installer & Runtime Provisioner

Usage:
  ./install_all.sh [options]

Options:
  --profile <name>       Runtime profile: minimal | python | go | python-go | full | custom
  --dry-run              Simulate provisioning without modifying system packages
  --non-interactive, -y  Run in non-interactive batch mode
  --help, -h             Show this help message

Profiles:
  minimal            Essential core native packages and Python runtime only (<500MB)
  python             Pure Python environment + reporting libraries (no Go/Rust build)
  go                 Core native packages + Go toolchain & high-throughput native helpers
  python-go          Recommended: Python application logic + Go streaming/hashing acceleration
  full               Comprehensive OSINT/DFIR stack (Python + Go + Ruby + Cargo + native tools)
  custom             Load individual component preferences from TraceForge configuration
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="${2:-}"
            PROFILE_EXPLICIT=1
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --non-interactive|-y)
            NON_INTERACTIVE=1
            PROFILE_EXPLICIT=1
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            log_err "Unknown option: $1"
            usage
            ;;
    esac
done

# Normalize profile names
PROFILE_NORM="$(echo "$PROFILE" | tr '[:upper:]' '[:lower:]')"
case "$PROFILE_NORM" in
    core|minimal)
        PROFILE="minimal"
        ;;
    py|python)
        PROFILE="python"
        ;;
    go)
        PROFILE="go"
        ;;
    recommended|python-go|python+go)
        PROFILE="python-go"
        ;;
    full|all)
        PROFILE="full"
        ;;
    custom)
        PROFILE="custom"
        ;;
    *)
        log_warn "Unknown profile '$PROFILE'; defaulting to 'python-go'."
        PROFILE="python-go"
        ;;
esac

prompt_interactive_profile() {
    if [[ "$PROFILE_EXPLICIT" -eq 1 || "$DRY_RUN" -eq 1 || "$NON_INTERACTIVE" -eq 1 || ! -t 0 ]]; then
        return 0
    fi

    # Try Python environment detector if python3 available
    if need_cmd python3; then
        local detected_prof
        detected_prof=$(python3 -c "from traceforge.platform_detect import recommend_runtime_profile; print(recommend_runtime_profile()['profile'])" 2>/dev/null || echo "python-go")
        PROFILE="$detected_prof"
    fi

    local prof_upper
    prof_upper="$(echo "$PROFILE" | tr '[:lower:]' '[:upper:]')"

    echo
    printf '%b╔══════════════════════════════════════════════════════════════════════╗%b\n' "$C_BLUE" "$C_RESET"
    printf '%b║                TraceForge Runtime Profile Setup                      ║%b\n' "$C_BLUE" "$C_RESET"
    printf '%b╚══════════════════════════════════════════════════════════════════════╝%b\n\n' "$C_BLUE" "$C_RESET"

    printf 'Detected Platform: %s (%s %s)\n' "$OS_NAME" "$OS_TYPE" "$OS_ARCH"
    printf 'Recommended Profile: %b%s%b\n\n' "$C_GREEN" "$prof_upper" "$C_RESET"

    printf 'Choose your runtime installation profile:\n'
    printf '  [1] Recommended (Python + Go) — Best balance of features & speed\n'
    printf '  [2] Python                   — Pure Python runtime & document reports\n'
    printf '  [3] Go                       — Core tools + Go native acceleration\n'
    printf '  [4] Minimal                  — Smallest footprint (core utilities only)\n'
    printf '  [5] Full                     — All installable tools in the catalog\n'
    printf '  [6] Custom                   — Load user component toggles\n'
    printf '  [Enter to accept Recommended]\n\n'

    local user_choice
    user_choice="$(read_input "Select Profile [1-6]" "1")"
    case "$user_choice" in
        1|"") PROFILE="python-go" ;;
        2) PROFILE="python" ;;
        3) PROFILE="go" ;;
        4) PROFILE="minimal" ;;
        5) PROFILE="full" ;;
        6) PROFILE="custom" ;;
    esac

    # Persist profile to config if python3 available
    if need_cmd python3; then
        python3 -c "from traceforge.config import set_runtime_profile; set_runtime_profile('$PROFILE')" 2>/dev/null || true
    fi
}

setup_project_structure() {
    mkdir -p "$WORKSPACE_DIR" "$ROOT_DIR/docs" "$ROOT_DIR/catalog" "$ROOT_DIR/modules" "$ROOT_DIR/scripts" "$ROOT_DIR/bin"
    touch "$WORKSPACE_DIR/.gitkeep"
    chmod 755 "$ROOT_DIR/main.sh" "$ROOT_DIR/install_all.sh" \
        "$ROOT_DIR/modules"/*.sh "$ROOT_DIR/scripts"/*.sh 2>/dev/null || true
}

provision_native_stack() {
    log_step "Configuring native OS packages for profile '$PROFILE' ($OS_NAME)..."

    local -a mac_formulas=()
    local -a linux_packages=()
    local -a termux_packages=()

    # Core native dependencies
    local -a mac_core=(exiftool binwalk xxd poppler ripgrep jq bind whois tshark tcpdump mat2 tor proxychains-ng)
    local -a linux_core=(libimage-exiftool-perl binwalk xxd poppler-utils ripgrep jq dnsutils whois tshark tcpdump mat2 tor proxychains4)
    local -a termux_core=(exiftool binwalk xxd poppler ripgrep jq dnsutils whois tshark tcpdump mat2 tor proxychains-ng)

    # Recommended native dependencies
    local -a mac_rec=(
        imagemagick graphicsmagick jhead pngcheck jpeginfo exiv2 ffmpeg foremost
        scalpel bulk-extractor testdisk yara tesseract gpsbabel gdal mediainfo
        graphviz nmap masscan nikto hydra john testssl openssl socat radare2
    )
    local -a linux_rec=(
        imagemagick graphicsmagick jhead pngcheck jpeginfo exiv2 ffmpeg foremost
        scalpel bulk-extractor testdisk yara tesseract-ocr gpsbabel gdal-bin mediainfo
        graphviz nmap masscan nikto hydra john testssl.sh openssl socat radare2
    )
    local -a termux_rec=(
        imagemagick graphicsmagick jhead pngcheck jpeginfo exiv2 ffmpeg foremost
        testdisk yara tesseract mediainfo graphviz nmap masscan nikto hydra john
        openssl socat radare2
    )

    if [[ "$PROFILE" == "minimal" ]]; then
        mac_formulas=("${mac_core[@]}")
        linux_packages=("${linux_core[@]}")
        termux_packages=("${termux_core[@]}")
    else
        mac_formulas=("${mac_core[@]}" "${mac_rec[@]}")
        linux_packages=("${linux_core[@]}" "${linux_rec[@]}")
        termux_packages=("${termux_core[@]}" "${termux_rec[@]}")
    fi

    if [[ "$OS_TYPE" == "termux" ]]; then
        ensure_termux_storage || true
        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_info "[DRY-RUN] Termux 'pkg' packages to install (${#termux_packages[@]} items):"
            for pkg in "${termux_packages[@]}"; do
                printf '  - %-20s [Termux: pkg install %s]\n' "$pkg" "$pkg"
            done
        else
            termux_update_cached
            for pkg in "${termux_packages[@]}"; do
                install_termux_package "$pkg" "" || log_warn "Termux package failed: $pkg"
            done
        fi
    elif [[ "$OS_TYPE" == "darwin" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_info "[DRY-RUN] macOS Homebrew packages to install (${#mac_formulas[@]} items):"
            for formula in "${mac_formulas[@]}"; do
                printf '  - %-20s [Homebrew: brew install %s]\n' "$formula" "$formula"
            done
        else
            ensure_homebrew_installed
            for formula in "${mac_formulas[@]}"; do
                install_brew_formula "$formula" || log_warn "Package failed: $formula"
            done
        fi
    elif [[ "$OS_TYPE" == "linux" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_info "[DRY-RUN] Linux APT packages to install (${#linux_packages[@]} items):"
            for pkg in "${linux_packages[@]}"; do
                printf '  - %-20s [APT: apt-get install -y %s]\n' "$pkg" "$pkg"
            done
        else
            apt_update_cached
            for pkg in "${linux_packages[@]}"; do
                install_apt_package "$pkg" "" || log_warn "Package failed: $pkg"
            done
        fi
    fi
}

provision_python_stack() {
    if [[ "$PROFILE" == "go" ]]; then
        log_info "Profile 'go' selected; skipping optional Python pipx applications."
        return 0
    fi

    log_step "Installing Python tools in isolated virtual environments via pipx..."

    local -a python_apps=()
    local -a py_core=("sherlock-project:sherlock" "holehe:holehe" "oletools:olevba")
    local -a py_rec=(
        "maigret:maigret" "h8mail:h8mail" "theHarvester:theHarvester" "ghunt:ghunt"
        "emailrep:emailrep" "ggshield:ggshield" "socialscan:socialscan" "twarc:twarc2"
        "snscrape:snscrape" "spiderfoot:spiderfoot" "intelx:intelx" "mitmproxy:mitmproxy"
        "scapy:scapy" "dnsrecon:dnsrecon" "dnstwist:dnstwist" "wafw00f:wafw00f"
        "prowler:prowler" "shodan:shodan" "censys:censys" "s3scanner:s3scanner"
        "yt-dlp:yt-dlp" "gallery-dl:gallery-dl" "ocrmypdf:ocrmypdf"
        "hachoir:hachoir-metadata" "checkdmarc:checkdmarc" "pwnedornot:pwnedornot"
        "crosslinked:crosslinked" "cloud-enum:cloud_enum" "flare-capa:capa" "flare-floss:floss"
    )

    if [[ "$PROFILE" == "minimal" ]]; then
        python_apps=("${py_core[@]}")
    else
        python_apps=("${py_core[@]}" "${py_rec[@]}")
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_info "[DRY-RUN] Python applications via pipx (${#python_apps[@]} items):"
        for app_spec in "${python_apps[@]}"; do
            local pkg="${app_spec%%:*}"
            local bin="${app_spec#*:}"
            printf '  - %-20s (binary: %-18s) [pipx install %s]\n' "$pkg" "$bin" "$pkg"
        done
        return 0
    fi

    ensure_pipx
    for app_spec in "${python_apps[@]}"; do
        local pkg="${app_spec%%:*}"
        local bin="${app_spec#*:}"
        install_pipx_app "$pkg" "$bin" || log_warn "pipx package install failed: $pkg"
    done
}

provision_go_stack() {
    if [[ "$PROFILE" == "python" ]]; then
        log_info "Profile 'python' selected; skipping optional Go utilities."
        return 0
    fi

    log_step "Installing Go security and recon tools..."

    local -a go_tools=(
        "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "amass:github.com/owasp-amass/amass/v4/...@master"
        "assetfinder:github.com/tomnomnom/assetfinder@latest"
        "waybackurls:github.com/tomnomnom/waybackurls@latest"
        "gau:github.com/lc/gau/v2/cmd/gau@latest"
        "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
        "tlsx:github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
        "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
        "chaos-client:github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    )

    if [[ "$PROFILE" == "minimal" ]]; then
        go_tools=(
            "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
        )
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_info "[DRY-RUN] Go tools to install via 'go install' (${#go_tools[@]} items):"
        for tool_spec in "${go_tools[@]}"; do
            local bin="${tool_spec%%:*}"
            local mod="${tool_spec#*:}"
            printf '  - %-20s [go install %s]\n' "$bin" "$mod"
        done
        return 0
    fi

    ensure_go
    for tool_spec in "${go_tools[@]}"; do
        local bin="${tool_spec%%:*}"
        local mod="${tool_spec#*:}"
        install_go_tool "$bin" "$mod" || log_warn "Go tool install failed: $bin"
    done
}

provision_full_stack_extras() {
    if [[ "$PROFILE" != "full" ]]; then
        return 0
    fi

    log_step "Installing Full Profile Extras (Ruby Gems, Cargo Crates)..."

    # Ruby Gems
    local -a ruby_gems=("zsteg" "wpscan")
    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_info "[DRY-RUN] Ruby Gems (${#ruby_gems[@]} items):"
        for g in "${ruby_gems[@]}"; do
            printf '  - %-20s [gem install %s]\n' "$g" "$g"
        done
    else
        ensure_ruby
        for g in "${ruby_gems[@]}"; do
            install_gem_tool "$g" "$g" || log_warn "Ruby gem install failed: $g"
        done
    fi

    # Cargo Crates
    local -a cargo_crates=("feroxbuster" "ripasso-cursive" "sniffglue")
    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_info "[DRY-RUN] Rust / Cargo crates (${#cargo_crates[@]} items):"
        for c in "${cargo_crates[@]}"; do
            printf '  - %-20s [cargo install %s]\n' "$c" "$c"
        done
    else
        ensure_cargo
        for c in "${cargo_crates[@]}"; do
            install_cargo_tool "$c" "$c" || log_warn "Cargo crate install failed: $c"
        done
    fi
}

main() {
    prompt_interactive_profile
    setup_project_structure

    local prof_upper
    prof_upper="$(echo "$PROFILE" | tr '[:lower:]' '[:upper:]')"
    log_info "Initiating TraceForge Provisioning Pipeline [Profile: $prof_upper]"

    provision_native_stack
    provision_python_stack
    provision_go_stack
    provision_full_stack_extras

    init_environment_paths

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_ok "Dry run simulation complete. No system modifications were performed."
        exit 0
    fi

    log_ok "TraceForge dependency provisioning completed successfully."
}

main "$@"
