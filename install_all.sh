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

usage() {
    cat << EOF
TraceForge Installer & Runtime Provisioner

Usage:
  ./install_all.sh [options]

Options:
  --profile <name>   Runtime profile: minimal | python | go | python-go | full | custom
  --dry-run          Simulate provisioning without modifying system packages
  --help, -h         Show this help message

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
        --help|-h)
            usage
            ;;
        *)
            err "Unknown option: $1"
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
        warn "Unknown profile '$PROFILE'; defaulting to 'python-go'."
        PROFILE="python-go"
        ;;
esac

prompt_interactive_profile() {
    if [[ "$PROFILE_EXPLICIT" -eq 1 || "$DRY_RUN" -eq 1 || ! -t 0 ]]; then
        return 0
    fi

    # Try Python environment detector if python3 available
    if need_cmd python3; then
        local detected_prof
        detected_prof=$(python3 -c "from traceforge.platform_detect import recommend_runtime_profile; print(recommend_runtime_profile()['profile'])" 2>/dev/null || echo "python-go")
        PROFILE="$detected_prof"
    fi

    echo
    printf '%b╔══════════════════════════════════════════════════════════════════════╗%b\n' "$C_BLUE" "$C_RESET"
    printf '%b║                TraceForge Runtime Profile Setup                      ║%b\n' "$C_BLUE" "$C_RESET"
    printf '%b╚══════════════════════════════════════════════════════════════════════╝%b\n\n' "$C_BLUE" "$C_RESET"

    printf 'Detected Platform: %s (%s %s)\n' "$OS_NAME" "$OS_TYPE" "$OS_ARCH"
    printf 'Recommended Profile: %b%s%b\n\n' "$C_GREEN" "${PROFILE^^}" "$C_RESET"

    printf 'Choose your runtime installation profile:\n'
    printf '  [1] Recommended (Python + Go) — Best balance of features & speed\n'
    printf '  [2] Python                   — Pure Python runtime & document reports\n'
    printf '  [3] Go                       — Core tools + Go native acceleration\n'
    printf '  [4] Minimal                  — Smallest footprint (core utilities only)\n'
    printf '  [5] Full                     — All installable tools in the catalog\n'
    printf '  [6] Custom                   — Load user component toggles\n'
    printf '  [Enter to accept Recommended]\n\n'

    read -r -p "Select Profile [1-6] > " user_choice
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
    mkdir -p "$WORKSPACE_DIR" "$ROOT_DIR/docs" "$ROOT_DIR/catalog" "$ROOT_DIR/modules" "$ROOT_DIR/scripts" "$ROOT_DIR/tests"
    touch "$WORKSPACE_DIR/.gitkeep"
    chmod 755 "$ROOT_DIR/main.sh" "$ROOT_DIR/install_all.sh" \
        "$ROOT_DIR/modules"/*.sh "$ROOT_DIR/scripts"/*.sh "$ROOT_DIR/tests"/*.sh 2>/dev/null || true
}

provision_native_stack() {
    step "Configuring native OS packages for profile '$PROFILE' ($OS_NAME)..."

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
            info "[DRY-RUN] Termux 'pkg' packages to install (${#termux_packages[@]} items):"
            for pkg in "${termux_packages[@]}"; do
                printf '  - %-20s [Termux: pkg install %s]\n' "$pkg" "$pkg"
            done
        else
            termux_update_cached
            for pkg in "${termux_packages[@]}"; do
                install_termux_package "$pkg" "" || warn "Termux package failed: $pkg"
            done
        fi
    elif [[ "$OS_TYPE" == "darwin" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            info "[DRY-RUN] macOS Homebrew packages to install (${#mac_formulas[@]} items):"
            for formula in "${mac_formulas[@]}"; do
                printf '  - %-20s [Homebrew: brew install %s]\n' "$formula" "$formula"
            done
        else
            ensure_homebrew_installed
            for formula in "${mac_formulas[@]}"; do
                install_brew_formula "$formula" || warn "Package failed: $formula"
            done
        fi
    elif [[ "$OS_TYPE" == "linux" ]]; then
        if [[ "$DRY_RUN" -eq 1 ]]; then
            info "[DRY-RUN] Linux APT packages to install (${#linux_packages[@]} items):"
            for pkg in "${linux_packages[@]}"; do
                printf '  - %-20s [APT: apt-get install -y %s]\n' "$pkg" "$pkg"
            done
        else
            apt_update_cached
            for pkg in "${linux_packages[@]}"; do
                install_apt_package "$pkg" "" || warn "Package failed: $pkg"
            done
        fi
    fi
}

provision_python_stack() {
    if [[ "$PROFILE" == "go" ]]; then
        info "Profile 'go' selected; skipping optional Python pipx applications."
        return 0
    fi

    step "Installing Python tools in isolated virtual environments via pipx..."

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
        info "[DRY-RUN] Python applications to provision via pipx (${#python_apps[@]} items):"
        local spec pkg bin
        for spec in "${python_apps[@]}"; do
            pkg="${spec%%:*}"
            bin="${spec#*:}"
            printf '  - %-20s [pipx: pipx install %s -> %s]\n' "$bin" "$pkg" "$bin"
        done
        return 0
    fi

    ensure_pipx
    local spec pkg bin
    for spec in "${python_apps[@]}"; do
        pkg="${spec%%:*}"
        bin="${spec#*:}"
        install_pipx_app "$pkg" "$bin" || warn "Python tool failed: $pkg"
    done
}

provision_go_stack() {
    if [[ "$PROFILE" == "python" || "$PROFILE" == "minimal" ]]; then
        info "Profile '$PROFILE' selected; skipping external Go toolchain build."
        return 0
    fi

    step "Installing Go security binaries into \$HOME/go/bin..."

    local -a go_tools=()
    local -a go_core=(
        "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
    )
    local -a go_rec=(
        "amass:github.com/owasp-amass/amass/v4/...@latest"
        "assetfinder:github.com/tomnomnom/assetfinder@latest"
        "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
        "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "uncover:github.com/projectdiscovery/uncover/cmd/uncover@latest"
        "notify:github.com/projectdiscovery/notify/cmd/notify@latest"
        "pdtm:github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
        "gau:github.com/lc/gau/v2/cmd/gau@latest"
        "waybackurls:github.com/tomnomnom/waybackurls@latest"
        "gowitness:github.com/sensepost/gowitness@latest"
        "mapcidr:github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
        "asnmap:github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
        "cdncheck:github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
        "tlsx:github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
        "shuffledns:github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
        "puredns:github.com/d3mondev/puredns/v2@latest"
        "alterx:github.com/projectdiscovery/alterx/cmd/alterx@latest"
        "cero:github.com/glebarez/cero@latest"
    )

    if [[ "$PROFILE" == "go" || "$PROFILE" == "python-go" ]]; then
        go_tools=("${go_core[@]}" "${go_rec[@]}")
    else
        go_tools=("${go_core[@]}" "${go_rec[@]}")
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        info "[DRY-RUN] Go utilities to build via go install (${#go_tools[@]} items):"
        local spec bin mod
        for spec in "${go_tools[@]}"; do
            bin="${spec%%:*}"
            mod="${spec#*:}"
            printf '  - %-20s [Go: go install %s]\n' "$bin" "$mod"
        done
        return 0
    fi

    ensure_go
    if ! need_cmd go; then
        warn "Go toolchain unavailable; skipping Go tools."
        return 0
    fi

    local spec bin mod
    for spec in "${go_tools[@]}"; do
        bin="${spec%%:*}"
        mod="${spec#*:}"
        install_go_tool "$bin" "$mod" || warn "Go tool failed: $bin"
    done

    # Build first-party native Go binary
    if [[ -d "$ROOT_DIR/go" ]]; then
        step "Building first-party Go binary into \$ROOT_DIR/bin/traceforge-native..."
        mkdir -p "$ROOT_DIR/bin"
        (cd "$ROOT_DIR/go" && go build -trimpath -ldflags="-s -w" -o "$ROOT_DIR/bin/traceforge-native" .) || warn "Failed to build traceforge-native"
        cp "$ROOT_DIR/bin/traceforge-native" "$ROOT_DIR/bin/omni-tools" 2>/dev/null || true
        cp "$ROOT_DIR/bin/traceforge-native" "$ROOT_DIR/bin/tracehash" 2>/dev/null || true
        cp "$ROOT_DIR/bin/traceforge-native" "$ROOT_DIR/bin/tracepcap" 2>/dev/null || true
    fi
}

provision_ruby_stack() {
    if [[ "$PROFILE" != "full" ]]; then
        return 0
    fi

    step "Installing Ruby gems..."
    if [[ "$DRY_RUN" -eq 1 ]]; then
        info "[DRY-RUN] RubyGems packages to install:"
        printf '  - %-20s [Gem: gem install --user-install zsteg]\n' "zsteg"
        printf '  - %-20s [Gem: gem install --user-install cewl]\n' "cewl"
        return 0
    fi

    ensure_ruby
    if ! need_cmd gem; then
        warn "RubyGems unavailable; skipping Ruby tools."
        return 0
    fi

    install_gem_tool "zsteg" "zsteg" || warn "Gem failed: zsteg"
    install_gem_tool "cewl" "cewl" || warn "Gem failed: cewl"
}

provision_cargo_stack() {
    if [[ "$PROFILE" != "full" ]]; then
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        info "[DRY-RUN] Rust crates to install via cargo:"
        printf '  - %-20s [Cargo: cargo install rustscan]\n' "rustscan"
        printf '  - %-20s [Cargo: cargo install sn0int]\n' "sn0int"
        return 0
    fi

    if need_cmd cargo; then
        step "Installing Rust security crates..."
        install_cargo_tool "rustscan" "rustscan" || warn "Cargo crate failed: rustscan"
        install_cargo_tool "sn0int" "sn0int" || warn "Cargo crate failed: sn0int"
    fi
}

write_install_manifest() {
    local manifest_file="$WORKSPACE_DIR/install_manifest.txt"
    info "Writing installation manifest to $manifest_file..."

    {
        printf '===============================================================================\n'
        printf 'TraceForge — Installation Manifest (Profile: %s)\n' "$PROFILE"
        printf '===============================================================================\n'
        printf 'Generated At     : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
        printf 'Host Platform    : %s (%s)\n' "$OS_NAME" "$OS_TYPE"
        printf 'Architecture     : %s\n' "$OS_ARCH"
        printf 'Total Catalog    : %s tools\n\n' "$(catalog_count)"

        printf '%-22s %-14s %-10s %s\n' 'Tool Binary' 'Category' 'Status' 'Resolved Path'
        printf '%-22s %-14s %-10s %s\n' '----------------------' '--------------' '----------' '-----------------------------------'

        while IFS=$'\t' read -r id _ bin cat _ _ _ _ _ _ _ _ _ _ _; do
            [[ "$id" == "id" ]] && continue
            if need_cmd "$bin"; then
                printf '%-22s %-14s %-10s %s\n' "$bin" "${cat:0:14}" "INSTALLED" "$(command -v "$bin")"
            else
                printf '%-22s %-14s %-10s %s\n' "$bin" "${cat:0:14}" "MISSING" "-"
            fi
        done < "$CATALOG_PATH"
    } > "$manifest_file"
}

main() {
    print_banner "Dependency Installer"
    prompt_interactive_profile

    if [[ "$DRY_RUN" -eq 1 ]]; then
        info "Running in DRY-RUN simulation mode (Profile: $PROFILE, Host: $OS_NAME $OS_ARCH)"
    else
        info "Starting package installation for profile: $PROFILE"
    fi

    setup_project_structure
    init_environment_paths
    catalog_validate

    provision_native_stack
    provision_python_stack
    provision_go_stack
    provision_ruby_stack
    provision_cargo_stack

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '\n%b[+] Dry-run simulation complete for profile: %s%b\n' "$C_GREEN" "$PROFILE" "$C_RESET"
        printf 'To execute actual installation, run: ./install_all.sh --profile %s\n\n' "$PROFILE"
    else
        init_environment_paths
        write_install_manifest

        printf '\n%b[+] Provisioning complete for profile: %s%b\n' "$C_GREEN" "$PROFILE" "$C_RESET"
        printf 'Launch Console with: ./main.sh\n\n'
    fi
}

main "$@"
