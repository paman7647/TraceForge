#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# TraceForge — scripts/install_tool.sh
# Standalone CLI for resolving and installing any audited catalog tool.

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"
# shellcheck source=lib/packages.sh
source "$ROOT_DIR/lib/packages.sh"
# shellcheck source=lib/catalog.sh
source "$ROOT_DIR/lib/catalog.sh"

usage() {
    cat << 'EOF'
TraceForge — Individual Tool Installer

Usage:
  ./scripts/install_tool.sh <tool-id-or-binary-name>

Examples:
  ./scripts/install_tool.sh 1
  ./scripts/install_tool.sh exiftool
  ./scripts/install_tool.sh sherlock
EOF
    exit 0
}

if [[ $# -eq 0 ]]; then
    usage
fi

TOOL_QUERY="$1"
RECORD=""

if [[ "$TOOL_QUERY" =~ ^[0-9]+$ ]]; then
    RECORD="$(catalog_get_by_id "$TOOL_QUERY")"
else
    RECORD="$(catalog_get_by_binary "$TOOL_QUERY")"
fi

if [[ -z "$RECORD" ]]; then
    log_err "Tool not found in catalog: '$TOOL_QUERY'"
    exit 1
fi

t_id="" t_name="" t_bin="" t_cat="" t_subcat="" t_eco="" t_mac="" t_lin="" t_desc="" t_stat="" t_root="" t_api="" t_hw="" t_notes="" t_url=""
IFS=$'\t' read -r t_id t_name t_bin t_cat t_subcat t_eco t_mac t_lin t_desc t_stat t_root t_api t_hw t_notes t_url <<< "$RECORD"

log_info "Found catalog entry: #$t_id - $t_name ($t_bin) [Ecosystem: $t_eco]"

if need_cmd "$t_bin"; then
    log_ok "Tool '$t_bin' is already installed and available on PATH ($(command -v "$t_bin"))."
    exit 0
fi

log_step "Resolving platform compatibility for $t_name ($t_bin)..."

case "$t_eco" in
    native)
        if [[ "$OS_TYPE" == "darwin" ]]; then
            if [[ -z "$t_mac" || "$t_mac" == "-" || "$t_mac" == "n/a" || "$t_mac" == "none" || "$t_mac" == "unsupported" || "$t_mac" == "linux-only" ]]; then
                log_err "Tool '$t_name' ($t_bin) is NOT available on macOS (Linux only)."
                log_info "No installation was attempted."
                exit 1
            fi
            if [[ "$t_mac" == "manual" ]]; then
                log_warn "Tool '$t_name' ($t_bin) requires manual installation on macOS."
                log_info "Upstream URL: $t_url"
                exit 1
            fi
            install_brew_formula "$t_mac"
        elif [[ "$OS_TYPE" == "termux" ]]; then
            if [[ -z "$t_lin" || "$t_lin" == "-" || "$t_lin" == "n/a" || "$t_lin" == "none" || "$t_lin" == "unsupported" ]]; then
                log_err "Tool '$t_name' ($t_bin) is NOT available on Termux / Android."
                log_info "No installation was attempted."
                exit 1
            fi
            if [[ "$t_lin" == "manual" ]]; then
                log_warn "Tool '$t_name' ($t_bin) requires manual installation on Termux."
                log_info "Upstream URL: $t_url"
                exit 1
            fi
            install_termux_package "$t_lin" "$t_bin"
        elif [[ "$OS_TYPE" == "linux" ]]; then
            if [[ -z "$t_lin" || "$t_lin" == "-" || "$t_lin" == "n/a" || "$t_lin" == "none" || "$t_lin" == "unsupported" ]]; then
                log_err "Tool '$t_name' ($t_bin) is NOT available on Linux."
                exit 1
            fi
            if [[ "$t_lin" == "manual" ]]; then
                log_warn "Tool '$t_name' ($t_bin) requires manual installation on Linux."
                log_info "Upstream URL: $t_url"
                exit 1
            fi
            install_apt_package "$t_lin" "$t_bin"
        else
            log_warn "Manual installation required for platform $OS_NAME: $t_url"
            exit 1
        fi
        ;;
    pipx)
        install_pipx_app "$t_lin" "$t_bin"
        ;;
    go)
        install_go_tool "$t_bin" "$t_lin"
        ;;
    ruby_gem)
        install_gem_tool "$t_lin" "$t_bin"
        ;;
    cargo)
        install_cargo_tool "$t_lin" "$t_bin"
        ;;
    *)
        log_warn "Tool '$t_name' requires manual installation or API key configuration."
        log_info "Upstream URL: $t_url"
        exit 1
        ;;
esac

init_environment_paths
if need_cmd "$t_bin"; then
    log_ok "Successfully installed: $t_bin ($(command -v "$t_bin"))"
else
    log_warn "Installation command completed, but '$t_bin' was not found on PATH. You may need to restart your shell."
fi
