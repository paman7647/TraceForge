#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# TraceForge — Go Native Acceleration Helper Builder
# Builds high-throughput native streaming and indexing utilities into bin/traceforge-native.

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)
# shellcheck source=lib/common.sh
source "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$ROOT_DIR/lib/platform.sh"

FORCE_BUILD=0
VERBOSE=0

usage() {
    local exit_code="${1:-0}"
    cat << 'EOF'
TraceForge Go Native Helper Builder

Usage:
  ./scripts/build_native.sh [options]

Options:
  --force, -f    Force rebuild even if source files are unchanged
  --verbose, -v  Show detailed compiler output
  --help, -h     Show this help message
EOF
    exit "$exit_code"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force|-f)
            FORCE_BUILD=1
            shift
            ;;
        --verbose|-v)
            VERBOSE=1
            shift
            ;;
        --help|-h)
            usage 0
            ;;
        *)
            log_err "Unknown option: $1"
            usage 1
            ;;
    esac
done


main() {
    detect_platform
    init_environment_paths

    local GO_DIR="$ROOT_DIR/go"
    local BIN_DIR="$ROOT_DIR/bin"
    local TARGET_BIN="$BIN_DIR/traceforge-native"
    local HASH_FILE="$BIN_DIR/.native_source_hash"

    if [[ ! -d "$GO_DIR" ]]; then
        log_err "Go source directory not found at: $GO_DIR"
        exit 1
    fi

    if ! command -v go >/dev/null 2>&1; then
        log_warn "Go compiler ('go') not found in PATH."
        log_info "TraceForge will automatically use pure Python high-throughput fallbacks."
        exit 0
    fi

    local GO_VERSION
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Detected Go compiler: v$GO_VERSION ($(command -v go))"

    mkdir -p "$BIN_DIR"
    local CURRENT_HASH
    CURRENT_HASH=$(compute_source_hash "$GO_DIR")
    local STORED_HASH=""
    if [[ -f "$HASH_FILE" ]]; then
        STORED_HASH=$(cat "$HASH_FILE" 2>/dev/null || echo "")
    fi

    if [[ "$FORCE_BUILD" -eq 0 ]] && [[ -x "$TARGET_BIN" ]] && [[ "$CURRENT_HASH" == "$STORED_HASH" ]]; then
        log_ok "Native Go acceleration binary is up to date ($TARGET_BIN)."
        exit 0
    fi

    log_step "Building Go fast-path binary (traceforge-native)..."

    local -a BUILD_CMD=(go build -trimpath -ldflags="-s -w" -o "$TARGET_BIN" .)

    if [[ "$VERBOSE" -eq 1 ]]; then
        (cd "$GO_DIR" && "${BUILD_CMD[@]}")
    else
        if ! (cd "$GO_DIR" && "${BUILD_CMD[@]}" 2>/dev/null); then
            log_warn "Go build encountered warnings; retrying with standard flags..."
            (cd "$GO_DIR" && go build -o "$TARGET_BIN" .) 2>/dev/null || {
                log_err "Failed to compile Go native helpers."
                exit 1
            }
        fi
    fi

    if [[ -x "$TARGET_BIN" ]]; then
        echo "$CURRENT_HASH" > "$HASH_FILE"
        chmod +x "$TARGET_BIN"
        log_ok "Successfully compiled Go acceleration binary: $TARGET_BIN"
    else
        log_err "Binary was not created at expected location: $TARGET_BIN"
        exit 1
    fi
}

compute_source_hash() {
    local target_dir="$1"
    local files=()
    while IFS= read -r -d '' f; do
        files+=("$f")
    done < <(find "$target_dir" -type f \( -name "*.go" -o -name "go.mod" -o -name "go.sum" \) -print0 | sort -z)

    if [[ ${#files[@]} -eq 0 ]]; then
        echo "none"
        return
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${files[@]}" | sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${files[@]}" | shasum -a 256 | awk '{print $1}'
    else
        cksum "${files[@]}" | cksum | awk '{print $1}'
    fi
}

main "$@"
