#!/usr/bin/env bash
# WASM component rollback script for OIDC Hub
# Restores a previous WASM artifact and restarts the service
#
# Usage: ./scripts/rollback.sh [OPTIONS]
#
# Options:
#   --version VER     Version to rollback to (timestamp or 'previous')
#   --wasm-dir DIR    WASM artifact directory (default: ./wasm)
#   --no-restart      Don't restart the service after rollback
#   --list            List available versions
#
# The script maintains versioned copies:
#   wasm/openid_connect_wasi.wasm                              — current version
#   wasm/versions/openid_connect_wasi_YYYYMMDD_HHMMSS.wasm    — previous versions

set -euo pipefail

# Defaults
WASM_DIR="./wasm"
VERSION="previous"
NO_RESTART=false
LIST_ONLY=false
HEALTH_URL="http://localhost:8080/health/ready"
WASM_FILENAME="openid_connect_wasi.wasm"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)   VERSION="$2"; shift 2 ;;
        --wasm-dir)  WASM_DIR="$2"; shift 2 ;;
        --no-restart) NO_RESTART=true; shift ;;
        --list)      LIST_ONLY=true; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --version VER     Version to rollback to (timestamp or 'previous')"
            echo "  --wasm-dir DIR    WASM artifact directory (default: ./wasm)"
            echo "  --no-restart      Don't restart the service after rollback"
            echo "  --list            List available versions"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

VERSIONS_DIR="${WASM_DIR}/versions"
ACTIVE_WASM="${WASM_DIR}/${WASM_FILENAME}"

# List available versions
if [[ "$LIST_ONLY" == "true" ]]; then
    echo "=== Available WASM Versions ==="
    if [[ -d "$VERSIONS_DIR" ]]; then
        ls -1t "${VERSIONS_DIR}/"*.wasm 2>/dev/null | while read -r f; do
            SIZE=$(du -h "$f" | cut -f1)
            TS=$(basename "$f" | sed "s/${WASM_FILENAME}_//" | sed 's/\.wasm$//')
            echo "  ${TS}  (${SIZE})"
        done
    else
        echo "  No versions directory found"
    fi
    echo ""
    if [[ -f "$ACTIVE_WASM" ]]; then
        SIZE=$(du -h "$ACTIVE_WASM" | cut -f1)
        echo "Current: ${ACTIVE_WASM} (${SIZE})"
    else
        echo "Current: (none)"
    fi
    exit 0
fi

# Validate active WASM exists
if [[ ! -f "$ACTIVE_WASM" ]]; then
    echo "ERROR: No active WASM found at ${ACTIVE_WASM}"
    exit 1
fi

# Create versions directory
mkdir -p "$VERSIONS_DIR"

# Resolve version
if [[ "$VERSION" == "previous" ]]; then
    # Find the most recent version
    TARGET=$(ls -1t "${VERSIONS_DIR}/"*.wasm 2>/dev/null | head -1)
    if [[ -z "$TARGET" ]]; then
        echo "ERROR: No previous versions found in ${VERSIONS_DIR}/"
        echo "Run a deploy first to create versioned backups."
        exit 1
    fi
else
    # Find by timestamp
    TARGET="${VERSIONS_DIR}/${WASM_FILENAME}_${VERSION}.wasm"
    if [[ ! -f "$TARGET" ]]; then
        echo "ERROR: Version not found: ${TARGET}"
        echo "Use --list to see available versions."
        exit 1
    fi
fi

TARGET_SIZE=$(du -h "$TARGET" | cut -f1)
TARGET_TS=$(basename "$TARGET" | sed "s/${WASM_FILENAME}_//" | sed 's/\.wasm$//')

echo "=== OIDC Hub WASM Rollback ==="
echo "Current:  ${ACTIVE_WASM}"
echo "Target:   ${TARGET_TS} (${TARGET_SIZE})"
echo ""

# Verify target is valid
TARGET_BYTES=$(stat -f%z "$TARGET" 2>/dev/null || stat -c%s "$TARGET" 2>/dev/null || echo "0")
if [[ "$TARGET_BYTES" -lt 1000 ]]; then
    echo "ERROR: Target WASM file is too small (${TARGET_BYTES} bytes). Likely corrupted."
    exit 1
fi

# Backup current version before rollback (in case we need to undo)
CURRENT_TS=$(date +%Y%m%d_%H%M%S)
CURRENT_BACKUP="${VERSIONS_DIR}/${WASM_FILENAME}_pre-rollback-${CURRENT_TS}.wasm"
echo "Backing up current version to: $(basename "$CURRENT_BACKUP")"
cp "$ACTIVE_WASM" "$CURRENT_BACKUP"

# Replace active WASM with target
echo "Restoring version ${TARGET_TS}..."
cp "$TARGET" "$ACTIVE_WASM"
echo "WASM artifact replaced."

# Restart service
if [[ "$NO_RESTART" == "false" ]]; then
    echo "Restarting service..."
    # Try to find and restart the wasmtime process
    if pgrep -f "wasmtime.*openid_connect_wasi" &>/dev/null; then
        pkill -f "wasmtime.*openid_connect_wasi" || true
        sleep 2
        echo "Service stopped. Restart manually or via your process manager."
    else
        echo "No running wasmtime process found. Start the service manually."
    fi
fi

# Health check
echo "Checking health endpoint..."
sleep 3
if curl -sf "${HEALTH_URL}" &>/dev/null; then
    echo "Health check: OK ✓"
else
    echo "WARNING: Health check failed. The service may not be running."
    echo "  - Start the service: wasmtime run --wasi inherit-network --wasi inherit-env ${ACTIVE_WASM}"
    echo "  - Undo rollback: cp ${CURRENT_BACKUP} ${ACTIVE_WASM}"
fi

echo ""
echo "=== Rollback complete ==="
echo "Rolled back to: ${TARGET_TS}"
echo "Pre-rollback backup: $(basename "$CURRENT_BACKUP")"
