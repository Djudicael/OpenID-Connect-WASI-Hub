#!/usr/bin/env bash
# Deployment script for OIDC Hub
# Builds, backs up current version, deploys new version, verifies health
#
# Usage: ./scripts/deploy.sh [OPTIONS]
#
# Options:
#   --wasm-path PATH  Path to new WASM artifact (default: build from source)
#   --wasm-dir DIR    WASM deployment directory (default: ./wasm)
#   --skip-build      Skip the build step
#   --skip-migrate    Skip database migrations
#   --skip-health     Skip health check after deploy
#   --no-backup       Skip backing up current version (NOT recommended)
#
# Environment:
#   OIDC_DATABASE_URL  PostgreSQL connection URL (for migrations)

set -euo pipefail

# Defaults
WASM_PATH=""
WASM_DIR="./wasm"
SKIP_BUILD=false
SKIP_MIGRATE=false
SKIP_HEALTH=false
NO_BACKUP=false
HEALTH_URL="http://localhost:8080/health/ready"
HEALTH_RETRIES=10
HEALTH_INTERVAL=3
WASM_FILENAME="openid_connect_wasi.wasm"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --wasm-path)   WASM_PATH="$2"; shift 2 ;;
        --wasm-dir)    WASM_DIR="$2"; shift 2 ;;
        --skip-build)  SKIP_BUILD=true; shift ;;
        --skip-migrate) SKIP_MIGRATE=true; shift ;;
        --skip-health) SKIP_HEALTH=true; shift ;;
        --no-backup)   NO_BACKUP=true; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --wasm-path PATH  Path to new WASM artifact (default: build from source)"
            echo "  --wasm-dir DIR    WASM deployment directory (default: ./wasm)"
            echo "  --skip-build      Skip the build step"
            echo "  --skip-migrate    Skip database migrations"
            echo "  --skip-health     Skip health check after deploy"
            echo "  --no-backup       Skip backing up current version"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

ACTIVE_WASM="${WASM_DIR}/${WASM_FILENAME}"
VERSIONS_DIR="${WASM_DIR}/versions"

echo "=== OIDC Hub Deployment ==="
echo "Time:      $(date -Iseconds)"
echo "WASM dir:  ${WASM_DIR}"
echo ""

# Step 1: Build
if [[ "$SKIP_BUILD" == "false" ]]; then
    echo "[1/5] Building WASM artifact..."
    cd "$PROJECT_ROOT"
    if cargo build -p openid-connect-wasi --target wasm32-wasip2 --release 2>&1; then
        WASM_PATH="${PROJECT_ROOT}/target/wasm32-wasip2/release/${WASM_FILENAME}"
        echo "Build complete: ${WASM_PATH}"
    else
        echo "ERROR: Build failed"
        exit 1
    fi
else
    echo "[1/5] Skipping build (--skip-build)"
    if [[ -z "$WASM_PATH" ]]; then
        WASM_PATH="${PROJECT_ROOT}/target/wasm32-wasip2/release/${WASM_FILENAME}"
    fi
fi

# Verify the new WASM exists
if [[ ! -f "$WASM_PATH" ]]; then
    echo "ERROR: WASM artifact not found: ${WASM_PATH}"
    exit 1
fi

NEW_SIZE=$(du -h "$WASM_PATH" | cut -f1)
echo "New artifact: ${NEW_SIZE}"
echo ""

# Step 2: Backup current version
if [[ "$NO_BACKUP" == "false" && -f "$ACTIVE_WASM" ]]; then
    echo "[2/5] Backing up current version..."
    mkdir -p "$VERSIONS_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_PATH="${VERSIONS_DIR}/${WASM_FILENAME}_${TIMESTAMP}.wasm"
    cp "$ACTIVE_WASM" "$BACKUP_PATH"
    echo "Backed up to: $(basename "$BACKUP_PATH")"
else
    echo "[2/5] Skipping backup (--no-backup or no current version)"
fi
echo ""

# Step 3: Run migrations
if [[ "$SKIP_MIGRATE" == "false" ]]; then
    echo "[3/5] Running database migrations..."
    cd "$PROJECT_ROOT"
    if [[ -n "${OIDC_DATABASE_URL:-}" ]]; then
        if cargo run -p oidc-migrate -- migrate 2>&1; then
            echo "Migrations complete"
        else
            echo "WARNING: Migrations failed. Continuing deployment."
            echo "You may need to run migrations manually."
        fi
    else
        echo "WARNING: OIDC_DATABASE_URL not set. Skipping migrations."
    fi
else
    echo "[3/5] Skipping migrations (--skip-migrate)"
fi
echo ""

# Step 4: Deploy new WASM
echo "[4/5] Deploying new WASM artifact..."
mkdir -p "$WASM_DIR"
cp "$WASM_PATH" "$ACTIVE_WASM"
echo "Deployed: ${ACTIVE_WASM} (${NEW_SIZE})"
echo ""

# Step 5: Health check
if [[ "$SKIP_HEALTH" == "false" ]]; then
    echo "[5/5] Verifying health..."
    RETRY=0
    while [[ $RETRY -lt $HEALTH_RETRIES ]]; do
        if curl -sf "${HEALTH_URL}" &>/dev/null; then
            echo "Health check: OK ✓"
            echo ""
            echo "=== Deployment complete ==="
            exit 0
        fi
        RETRY=$((RETRY + 1))
        echo "  Waiting for service... (attempt ${RETRY}/${HEALTH_RETRIES})"
        sleep "$HEALTH_INTERVAL"
    done

    echo ""
    echo "ERROR: Health check failed after ${HEALTH_RETRIES} attempts."
    echo "The service may not have started correctly."
    echo ""
    echo "Rollback options:"
    echo "  ./scripts/rollback.sh --wasm-dir ${WASM_DIR}"
    echo "  Manual: cp ${VERSIONS_DIR}/${WASM_FILENAME}_*.wasm ${ACTIVE_WASM}"
    exit 1
else
    echo "[5/5] Skipping health check (--skip-health)"
    echo ""
    echo "=== Deployment complete ==="
fi
