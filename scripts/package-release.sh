#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/dist/packages"
VERSION=""
SKIP_BUILD=false
PACKAGE_PREFIX="openid-connect-wasi"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Create a release bundle containing the production WASM build and the minified admin frontend.

Options:
  --version VERSION   Version suffix for the output directory/archive
  --output-dir DIR    Output directory for staged package and archive
  --skip-build        Reuse existing build artifacts instead of rebuilding
  -h, --help          Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    if [[ -n "${GITHUB_REF_NAME:-}" ]]; then
        VERSION="$GITHUB_REF_NAME"
    else
        VERSION="manual-$(date +%Y%m%d_%H%M%S)"
    fi
fi

VERSION="${VERSION//\//-}"
PACKAGE_NAME="${PACKAGE_PREFIX}-${VERSION}"
PACKAGE_DIR="${OUTPUT_DIR}/${PACKAGE_NAME}"
ARCHIVE_PATH="${OUTPUT_DIR}/${PACKAGE_NAME}.tar.gz"
WASM_PATH="${PROJECT_ROOT}/target/wasm32-wasip2/release/openid_connect_wasi.wasm"
FRONTEND_DIR="${PROJECT_ROOT}/front/admin"
FRONTEND_DIST_DIR="${FRONTEND_DIR}/dist"

mkdir -p "$OUTPUT_DIR"
rm -rf "$PACKAGE_DIR" "$ARCHIVE_PATH"

if [[ "$SKIP_BUILD" == "false" ]]; then
    echo "[1/4] Building minified admin frontend..."
    (
        cd "$FRONTEND_DIR"
        npm ci
        npm run build
    )

    echo "[2/4] Building release WASM artifact..."
    (
        cd "$PROJECT_ROOT"
        cargo build -p openid-connect-wasi --target wasm32-wasip2 --release
    )
else
    echo "[1/4] Skipping builds (--skip-build)"
fi

if [[ ! -f "$WASM_PATH" ]]; then
    echo "ERROR: WASM artifact not found at $WASM_PATH" >&2
    exit 1
fi

if [[ ! -f "$FRONTEND_DIST_DIR/index.html" ]]; then
    echo "ERROR: Frontend build output not found at $FRONTEND_DIST_DIR" >&2
    exit 1
fi

echo "[3/4] Staging package contents..."
mkdir -p "$PACKAGE_DIR/wasm" "$PACKAGE_DIR/front/admin" "$PACKAGE_DIR/scripts"
cp "$WASM_PATH" "$PACKAGE_DIR/wasm/"
cp -R "$FRONTEND_DIST_DIR" "$PACKAGE_DIR/front/admin/dist"
cp "$PROJECT_ROOT/scripts/deploy.sh" "$PACKAGE_DIR/scripts/"
cp "$PROJECT_ROOT/scripts/rollback.sh" "$PACKAGE_DIR/scripts/"
cp "$PROJECT_ROOT/scripts/README.md" "$PACKAGE_DIR/scripts/"
cp "$PROJECT_ROOT/README.md" "$PACKAGE_DIR/"

(
    cd "$PACKAGE_DIR"
    find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt
)

echo "[4/4] Creating release archive..."
tar -czf "$ARCHIVE_PATH" -C "$OUTPUT_DIR" "$PACKAGE_NAME"

echo "Package ready:"
echo "  Directory: $PACKAGE_DIR"
echo "  Archive:   $ARCHIVE_PATH"
