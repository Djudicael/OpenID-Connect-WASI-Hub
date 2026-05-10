#!/usr/bin/env bash
# =============================================================================
# OWASP ZAP Baseline Scan for OIDC Hub
# =============================================================================
# Runs a non-invasive (passive) security scan against a running OIDC server.
#
# Usage: ./security/zap-baseline.sh [OPTIONS]
#
# Options:
#   --target URL      Target URL (default: http://localhost:8080)
#   --duration MIN    Scan duration in minutes (default: 5)
#   --report FILE     Output report file (default: security/zap-report.html)
#   --json            Also output JSON report
#   --help            Show this help message
#
# Environment:
#   ZAP_TARGET_URL    Target URL override
#   ZAP_API_KEY       ZAP API key (if using ZAP daemon mode)
#   ZAP_DOCKER_IMAGE  ZAP Docker image (default: owasp/zap2docker-stable)
#
# Prerequisites:
#   - Docker must be installed and running
#   - The OIDC server must be running and accessible at the target URL
#
# Exit codes:
#   0 — Scan completed with no HIGH or CRITICAL alerts
#   1 — Scan completed with HIGH or CRITICAL alerts found
#   2 — Scan failed to start or encountered an error
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
TARGET_URL="${ZAP_TARGET_URL:-http://localhost:8080}"
DURATION_MIN=5
REPORT_FILE="security/zap-report.html"
JSON_REPORT=false
ZAP_IMAGE="${ZAP_DOCKER_IMAGE:-owasp/zap2docker-stable}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/zap-config.conf"

# ---------------------------------------------------------------------------
# Color helpers (no-op if not a terminal)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
    sed -n '/^# Usage:/,/^# =/\{ /^# =/d; s/^# \?//; p \}' "$0"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET_URL="$2"
            shift 2
            ;;
        --duration)
            DURATION_MIN="$2"
            shift 2
            ;;
        --report)
            REPORT_FILE="$2"
            shift 2
            ;;
        --json)
            JSON_REPORT=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            error "Unknown option: $1"
            error "Run with --help for usage information."
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
info "OWASP ZAP Baseline Scan — OIDC Hub"
info "===================================="

# Check Docker
if ! command -v docker &>/dev/null; then
    error "Docker is not installed or not in PATH."
    error "Install Docker: https://docs.docker.com/get-docker/"
    exit 2
fi

if ! docker info &>/dev/null; then
    error "Docker daemon is not running."
    exit 2
fi

# Check target is reachable
info "Checking target reachability: ${TARGET_URL}"
if ! curl -sf -o /dev/null "${TARGET_URL}/health" 2>/dev/null; then
    warn "Target ${TARGET_URL}/health did not respond — scan may fail."
    warn "Ensure the OIDC server is running before starting the scan."
fi

# Resolve report paths
REPORT_DIR="$(dirname "${REPORT_FILE}")"
REPORT_BASENAME="$(basename "${REPORT_FILE}")"
JSON_REPORT_FILE="${REPORT_DIR}/${REPORT_BASENAME%.html}.json"

mkdir -p "${REPORT_DIR}"

# ---------------------------------------------------------------------------
# OIDC Hub endpoints to scan
# ---------------------------------------------------------------------------
OIDC_ENDPOINTS=(
    "/.well-known/openid-configuration"
    "/oidc/jwks"
    "/oidc/authorize"
    "/oidc/token"
    "/oidc/userinfo"
    "/oidc/introspect"
    "/oidc/revoke"
    "/api/keys"
    "/health"
    "/health/ready"
)

# ---------------------------------------------------------------------------
# Pull ZAP Docker image
# ---------------------------------------------------------------------------
info "Pulling ZAP Docker image: ${ZAP_IMAGE}"
docker pull "${ZAP_IMAGE}" 2>/dev/null || warn "Pull failed — using local image if available."

# ---------------------------------------------------------------------------
# Run ZAP baseline scan
# ---------------------------------------------------------------------------
# Duration in seconds (ZAP uses -m for minutes)
ZAP_DURATION_MIN="${DURATION_MIN}"

# Build the ZAP command
# -t  : target URL
# -m  : max duration in minutes
# -c  : config file for thresholds
# -r  : HTML report file
# -w  : MD report file
# -J  : JSON report file
# -z  : ZAP command-line options passed through

ZAP_CMD=(
    "zap-baseline.py"
    "-t" "${TARGET_URL}"
    "-m" "${ZAP_DURATION_MIN}"
    "-r" "/zap/reports/${REPORT_BASENAME}"
)

# Add config file if it exists
if [[ -f "${CONFIG_FILE}" ]]; then
    info "Using ZAP config: ${CONFIG_FILE}"
    ZAP_CMD+=("-c" "/zap/config/zap-config.conf")
fi

# Add JSON report if requested
if [[ "${JSON_REPORT}" == true ]]; then
    ZAP_CMD+=("-J" "/zap/reports/${REPORT_BASENAME%.html}.json")
fi

# Pass through additional ZAP options
ZAP_EXTRA_OPTS=""
for endpoint in "${OIDC_ENDPOINTS[@]}"; do
    ZAP_EXTRA_OPTS="${ZAP_EXTRA_OPTS} -config contexts.0.include.regexes${endpoint}=${TARGET_URL}${endpoint}"
done

if [[ -n "${ZAP_EXTRA_OPTS}" ]]; then
    ZAP_CMD+=("-z" "${ZAP_EXTRA_OPTS}")
fi

info "Running ZAP baseline scan..."
info "  Target:   ${TARGET_URL}"
info "  Duration: ${ZAP_DURATION_MIN} minutes"
info "  Report:   ${REPORT_FILE}"
if [[ "${JSON_REPORT}" == true ]]; then
    info "  JSON:     ${JSON_REPORT_FILE}"
fi

# Docker volume mounts
REPORT_DIR_ABS="$(cd "${REPORT_DIR}" && pwd)"
CONFIG_DIR_ABS="$(cd "${SCRIPT_DIR}" && pwd)"

DOCKER_RUN_ARGS=(
    "--rm"
    "--name" "zap-baseline-oidc-$$"
    "-v" "${REPORT_DIR_ABS}:/zap/reports:rw"
    "-v" "${CONFIG_DIR_ABS}:/zap/config:ro"
    "--network" "host"
)

# Add API key if provided
if [[ -n "${ZAP_API_KEY:-}" ]]; then
    DOCKER_RUN_ARGS+=("-e" "ZAP_API_KEY=${ZAP_API_KEY}")
fi

info "Starting ZAP container..."
set +e
docker run "${DOCKER_RUN_ARGS[@]}" "${ZAP_IMAGE}" "${ZAP_CMD[@]}"
ZAP_EXIT_CODE=$?
set -e

# ---------------------------------------------------------------------------
# Interpret ZAP exit codes
# ---------------------------------------------------------------------------
# ZAP baseline exit codes:
#   0 — PASS: No alerts found
#   1 — WARN: Intermediate alerts found (ignored by default)
#   2 — FAIL: High/Critical alerts found
#   3 — ERROR: ZAP failed to run

case ${ZAP_EXIT_CODE} in
    0)
        info "ZAP scan PASSED — no alerts found."
        info "Report saved to: ${REPORT_FILE}"
        ;;
    1)
        warn "ZAP scan found WARN-level alerts (informational)."
        warn "Review the report at: ${REPORT_FILE}"
        info "These are typically informational and do not block the build."
        # Exit 0 — WARN-level alerts are not blocking
        ;;
    2)
        error "ZAP scan FAILED — HIGH or CRITICAL alerts found!"
        error "Review the report at: ${REPORT_FILE}"
        error "Fix the issues or add exceptions to ${CONFIG_FILE}"
        exit 1
        ;;
    3)
        error "ZAP scan encountered an ERROR."
        error "Check that the target server is running and accessible."
        exit 2
        ;;
    *)
        error "ZAP exited with unexpected code: ${ZAP_EXIT_CODE}"
        exit 2
        ;;
esac

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
info "========== Scan Summary =========="
info "Target:        ${TARGET_URL}"
info "Duration:      ${ZAP_DURATION_MIN} minutes"
info "HTML Report:   ${REPORT_FILE}"
if [[ "${JSON_REPORT}" == true ]]; then
    info "JSON Report:   ${JSON_REPORT_FILE}"
fi
info "ZAP Exit Code: ${ZAP_EXIT_CODE}"
info "=================================="

echo ""
info "Endpoints scanned:"
for endpoint in "${OIDC_ENDPOINTS[@]}"; do
    info "  ${TARGET_URL}${endpoint}"
done

echo ""
info "To view the HTML report:"
info "  open ${REPORT_FILE}"
echo ""
info "To add exceptions for false positives, edit:"
info "  ${CONFIG_FILE}"

exit 0
