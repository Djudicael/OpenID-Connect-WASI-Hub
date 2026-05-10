#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run-all.sh — Run the full k6 load-test suite for the OIDC Hub
#
# Runs each test in sequence, outputting JSON results to the results/ directory.
# Prints a summary after all tests complete.
#
# Usage:
#   ./load-tests/k6/run-all.sh
#   BASE_URL=http://my-server:8080 ./load-tests/k6/run-all.sh
#   SKIP_SMOKE=1 ./load-tests/k6/run-all.sh        # skip smoke gate
#   TESTS="discovery token" ./load-tests/k6/run-all.sh  # run subset
#
# Environment variables (all optional — sensible defaults provided):
#   BASE_URL        — OIDC Hub base URL          (default: http://localhost:8080)
#   ADMIN_EMAIL     — Admin user email           (default: admin@localhost)
#   ADMIN_PASSWORD  — Admin user password        (default: admin123)
#   CLIENT_ID       — Service client ID          (default: test-service-client)
#   CLIENT_SECRET   — Service client secret      (default: test-service-secret)
#   API_KEY         — Raw API key                (default: sk_test_admin_key_placeholder)
#   REALM_ID        — Realm UUID                 (default: 00000000-0000-0000-0000-000000000001)
#   RESULTS_DIR     — Output directory           (default: <script_dir>/results)
#   SKIP_SMOKE      — Set to "1" to skip smoke   (default: unset — smoke runs first)
#   TESTS           — Space-separated test list  (default: all)
#   K6_OPTIONS      — Extra k6 flags             (default: "")
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K6_DIR="${SCRIPT_DIR}"
RESULTS_DIR="${RESULTS_DIR:-${K6_DIR}/results}"
mkdir -p "${RESULTS_DIR}"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
BASE_URL="${BASE_URL:-http://localhost:8080}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@localhost}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin123}"
CLIENT_ID="${CLIENT_ID:-test-service-client}"
CLIENT_SECRET="${CLIENT_SECRET:-test-service-secret}"
API_KEY="${API_KEY:-sk_test_admin_key_placeholder}"
REALM_ID="${REALM_ID:-00000000-0000-0000-0000-000000000001}"
K6_OPTIONS="${K6_OPTIONS:-}"

# Timestamp for this run
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------
if ! command -v k6 &>/dev/null; then
  echo "ERROR: k6 is not installed."
  echo ""
  echo "Install it with:"
  echo "  macOS:   brew install k6"
  echo "  Linux:   https://k6.io/docs/get-started/installation/"
  echo "  Windows: choco install k6"
  exit 1
fi

echo "============================================"
echo "  OIDC Hub — k6 Load Test Suite"
echo "============================================"
echo "  BASE_URL:       ${BASE_URL}"
echo "  ADMIN_EMAIL:    ${ADMIN_EMAIL}"
echo "  CLIENT_ID:      ${CLIENT_ID}"
echo "  API_KEY:        ${API_KEY:0:12}..."
echo "  RESULTS_DIR:    ${RESULTS_DIR}"
echo "  TIMESTAMP:      ${TIMESTAMP}"
echo "  k6 version:     $(k6 version 2>/dev/null || echo 'unknown')"
echo "============================================"
echo ""

# ---------------------------------------------------------------------------
# Common k6 environment flags
# ---------------------------------------------------------------------------
K6_ENV=(
  -e "BASE_URL=${BASE_URL}"
  -e "ADMIN_EMAIL=${ADMIN_EMAIL}"
  -e "ADMIN_PASSWORD=${ADMIN_PASSWORD}"
  -e "CLIENT_ID=${CLIENT_ID}"
  -e "CLIENT_SECRET=${CLIENT_SECRET}"
  -e "API_KEY=${API_KEY}"
  -e "REALM_ID=${REALM_ID}"
)

# ---------------------------------------------------------------------------
# Test definitions: name → script path
# ---------------------------------------------------------------------------
declare -A ALL_TESTS=(
  [smoke]="smoke.js"
  [discovery]="discovery.js"
  [token]="token.js"
  [userinfo]="userinfo.js"
  [apikey]="apikey.js"
  [full-flow]="full-flow.js"
)

# Determine which tests to run
if [ -n "${TESTS:-}" ]; then
  # User specified a subset
  read -ra SELECTED <<< "${TESTS}"
else
  # Default: all tests
  SELECTED=(smoke discovery token userinfo apikey full-flow)
fi

# ---------------------------------------------------------------------------
# Run a single test
# ---------------------------------------------------------------------------
# Arguments: $1 = test name, $2 = script filename
# Returns: 0 on success, 1 on failure
run_test() {
  local name="$1"
  local script="$2"
  local script_path="${K6_DIR}/${script}"
  local output_file="${RESULTS_DIR}/${name}-${TIMESTAMP}.json"

  if [ ! -f "${script_path}" ]; then
    echo "  ⚠ Script not found: ${script_path}"
    return 1
  fi

  echo "────────────────────────────────────────────"
  echo "  Running: ${name}"
  echo "  Script:  ${script}"
  echo "  Output: ${output_file}"
  echo "────────────────────────────────────────────"

  local start_time end_time elapsed exit_code

  start_time=$(date +%s)

  # Run k6 — capture exit code but don't exit the script
  set +e
  k6 run \
    "${K6_ENV[@]}" \
    --out "json=${output_file}" \
    ${K6_OPTIONS} \
    "${script_path}"
  exit_code=$?
  set -e

  end_time=$(date +%s)
  elapsed=$((end_time - start_time))

  if [ ${exit_code} -eq 0 ]; then
    echo "  ✅ ${name} PASSED (${elapsed}s)"
    PASSED+=("${name}")
  else
    echo "  ❌ ${name} FAILED (exit ${exit_code}, ${elapsed}s)"
    FAILED+=("${name}")
  fi
  echo ""

  return ${exit_code}
}

# ---------------------------------------------------------------------------
# Smoke test gate
# ---------------------------------------------------------------------------
PASSED=()
FAILED=()

if [ "${SKIP_SMOKE:-0}" != "1" ]; then
  echo "🚦 Running smoke test as gate..."
  echo ""

  if ! run_test "smoke" "smoke.js"; then
    echo "============================================"
    echo "  ⛔ SMOKE TEST FAILED — aborting suite."
    echo "  The server may not be running or test data"
    echo "  may not be seeded. See errors above."
    echo "============================================"
    echo ""
    echo "To skip the smoke gate, set SKIP_SMOKE=1"
    exit 1
  fi

  echo "✅ Smoke test passed — proceeding with load tests."
  echo ""
fi

# ---------------------------------------------------------------------------
# Run load tests
# ---------------------------------------------------------------------------
for test_name in "${SELECTED[@]}"; do
  # Skip smoke if it was already run as the gate (unless explicitly in TESTS)
  if [ "${test_name}" = "smoke" ] && [ "${SKIP_SMOKE:-0}" != "1" ]; then
    continue
  fi

  script="${ALL_TESTS[${test_name}]:-}"
  if [ -z "${script}" ]; then
    echo "⚠ Unknown test: ${test_name}"
    echo "  Available: ${!ALL_TESTS[*]}"
    FAILED+=("${test_name}")
    continue
  fi

  run_test "${test_name}" "${script}"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$(( ${#PASSED[@]} + ${#FAILED[@]} ))
echo "============================================"
echo "  Load Test Suite — Summary"
echo "============================================"
echo "  Total:  ${TOTAL}"
echo "  Passed: ${#PASSED[@]}"
echo "  Failed: ${#FAILED[@]}"
echo ""

if [ ${#PASSED[@]} -gt 0 ]; then
  echo "  ✅ Passed:"
  for t in "${PASSED[@]}"; do
    echo "     • ${t}"
  done
  echo ""
fi

if [ ${#FAILED[@]} -gt 0 ]; then
  echo "  ❌ Failed:"
  for t in "${FAILED[@]}"; do
    echo "     • ${t}"
  done
  echo ""
fi

echo "  📁 Results: ${RESULTS_DIR}/"
echo "  📊 Parse:   node ${K6_DIR}/parse-results.js ${RESULTS_DIR}/*-${TIMESTAMP}.json"
echo "============================================"

if [ ${#FAILED[@]} -gt 0 ]; then
  exit 1
fi

exit 0
