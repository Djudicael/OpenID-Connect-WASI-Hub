#!/usr/bin/env bash
# =============================================================================
# check-coverage.sh — Local code coverage check for OpenID Connect WASI Hub
#
# Usage:
#   ./scripts/check-coverage.sh          # Terminal report + fail-under-lines 60%
#   ./scripts/check-coverage.sh --html   # Also generate HTML report in target/llvm-cov/html/
#
# Prerequisites:
#   - rustup component llvm-tools-preview
#   - cargo-llvm-cov (installed automatically if missing)
#
# Notes:
#   - Coverage only works for native targets (not wasm32-wasip2).
#   - integration-tests and oidc-dev are excluded (they require Docker/process deps).
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MIN_LINE_COVERAGE=60
EXCLUDE_CRATES="integration-tests,oidc-dev"
HTML_REPORT=false

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --html)
            HTML_REPORT=true
            ;;
        -h|--help)
            echo "Usage: $0 [--html]"
            echo ""
            echo "Options:"
            echo "  --html    Generate an HTML coverage report in target/llvm-cov/html/"
            echo "  -h,--help Show this help message"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument: $arg"
            echo "Run '$0 --help' for usage."
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Colors (if terminal supports it)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    BOLD=''
    RESET=''
fi

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------
echo -e "${CYAN}==> Checking prerequisites...${RESET}"

# Check rustup
if ! command -v rustup &>/dev/null; then
    echo -e "${RED}ERROR: rustup is not installed. Please install it from https://rustup.rs/${RESET}"
    exit 1
fi

# Check/install llvm-tools-preview
if ! rustup component list --installed | grep -q "llvm-tools-preview"; then
    echo -e "${YELLOW}    llvm-tools-preview not found. Installing...${RESET}"
    rustup component add llvm-tools-preview
fi
echo -e "    llvm-tools-preview: ${GREEN}OK${RESET}"

# Check/install cargo-llvm-cov
if ! command -v cargo-llvm-cov &>/dev/null; then
    echo -e "${YELLOW}    cargo-llvm-cov not found. Installing...${RESET}"
    cargo install cargo-llvm-cov --locked
fi
echo -e "    cargo-llvm-cov:     ${GREEN}OK${RESET}"

# ---------------------------------------------------------------------------
# Build the --exclude flags
# ---------------------------------------------------------------------------
EXCLUDE_FLAGS=""
for crate in ${EXCLUDE_CRATES//,/ }; do
    EXCLUDE_FLAGS="$EXCLUDE_FLAGS --exclude $crate"
done

# ---------------------------------------------------------------------------
# Run coverage
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}==> Running cargo llvm-cov (this may take a while on first run)...${RESET}"

# Capture the text report for parsing
TEXT_OUTPUT=$(cargo llvm-cov --workspace $EXCLUDE_FLAGS 2>&1) || {
    echo -e "${RED}ERROR: cargo llvm-cov failed. Output:${RESET}"
    echo "$TEXT_OUTPUT"
    exit 1
}

# ---------------------------------------------------------------------------
# Print summary table by crate
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Coverage Summary by Crate:${RESET}"
echo -e "${BOLD}───────────────────────────────────────────────────────────${RESET}"
printf "  %-30s %10s %10s %10s\n" "Crate" "Lines" "Regions" "Functions"
echo -e "${BOLD}───────────────────────────────────────────────────────────${RESET}"

# Parse the cargo llvm-cov output — each crate line looks like:
#   crate_name    X.X%  Y/Y    A.A%  B/B    C.C%  D/D
# We extract the crate name and the three percentage columns.
echo "$TEXT_OUTPUT" | tail -n +2 | while IFS= read -r line; do
    # Skip empty lines and the total line (we handle total separately)
    if [ -z "$line" ] || echo "$line" | grep -q "^Total"; then
        continue
    fi

    # Extract fields: name, line%, region%, function%
    crate_name=$(echo "$line" | awk '{print $1}')
    line_pct=$(echo "$line" | awk '{print $2}')
    region_pct=$(echo "$line" | awk '{print $4}')
    func_pct=$(echo "$line" | awk '{print $6}')

    # Color-code line coverage
    line_num="${line_pct%\%}"
    if [ "$(echo "$line_num >= 80" | bc -l 2>/dev/null || echo 0)" -eq 1 ]; then
        color="$GREEN"
    elif [ "$(echo "$line_num >= 60" | bc -l 2>/dev/null || echo 0)" -eq 1 ]; then
        color="$YELLOW"
    else
        color="$RED"
    fi

    printf "  %-30s ${color}%10s${RESET} %10s %10s\n" "$crate_name" "$line_pct" "$region_pct" "$func_pct"
done

# Print total line
TOTAL_LINE=$(echo "$TEXT_OUTPUT" | grep "^Total" || true)
if [ -n "$TOTAL_LINE" ]; then
    echo -e "${BOLD}───────────────────────────────────────────────────────────${RESET}"
    total_line_pct=$(echo "$TOTAL_LINE" | awk '{print $2}')
    total_region_pct=$(echo "$TOTAL_LINE" | awk '{print $4}')
    total_func_pct=$(echo "$TOTAL_LINE" | awk '{print $6}')

    total_line_num="${total_line_pct%\%}"
    if [ "$(echo "$total_line_num >= 80" | bc -l 2>/dev/null || echo 0)" -eq 1 ]; then
        color="$GREEN"
    elif [ "$(echo "$total_line_num >= 60" | bc -l 2>/dev/null || echo 0)" -eq 1 ]; then
        color="$YELLOW"
    else
        color="$RED"
    fi

    printf "  %-30s ${color}${BOLD}%10s${RESET} %10s %10s\n" "TOTAL" "$total_line_pct" "$total_region_pct" "$total_func_pct"
fi

echo -e "${BOLD}───────────────────────────────────────────────────────────${RESET}"

# ---------------------------------------------------------------------------
# Generate lcov.info
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}==> Generating lcov.info...${RESET}"
cargo llvm-cov --workspace $EXCLUDE_FLAGS --lcov --output-path lcov.info
echo -e "    ${GREEN}lcov.info written to project root${RESET}"

# ---------------------------------------------------------------------------
# Optional: HTML report
# ---------------------------------------------------------------------------
if [ "$HTML_REPORT" = true ]; then
    echo ""
    echo -e "${CYAN}==> Generating HTML coverage report...${RESET}"
    cargo llvm-cov --workspace $EXCLUDE_FLAGS --html
    echo -e "    ${GREEN}HTML report written to target/llvm-cov/html/${RESET}"
fi

# ---------------------------------------------------------------------------
# Enforce minimum coverage threshold
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}==> Checking minimum line coverage threshold (${MIN_LINE_COVERAGE}%)...${RESET}"

if cargo llvm-cov --workspace $EXCLUDE_FLAGS --fail-under-lines "$MIN_LINE_COVERAGE" 2>&1; then
    echo ""
    echo -e "${GREEN}${BOLD}✓ Coverage check PASSED (>= ${MIN_LINE_COVERAGE}% line coverage)${RESET}"
else
    echo ""
    echo -e "${RED}${BOLD}✗ Coverage check FAILED (< ${MIN_LINE_COVERAGE}% line coverage)${RESET}"
    echo -e "${YELLOW}    Tip: Run with --html to see a detailed report of uncovered lines.${RESET}"
    exit 1
fi
