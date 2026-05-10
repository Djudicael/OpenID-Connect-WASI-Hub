#!/usr/bin/env bash
# Database backup script for OIDC Hub
# Creates a compressed PostgreSQL dump with timestamp
#
# Usage: ./scripts/backup-db.sh [OPTIONS]
#
# Options:
#   --db-url URL      PostgreSQL connection URL (default: $OIDC_DATABASE_URL)
#   --output DIR      Output directory (default: ./backups)
#   --retain N        Number of backups to retain (default: 7)
#   --no-verify       Skip backup integrity verification
#
# Environment:
#   OIDC_DATABASE_URL  PostgreSQL connection URL (required)

set -euo pipefail

# Defaults
DB_URL="${OIDC_DATABASE_URL:-}"
OUTPUT_DIR="${OIDC_BACKUP_DIR:-./backups}"
RETAIN=7
VERIFY=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --db-url)   DB_URL="$2"; shift 2 ;;
        --output)   OUTPUT_DIR="$2"; shift 2 ;;
        --retain)   RETAIN="$2"; shift 2 ;;
        --no-verify) VERIFY=false; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --db-url URL      PostgreSQL connection URL (default: \$OIDC_DATABASE_URL)"
            echo "  --output DIR      Output directory (default: ./backups)"
            echo "  --retain N        Number of backups to retain (default: 7)"
            echo "  --no-verify       Skip backup integrity verification"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Validate
if [[ -z "$DB_URL" ]]; then
    echo "ERROR: No database URL provided. Set OIDC_DATABASE_URL or use --db-url"
    exit 1
fi

# Check pg_dump is available
if ! command -v pg_dump &>/dev/null; then
    echo "ERROR: pg_dump not found. Install PostgreSQL client tools."
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${OUTPUT_DIR}/oidc_hub_${TIMESTAMP}.dump"

echo "=== OIDC Hub Database Backup ==="
echo "Timestamp: ${TIMESTAMP}"
echo "Output:    ${BACKUP_FILE}"
echo ""

# Create backup using custom format (compressed, selective restore)
echo "Creating backup..."
if pg_dump --format=custom --no-owner --no-privileges "$DB_URL" > "$BACKUP_FILE" 2>/dev/null; then
    SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "Backup created: ${BACKUP_FILE} (${SIZE})"
else
    echo "ERROR: pg_dump failed"
    rm -f "$BACKUP_FILE"
    exit 1
fi

# Verify backup integrity
if [[ "$VERIFY" == "true" ]]; then
    echo "Verifying backup integrity..."
    if pg_restore --list "$BACKUP_FILE" &>/dev/null; then
        echo "Backup verified: integrity OK"
    else
        echo "WARNING: Backup verification failed. The file may be corrupted."
        echo "Keeping the file for manual inspection."
    fi
fi

# Rotate old backups
echo "Rotating old backups (keeping last ${RETAIN})..."
ls -1t "${OUTPUT_DIR}/oidc_hub_"*.dump 2>/dev/null | tail -n +"$((RETAIN + 1))" | while read -r old_file; do
    echo "  Removing: $(basename "$old_file")"
    rm -f "$old_file"
done

REMAINING=$(ls -1 "${OUTPUT_DIR}/oidc_hub_"*.dump 2>/dev/null | wc -l)
echo "Backups retained: ${REMAINING}"
echo ""
echo "=== Backup complete ==="
