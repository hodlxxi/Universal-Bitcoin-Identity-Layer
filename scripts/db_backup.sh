#!/bin/bash
#
# Database backup script for HODLXXI
#
# Usage: ./scripts/db_backup.sh [backup_directory]
#

set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Configuration
BACKUP_DIR="${1:-./backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_NAME="${DB_NAME:-hodlxxi}"
DB_USER="${DB_USER:-hodlxxi}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
BACKUP_FILE="${BACKUP_DIR}/hodlxxi_backup_${TIMESTAMP}.sql"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

echo "========================================"
echo "HODLXXI Database Backup"
echo "========================================"
echo "Database: $DB_NAME"
echo "Host: $DB_HOST:$DB_PORT"
echo "Backup file: $BACKUP_FILE"
echo ""

# Create backup
echo "Creating backup..."
PGPASSWORD="$DB_PASSWORD" pg_dump \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    -F p \
    -f "$BACKUP_FILE"

# Compress backup
echo "Compressing backup..."
gzip "$BACKUP_FILE"
BACKUP_FILE="${BACKUP_FILE}.gz"

# Get file size
SIZE=$(du -h "$BACKUP_FILE" | cut -f1)

echo ""
echo "✅ Backup complete!"
echo "File: $BACKUP_FILE"
echo "Size: $SIZE"
echo ""

# Keep only last 7 backups
echo "Cleaning old backups (keeping last 7)..."
ls -t "${BACKUP_DIR}"/hodlxxi_backup_*.sql.gz 2>/dev/null | tail -n +8 | xargs -r rm
echo "✅ Cleanup complete"

# List all backups
echo ""
echo "Available backups:"
ls -lh "${BACKUP_DIR}"/hodlxxi_backup_*.sql.gz 2>/dev/null || echo "No backups found"
