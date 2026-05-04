#!/bin/bash
#
# Database restore script for HODLXXI
#
# Usage: ./scripts/db_restore.sh <backup_file>
#

set -e

# Check if backup file provided
if [ -z "$1" ]; then
    echo "Usage: $0 <backup_file>"
    echo ""
    echo "Available backups:"
    ls -lh ./backups/hodlxxi_backup_*.sql.gz 2>/dev/null || echo "No backups found"
    exit 1
fi

BACKUP_FILE="$1"

# Check if backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Load database environment variables safely
load_db_env() {
    if [ ! -f .env ]; then
        return 0
    fi

    # Parse .env without shell-expanding arbitrary file contents.
    # Only export DB_* values needed by backup/restore.
    eval "$(
        python3 - <<'PYENV'
from pathlib import Path
from urllib.parse import urlparse, unquote
import shlex

env = {}
for raw in Path(".env").read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip().strip('"').strip("'")
    env[key] = value

url = env.get("DATABASE_URL", "")
if url and url.startswith(("postgresql://", "postgresql+psycopg2://")):
    parsed = urlparse(url)
    env.setdefault("DB_HOST", parsed.hostname or "localhost")
    env.setdefault("DB_PORT", str(parsed.port or 5432))
    env.setdefault("DB_NAME", (parsed.path or "/hodlxxi").lstrip("/"))
    env.setdefault("DB_USER", unquote(parsed.username or "hodlxxi"))
    env.setdefault("DB_PASSWORD", unquote(parsed.password or ""))

allowed = ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD")
for key in allowed:
    if key in env and env[key] != "":
        print(f"export {key}={shlex.quote(env[key])}")
PYENV
    )"
}

load_db_env

# Configuration
DB_NAME="${DB_NAME:-hodlxxi}"
DB_USER="${DB_USER:-hodlxxi}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

echo "========================================"
echo "HODLXXI Database Restore"
echo "========================================"
echo "⚠️  WARNING: This will overwrite the current database!"
echo ""
echo "Database: $DB_NAME"
echo "Host: $DB_HOST:$DB_PORT"
echo "Backup file: $BACKUP_FILE"
echo ""

# Ask for confirmation
read -p "Are you sure you want to continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Restore cancelled"
    exit 0
fi

echo ""
echo "Restoring database..."

# Decompress if needed
if [[ "$BACKUP_FILE" == *.gz ]]; then
    echo "Decompressing backup..."
    TEMP_FILE="/tmp/hodlxxi_restore_temp.sql"
    gunzip -c "$BACKUP_FILE" > "$TEMP_FILE"
    RESTORE_FILE="$TEMP_FILE"
else
    RESTORE_FILE="$BACKUP_FILE"
fi

# Drop and recreate database (be careful!)
echo "Dropping existing database..."
PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d postgres \
    -c "DROP DATABASE IF EXISTS $DB_NAME;"

echo "Creating new database..."
PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d postgres \
    -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

# Restore backup
echo "Restoring backup..."
PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    -f "$RESTORE_FILE"

# Clean up temp file
if [ -f "$TEMP_FILE" ]; then
    rm "$TEMP_FILE"
fi

echo ""
echo "✅ Database restored successfully!"
echo ""
echo "Run migrations to ensure schema is up to date:"
echo "  alembic upgrade head"
