#!/bin/bash
# HODLXXI Automated Backup Setup
# Run as root: sudo bash setup-automated-backups.sh

set -e  # Exit on error

echo "========================================"
echo "HODLXXI Automated Backup Setup"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root"
    exit 1
fi

# Configuration
BACKUP_DIR="/backup/hodlxxi"
BACKUP_SCRIPT="/usr/local/bin/hodlxxi-backup.sh"

echo -e "${GREEN}Step 1: Create Backup Directory${NC}"
echo "----------------------------------------"

mkdir -p "$BACKUP_DIR"
chmod 750 "$BACKUP_DIR"
chown hodlxxi:hodlxxi "$BACKUP_DIR"

echo "Created: $BACKUP_DIR"
echo ""

echo -e "${GREEN}Step 2: Create Backup Script${NC}"
echo "----------------------------------------"

cat > "$BACKUP_SCRIPT" <<'EOFBACKUP'
#!/bin/bash
#
# HODLXXI Automated Backup Script
# Backs up: PostgreSQL database, Redis data, application config
#

set -e

# Configuration
BACKUP_DIR="/backup/hodlxxi"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30
LOG_FILE="/var/log/hodlxxi/backup.log"

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=========================================="
log "Starting HODLXXI backup: $DATE"
log "=========================================="

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# 1. Backup PostgreSQL database
log "Backing up PostgreSQL database..."
if command -v pg_dump &> /dev/null; then
    sudo -u postgres pg_dump hodlxxi | gzip > "$BACKUP_DIR/hodlxxi_db_$DATE.sql.gz"
    log "✓ PostgreSQL backup completed: hodlxxi_db_$DATE.sql.gz"
else
    log "⚠ WARNING: pg_dump not found, skipping PostgreSQL backup"
fi

# 2. Backup Redis data (if Redis is running)
log "Backing up Redis data..."
if systemctl is-active --quiet redis-server; then
    # Trigger Redis save
    redis-cli -a "${REDIS_PASSWORD:-RedisSecure2025!}" SAVE > /dev/null 2>&1 || log "⚠ Redis save failed (might be password issue)"

    # Copy RDB file if it exists
    if [ -f /var/lib/redis/dump.rdb ]; then
        cp /var/lib/redis/dump.rdb "$BACKUP_DIR/redis_$DATE.rdb"
        log "✓ Redis backup completed: redis_$DATE.rdb"
    else
        log "⚠ WARNING: Redis dump.rdb not found"
    fi
else
    log "⚠ WARNING: Redis is not running, skipping Redis backup"
fi

# 3. Backup application configuration
log "Backing up application configuration..."
if [ -f /srv/app/.env ]; then
    tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" \
        /srv/app/.env \
        /srv/app/app/models.py \
        /srv/app/app/database.py \
        /srv/app/app/db_storage.py \
        /etc/systemd/system/app.service \
        /etc/nginx/sites-available/hodlxxi 2>/dev/null || true
    log "✓ Configuration backup completed: config_$DATE.tar.gz"
else
    log "⚠ WARNING: /srv/app/.env not found"
fi

# 4. Calculate backup sizes
log "Backup sizes:"
if [ -f "$BACKUP_DIR/hodlxxi_db_$DATE.sql.gz" ]; then
    DB_SIZE=$(du -h "$BACKUP_DIR/hodlxxi_db_$DATE.sql.gz" | cut -f1)
    log "  Database: $DB_SIZE"
fi
if [ -f "$BACKUP_DIR/redis_$DATE.rdb" ]; then
    REDIS_SIZE=$(du -h "$BACKUP_DIR/redis_$DATE.rdb" | cut -f1)
    log "  Redis: $REDIS_SIZE"
fi
if [ -f "$BACKUP_DIR/config_$DATE.tar.gz" ]; then
    CONFIG_SIZE=$(du -h "$BACKUP_DIR/config_$DATE.tar.gz" | cut -f1)
    log "  Config: $CONFIG_SIZE"
fi

# 5. Remove old backups (retention policy)
log "Cleaning old backups (retention: ${RETENTION_DAYS} days)..."
DELETED_COUNT=0

# Remove old database backups
DELETED_COUNT=$(find "$BACKUP_DIR" -name "hodlxxi_db_*.sql.gz" -mtime +$RETENTION_DAYS -delete -print | wc -l)
if [ $DELETED_COUNT -gt 0 ]; then
    log "  Deleted $DELETED_COUNT old database backup(s)"
fi

# Remove old Redis backups
DELETED_COUNT=$(find "$BACKUP_DIR" -name "redis_*.rdb" -mtime +$RETENTION_DAYS -delete -print | wc -l)
if [ $DELETED_COUNT -gt 0 ]; then
    log "  Deleted $DELETED_COUNT old Redis backup(s)"
fi

# Remove old config backups
DELETED_COUNT=$(find "$BACKUP_DIR" -name "config_*.tar.gz" -mtime +$RETENTION_DAYS -delete -print | wc -l)
if [ $DELETED_COUNT -gt 0 ]; then
    log "  Deleted $DELETED_COUNT old config backup(s)"
fi

# 6. Summary
TOTAL_BACKUPS=$(ls -1 "$BACKUP_DIR" | wc -l)
DISK_USAGE=$(du -sh "$BACKUP_DIR" | cut -f1)

log "=========================================="
log "Backup completed successfully!"
log "Total backups in directory: $TOTAL_BACKUPS"
log "Total disk usage: $DISK_USAGE"
log "=========================================="

# Optional: Upload to remote storage (uncomment and configure)
# if command -v rclone &> /dev/null; then
#     log "Uploading to remote storage..."
#     rclone copy "$BACKUP_DIR" remote:hodlxxi-backups/
#     log "✓ Remote upload completed"
# fi

exit 0
EOFBACKUP

chmod +x "$BACKUP_SCRIPT"
chown root:root "$BACKUP_SCRIPT"

echo "Created: $BACKUP_SCRIPT"
echo ""

echo -e "${GREEN}Step 3: Test Backup Script${NC}"
echo "----------------------------------------"

echo "Running test backup..."
bash "$BACKUP_SCRIPT"

echo ""
echo -e "${GREEN}Step 4: Configure Cron Job${NC}"
echo "----------------------------------------"

# Add cron job for hodlxxi user (runs daily at 2:00 AM)
CRON_JOB="0 2 * * * $BACKUP_SCRIPT"

# Check if cron job already exists
if crontab -u hodlxxi -l 2>/dev/null | grep -q "$BACKUP_SCRIPT"; then
    echo "Cron job already exists for hodlxxi user"
else
    # Add cron job
    (crontab -u hodlxxi -l 2>/dev/null; echo "$CRON_JOB") | crontab -u hodlxxi -
    echo "Added cron job: Daily backup at 2:00 AM"
fi

# Show current crontab
echo ""
echo "Current backup schedule for hodlxxi user:"
crontab -u hodlxxi -l | grep -v "^#" || echo "No cron jobs found"

echo ""
echo -e "${GREEN}Step 5: Create Restore Script${NC}"
echo "----------------------------------------"

cat > /usr/local/bin/hodlxxi-restore.sh <<'EOFRESTORE'
#!/bin/bash
#
# HODLXXI Database Restore Script
# Usage: sudo bash hodlxxi-restore.sh <backup_file.sql.gz>
#

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <backup_file.sql.gz>"
    echo ""
    echo "Available backups:"
    ls -lh /backup/hodlxxi/*.sql.gz 2>/dev/null || echo "No backups found"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "========================================"
echo "HODLXXI Database Restore"
echo "========================================"
echo ""
echo "⚠ WARNING: This will DROP and recreate the database!"
echo "Backup file: $BACKUP_FILE"
echo ""
read -p "Are you sure you want to continue? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Restore cancelled."
    exit 0
fi

echo ""
echo "Stopping application..."
systemctl stop app

echo "Dropping and recreating database..."
sudo -u postgres psql <<EOF
DROP DATABASE IF EXISTS hodlxxi;
CREATE DATABASE hodlxxi OWNER hodlxxi;
EOF

echo "Restoring database from backup..."
gunzip -c "$BACKUP_FILE" | sudo -u postgres psql hodlxxi

echo "Restarting application..."
systemctl start app

echo ""
echo "✓ Database restore completed!"
echo ""
echo "Verification:"
systemctl status app
EOFRESTORE

chmod +x /usr/local/bin/hodlxxi-restore.sh

echo "Created: /usr/local/bin/hodlxxi-restore.sh"
echo ""

echo -e "${GREEN}========================================"
echo "Automated Backup Setup Complete!"
echo "========================================${NC}"
echo ""
echo "Summary:"
echo "  ✓ Backup directory: $BACKUP_DIR"
echo "  ✓ Backup script: $BACKUP_SCRIPT"
echo "  ✓ Restore script: /usr/local/bin/hodlxxi-restore.sh"
echo "  ✓ Cron job: Daily at 2:00 AM"
echo "  ✓ Retention: $RETENTION_DAYS days"
echo ""
echo "Latest backup:"
ls -lh "$BACKUP_DIR" | tail -n 5
echo ""
echo "Manual backup: sudo $BACKUP_SCRIPT"
echo "Manual restore: sudo /usr/local/bin/hodlxxi-restore.sh /backup/hodlxxi/hodlxxi_db_YYYYMMDD_HHMMSS.sql.gz"
echo ""
