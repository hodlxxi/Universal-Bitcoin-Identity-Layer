#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

DATABASE_NAME="${DATABASE_NAME:-hodlxxi}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/hodlxxi/postgresql}"
POSTGRES_OS_USER="${POSTGRES_OS_USER:-postgres}"
COMPRESSION="${COMPRESSION:-6}"

[[ "$DATABASE_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
[[ "$POSTGRES_OS_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]]
[[ "$COMPRESSION" =~ ^[0-9]$ ]]
[[ "$BACKUP_DIR" = /* ]]
[ "$EUID" -eq 0 ]

install -d -m 0700 -o root -g root "$BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_name="${DATABASE_NAME}_${timestamp}.dump"
backup_path="${BACKUP_DIR}/${backup_name}"
checksum_path="${backup_path}.sha256"

runuser -u "$POSTGRES_OS_USER" -- pg_dump --dbname="$DATABASE_NAME" --format=custom --compress="$COMPRESSION" --no-password > "$backup_path"
chmod 0600 "$backup_path"
pg_restore --list "$backup_path" >/dev/null

(
  cd "$BACKUP_DIR"
  sha256sum "$backup_name" > "${backup_name}.sha256"
  chmod 0600 "${backup_name}.sha256"
  sha256sum --check "${backup_name}.sha256"
)

archive_entries="$(pg_restore --list "$backup_path" | awk '!/^[[:space:]]*;/ && NF { count += 1 } END { print count + 0 }')"
[ "$archive_entries" -gt 0 ]

echo "backup_status=success"
echo "database=$DATABASE_NAME"
echo "backup_path=$backup_path"
echo "checksum_path=$checksum_path"
echo "archive_entries=$archive_entries"
