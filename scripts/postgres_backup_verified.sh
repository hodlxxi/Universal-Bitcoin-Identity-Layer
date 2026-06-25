#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
export LC_ALL=C

DATABASE_NAME="${DATABASE_NAME:-hodlxxi}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/hodlxxi/postgresql}"
POSTGRES_OS_USER="${POSTGRES_OS_USER:-postgres}"
COMPRESSION="${COMPRESSION:-6}"
TEMPORARY_PATH=""
TEMPORARY_CHECKSUM_PATH=""

cleanup() {
  [ -z "$TEMPORARY_PATH" ] || rm -f -- "$TEMPORARY_PATH"
  [ -z "$TEMPORARY_CHECKSUM_PATH" ] || rm -f -- "$TEMPORARY_CHECKSUM_PATH"
}

trap cleanup EXIT

[ "$EUID" -eq 0 ]
[[ "$DATABASE_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
[[ "$POSTGRES_OS_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]]
[[ "$COMPRESSION" =~ ^[0-9]$ ]]
[[ "$BACKUP_DIR" = /* ]]
[ "$BACKUP_DIR" != "/" ]

install -d -m 0700 -o root -g root "$BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_name="${DATABASE_NAME}_${timestamp}.dump"
backup_path="${BACKUP_DIR}/${backup_name}"
checksum_path="${backup_path}.sha256"
[ ! -e "$backup_path" ]
[ ! -e "$checksum_path" ]

TEMPORARY_PATH="$(mktemp "${BACKUP_DIR}/.${backup_name}.tmp.XXXXXX")"
TEMPORARY_CHECKSUM_PATH="$(mktemp "${BACKUP_DIR}/.${backup_name}.sha256.tmp.XXXXXX")"
chmod 0600 "$TEMPORARY_PATH" "$TEMPORARY_CHECKSUM_PATH"

runuser -u "$POSTGRES_OS_USER" -- pg_dump --dbname="$DATABASE_NAME" --format=custom --compress="$COMPRESSION" --no-password > "$TEMPORARY_PATH"
[ -s "$TEMPORARY_PATH" ]
pg_restore --list "$TEMPORARY_PATH" >/dev/null

archive_entries="$(pg_restore --list "$TEMPORARY_PATH" | awk '!/^[[:space:]]*;/ && NF { count += 1 } END { print count + 0 }')"
[ "$archive_entries" -gt 0 ]

checksum="$(sha256sum "$TEMPORARY_PATH" | awk '{print $1}')"
printf '%s  %s\n' "$checksum" "$backup_name" > "$TEMPORARY_CHECKSUM_PATH"

mv -- "$TEMPORARY_PATH" "$backup_path"
TEMPORARY_PATH=""
mv -- "$TEMPORARY_CHECKSUM_PATH" "$checksum_path"
TEMPORARY_CHECKSUM_PATH=""
chmod 0600 "$backup_path" "$checksum_path"

(
  cd "$BACKUP_DIR"
  sha256sum --check "${backup_name}.sha256"
)
pg_restore --list "$backup_path" >/dev/null

echo "backup_status=success"
echo "database=$DATABASE_NAME"
echo "backup_path=$backup_path"
echo "checksum_path=$checksum_path"
echo "archive_entries=$archive_entries"
