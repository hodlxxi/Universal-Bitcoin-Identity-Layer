#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

BACKUP_PATH="${1:-}"
PRODUCTION_DATABASE="${PRODUCTION_DATABASE:-hodlxxi}"
SCRATCH_DATABASE="${SCRATCH_DATABASE:-}"
POSTGRES_OS_USER="${POSTGRES_OS_USER:-postgres}"
TMPDIR_PATH="$(mktemp -d /tmp/ubid-postgres-verify.XXXXXX)"

cleanup_files() {
  rm -f -- "$TMPDIR_PATH"/*
  rmdir "$TMPDIR_PATH"
}

trap cleanup_files EXIT

validate_scratch_name() {
  case "$SCRATCH_DATABASE" in
    ubid_restore_verify_*) return 0 ;;
    *) return 1 ;;
  esac
}

[ "$EUID" -eq 0 ]
[ -n "$BACKUP_PATH" ]
[ -n "$SCRATCH_DATABASE" ]
[[ "$BACKUP_PATH" = /* ]]
[[ "$PRODUCTION_DATABASE" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
[[ "$POSTGRES_OS_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]]
validate_scratch_name
[ "$SCRATCH_DATABASE" != "$PRODUCTION_DATABASE" ]
[ -f "$BACKUP_PATH" ]
[ ! -L "$BACKUP_PATH" ]
[ -f "${BACKUP_PATH}.sha256" ]
[ ! -L "${BACKUP_PATH}.sha256" ]

(
  cd "$(dirname "$BACKUP_PATH")"
  sha256sum --check "$(basename "${BACKUP_PATH}.sha256")"
)
pg_restore --list "$BACKUP_PATH" >/dev/null

scratch_exists="$(runuser -u "$POSTGRES_OS_USER" -- psql -X -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname = '$SCRATCH_DATABASE';")"
[ "$scratch_exists" = "1" ]

scratch_relations="$(runuser -u "$POSTGRES_OS_USER" -- psql -X -d "$SCRATCH_DATABASE" -Atc "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%';")"
[ "$scratch_relations" = "0" ]

runuser -u "$POSTGRES_OS_USER" -- pg_restore --exit-on-error --dbname="$SCRATCH_DATABASE" < "$BACKUP_PATH"

object_counts() {
  runuser -u "$POSTGRES_OS_USER" -- psql -X -d "$1" -AtF '|' -c "SELECT count(*) FILTER (WHERE c.relkind IN ('r','p')), count(*) FILTER (WHERE c.relkind='S'), count(*) FILTER (WHERE c.relkind='i') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%';"
}

[ "$(object_counts "$PRODUCTION_DATABASE")" = "$(object_counts "$SCRATCH_DATABASE")" ]

runuser -u "$POSTGRES_OS_USER" -- pg_dump --dbname="$PRODUCTION_DATABASE" --schema-only --no-owner --no-privileges --no-comments > "$TMPDIR_PATH/production.sql"
runuser -u "$POSTGRES_OS_USER" -- pg_dump --dbname="$SCRATCH_DATABASE" --schema-only --no-owner --no-privileges --no-comments > "$TMPDIR_PATH/scratch.sql"
sed -E '/^\\(un)?restrict[[:space:]]/d' "$TMPDIR_PATH/production.sql" > "$TMPDIR_PATH/production.normalized.sql"
sed -E '/^\\(un)?restrict[[:space:]]/d' "$TMPDIR_PATH/scratch.sql" > "$TMPDIR_PATH/scratch.normalized.sql"
cmp -s "$TMPDIR_PATH/production.normalized.sql" "$TMPDIR_PATH/scratch.normalized.sql"

ownership_sql="SELECT n.nspname,c.relkind,c.relname,pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','S','v','m') ORDER BY n.nspname,c.relkind,c.relname;"
runuser -u "$POSTGRES_OS_USER" -- psql -X -d "$PRODUCTION_DATABASE" -AtF '|' -c "$ownership_sql" > "$TMPDIR_PATH/production.owners"
runuser -u "$POSTGRES_OS_USER" -- psql -X -d "$SCRATCH_DATABASE" -AtF '|' -c "$ownership_sql" > "$TMPDIR_PATH/scratch.owners"
cmp -s "$TMPDIR_PATH/production.owners" "$TMPDIR_PATH/scratch.owners"

echo "restore_verification=success"
echo "normalized_schema_match=yes"
echo "relation_ownership_contract_match=yes"
echo "production_database_unchanged=yes"
echo "scratch_database=$SCRATCH_DATABASE"
echo "scratch_cleanup_required=yes"
echo "verified_backup=$BACKUP_PATH"
