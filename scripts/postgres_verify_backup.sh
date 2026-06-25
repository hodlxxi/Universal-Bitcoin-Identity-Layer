#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

BACKUP_PATH=""
PRODUCTION_DATABASE="${PRODUCTION_DATABASE:-hodlxxi}"
POSTGRES_OS_USER="${POSTGRES_OS_USER:-postgres}"
SCRATCH_DATABASE="${SCRATCH_DATABASE:-}"
TMPDIR_PATH="$(mktemp -d /tmp/ubid-postgres-verify.XXXXXX)"

usage() {
  cat <<'USAGE'
Usage:
  sudo bash scripts/postgres_verify_backup.sh --backup ABSOLUTE_PATH [options]

Options:
  --production-database NAME
  --postgres-os-user USER
  --scratch-database NAME
  --help
USAGE
}

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

while [ "$#" -gt 0 ]; do
  case "$1" in
    --backup)
      [ "$#" -ge 2 ]
      BACKUP_PATH="$2"
      shift 2
      ;;
    --production-database)
      [ "$#" -ge 2 ]
      PRODUCTION_DATABASE="$2"
      shift 2
      ;;
    --postgres-os-user)
      [ "$#" -ge 2 ]
      POSTGRES_OS_USER="$2"
      shift 2
      ;;
    --scratch-database)
      [ "$#" -ge 2 ]
      SCRATCH_DATABASE="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

[ "$EUID" -eq 0 ]
[ -n "$BACKUP_PATH" ]
[[ "$BACKUP_PATH" = /* ]]
[[ "$PRODUCTION_DATABASE" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
[[ "$POSTGRES_OS_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]]
[ -f "$BACKUP_PATH" ]
[ ! -L "$BACKUP_PATH" ]
[ -f "${BACKUP_PATH}.sha256" ]
[ ! -L "${BACKUP_PATH}.sha256" ]

for protected_path in "$BACKUP_PATH" "${BACKUP_PATH}.sha256"; do
  [ "$(stat -c '%U:%G' "$protected_path")" = "root:root" ]
  mode="$(stat -c '%a' "$protected_path")"
  (( (8#$mode & 077) == 0 ))
done

(
  cd "$(dirname "$BACKUP_PATH")"
  sha256sum --check "$(basename "${BACKUP_PATH}.sha256")"
)
pg_restore --list "$BACKUP_PATH" >/dev/null

production_contract="$(runuser -u "$POSTGRES_OS_USER" -- psql -X -d postgres -AtF '|' -c "SELECT pg_encoding_to_char(encoding), datcollate, datctype FROM pg_database WHERE datname = '$PRODUCTION_DATABASE';")"
[ -n "$production_contract" ]
IFS='|' read -r database_encoding database_collation database_ctype <<< "$production_contract"

if [ -z "$SCRATCH_DATABASE" ]; then
  SCRATCH_DATABASE="ubid_restore_verify_$(date -u +%Y%m%dT%H%M%SZ)_$$"
fi
validate_scratch_name
[ "$SCRATCH_DATABASE" != "$PRODUCTION_DATABASE" ]

scratch_exists="$(runuser -u "$POSTGRES_OS_USER" -- psql -X -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname = '$SCRATCH_DATABASE';")"
[ -z "$scratch_exists" ]

echo "scratch_database=$SCRATCH_DATABASE"
echo "scratch_cleanup_required=yes"

runuser -u "$POSTGRES_OS_USER" -- createdb --template=template0 --encoding="$database_encoding" --lc-collate="$database_collation" --lc-ctype="$database_ctype" "$SCRATCH_DATABASE"
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

runuser -u "$POSTGRES_OS_USER" -- psql -X -d "$SCRATCH_DATABASE" <<'SQL'
DO $$
DECLARE
  relation record;
BEGIN
  FOR relation IN
    SELECT n.nspname AS schema_name, c.relname AS relation_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r','p')
      AND n.nspname NOT IN ('pg_catalog','information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
  LOOP
    EXECUTE format('SELECT 1 FROM %I.%I LIMIT 1', relation.schema_name, relation.relation_name);
  END LOOP;
END
$$;
SQL

echo "restore_verification=success"
echo "normalized_schema_match=yes"
echo "relation_ownership_contract_match=yes"
echo "restored_tables_queryable=yes"
echo "production_database_unchanged=yes"
echo "scratch_database=$SCRATCH_DATABASE"
echo "scratch_cleanup_required=yes"
echo "verified_backup=$BACKUP_PATH"
