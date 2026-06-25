# PostgreSQL Backup and Restore Verification

This runbook defines the production operator contract for creating and verifying HODLXXI PostgreSQL backups.

## Safety boundary

The operator tooling:

- uses local PostgreSQL peer authentication through the `postgres` Unix user;
- does not read `.env`, `DATABASE_URL`, passwords, tokens, or application secrets;
- creates custom-format `pg_dump` archives;
- publishes archives and checksums only after validating a temporary archive;
- stores artifacts in a root-only directory with root-only file permissions;
- performs no automatic retention deletion;
- never stops or restarts the application service;
- never writes to, recreates, or migrates the production database;
- restores only into a uniquely named scratch database.

Run both scripts as root on the database host.

## Create a backup

The helper uses explicit environment overrides and has no dependency on application environment files:

```bash
sudo DATABASE_NAME=hodlxxi \
  BACKUP_DIR=/var/backups/hodlxxi/postgresql \
  POSTGRES_OS_USER=postgres \
  COMPRESSION=6 \
  bash scripts/postgres_backup_verified.sh
```

Expected terminal contract:

```text
backup_status=success
database=hodlxxi
backup_path=/var/backups/hodlxxi/postgresql/hodlxxi_<UTC timestamp>.dump
checksum_path=/var/backups/hodlxxi/postgresql/hodlxxi_<UTC timestamp>.dump.sha256
archive_entries=<positive integer>
```

The archive and checksum must both be owned by `root:root` and must not be accessible to group or other users.

If `pg_dump`, archive inspection, or checksum preparation fails, the helper removes temporary files and does not publish a partial archive under the final backup name.

## Verify restore capability

Run verification against the exact archive reported by the backup helper:

```bash
sudo bash scripts/postgres_verify_backup.sh \
  --backup /var/backups/hodlxxi/postgresql/hodlxxi_<UTC timestamp>.dump \
  --production-database hodlxxi \
  --postgres-os-user postgres
```

The verifier:

1. validates root-only artifact ownership and permissions;
2. verifies the adjacent SHA-256 checksum;
3. verifies that the archive table of contents is readable;
4. reads the production database encoding, collation, and character type;
5. creates a database whose name matches `ubid_restore_verify_[A-Za-z0-9_]+`;
6. restores with `pg_restore --exit-on-error`;
7. compares table, sequence, and index counts;
8. compares normalized schema and relation ownership;
9. verifies every restored application table can be queried;
10. leaves the scratch database in place for explicit operator cleanup.

PostgreSQL `pg_dump` emits random `\restrict` and `\unrestrict` markers. The verifier removes only those markers before comparing normalized schema output.

Expected terminal contract:

```text
restore_verification=success
normalized_schema_match=yes
relation_ownership_contract_match=yes
restored_tables_queryable=yes
production_database_unchanged=yes
scratch_database=ubid_restore_verify_<UTC timestamp>_<PID>
scratch_cleanup_required=yes
verified_backup=<absolute archive path>
```

A successful `pg_restore --list` is not sufficient evidence by itself. The scratch restore must complete successfully.

## Explicit operator cleanup

The verifier intentionally does not remove databases. This keeps destructive authority outside the verification helper and makes cleanup a separate, reviewable operator action.

After checking the exact `scratch_database` value printed by the verifier, remove only that scratch database using the approved database administration procedure. Never substitute the production database name. If verification fails, the scratch name is printed before creation so the same explicit cleanup procedure can be used.

## Production recovery boundary

Production restore is intentionally not automated by these scripts. A real production restore requires a separate reviewed maintenance procedure covering outage authorization, exact recovery-point selection, application write shutdown, database connection termination, ownership and privilege restoration, health verification, rollback, and incident evidence.

## Legacy helpers

The following files are legacy development helpers and are not the production backup or restore contract:

```text
scripts/db_backup.sh
scripts/db_restore.sh
```

They remain unchanged for backward compatibility. Do not use them for production backup or production recovery.
