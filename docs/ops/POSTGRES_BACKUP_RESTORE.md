# PostgreSQL Backup and Restore Verification

This runbook defines the production operator contract for creating and verifying HODLXXI PostgreSQL backups.

## Safety boundary

The operator tooling:

- uses local PostgreSQL peer authentication through the `postgres` Unix user;
- does not read `.env`, `DATABASE_URL`, passwords, tokens, or application secrets;
- creates custom-format `pg_dump` archives;
- creates a SHA-256 checksum beside every archive;
- stores artifacts in a root-only directory with root-only file permissions;
- performs no automatic retention deletion;
- never stops or restarts the application service;
- never writes to, drops, recreates, or migrates the production database;
- verifies restore capability only through a disposable scratch database.

Run both scripts as root on the database host.

## Create a backup

```bash
sudo bash scripts/postgres_backup_verified.sh \
  --database hodlxxi \
  --backup-dir /var/backups/hodlxxi/postgresql \
  --postgres-os-user postgres \
  --compression 6
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

## Verify restore capability

```bash
sudo bash scripts/postgres_verify_backup.sh \
  --backup /var/backups/hodlxxi/postgresql/hodlxxi_<UTC timestamp>.dump \
  --production-database hodlxxi \
  --postgres-os-user postgres
```

The verifier validates the adjacent checksum, restores only into a database named `ubid_restore_verify_<UTC timestamp>_<PID>`, compares object counts, normalized schema, and relation ownership, verifies restored tables are queryable, and removes the scratch database.

PostgreSQL `pg_dump` emits random `\restrict` and `\unrestrict` markers. The verifier removes only those markers before computing schema hashes.

Expected terminal contract:

```text
restore_verification=success
normalized_schema_match=yes
relation_ownership_contract_match=yes
production_database_unchanged=yes
scratch_database_removed=yes
verified_backup=<absolute archive path>
```

A successful `pg_restore --list` is not sufficient evidence by itself. The scratch restore must complete successfully.

## Failure behavior

The verifier uses a cleanup trap. If restoration or comparison fails after scratch creation, it attempts to remove only a database whose name begins with `ubid_restore_verify_`.

It must never execute `dropdb` against the production database.

## Production recovery boundary

Production restore is intentionally not automated by these scripts. A real production restore requires a separate reviewed maintenance procedure covering outage authorization, exact recovery-point selection, application write shutdown, database connection termination, ownership and privilege restoration, health verification, rollback, and incident evidence.

## Legacy helpers

The following files are legacy development helpers and are not the production backup or restore contract:

```text
scripts/db_backup.sh
scripts/db_restore.sh
```

They remain unchanged for backward compatibility. Do not use them for production backup or production recovery.
