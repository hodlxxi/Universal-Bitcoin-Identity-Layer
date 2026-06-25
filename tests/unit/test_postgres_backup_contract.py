"""PostgreSQL backup and restore operator contract."""

from __future__ import annotations

from pathlib import Path

BACKUP_SCRIPT = Path("scripts/postgres_backup_verified.sh")
VERIFY_SCRIPT = Path("scripts/postgres_verify_backup.sh")
RUNBOOK = Path("docs/ops/POSTGRES_BACKUP_RESTORE.md")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_postgres_operator_files_exist():
    for path in (BACKUP_SCRIPT, VERIFY_SCRIPT, RUNBOOK):
        assert path.exists()


def test_backup_script_publishes_only_validated_artifacts():
    text = _read(BACKUP_SCRIPT)

    for marker in (
        "#!/usr/bin/env bash",
        "set -Eeuo pipefail",
        "umask 077",
        "TEMPORARY_PATH",
        "TEMPORARY_CHECKSUM_PATH",
        "mktemp",
        "trap cleanup EXIT",
        "--format=custom",
        "--no-password",
        "pg_restore --list",
        "mv --",
        "sha256sum --check",
        "backup_status=success",
    ):
        assert marker in text


def test_restore_verifier_enforces_scratch_identity_contract():
    text = _read(VERIFY_SCRIPT)

    for marker in (
        "#!/usr/bin/env bash",
        "set -Eeuo pipefail",
        "umask 077",
        "validate_scratch_name",
        "^ubid_restore_verify_[A-Za-z0-9_]+$",
        "--template=template0",
        "--exit-on-error",
        "sha256sum --check",
        "ON_ERROR_STOP=1",
        "probe integer",
        "INTO probe",
        "normalized_schema_match=yes",
        "relation_ownership_contract_match=yes",
        "restored_tables_queryable=yes",
        "production_database_unchanged=yes",
        "scratch_cleanup_required=yes",
    ):
        assert marker in text


def test_runbook_documents_operator_and_recovery_boundaries():
    text = _read(RUNBOOK).lower()

    for marker in (
        "scripts/postgres_backup_verified.sh",
        "scripts/postgres_verify_backup.sh",
        "root-only",
        "temporary archive",
        "no automatic retention deletion",
        "scratch database",
        "explicit operator cleanup",
        "production restore is intentionally not automated",
        "scripts/db_backup.sh",
        "scripts/db_restore.sh",
        "backward compatibility",
        "production_database_unchanged=yes",
        "scratch_cleanup_required=yes",
    ):
        assert marker in text
