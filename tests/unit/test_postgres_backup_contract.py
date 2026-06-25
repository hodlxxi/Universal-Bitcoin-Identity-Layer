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


def test_backup_script_contract_markers():
    text = _read(BACKUP_SCRIPT)

    for marker in (
        "#!/usr/bin/env bash",
        "set -Eeuo pipefail",
        "umask 077",
        "POSTGRES_OS_USER",
        "--format=custom",
        "--no-password",
        "sha256sum",
        "pg_restore --list",
        "backup_status=success",
    ):
        assert marker in text


def test_restore_verifier_contract_markers():
    text = _read(VERIFY_SCRIPT)

    for marker in (
        "#!/usr/bin/env bash",
        "set -Eeuo pipefail",
        "umask 077",
        "ubid_restore_verify_",
        "validate_scratch_name",
        "--template=template0",
        "--exit-on-error",
        "sha256sum --check",
        "normalized_schema_match=yes",
        "relation_ownership_contract_match=yes",
        "production_database_unchanged=yes",
        "scratch_database_removed=yes",
    ):
        assert marker in text


def test_runbook_documents_operator_and_recovery_boundaries():
    text = _read(RUNBOOK).lower()

    for marker in (
        "scripts/postgres_backup_verified.sh",
        "scripts/postgres_verify_backup.sh",
        "root-only",
        "no automatic retention deletion",
        "scratch database",
        "production restore is intentionally not automated",
        "scripts/db_backup.sh",
        "scripts/db_restore.sh",
        "backward compatibility",
        "production_database_unchanged=yes",
        "scratch_database_removed=yes",
    ):
        assert marker in text
