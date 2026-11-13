from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/2026-09-10_social_messaging_device_binding_authorization_v1.sql"
OLD_MIGRATION = ROOT / "migrations/2026-09-04_social_messaging_device_bindings_v1.sql"


def test_authorization_migration_bytes_are_frozen_and_old_migration_is_unchanged():
    assert hashlib.sha256(MIGRATION.read_bytes()).hexdigest() == (
        "a7c08bdf25cdaba6caf8279f77e1e0757fb0ee4ce72f201c1fdd835847d7b137"
    )
    assert hashlib.sha256(OLD_MIGRATION.read_bytes()).hexdigest() == (
        "f3f3d3525e61485a54d15e22cb4f801df622b1e00c7d585b5a5d9214f7c02258"
    )


def test_authorization_migration_is_additive_and_fail_closed():
    sql = MIGRATION.read_text(encoding="ascii")

    assert "DROP TABLE" not in sql
    assert "DROP COLUMN" not in sql
    assert "TRUNCATE" not in sql
    assert "social_messaging_device_binding_authorization_evidence" in sql
    assert "social_messaging_device_binding_authorization_replay" in sql
    assert "PRIMARY KEY" in sql
    assert "UNIQUE (request_id)" in sql
    assert "DEFERRABLE INITIALLY DEFERRED" in sql
    assert "uq_social_messaging_device_historical_public_key" in sql
    assert "fk_social_device_authorization_evidence_binding" in sql
    assert "fk_social_device_authorization_replay_evidence" in sql
    assert "trg_social_device_authorization_evidence_immutable" in sql
    assert "trg_social_device_authorization_replay_immutable" in sql
    assert "octet_length(canonical_payload) BETWEEN 1 AND 8192" in sql
    assert "octet_length(result_payload) BETWEEN 1 AND 8192" in sql
