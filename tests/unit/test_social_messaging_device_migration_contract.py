from pathlib import Path

MIGRATION = Path("migrations/2026-09-04_social_messaging_device_bindings_v1.sql")


def test_social_messaging_device_migration_is_additive_and_multi_device():
    sql = MIGRATION.read_text(encoding="utf-8")
    lowered = sql.lower()

    assert "create table if not exists social_messaging_device_bindings" in lowered
    assert "binding_version between 1 and 1024" in lowered
    assert "unique (subject_pubkey, device_id, binding_version)" in lowered
    assert "unique (subject_pubkey, request_id)" in lowered
    assert "uq_social_messaging_device_active_device" in lowered
    assert "on social_messaging_device_bindings (subject_pubkey, device_id)" in lowered
    assert "where active = true" in lowered
    assert "uq_social_messaging_device_active_public_key" in lowered
    assert "foreign key (prior_binding_id)" in lowered
    assert "operation in ('register','rotate','revoke')" in lowered


def test_migration_does_not_modify_legacy_identity_x25519_registry():
    lowered = MIGRATION.read_text(encoding="utf-8").lower()
    assert "alter table x25519_identity_bindings" not in lowered
    assert "drop table" not in lowered
    assert "drop index" not in lowered
