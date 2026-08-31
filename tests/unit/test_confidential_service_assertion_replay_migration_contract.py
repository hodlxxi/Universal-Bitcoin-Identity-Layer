from pathlib import Path

MIGRATION = Path("migrations/2026-08-31_confidential_service_assertion_replay_markers_v1.sql")


def test_dedicated_forward_only_replay_marker_migration_contract():
    sql = MIGRATION.read_text(encoding="utf-8")
    lowered = sql.lower()

    assert "create table if not exists confidential_service_assertion_replay_markers" in lowered
    assert "jti_sha256 varchar(64) primary key" in lowered
    assert "retention_deadline_exclusive bigint not null" in lowered
    assert "check (length(jti_sha256) = 64)" in lowered
    assert "check (jti_sha256 ~ '^[0-9a-f]{64}$')" in lowered
    assert "check (retention_deadline_exclusive > 0)" in lowered
    assert "idx_confidential_service_assertion_replay_deadline" in lowered
    assert "on confidential_service_assertion_replay_markers (retention_deadline_exclusive)" in lowered
    assert lowered.count("create table") == 1
    assert lowered.count("create index") == 1

    for forbidden in (
        "drop ",
        "delete ",
        "update ",
        "access_token",
        "client_assertion",
        "raw_jti",
        "credential_claims",
        "public_key",
        "private_key",
    ):
        assert forbidden not in lowered
