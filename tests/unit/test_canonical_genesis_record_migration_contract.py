from pathlib import Path

SQL = Path("migrations/2026-07-26_canonical_e923_genesis_record_v1.sql").read_text()


def test_additive_migration_has_exact_constraints_and_nonunique_graph_index():
    for value in (
        "CREATE TABLE IF NOT EXISTS canonical_genesis_records",
        "hodlxxi.canonical_genesis_record.v1",
        "hodlxxi.canonical_genesis_record_service.v1",
        "hodlxxi.crt_membership_graph.v1",
        "E923",
        "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923",
        "proposed','effective','disputed','superseded','revoked",
        "idx_canonical_genesis_graph",
        "canonical_record_sha256 VARCHAR(64) NOT NULL UNIQUE",
    ):
        assert value in SQL
    assert "CREATE UNIQUE INDEX IF NOT EXISTS idx_canonical_genesis_graph" not in SQL
    assert ("lifecycle_state IN ('disputed','revoked')\n" "            AND superseded_by_record_id IS NULL") in SQL


def test_migration_is_not_destructive_or_executable():
    lowered = SQL.lower()
    assert all(
        value not in lowered
        for value in (
            "drop table",
            "truncate",
            "delete from",
            "insert into",
            "systemctl",
            "curl ",
        )
    )
