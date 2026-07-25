from pathlib import Path

SQL = (Path(__file__).parents[2] / "migrations/2026-07-25_trusted_covenant_registration.sql").read_text()


def test_migration_has_normalized_tables_constraints_and_indexes():
    required = (
        "CREATE TABLE IF NOT EXISTS trusted_covenant_registrations",
        "CREATE TABLE IF NOT EXISTS trusted_covenant_registered_outpoints",
        "registration_sha256",
        "earlier_leg_script_hex",
        "later_leg_script_hex",
        "witness_script_sha256",
        "UNIQUE (registration_id, direction)",
        "UNIQUE (txid, vout)",
        "ON DELETE CASCADE",
        "current_144",
        "legacy_777",
        "active",
        "revoked",
        "superseded",
        "disputed",
        "4294967295",
        "2100000000000000",
    )
    assert all(value in SQL for value in required)
    required_names = (
        "ck_trusted_registration_distinct_participants",
        "ck_trusted_registration_distinct_scripts",
        "uq_trusted_outpoint_registration_direction",
        "uq_trusted_outpoint_global_identity",
        "idx_trusted_registration_pair",
        "ck_trusted_outpoint_witness_script_hash",
    )
    assert all(value in SQL for value in required_names)
    pair_declaration = next(
        line.strip() for line in SQL.splitlines() if line.strip().startswith("pair_sha256 ")
    )
    assert pair_declaration == "pair_sha256 VARCHAR(64) NOT NULL,"
    assert "CREATE INDEX IF NOT EXISTS idx_trusted_registration_pair" in SQL
    assert "CREATE UNIQUE INDEX IF NOT EXISTS idx_trusted_registration_pair" not in SQL


def test_migration_contains_no_runtime_or_destructive_commands():
    lowered = SQL.lower()
    assert all(value not in lowered for value in ("drop table", "truncate", "delete from", "systemctl", "docker", "curl "))
