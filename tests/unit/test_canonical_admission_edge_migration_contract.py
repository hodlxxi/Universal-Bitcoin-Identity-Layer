from pathlib import Path


def test_additive_unseeded_migration_contract():
    sql = Path("migrations/2026-07-26_canonical_admission_edge_registry_v1.sql").read_text()
    assert "CREATE TABLE canonical_admission_edges" in sql
    assert "CREATE TABLE canonical_admission_edge_legs" in sql
    assert "WHERE lifecycle_state = 'effective'" in sql
    assert "UNIQUE (edge_id, direction)" in sql
    for required in (
        "uq_admission_leg_global_outpoint",
        "uq_admission_edge_effective_child_id",
        "uq_admission_edge_effective_child_key",
        "ck_admission_edge_profile",
        "ck_admission_edge_depth",
        "ck_admission_edge_heights",
        "ck_admission_edge_child_participant_convention",
        "ck_admission_edge_sponsor_convention",
        "substr(sponsor_compressed_public_key, 3) = sponsor_x_only_public_key",
        "substr(child_compressed_public_key, 3) = child_x_only_public_key",
        "ck_admission_edge_lifecycle_consistency",
        "ck_admission_edge_successor",
        "descriptor_sha256 IS NULL",
    ):
        assert required in sql
    for forbidden in ("INSERT INTO", "DROP TABLE", "ALTER TABLE"):
        assert forbidden not in sql.upper()
    assert "ON DELETE CASCADE" not in sql.upper()
