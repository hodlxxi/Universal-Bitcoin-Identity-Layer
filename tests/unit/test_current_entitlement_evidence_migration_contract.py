from pathlib import Path


def test_direct_sql_migration_contract():
    sql = Path("migrations/2026-07-22_current_entitlement_evidence.sql").read_text(encoding="utf-8")
    lowered = sql.lower()
    assert "create table if not exists current_entitlement_evidence" in lowered
    for column in (
        "evidence_id",
        "contract_version",
        "subject_pubkey",
        "identity_class",
        "current_full_relation_satisfied",
        "evidence_source",
        "evidence_version",
        "source_evidence_sha256",
        "observed_at",
        "valid_until",
        "revoked_at",
        "created_at",
    ):
        assert column in lowered
    assert lowered.count("timestamp with time zone") == 4
    for constraint in (
        "ck_current_entitlement_evidence_id_canonical",
        "ck_current_entitlement_contract_version",
        "ck_current_entitlement_subject_canonical",
        "ck_current_entitlement_identity_relation",
        "ck_current_entitlement_validity_duration",
        "ck_current_entitlement_revoked_order",
    ):
        assert f"constraint {constraint}" in lowered
    assert lowered.count("create index if not exists") >= 4
    for forbidden in ("drop ", "delete ", "update ", "flask", "systemctl", "psql -f migrations/"):
        assert forbidden not in lowered
