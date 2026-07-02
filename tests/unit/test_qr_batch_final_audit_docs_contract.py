from pathlib import Path

DOC_PATH = Path("docs/ops/QR_BATCH_FINAL_AUDIT.md")


def test_qr_batch_final_audit_doc_exists():
    assert DOC_PATH.exists()


def test_qr_batch_final_audit_doc_contract():
    text = DOC_PATH.read_text(encoding="utf-8")
    lowered = text.lower()

    for pr_number in ("#380", "#381", "#382", "#383", "#384", "#385", "#386", "#387", "#388", "#389"):
        assert pr_number in text

    assert "#387" in text
    assert "duplicate" in lowered or "not canonical" in lowered
    assert "integration branch" in lowered
    assert "staging validation is intentionally deferred" in lowered
    assert "/qr/<token>" in text
    assert "/agent/verify/<job_id>" in text
    assert "capabilities" in lowered
    assert "no auto-redirect" in lowered
    assert "no job mutation" in lowered
    assert "no receipt issuance" in lowered
    assert "no secrets" in lowered

    for secret_term in (
        "private keys",
        "macaroons",
        "cookies",
        "credentials",
        "access tokens",
        "refresh tokens",
        "invoices",
        "payment requests",
        "customer secrets",
    ):
        assert secret_term in lowered

    for non_authority_term in (
        "identity",
        "consent",
        "approval",
        "delegation",
        "authorization",
        "payment",
        "receipt validity",
        "reputation",
        "trust",
        "human presence",
    ):
        assert non_authority_term in lowered

    assert "offline export" in lowered
    assert "print/revocation workflow" in lowered
    assert "main merge only after staging" in lowered
    assert "production rollout is separate and later" in lowered
    assert "rollback" in lowered
