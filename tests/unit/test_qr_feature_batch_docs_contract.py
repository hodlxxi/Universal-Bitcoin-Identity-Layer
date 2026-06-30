from pathlib import Path

DOC_PATH = Path("docs/ops/QR_FEATURE_BATCH.md")


def test_qr_feature_batch_doc_exists_and_records_batch_contract():
    assert DOC_PATH.exists()

    text = DOC_PATH.read_text(encoding="utf-8")
    normalized = text.lower()

    for pr_number in ("#380", "#381", "#382", "#383", "#384", "#385"):
        assert pr_number in text

    assert "not being merged to main immediately" in text
    assert "staging validation is intentionally deferred" in text
    assert "integration branch" in normalized
    assert "black" in normalized

    for non_claim in (
        "consent",
        "approval",
        "delegation",
        "payment",
        "receipt validity",
        "trust",
        "human presence",
    ):
        assert non_claim in normalized
