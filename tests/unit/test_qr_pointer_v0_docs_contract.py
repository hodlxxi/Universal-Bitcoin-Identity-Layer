from pathlib import Path

DOC = Path("docs/QR_POINTER_V0.md")


def _doc() -> str:
    return DOC.read_text(encoding="utf-8").lower()


def test_qr_pointer_v0_doc_exists() -> None:
    assert DOC.exists()


def test_qr_pointer_v0_preserves_explicit_non_claims() -> None:
    text = _doc()
    for phrase in (
        "does not prove identity",
        "does not prove consent",
        "does not prove delegation",
        "does not prove approval",
        "does not prove trust",
    ):
        assert phrase in text


def test_qr_pointer_v0_is_docs_only_without_runtime_endpoint() -> None:
    text = _doc()
    assert "no qr pointer endpoint is added in v0" in text
    assert "this pr does not add that route" in text
    assert "runtime status: not live" in text


def test_qr_pointer_v0_doc_links_schema_without_live_endpoint() -> None:
    text = _doc()
    assert "docs/schemas/qr_pointer_v0.schema.json" in text
    assert "not a live runtime endpoint" in text
