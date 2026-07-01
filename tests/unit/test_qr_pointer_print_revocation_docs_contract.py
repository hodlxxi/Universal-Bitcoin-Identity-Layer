from pathlib import Path

DOC_PATH = Path("docs/ops/QR_POINTER_PRINT_REVOCATION.md")


def _doc_text() -> str:
    assert DOC_PATH.exists(), "QR Pointer print/revocation workflow doc must exist"
    return DOC_PATH.read_text(encoding="utf-8")


def test_qr_pointer_print_revocation_doc_exists_and_references_surfaces():
    text = _doc_text()

    assert "/qr/<token>" in text
    assert "scripts/export_qr_pointer.py" in text


def test_qr_pointer_print_revocation_doc_contains_safe_and_unsafe_wording():
    text = _doc_text()

    safe_examples = [
        "Open HODLXXI discovery page.",
        "Open HODLXXI receipt verification page.",
        "This QR code is a pointer only.",
        "Verify status on the HODLXXI page before relying on this information.",
    ]
    unsafe_examples = [
        "Scan to approve.",
        "Scan proves identity.",
        "Scan proves consent.",
        "Scan proves delegation.",
        "Scan proves payment.",
        "Scan proves receipt validity.",
        "Trusted by QR.",
        "Human approved.",
    ]

    for phrase in safe_examples + unsafe_examples:
        assert phrase in text


def test_qr_pointer_print_revocation_doc_contains_non_claim_terms():
    text = _doc_text().lower()

    non_claim_terms = [
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
    ]

    for term in non_claim_terms:
        assert term in text


def test_qr_pointer_print_revocation_doc_contains_operator_workflows():
    text = _doc_text().lower()

    required_terms = [
        "inventory",
        "rotation",
        "revocation",
        "incident workflow",
        "staging validation is deferred",
    ]

    for term in required_terms:
        assert term in text


def test_qr_pointer_print_revocation_doc_warns_against_secret_inventory():
    text = _doc_text().lower()

    prohibited_inventory_terms = [
        "private keys",
        "credentials",
        "customer secrets",
        "invoices",
        "payment requests",
        "cookies",
        "macaroons",
        "session tokens",
        "access tokens",
        "refresh tokens",
    ]

    for term in prohibited_inventory_terms:
        assert term in text
