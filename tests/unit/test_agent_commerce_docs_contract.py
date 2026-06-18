from pathlib import Path

DOC_PATHS = [
    Path("docs/AGENT_RECEIPT_V1.md"),
    Path("docs/AGENT_RECEIPT_QUICKSTART.md"),
    Path("docs/ops/PAID_EXECUTION_RECEIPT_SMOKE.md"),
    Path("docs/ops/COMMERCE_RUNTIME_STATE_2026-06-17.md"),
]


def _doc_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _all_docs_text() -> str:
    return "\n".join(_doc_text(path) for path in DOC_PATHS).lower()


def test_commerce_docs_exist():
    for path in DOC_PATHS:
        assert path.exists(), f"missing commerce doc: {path}"


def test_public_endpoint_markers_are_documented():
    text = _all_docs_text()

    for marker in [
        "/agent/request",
        "/agent/jobs/<job_id>",
        "/agent/verify/<job_id>",
        "/agent/attestations",
        "/agent/reputation",
        "/agent/capabilities",
        "/agent/marketplace/listing",
    ]:
        assert marker in text


def test_receipt_state_and_field_markers_are_documented():
    text = _all_docs_text()

    for marker in [
        "invoice_pending",
        "done",
        "verified",
        "valid",
        "payment_hash",
        "request_hash",
        "result_hash",
        "signature",
        "agent_pubkey",
        "job_receipt",
    ]:
        assert marker in text


def test_manual_payment_and_no_auto_pay_contract_is_documented():
    text = _all_docs_text()

    assert "manual payment" in text
    assert "never auto-pay" in text or "must never be changed to auto-pay" in text


def test_lightning_backend_markers_are_documented_where_appropriate():
    text = _all_docs_text()

    assert "ln_backend" in text or "lnd_cli" in text


def test_unpaid_verify_semantics_are_documented():
    text = _all_docs_text()

    assert "verification=unavailable" in text or "verification unavailable" in text
    assert "409" in text
    assert "no_receipt" in text
    assert "receipt_not_issued" in text
    assert "404 not_found" in text
    assert "receipt verifier" in text
    assert "lifecycle/status endpoint" in text


def test_latest_paid_receipt_evidence_is_documented_safely():
    text = _all_docs_text()

    for marker in [
        "1013ca86-f09e-40d3-b6ea-862620890b36",
        "529245bed836a0adf9fdd57ac46d2276e7ab85ce3e52ab8dcbb6f8ac9f9bdd44",
        "f6530836330ca1047f8d92a638c70d64597a34f299b49ef94c3aac621e1b82c1",
        "http 200 or http 201",
        "manual payment",
        "invoice strings are intentionally omitted",
        "chain_ok=true",
        "verified",
        "valid=true",
        "attestation",
        "does not prove locked capital",
        "does not prove legal identity",
    ]:
        assert marker in text
