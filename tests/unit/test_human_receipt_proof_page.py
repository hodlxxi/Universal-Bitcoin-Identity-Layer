from app.factory import create_app

CANONICAL_JOB_ID = "1013ca86-f09e-40d3-b6ea-862620890b36"
REVIEWER_PACKET_URL = (
    "https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer/blob/main/" "docs/EXTERNAL_REVIEWER_PACKET.md"
)


def test_receipt_proof_page_exposes_human_verification_path():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/agent/receipt-proof", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    for marker in [
        "HODLXXI Paid Receipt Proof",
        CANONICAL_JOB_ID,
        "E923",
        "f6530836330ca1047f8d92a638c70d64597a34f299b49ef94c3aac621e1b82c1",
        "d666c1696c7b7d03e80c762aecfedfcfbd6686334045ec2b84f94f691a646c0a",
        "d7fc571c7e5c5c98146fd1f6f94eda75717d04de7438713b24a3423d204d9e9b",
        "529245bed836a0adf9fdd57ac46d2276e7ab85ce3e52ab8dcbb6f8ac9f9bdd44",
        "scripts/verify_paid_receipt_evidence.sh",
        "Verify this job",
        f"/agent/verify/{CANONICAL_JOB_ID}",
        "Public attestations",
        "Public reputation",
        "Chain health",
        "Readiness report",
        "Open reviewer packet",
        "What this proves",
        "What this does not prove",
        "does not prove legal identity",
        "does not prove KYC",
        "does not prove custody",
        "does not prove locked capital",
    ]:
        assert marker in text


def test_homepage_receipt_card_links_to_human_receipt_proof_page():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "/agent/receipt-proof" in text
    assert "Open receipt proof" in text
    assert "Open receipt proof path" not in text

    receipt_card_start = text.index("Verify a paid agent receipt")
    next_card_start = text.index("Integrate Sign in with HODLXXI", receipt_card_start)
    receipt_card = text[receipt_card_start:next_card_start]
    assert REVIEWER_PACKET_URL not in receipt_card
