from pathlib import Path

from app.factory import create_app


def test_public_human_verify_page_renders_contract():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/agent/verify", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    for marker in [
        'id="job_id"',
        "/agent/verify/",
        "/agent/receipts/",
        "HODLXXI is a Bitcoin-native proof runtime: pay for an action, get a result, and verify the signed receipt later.",
        "I paid, I requested, I received, I can verify.",
        "What this proves",
        "What this does not prove",
        "not a token sale",
        "not an investment",
        "not KYC",
        "not legal identity",
        "not custody",
        "not a promise of profit",
        "not proof of moral trustworthiness",
        "not a guarantee of future performance",
        "not ownership of a network",
        "verified",
        "no receipt yet",
        "not found",
        "invalid signature / verification failed",
        "fetch/network error",
        "receipt download URL",
        "requester proof verified",
        "requester proof method",
        "/agent/attestations",
        "/agent/reputation",
        "/agent/chain/health",
        "factual runtime surfaces",
        "not human trust scores",
        "not a human trust score",
        "local append-only continuity",
        "not global consensus",
        "not authority",
        "not consent",
        "not an investment signal",
        "not token ownership",
        "attestations_url",
        "reputation_url",
        "chain_health_url",
    ]:
        assert marker in text


def test_public_human_verify_page_accepts_query_job_id():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/agent/verify?job_id=job_123", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'value="job_123"' in text


def test_human_demo_links_to_public_verify_page():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/demo", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Verify an existing receipt" in text
    assert 'href="/agent/verify"' in text


def test_public_human_verify_page_uses_receipt_v1_requester_proof_fields():
    template = Path("app/templates/agent/verify.html").read_text()

    assert "requester proof verified" in template
    assert "requester proof method" in template
    assert "receipt.requester_proof.verified" in template
    assert "receipt.requester_proof.method" in template
    assert "receipt.attestations_url" in template
    assert "receipt.reputation_url" in template
    assert "receipt.chain_health_url" in template
    assert "requester_proof.status" not in template
