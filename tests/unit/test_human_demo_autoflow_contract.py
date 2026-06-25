from app.factory import create_app


def test_human_demo_requires_a_key_and_auto_advances_after_payment():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/demo", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200

    for marker in [
        'name="requester_pubkey"',
        "required",
        "isValidRequesterPubkey",
        'demo: "human_proof_v2"',
        "demo_nonce",
        "newDemoNonce",
        "startPolling",
        "POLL_INTERVAL_MS",
        "checkJob({ fromPolling: true })",
        "await verifyJob()",
        "What the signed receipt remembers",
        "requester_pubkey_proof",
        "proofPaymentHash",
        "proofResultHash",
        "proofAgentPubkey",
        "verified agent signature",
    ]:
        assert marker in text


def test_human_demo_keeps_the_identity_boundary_explicit():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/demo")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "proven by a compatible Nostr signer" in text
    assert "This proves control of the signing key for this request" in text
    assert "signature_verified" in text
    assert "No private key is requested" in text


def test_human_demo_v2_bound_proof_contract_markers():
    from pathlib import Path

    text = Path("app/templates/agent/demo.html").read_text()
    assert "human_proof_v2" in text
    assert "window.nostr.getPublicKey" in text
    assert (
        text.index('fetch("/api/challenge"') < text.index('fetch("/api/verify"') < text.index('fetch("/agent/request"')
    )
    assert "demo_nonce: newDemoNonce()" in text
    assert "preparedRequestBody" in text
    assert "private" not in text.lower() or "No private key is requested" in text
    assert "It does not prove a legal name, government identity, or that one human controls only one key." in text
