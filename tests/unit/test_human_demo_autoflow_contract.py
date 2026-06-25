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
        'demo: "human_proof_v1"',
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
    assert "self-declared in this first demo" in text
    assert "does not yet prove control of the key" in text
    assert "self-declared, not yet signature-proven" in text
    assert "challenge/signature proof-of-control" in text
