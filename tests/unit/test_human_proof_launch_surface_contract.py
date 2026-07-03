from app.factory import create_app


def _client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_human_proof_demo_launch_surface_is_linked_and_bounded():
    response = _client().get("/demo", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    for marker in [
        "HODLXXI is a Bitcoin-native proof runtime: pay for an action, get a result, and verify the signed receipt later.",
        "Request",
        "Pay",
        "Result",
        "Verify",
        "Download receipt JSON",
        'href="/agent/verify"',
        "/agent/attestations",
        "/agent/reputation",
        "/agent/chain/health",
        "not a token sale",
        "not an investment",
        "not KYC",
        "not legal identity",
        "not custody",
        "not a promise of profit",
        "not proof of moral trustworthiness",
        "not a guarantee of future performance",
        "not ownership of a network",
        "not global consensus",
        "not authority",
        "not consent",
    ]:
        assert marker in text


def test_human_proof_public_verifier_surface_is_linked_and_bounded():
    response = _client().get("/agent/verify", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    for marker in [
        'id="job_id"',
        "/agent/verify/",
        "/agent/receipts/",
        "/agent/attestations",
        "/agent/reputation",
        "/agent/chain/health",
        "verified",
        "no_receipt",
        "not_found",
        "invalid",
        "fetch/network error",
        "not a token sale",
        "not an investment",
        "not KYC",
        "not legal identity",
        "not custody",
        "not a promise of profit",
        "not proof of moral trustworthiness",
        "not a guarantee of future performance",
        "not ownership of a network",
        "not global consensus",
        "not authority",
        "not consent",
    ]:
        assert marker in text
