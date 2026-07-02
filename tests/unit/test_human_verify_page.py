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
