from app.factory import create_app


def test_homepage_exposes_human_proof_path_without_overclaims():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/")
    text = response.get_data(as_text=True)

    assert response.status_code == 200

    for marker in [
        "Human proof page",
        "Open human proof demo",
        'href="/demo"',
        "Integrate Sign in with HODLXXI",
        "Open OIDC integration",
        'href="/oidc"',
        "Public proof surfaces",
        "Open evidence map",
        'href="/agent/evidence"',
        "Open receipt proof",
        'href="/agent/receipt-proof"',
        "Open readiness report",
        'href="/agent/readiness"',
        "PKCE S256",
        "integration boundaries",
    ]:
        assert marker in text

    assert 'href="/agent/request"' not in text

    for forbidden_claim in [
        "proves legal identity",
        "proves KYC",
        "custody of funds",
        "proves locked capital",
        "fully certified OIDC",
    ]:
        assert forbidden_claim not in text
