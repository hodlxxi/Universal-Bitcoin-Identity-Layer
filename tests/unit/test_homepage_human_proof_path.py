from app.factory import create_app


def test_homepage_exposes_human_proof_path_without_overclaims():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/")
    text = response.get_data(as_text=True)

    assert response.status_code == 200

    for marker in [
        "Review public evidence",
        "Verify a paid agent receipt",
        "Integrate Sign in with HODLXXI",
        "Inspect public trust surfaces",
        "/agent/evidence",
        "Open evidence map",
        "E923",
        "signed receipts",
        "public attestations",
        "Sign in with HODLXXI",
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
