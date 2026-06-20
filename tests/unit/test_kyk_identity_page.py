from app.factory import create_app


def test_my_kyc_id_route_renders_kyk_identity_page():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/my-kyc-id", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200

    for marker in [
        "KYK",
        "Know Your Key",
        "Be known without being exposed",
        "Key-owned identity for humans and agents",
        "/demo",
        "/oidc",
        "/agent/evidence",
        "/agent/receipt-proof",
        "/agent/readiness",
        "/.well-known/agent.json",
        "/agent/capabilities",
        "self_declared_no_signature",
        "does not prove legal identity",
        "does not prove KYC",
        "does not prove custody",
        "does not prove control of the key",
        "Never paste a seed phrase",
        "private key",
        "macaroon",
    ]:
        assert marker in text

    for legacy_claim in [
        "MY_KYC_ID gives",
        "KYC identity provider",
        "legal identity verification",
    ]:
        assert legacy_claim not in text
