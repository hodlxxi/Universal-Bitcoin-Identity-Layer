from urllib.parse import urlparse

from app.factory import create_app


def test_human_oidc_page_renders_public_integration_context():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/oidc", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200

    for marker in [
        "Sign in with HODLXXI",
        "Integration overview",
        "Public metadata",
        "Recommended client flow",
        "Related public evidence",
        "What this can support",
        "What this does not prove",
        "/.well-known/openid-configuration",
        "/oauth/jwks.json",
        "docs/OIDC_INTEGRATION.md",
        "/agent/evidence",
        "/agent/readiness",
        "/agent/receipt-proof",
        "/.well-known/hodlxxi-operator.json",
        "/.well-known/agent.json",
        "PKCE S256",
        "does not prove legal identity",
        "does not prove KYC",
        "does not prove custody",
        "does not prove locked capital",
        "does not replace normal OIDC token validation",
    ]:
        assert marker in text


def test_oidc_metadata_jwks_route_and_homepage_still_link_oidc():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    metadata = client.get("/.well-known/openid-configuration", base_url="https://hodlxxi.com")
    metadata_json = metadata.get_json()
    jwks_path = urlparse(metadata_json["jwks_uri"]).path
    jwks = client.get(jwks_path, base_url="https://hodlxxi.com")
    oidc_page = client.get("/oidc", base_url="https://hodlxxi.com")
    home = client.get("/", base_url="https://hodlxxi.com")
    home_text = home.get_data(as_text=True)

    assert metadata.status_code == 200
    assert metadata.is_json
    assert jwks_path == "/oauth/jwks.json"
    assert jwks.status_code == 200
    assert jwks.is_json
    assert jwks_path in oidc_page.get_data(as_text=True)
    assert home.status_code == 200
    assert "/oidc" in home_text
    assert "Open OIDC integration" in home_text
