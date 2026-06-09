"""P55 contract: OAuth protected resource metadata and auth.md."""


def test_oauth_authorization_server_metadata_is_available(client):
    response = client.get("/.well-known/oauth-authorization-server")
    data = response.get_json()

    assert response.status_code == 200
    assert response.content_type.startswith("application/json")
    assert data["issuer"]
    assert data["authorization_endpoint"].endswith("/oauth/authorize")
    assert data["token_endpoint"].endswith("/oauth/token")
    assert data["jwks_uri"].endswith("/oauth/jwks.json")
    assert "authorization_code" in data["grant_types_supported"]
    assert "S256" in data["code_challenge_methods_supported"]
    assert "agent_auth" in data
    assert data["agent_auth"]["register_uri"].endswith("/oauthx/docs")
    assert data["agent_auth"]["metadata_uri"].endswith("/auth.md")


def test_oauth_protected_resource_metadata_is_available(client):
    response = client.get("/.well-known/oauth-protected-resource")
    data = response.get_json()

    assert response.status_code == 200
    assert response.content_type.startswith("application/json")
    assert data["resource"]
    assert data["authorization_servers"] == [data["resource"]]
    assert data["jwks_uri"].endswith("/oauth/jwks.json")
    assert "read" in data["scopes_supported"]
    assert "covenant_read" in data["scopes_supported"]
    assert "header" in data["bearer_methods_supported"]
    assert data["resource_documentation"].endswith("/docs")


def test_auth_md_is_available_for_agent_registration(client):
    response = client.get("/auth.md")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.content_type.startswith("text/markdown")
    assert body.startswith("# HODLXXI Agent Authentication")
    assert "/.well-known/openid-configuration" in body
    assert "/.well-known/oauth-authorization-server" in body
    assert "/.well-known/oauth-protected-resource" in body
    assert "/oauth/authorize" in body
    assert "/oauth/token" in body
    assert "Sending, intake, and relay publishing are disabled" in body
