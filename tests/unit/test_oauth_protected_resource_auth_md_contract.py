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
    assert "urn:ietf:params:oauth:grant-type:jwt-bearer" in data["grant_types_supported"]
    assert "urn:workos:agent-auth:grant-type:claim" in data["grant_types_supported"]
    assert "S256" in data["code_challenge_methods_supported"]
    assert "agent_auth" in data
    agent_auth = data["agent_auth"]
    assert agent_auth["skill"].endswith("/auth.md")
    assert agent_auth["register_uri"].endswith("/oauthx/docs")
    assert agent_auth["identity_endpoint"].endswith("/agent/identity")
    assert agent_auth["claim_endpoint"].endswith("/agent/identity/claim")
    assert agent_auth["events_endpoint"].endswith("/agent/event/notify")
    assert agent_auth["metadata_uri"].endswith("/auth.md")
    assert "anonymous" in agent_auth["identity_types_supported"]
    assert "identity_assertion" in agent_auth["identity_types_supported"]
    assert "access_token" in agent_auth["credential_types_supported"]
    assert "identity_assertion" in agent_auth
    assert "credential_types_supported" in agent_auth["identity_assertion"]
    assert "urn:ietf:params:oauth:token-type:id-jag" in agent_auth["identity_assertion"]["assertion_types_supported"]
    assert "verified_email" in agent_auth["identity_assertion"]["assertion_types_supported"]
    assert "access_token" in agent_auth["identity_assertion"]["credential_types_supported"]
    assert "events_supported" in agent_auth


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
    assert body.startswith("# Auth.md")
    assert "## HODLXXI Agent Authentication" in body
    assert "/.well-known/openid-configuration" in body
    assert "/.well-known/oauth-authorization-server" in body
    assert "/.well-known/oauth-protected-resource" in body
    assert "/oauth/authorize" in body
    assert "/oauth/token" in body
    assert "## agent_auth metadata" in body
    assert "`agent_auth` block" in body
    assert "`identity_types_supported`" in body
    assert "`credential_types_supported`" in body
    assert "`identity_assertion.credential_types_supported`" in body
    assert "/agent/identity" in body
    assert "/agent/identity/claim" in body
    assert "/agent/event/notify" in body
    assert "urn:ietf:params:oauth:grant-type:jwt-bearer" in body
    assert "urn:workos:agent-auth:grant-type:claim" in body
    assert "## Standalone agent registration flow" in body
    assert "## Required agent_auth fields" in body
    assert "Sending, intake, and relay publishing are disabled" in body


def test_auth_md_agent_registration_endpoints_are_discovery_safe_stubs(client):
    for path in [
        "/agent/identity",
        "/agent/identity/claim",
        "/agent/event/notify",
    ]:
        response = client.post(path, json={})
        data = response.get_json()

        assert response.status_code == 501
        assert response.content_type.startswith("application/json")
        assert data["error"] == "not_implemented"
        assert data["enabled"] is False
