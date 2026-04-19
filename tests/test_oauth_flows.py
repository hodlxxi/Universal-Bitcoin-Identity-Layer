"""
Comprehensive OAuth2/OIDC Flow Tests

Tests OAuth 2.0 and OpenID Connect functionality:
- Client registration
- Authorization code flow
- PKCE (S256 and plain)
- Token issuance
- Token introspection
- JWKS endpoint
- OIDC discovery
"""

import base64
import hashlib
import json
import secrets
import time
from unittest.mock import patch

import jwt
import pytest

from app.factory import create_app


@pytest.fixture
def app():
    """Create test application."""
    test_config = {
        "FLASK_SECRET_KEY": "test_secret_key_oauth",
        "FLASK_ENV": "testing",
        "JWKS_DIR": "runtime/test_jwks_oauth",
        "DATABASE_URL": "sqlite:///:memory:",
        "JWT_ISSUER": "https://test.example.com",
        "JWT_AUDIENCE": "test_audience",
        "TESTING": True,
    }
    app = create_app(test_config)
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def registered_client(client):
    """Register an OAuth client."""
    response = client.post(
        "/oauth/register",
        json={
            "client_name": "Test App",
            "redirect_uris": ["https://app.example.com/callback"],
        },
    )
    return json.loads(response.data)


class TestOAuthDeveloperSurface:
    """Test restored OAuth developer-facing endpoints."""

    def test_oauthx_status_available(self, client):
        response = client.get("/oauthx/status")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["status"] == "available"
        assert "issuer" in data
        assert data["endpoints"]["register"] == "/oauth/register"
        assert data["endpoints"]["authorize"] == "/oauth/authorize"
        assert data["endpoints"]["token"] == "/oauth/token"

    def test_oauthx_docs_available(self, client):
        response = client.get("/oauthx/docs")
        assert response.status_code == 200
        assert b"OAuth2 / OIDC Developer Docs" in response.data
        assert b"/oauth/register" in response.data
        assert b"/oauth/authorize" in response.data
        assert b"/oauth/token" in response.data

    def test_oauth_clients_route_restored(self, client):
        response = client.get("/oauth/clients")

        # Conservative access model: endpoint exists but requires login
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data["error"] == "not_logged_in"

    def test_factory_registers_oauth_dev_blueprint_routes(self, app):
        routes = {rule.rule for rule in app.url_map.iter_rules()}
        assert "/oauthx/status" in routes
        assert "/oauthx/docs" in routes
        assert "/oauth/clients" in routes


class TestOIDCDiscovery:
    """Test OpenID Connect discovery endpoint."""

    def test_oidc_discovery_endpoint(self, client):
        """Test OIDC well-known configuration."""
        response = client.get("/.well-known/openid-configuration")

        assert response.status_code == 200
        data = json.loads(response.data)

        # Required OIDC fields
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "jwks_uri" in data
        assert "response_types_supported" in data
        assert "subject_types_supported" in data
        assert "id_token_signing_alg_values_supported" in data

        # Check RS256 is supported
        assert "RS256" in data["id_token_signing_alg_values_supported"]

    def test_jwks_endpoint(self, client):
        """Test JWKS endpoint returns valid keys."""
        response = client.get("/oauth/jwks.json")

        assert response.status_code == 200
        data = json.loads(response.data)

        assert "keys" in data
        assert len(data["keys"]) > 0

        # Validate first key structure
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert "kid" in key
        assert "n" in key
        assert "e" in key


class TestClientRegistration:
    """Test OAuth2 dynamic client registration."""

    def test_register_client_success(self, client):
        """Test successful client registration."""
        response = client.post(
            "/oauth/register",
            json={
                "client_name": "My Application",
                "redirect_uris": ["https://myapp.com/callback"],
                "grant_types": ["authorization_code"],
            },
        )

        assert response.status_code == 201
        data = json.loads(response.data)

        assert "client_id" in data
        assert "client_secret" in data
        assert data["client_name"] == "My Application"
        assert data["redirect_uris"] == ["https://myapp.com/callback"]
        assert "client_id_issued_at" in data

    def test_register_client_missing_name(self, client):
        """Test registration without client name."""
        response = client.post("/oauth/register", json={"redirect_uris": ["https://..."]})

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "client_name" in data["error"]

    def test_register_client_missing_redirect_uris(self, client):
        """Test registration without redirect URIs."""
        response = client.post("/oauth/register", json={"client_name": "App"})

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "redirect_uris" in data["error"]

    def test_register_client_invalid_redirect_uris(self, client):
        """Test registration with invalid redirect URIs."""
        response = client.post(
            "/oauth/register",
            json={"client_name": "App", "redirect_uris": "not_an_array"},
        )

        assert response.status_code == 400


class TestAuthorizationFlow:
    """Test OAuth2 authorization code flow."""

    def test_authorize_endpoint_requires_auth(self, client, registered_client):
        """Test that authorization requires user authentication."""
        response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
                "state": "random_state",
            },
        )

        # Should redirect to login
        assert response.status_code == 302
        assert "/login" in response.location

    def test_authorize_with_authenticated_user(self, client, registered_client):
        """Test authorization with authenticated user."""
        # Simulate authenticated user
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
                "state": "test_state",
                "scope": "openid profile",
            },
        )

        # Should redirect to client with authorization code
        assert response.status_code == 302
        assert "code=" in response.location
        assert "state=test_state" in response.location

    def test_authorize_invalid_redirect_uri(self, client, registered_client):
        """Test authorization with invalid redirect URI."""
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": "https://evil.com/callback",
            },
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "redirect_uri" in data["error_description"]

    def test_authorize_invalid_response_type(self, client, registered_client):
        """Test authorization with unsupported response type."""
        response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "token",  # Implicit flow not supported
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
            },
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "unsupported_response_type" in data["error"]


class TestPKCE:
    """Test Proof Key for Code Exchange (PKCE)."""

    def test_authorize_with_pkce_s256(self, client, registered_client):
        """Test authorization with PKCE S256 challenge."""
        # Generate PKCE verifier and challenge
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

        assert response.status_code == 302
        assert "code=" in response.location

    def test_token_with_pkce_verification(self, client, registered_client):
        """Test token exchange with PKCE verification."""
        # Generate PKCE parameters
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

        # 1. Get authorization code with PKCE
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        auth_response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

        # Extract authorization code from redirect
        code = auth_response.location.split("code=")[1].split("&")[0]

        # 2. Exchange code for token with verifier
        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "code_verifier": verifier,
            },
        )

        assert token_response.status_code == 200
        token_data = json.loads(token_response.data)
        assert "access_token" in token_data
        assert "id_token" in token_data

    def test_token_with_invalid_pkce_verifier(self, client, registered_client):
        """Test token exchange with wrong PKCE verifier."""
        # Generate PKCE with correct challenge
        correct_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(correct_verifier.encode()).digest()).rstrip(b"=").decode()

        # Get authorization code
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        auth_response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

        code = auth_response.location.split("code=")[1].split("&")[0]

        # Try to exchange with wrong verifier
        wrong_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()

        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "code_verifier": wrong_verifier,
            },
        )

        assert token_response.status_code == 400
        data = json.loads(token_response.data)
        assert "invalid_grant" in data["error"]


class TestPKCESafety:
    """Security-specific PKCE regression tests."""

    def test_token_rejects_swapped_pkce_values(self, client, registered_client):
        """Swapped challenge/verifier order must not be accepted."""
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "b" * 64

        auth_response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        code = auth_response.location.split("code=")[1].split("&")[0]

        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                # intentionally supply challenge where verifier is expected
                "code_verifier": challenge,
            },
        )

        assert token_response.status_code == 400
        payload = json.loads(token_response.data)
        assert payload["error"] == "invalid_grant"


class TestOAuthErrorLeakage:
    """Ensure auth server errors do not expose internals."""

    def test_token_endpoint_hides_exception_details(self, client, registered_client, monkeypatch):
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "d" * 64

        auth_response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
            },
        )
        code = auth_response.location.split("code=")[1].split("&")[0]

        def _boom(*_args, **_kwargs):
            raise RuntimeError("DB hostname leaked in error")

        monkeypatch.setattr("app.blueprints.oauth.issue_jwt_compat", _boom)

        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
            },
        )

        assert token_response.status_code == 500
        payload = json.loads(token_response.data)
        assert payload["error"] == "server_error"
        assert payload["error_description"] == "Token issuance failed"


class TestTokenEndpoint:
    """Test OAuth2 token endpoint."""

    def test_token_exchange_success(self, client, registered_client):
        """Test successful authorization code to token exchange."""
        # Get authorization code first
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        auth_response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
            },
        )

        code = auth_response.location.split("code=")[1].split("&")[0]

        # Exchange for token
        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
            },
        )

        assert token_response.status_code == 200
        data = json.loads(token_response.data)

        assert "access_token" in data
        assert "id_token" in data
        assert data["token_type"] == "Bearer"
        assert "expires_in" in data
        assert "scope" in data

    def test_token_invalid_client_credentials(self, client, registered_client):
        """Test token exchange with invalid client credentials."""
        response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "some_code",
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": "wrong_secret",
            },
        )

        assert response.status_code == 401
        data = json.loads(response.data)
        assert data["error"] == "invalid_client"

    def test_token_code_reuse_prevented(self, client, registered_client):
        """Test that authorization codes can only be used once."""
        # Get code
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        auth_response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
            },
        )

        code = auth_response.location.split("code=")[1].split("&")[0]

        # Use code first time
        response1 = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
            },
        )

        assert response1.status_code == 200

        # Try to reuse code
        response2 = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,  # Same code
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
            },
        )

        assert response2.status_code == 400
        data = json.loads(response2.data)
        assert data["error"] == "invalid_grant"


class TestTokenIntrospection:
    """Test OAuth2 token introspection."""

    def test_introspect_active_token(self, client, registered_client, app):
        """Test introspection of active token."""
        # Get a valid token
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        auth_response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
            },
        )

        code = auth_response.location.split("code=")[1]

        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
            },
        )

        token = json.loads(token_response.data)["access_token"]

        # Introspect token
        introspect_response = client.post(
            "/oauth/introspect",
            data={
                "token": token,
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
            },
        )

        assert introspect_response.status_code == 200
        data = json.loads(introspect_response.data)
        assert data["active"] is True
        assert "sub" in data
        assert "exp" in data

    def test_introspect_invalid_token(self, client, registered_client):
        """Test introspection of invalid token."""
        response = client.post(
            "/oauth/introspect",
            data={
                "token": "invalid.jwt.token",
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
            },
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["active"] is False

    def test_introspect_rejects_forged_rs256_token(self, client, registered_client):
        """Introspection must reject forged tokens even if claim shape looks valid."""
        now = int(time.time())
        forged = jwt.encode(
            {
                "iss": "http://localhost:5000",
                "aud": registered_client["client_id"],
                "sub": "forged-user",
                "iat": now,
                "exp": now + 3600,
                "scope": "read",
            },
            "attacker-secret",
            algorithm="HS256",
            headers={"kid": "9999999999", "alg": "HS256"},
        )

        response = client.post(
            "/oauth/introspect",
            data={
                "token": forged,
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
            },
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["active"] is False


class TestJWTTokens:
    """Test JWT token structure and validation."""

    def test_jwt_token_structure(self, client, registered_client):
        """Opaque access_token + introspection works (with PKCE)."""
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "test_pubkey"

        verifier = "test_verifier_opaque_access"
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        auth_response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
                "scope": "read_limited",
                "state": "s1",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert auth_response.status_code == 302
        code = auth_response.location.split("code=")[1].split("&", 1)[0]

        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "code_verifier": verifier,
            },
        )
        token_data = json.loads(token_response.data)
        assert "access_token" in token_data, token_data
        access_token = token_data["access_token"]
        assert isinstance(access_token, str) and access_token

        # access token is opaque in the new design; do not require JWT structure here
        # (some implementations may still return JWT; we only require introspection to work)
        introspect = client.post(
            "/oauth/introspect",
            data={
                "token": access_token,
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
            },
        )
        assert introspect.status_code == 200
        data = json.loads(introspect.data)
        assert data["active"] is True
        assert "sub" in data
        assert "exp" in data

    def test_id_token_is_rs256(self, client, registered_client):
        """id_token should be RS256 and include kid when scope includes openid."""
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "02" + "a" * 64

        verifier = "test_verifier_id_token"
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        auth_response = client.get(
            "/oauth/authorize",
            query_string={
                "response_type": "code",
                "client_id": registered_client["client_id"],
                "redirect_uri": registered_client["redirect_uris"][0],
                "scope": "openid read_limited",
                "nonce": "n1",
                "state": "s2",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert auth_response.status_code == 302
        code = auth_response.location.split("code=")[1].split("&", 1)[0]

        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": registered_client["redirect_uris"][0],
                "client_id": registered_client["client_id"],
                "client_secret": registered_client["client_secret"],
                "code_verifier": verifier,
            },
        )
        token_data = json.loads(token_response.data)
        assert "id_token" in token_data, token_data
        id_token = token_data["id_token"]
        assert id_token and isinstance(id_token, str)

        header = jwt.get_unverified_header(id_token)
        assert header.get("alg") == "RS256"
        assert "kid" in header
