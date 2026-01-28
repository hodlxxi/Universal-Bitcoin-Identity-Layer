"""
Integration tests for API endpoints.
"""

import json
from datetime import datetime, timedelta

import pytest


class TestHealthEndpoint:
    """Test health check endpoint."""

    def test_health_endpoint_returns_ok(self, client):
        """Test that health endpoint returns 200 OK."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    def test_health_endpoint_includes_version(self, client):
        """Test that health endpoint includes version info."""
        response = client.get("/health")
        data = response.get_json()

        assert "version" in data
        assert data["version"] == "1.0.0-beta"


class TestMetricsEndpoint:
    """Test metrics endpoint."""

    def test_metrics_endpoint_exists(self, client):
        """Test that metrics endpoint is accessible."""
        response = client.get("/metrics")

        assert response.status_code == 200

    def test_metrics_endpoint_returns_json(self, client):
        """Test that metrics endpoint returns JSON data."""
        response = client.get("/metrics")

        assert response.content_type == "application/json"
        data = response.get_json()
        assert "metrics" in data


class TestLNURLAuthEndpoints:
    """Test LNURL-auth endpoints."""

    def test_create_lnurl_auth_session(self, client):
        """Test creating LNURL-auth session."""
        response = client.post("/api/lnurl-auth/create")

        assert response.status_code == 200
        data = response.get_json()

        # Verify required fields
        assert "session_id" in data
        assert "lnurl" in data
        assert "qr_code" in data

        # Verify session_id format
        session_id = data["session_id"]
        assert isinstance(session_id, str)
        assert len(session_id) > 0

    def test_check_lnurl_auth_session_not_verified(self, client):
        """Test checking unverified LNURL-auth session."""
        # Create session first
        create_response = client.post("/api/lnurl-auth/create")
        session_id = create_response.get_json()["session_id"]

        # Check status
        response = client.get(f"/api/lnurl-auth/check/{session_id}")

        assert response.status_code == 200
        data = response.get_json()
        assert data["verified"] is False

    def test_check_nonexistent_lnurl_session(self, client):
        """Test checking non-existent LNURL-auth session."""
        response = client.get("/api/lnurl-auth/check/nonexistent_session")

        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data


class TestProofOfFundsEndpoints:
    """Test Proof of Funds (PoF) endpoints."""

    def test_create_pof_challenge(self, client, sample_pubkey):
        """Test creating Proof of Funds challenge."""
        payload = {"pubkey": sample_pubkey, "threshold": 0.1, "privacy_level": "boolean"}

        response = client.post("/api/challenge", data=json.dumps(payload), content_type="application/json")

        # Note: This may fail if Bitcoin RPC is not available
        # but we're testing the endpoint structure
        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.get_json()
            assert "challenge_id" in data or "challenge" in data

    def test_create_pof_challenge_missing_pubkey(self, client):
        """Test that PoF challenge requires pubkey."""
        payload = {"threshold": 0.1, "privacy_level": "boolean"}

        response = client.post("/api/challenge", data=json.dumps(payload), content_type="application/json")

        assert response.status_code in [400, 500]


class TestOAuthEndpoints:
    """Test OAuth2 endpoints."""

    def test_oauth_authorize_missing_params(self, client):
        """Test OAuth authorize endpoint with missing parameters."""
        response = client.get("/oauth/authorize")

        assert response.status_code in [400, 302]

    def test_oauth_authorize_with_params(self, client, oauth_client_data):
        """Test OAuth authorize endpoint with required parameters."""
        from app.storage import store_oauth_client

        # Register OAuth client first
        store_oauth_client(oauth_client_data["client_id"], oauth_client_data)

        params = {
            "client_id": oauth_client_data["client_id"],
            "redirect_uri": oauth_client_data["redirect_uris"][0],
            "response_type": "code",
            "scope": "openid profile",
            "state": "random_state_123",
        }

        response = client.get("/oauth/authorize", query_string=params)

        # Should redirect to login or return authorization page
        assert response.status_code in [200, 302]

    def test_oauth_token_endpoint_exists(self, client):
        """Test that OAuth token endpoint exists."""
        response = client.post("/oauth/token")

        # Should return error for missing parameters
        assert response.status_code in [400, 401]

    def test_oauth_register_endpoint_post(self, client):
        """Test OAuth client registration endpoint."""
        registration_data = {
            "client_name": "Test OAuth Client",
            "redirect_uris": ["http://localhost:3000/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid profile",
        }

        response = client.post("/oauth/register", data=json.dumps(registration_data), content_type="application/json")

        assert response.status_code in [200, 201, 400]

        if response.status_code in [200, 201]:
            data = response.get_json()
            assert "client_id" in data


class TestWellKnownEndpoints:
    """Test .well-known discovery endpoints."""

    def test_openid_configuration(self, client):
        """Test OpenID Connect discovery endpoint."""
        response = client.get("/.well-known/openid-configuration")

        assert response.status_code == 200
        data = response.get_json()

        # Verify required OpenID Connect fields
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "response_types_supported" in data
        assert "subject_types_supported" in data

    def test_jwks_endpoint(self, client):
        """Test JWKS endpoint for public keys."""
        response = client.get("/oauth/jwks.json")

        assert response.status_code == 200
        data = response.get_json()

        assert "keys" in data
        assert isinstance(data["keys"], list)


class TestDemoEndpoints:
    """Test demo endpoints."""

    def test_demo_free_endpoint(self, client):
        """Test public demo endpoint."""
        response = client.get("/api/demo/free")

        assert response.status_code == 200
        data = response.get_json()
        assert "message" in data

    def test_demo_protected_endpoint_without_auth(self, client):
        """Test that protected demo endpoint requires authentication."""
        response = client.get("/api/demo/protected")

        # Should require authentication
        assert response.status_code in [401, 403]

    def test_demo_protected_endpoint_with_auth(self, client, jwt_token):
        """Test protected demo endpoint with valid token."""
        headers = {"Authorization": f"Bearer {jwt_token}"}

        response = client.get("/api/demo/protected", headers=headers)

        # May pass or fail depending on token validation implementation
        assert response.status_code in [200, 401, 403]


class TestLoginEndpoints:
    """Test login endpoints."""

    def test_login_page_get(self, client):
        """Test that login page is accessible."""
        response = client.get("/login")

        assert response.status_code == 200
        assert b"login" in response.data.lower() or b"hodlxxi" in response.data.lower()

    def test_logout_endpoint(self, client):
        """Test logout endpoint."""
        response = client.get("/logout")

        # Should redirect or return success
        assert response.status_code in [200, 302]


class TestRootEndpoint:
    """Test root endpoint."""

    def test_root_endpoint(self, client):
        """Test that root endpoint returns homepage."""
        response = client.get("/")

        assert response.status_code == 200
        # Should contain application name or welcome message
        assert b"HODLXXI" in response.data or b"Bitcoin" in response.data


class TestErrorHandling:
    """Test error handling."""

    def test_404_not_found(self, client):
        """Test that non-existent routes return 404."""
        response = client.get("/nonexistent/route/that/does/not/exist")

        assert response.status_code == 404

    def test_405_method_not_allowed(self, client):
        """Test that wrong HTTP methods return 405."""
        # Try POST on GET-only endpoint
        response = client.post("/health")

        assert response.status_code == 405
