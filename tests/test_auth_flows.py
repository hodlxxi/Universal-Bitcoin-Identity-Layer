"""
Comprehensive Authentication Flow Tests

Tests all authentication methods:
- Bitcoin signature verification
- LNURL-Auth challenges
- Guest login
- Session management
- Access control
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from app.factory import create_app
from app.utils import derive_legacy_address_from_pubkey, generate_challenge


@pytest.fixture
def app():
    """Create test application."""
    test_config = {
        "FLASK_SECRET_KEY": "test_secret_key_12345",
        "FLASK_ENV": "testing",
        "JWKS_DIR": "/tmp/test_jwks",
        "DATABASE_URL": "sqlite:///:memory:",
        "TESTING": True,
    }
    app = create_app(test_config)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def mock_rpc():
    """Mock Bitcoin RPC connection."""
    with patch("app.utils.get_rpc_connection") as mock:
        rpc = MagicMock()
        mock.return_value = rpc
        yield rpc


class TestBitcoinSignatureAuth:
    """Test Bitcoin signature-based authentication."""

    def test_verify_signature_success(self, client, mock_rpc):
        """Test successful signature verification."""
        # Arrange
        test_pubkey = "02" + "a" * 64
        test_challenge = generate_challenge()
        test_signature = "test_signature_base64"

        # Mock RPC to return True for signature verification
        mock_rpc.verifymessage.return_value = True

        # Create session with challenge
        with client.session_transaction() as sess:
            sess["challenge"] = test_challenge
            sess["challenge_timestamp"] = time.time()

        # Act
        response = client.post(
            "/verify_signature",
            json={
                "pubkey": test_pubkey,
                "signature": test_signature,
                "challenge": test_challenge,
            },
        )

        # Assert
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["verified"] is True
        assert data["pubkey"] == test_pubkey
        assert "access_level" in data

    def test_verify_signature_invalid_challenge(self, client):
        """Test signature verification with invalid challenge."""
        response = client.post(
            "/verify_signature",
            json={
                "pubkey": "02" + "a" * 64,
                "signature": "test_sig",
                "challenge": "wrong_challenge",
            },
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["verified"] is False
        assert "challenge" in data["error"].lower()

    def test_verify_signature_expired_challenge(self, client):
        """Test signature verification with expired challenge."""
        test_challenge = generate_challenge()

        # Create expired challenge (11 minutes old)
        with client.session_transaction() as sess:
            sess["challenge"] = test_challenge
            sess["challenge_timestamp"] = time.time() - 660

        response = client.post(
            "/verify_signature",
            json={
                "pubkey": "02" + "a" * 64,
                "signature": "test_sig",
                "challenge": test_challenge,
            },
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["verified"] is False
        assert "expired" in data["error"].lower()

    def test_verify_signature_missing_signature(self, client):
        """Test verification without signature."""
        test_challenge = generate_challenge()

        with client.session_transaction() as sess:
            sess["challenge"] = test_challenge
            sess["challenge_timestamp"] = time.time()

        response = client.post(
            "/verify_signature",
            json={"pubkey": "02" + "a" * 64, "challenge": test_challenge},
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "signature" in data["error"].lower()

    def test_verify_signature_invalid_pubkey_format(self, client):
        """Test verification with invalid pubkey format."""
        test_challenge = generate_challenge()

        with client.session_transaction() as sess:
            sess["challenge"] = test_challenge
            sess["challenge_timestamp"] = time.time()

        response = client.post(
            "/verify_signature",
            json={
                "pubkey": "invalid_pubkey",
                "signature": "test_sig",
                "challenge": test_challenge,
            },
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "66 hex" in data["error"]

    def test_verify_signature_rpc_failure(self, client, mock_rpc):
        """Test signature verification with RPC failure."""
        test_pubkey = "02" + "a" * 64
        test_challenge = generate_challenge()

        mock_rpc.verifymessage.side_effect = Exception("RPC connection failed")

        with client.session_transaction() as sess:
            sess["challenge"] = test_challenge
            sess["challenge_timestamp"] = time.time()

        response = client.post(
            "/verify_signature",
            json={
                "pubkey": test_pubkey,
                "signature": "test_sig",
                "challenge": test_challenge,
            },
        )

        assert response.status_code == 500


class TestGuestLogin:
    """Test guest and PIN-based login."""

    def test_guest_login_with_valid_pin(self, client):
        """Test guest login with valid PIN."""
        with patch.dict("os.environ", {"GUEST_STATIC_PINS": "1234:TestUser"}):
            response = client.post("/guest_login", json={"pin": "1234"})

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["ok"] is True
            assert data["label"] == "TestUser"

    def test_guest_login_with_invalid_pin(self, client):
        """Test guest login with invalid PIN."""
        with patch.dict("os.environ", {"GUEST_STATIC_PINS": "1234:TestUser"}):
            response = client.post("/guest_login", json={"pin": "9999"})

            assert response.status_code == 403
            data = json.loads(response.data)
            assert "error" in data

    def test_guest_login_anonymous(self, client):
        """Test anonymous guest login without PIN."""
        response = client.post("/guest_login", json={})

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["ok"] is True
        assert "Guest_" in data["label"]

    def test_guest_login_resume_existing_session(self, client):
        """Test resuming existing guest session."""
        # First login
        response1 = client.post("/guest_login", json={})
        data1 = json.loads(response1.data)
        label1 = data1["label"]

        # Second login should resume
        response2 = client.post("/guest_login", json={})
        data2 = json.loads(response2.data)

        assert data2["label"] == label1


class TestSessionManagement:
    """Test session creation, validation, and expiry."""

    def test_logout_clears_session(self, client):
        """Test that logout clears session."""
        # Create session
        with client.session_transaction() as sess:
            sess["logged_in_pubkey"] = "test_pubkey"
            sess["access_level"] = "full"

        # Logout
        response = client.get("/logout")

        assert response.status_code == 302  # Redirect

        # Check session cleared
        with client.session_transaction() as sess:
            assert "logged_in_pubkey" not in sess

    def test_session_persistence_after_login(self, client, mock_rpc):
        """Test that session persists after successful login."""
        test_pubkey = "02" + "a" * 64
        test_challenge = generate_challenge()

        mock_rpc.verifymessage.return_value = True

        with client.session_transaction() as sess:
            sess["challenge"] = test_challenge
            sess["challenge_timestamp"] = time.time()

        # Login
        client.post(
            "/verify_signature",
            json={
                "pubkey": test_pubkey,
                "signature": "sig",
                "challenge": test_challenge,
            },
        )

        # Check session persists
        with client.session_transaction() as sess:
            assert sess["logged_in_pubkey"] == test_pubkey
            assert "access_level" in sess


class TestAccessControl:
    """Test access level assignment and enforcement."""

    def test_special_user_gets_full_access(self, client, mock_rpc):
        """Test that special users receive full access."""
        special_pubkey = "02" + "b" * 64
        test_challenge = generate_challenge()

        mock_rpc.verifymessage.return_value = True

        with patch.dict("os.environ", {"SPECIAL_USERS": special_pubkey}):
            with client.session_transaction() as sess:
                sess["challenge"] = test_challenge
                sess["challenge_timestamp"] = time.time()

            response = client.post(
                "/verify_signature",
                json={
                    "signature": "sig",
                    "challenge": test_challenge,
                    # No pubkey - should try special users
                },
            )

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["verified"] is True
            assert data["access_level"] == "full"


class TestRateLimiting:
    """Test rate limiting on authentication endpoints."""

    def test_verify_signature_rate_limit(self, client):
        """Test that verify_signature has rate limiting."""
        test_challenge = generate_challenge()

        with client.session_transaction() as sess:
            sess["challenge"] = test_challenge
            sess["challenge_timestamp"] = time.time()

        # Make many requests rapidly
        responses = []
        for _ in range(15):  # Limit is 10 per minute
            response = client.post(
                "/verify_signature",
                json={
                    "pubkey": "02" + "a" * 64,
                    "signature": "sig",
                    "challenge": test_challenge,
                },
            )
            responses.append(response.status_code)

        # Should eventually get 429 (rate limited)
        assert 429 in responses


class TestUtilityFunctions:
    """Test authentication utility functions."""

    def test_derive_legacy_address(self):
        """Test Bitcoin address derivation from pubkey."""
        # Known test vector
        pubkey = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        address = derive_legacy_address_from_pubkey(pubkey)

        # Should return a valid Bitcoin address
        assert len(address) >= 26
        assert len(address) <= 35
        assert address[0] in ["1", "3"]

    def test_generate_challenge_uniqueness(self):
        """Test that challenges are unique."""
        challenges = {generate_challenge() for _ in range(100)}
        assert len(challenges) == 100  # All unique

    def test_generate_challenge_format(self):
        """Test challenge format (UUID)."""
        challenge = generate_challenge()
        assert len(challenge) == 36  # UUID format
        assert challenge.count("-") == 4
