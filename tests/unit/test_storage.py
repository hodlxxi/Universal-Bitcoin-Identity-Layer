"""
Unit tests for storage backend.
"""

from datetime import datetime, timedelta

import pytest

from app.storage import (
    STORAGE,
    delete_oauth_code,
    delete_session,
    generic_get,
    generic_store,
    get_lnurl_challenge,
    get_oauth_client,
    get_oauth_code,
    get_session,
    init_storage,
    store_lnurl_challenge,
    store_oauth_client,
    store_oauth_code,
    store_session,
)


class TestOAuthClientStorage:
    """Test OAuth client storage operations."""

    def test_store_and_retrieve_oauth_client(self):
        """Test storing and retrieving OAuth client data."""
        client_data = {
            "client_id": "test_client_123",
            "client_secret": "secret_456",
            "client_name": "Test Client",
            "redirect_uris": ["http://localhost:3000/callback"],
        }

        store_oauth_client("test_client_123", client_data)
        retrieved = get_oauth_client("test_client_123")

        assert retrieved is not None
        assert retrieved["client_id"] == "test_client_123"
        assert retrieved["client_name"] == "Test Client"
        assert "http://localhost:3000/callback" in retrieved["redirect_uris"]

    def test_get_nonexistent_oauth_client(self):
        """Test retrieving non-existent OAuth client returns None."""
        result = get_oauth_client("nonexistent_client")
        assert result is None

    def test_overwrite_oauth_client(self):
        """Test that storing a client with existing ID overwrites it."""
        client_data_v1 = {"client_id": "test_client", "client_name": "Version 1"}
        client_data_v2 = {"client_id": "test_client", "client_name": "Version 2"}

        store_oauth_client("test_client", client_data_v1)
        store_oauth_client("test_client", client_data_v2)

        retrieved = get_oauth_client("test_client")
        assert retrieved["client_name"] == "Version 2"


class TestOAuthCodeStorage:
    """Test OAuth authorization code storage operations."""

    def test_store_and_retrieve_oauth_code(self):
        """Test storing and retrieving OAuth authorization codes."""
        code_data = {
            "code": "auth_code_123",
            "client_id": "test_client",
            "user_id": "user_123",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile",
            "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat(),
        }

        store_oauth_code("auth_code_123", code_data)
        retrieved = get_oauth_code("auth_code_123")

        assert retrieved is not None
        assert retrieved["code"] == "auth_code_123"
        assert retrieved["client_id"] == "test_client"
        assert retrieved["scope"] == "openid profile"

    def test_delete_oauth_code(self):
        """Test deleting OAuth authorization codes."""
        code_data = {"code": "auth_code_123", "client_id": "test_client"}

        store_oauth_code("auth_code_123", code_data)
        assert get_oauth_code("auth_code_123") is not None

        delete_oauth_code("auth_code_123")
        assert get_oauth_code("auth_code_123") is None

    def test_delete_nonexistent_oauth_code(self):
        """Test that deleting non-existent code doesn't raise error."""
        delete_oauth_code("nonexistent_code")  # Should not raise


class TestSessionStorage:
    """Test session storage operations."""

    def test_store_and_retrieve_session(self):
        """Test storing and retrieving session data."""
        session_data = {
            "session_id": "sess_123",
            "user_id": "user_456",
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
        }

        store_session("sess_123", session_data)
        retrieved = get_session("sess_123")

        assert retrieved is not None
        assert retrieved["session_id"] == "sess_123"
        assert retrieved["user_id"] == "user_456"

    def test_delete_session(self):
        """Test deleting session data."""
        session_data = {"session_id": "sess_123", "user_id": "user_456"}

        store_session("sess_123", session_data)
        delete_session("sess_123")

        assert get_session("sess_123") is None


class TestLNURLChallengeStorage:
    """Test LNURL-auth challenge storage operations."""

    def test_store_and_retrieve_lnurl_challenge(self):
        """Test storing and retrieving LNURL challenges."""
        challenge_data = {
            "session_id": "lnurl_sess_123",
            "k1": "a" * 64,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
        }

        store_lnurl_challenge("lnurl_sess_123", challenge_data)
        retrieved = get_lnurl_challenge("lnurl_sess_123")

        assert retrieved is not None
        assert retrieved["k1"] == "a" * 64
        assert len(retrieved["k1"]) == 64


class TestGenericStorage:
    """Test generic key-value storage operations."""

    def test_generic_store_and_get(self):
        """Test generic storage operations."""
        test_data = {"foo": "bar", "baz": 123}

        generic_store("test_key", test_data)
        retrieved = generic_get("test_key")

        assert retrieved is not None
        assert retrieved["foo"] == "bar"
        assert retrieved["baz"] == 123

    def test_generic_get_nonexistent(self):
        """Test retrieving non-existent key returns None."""
        result = generic_get("nonexistent_key")
        assert result is None

    def test_generic_store_overwrites(self):
        """Test that generic store overwrites existing values."""
        generic_store("key", {"value": 1})
        generic_store("key", {"value": 2})

        retrieved = generic_get("key")
        assert retrieved["value"] == 2


class TestStorageInitialization:
    """Test storage initialization."""

    def test_init_storage_creates_dictionaries(self):
        """Test that init_storage creates all required storage dictionaries."""
        init_storage()

        assert "oauth_clients" in STORAGE
        assert "oauth_codes" in STORAGE
        assert "oauth_tokens" in STORAGE
        assert "sessions" in STORAGE
        assert "lnurl_challenges" in STORAGE
        assert "pof_challenges" in STORAGE
        assert "refresh_tokens" in STORAGE
        assert "generic_storage" in STORAGE

        # All should be dictionaries
        for key in STORAGE:
            assert isinstance(STORAGE[key], dict)
