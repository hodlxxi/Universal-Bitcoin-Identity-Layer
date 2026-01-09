"""
Pytest configuration and shared fixtures for HODLXXI tests.
"""

import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock

import pytest


import time

# ------------------------------
# Flask app + test client fixtures
# ------------------------------
import pytest

@pytest.fixture
def app():
    from app.factory import create_app
    app = create_app()
    app.config.update(TESTING=True)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


# Set test environment before importing app
os.environ["FLASK_ENV"] = "testing"
os.environ["FLASK_SECRET_KEY"] = "test-secret-key-for-testing-only"
os.environ["JWT_SECRET"] = "test-jwt-secret"
os.environ["RPC_HOST"] = "localhost"
os.environ["RPC_PORT"] = "8332"
os.environ["RPC_USER"] = "test_user"
os.environ["RPC_PASSWORD"] = "test_password"
os.environ["LNURL_BASE_URL"] = "http://localhost:5000"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["RATE_LIMIT_ENABLED"] = "false"

# Import app after setting environment
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ------------------------------
# Global RPC mocking (tests)
# ------------------------------
import sys
import pytest
from unittest.mock import MagicMock

@pytest.fixture
def mock_rpc(monkeypatch, client):
    """
    Provide a MagicMock RPC connection and patch get_rpc_connection() everywhere it
    might be imported (app.utils and any already-loaded app.* modules).
    This prevents tests from accidentally calling the real Bitcoin Core RPC.
    """
    rpc = MagicMock(name="rpc_conn")

    # sensible defaults used across tests (add more if a failure complains)
    rpc.getblockchaininfo.return_value = {"chain": "regtest", "blocks": 100}
    rpc.listwallets.return_value = ["test_wallet"]
    rpc.getwalletinfo.return_value = {"walletname": "test_wallet", "balance": 0}
    rpc.getnewaddress.return_value = "bc1qtest1234567890abcdefghijk"
    rpc.getaddressinfo.return_value = {"ismine": True, "iswatchonly": False}
    rpc.verifymessage.return_value = True

    import app.utils as utils
    monkeypatch.setattr(utils, "get_rpc_connection", lambda: rpc)

    # Patch any already-imported app.* module that grabbed get_rpc_connection into its globals
    for name, mod in list(sys.modules.items()):
        if not name or not name.startswith("app."):
            continue
        if hasattr(mod, "get_rpc_connection"):
            try:
                monkeypatch.setattr(mod, "get_rpc_connection", lambda: rpc)
            except Exception:
                pass

    return rpc

# ------------------------------
# Common fixtures used by integration tests
# ------------------------------
import pytest

@pytest.fixture
def sample_pubkey() -> str:
    # 33-byte compressed pubkey (66 hex chars)
    return "02" + ("a" * 64)


@pytest.fixture
def oauth_client_data():
    return {
        "client_id": "test_client_123",
        "client_name": "Test OAuth Client",
        "redirect_uris": ["http://localhost:3000/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "openid profile",
    }


@pytest.fixture
def jwt_token(app):
    """
    Produce a JWT for tests that need Authorization: Bearer <token>.
    Tries app-native token creation first; otherwise falls back to HS256 using app SECRET_KEY.
    """
    # 1) Try app-native helpers if they exist
    candidates = [
        ("app.security", "mint_jwt"),
        ("app.security", "create_jwt"),
        ("app.security", "create_access_token"),
        ("app.jwt_utils", "create_access_token"),
        ("app.jwt_utils", "mint_jwt"),
    ]
    for mod_name, fn_name in candidates:
        try:
            mod = __import__(mod_name, fromlist=[fn_name])
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                try:
                    return fn(sub="test", scope="openid profile")
                except TypeError:
                    # different signature
                    return fn("test")
        except Exception:
            pass

    # 2) Fallback: HS256 JWT using app.secret key
    try:
        import jwt  # PyJWT
    except Exception as e:
        raise RuntimeError("PyJWT not installed and no app-native jwt minting function found") from e

    secret = app.config.get("JWT_SECRET") or app.config.get("SECRET_KEY") or "dev-secret"
    now = int(time.time())
    payload = {
        "iss": app.config.get("ISSUER", "http://localhost"),
        "sub": "test",
        "iat": now,
        "exp": now + 3600,
        "scope": "openid profile",
    }
    return jwt.encode(payload, secret, algorithm="HS256")
