"""
Pytest configuration and shared fixtures for HODLXXI tests.
"""

import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock

import pytest

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


@pytest.fixture
def app():
    """Create and configure a test Flask application instance."""
    from app.app import app as flask_app
    from app.storage import init_storage

    # Configure for testing
    flask_app.config.update(
        {"TESTING": True, "SECRET_KEY": "test-secret-key", "WTF_CSRF_ENABLED": False, "SERVER_NAME": "localhost:5000"}
    )

    # Initialize test storage
    init_storage()

    # Create application context
    with flask_app.app_context():
        yield flask_app


@pytest.fixture
def client(app):
    """Create a test client for the Flask application."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create a test CLI runner for the Flask application."""
    return app.test_cli_runner()


@pytest.fixture
def auth_headers():
    """Provide authentication headers for API requests."""
    return {"Authorization": "Bearer test_access_token", "Content-Type": "application/json"}


@pytest.fixture
def mock_bitcoin_rpc():
    """Mock Bitcoin RPC connection for testing."""
    mock_rpc = MagicMock()

    # Mock common RPC methods
    mock_rpc.getblockchaininfo.return_value = {
        "chain": "test",
        "blocks": 2500000,
        "headers": 2500000,
        "bestblockhash": "0000000000000000000000000000000000000000000000000000000000000000",
        "difficulty": 1.0,
        "verificationprogress": 1.0,
    }

    mock_rpc.listwallets.return_value = ["test_wallet"]

    mock_rpc.getwalletinfo.return_value = {
        "walletname": "test_wallet",
        "walletversion": 169900,
        "balance": 1.5,
        "unconfirmed_balance": 0.0,
        "immature_balance": 0.0,
    }

    mock_rpc.getnewaddress.return_value = "bc1qtest1234567890abcdefghijk"

    mock_rpc.getaddressinfo.return_value = {
        "address": "bc1qtest1234567890abcdefghijk",
        "scriptPubKey": "0014test",
        "ismine": True,
        "iswatchonly": False,
        "isscript": False,
        "iswitness": True,
    }

    return mock_rpc


@pytest.fixture
def sample_pubkey():
    """Provide a sample Bitcoin public key for testing."""
    return "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"


@pytest.fixture
def sample_privkey():
    """Provide a sample Bitcoin private key for testing (compressed WIF)."""
    return "L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy"


@pytest.fixture
def sample_bitcoin_address():
    """Provide a sample Bitcoin address for testing."""
    return "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"


@pytest.fixture
def sample_signature():
    """Provide a sample Bitcoin signature for testing."""
    return "H9J8VN9xVZ5L0gPJ9KqMQj6LbLxYqI8CjJU7xBm0pRBqK3vYk2JRZVLGsI5bR6rP8TQ9xK"


@pytest.fixture
def oauth_client_data():
    """Provide sample OAuth2 client data for testing."""
    return {
        "client_id": "test_client_123",
        "client_secret": "test_secret_456",
        "client_name": "Test OAuth Client",
        "redirect_uris": ["http://localhost:3000/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "openid profile bitcoin:read",
        "token_endpoint_auth_method": "client_secret_basic",
    }


@pytest.fixture
def lnurl_auth_challenge():
    """Provide sample LNURL-auth challenge data."""
    return {
        "session_id": "test_session_123",
        "k1": "a" * 64,  # 64 hex characters
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
    }


@pytest.fixture
def pof_challenge():
    """Provide sample Proof of Funds challenge data."""
    return {
        "challenge_id": "pof_challenge_123",
        "pubkey": "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        "challenge": "Sign this message to prove ownership",
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
    }


@pytest.fixture
def jwt_token():
    """Generate a valid JWT token for testing."""
    from datetime import datetime, timedelta

    import jwt

    payload = {
        "sub": "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "scope": "openid profile bitcoin:read",
    }

    token = jwt.encode(payload, "test-jwt-secret", algorithm="HS256")
    return token


@pytest.fixture
def mock_socketio_client(app):
    """Create a mock SocketIO client for WebSocket testing."""
    from flask_socketio import SocketIOTestClient

    from app.app import socketio

    return socketio.test_client(app)


@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        yield f
    os.unlink(f.name)


@pytest.fixture
def mock_audit_logger():
    """Mock audit logger for testing."""
    mock_logger = MagicMock()
    return mock_logger


@pytest.fixture(autouse=True)
def reset_storage():
    """Reset in-memory storage before each test."""
    from app.storage import STORAGE

    # Clear all storage
    STORAGE["oauth_clients"].clear()
    STORAGE["oauth_codes"].clear()
    STORAGE["oauth_tokens"].clear()
    STORAGE["sessions"].clear()
    STORAGE["lnurl_challenges"].clear()
    STORAGE["pof_challenges"].clear()
    STORAGE["refresh_tokens"].clear()
    STORAGE["generic_storage"].clear()

    yield

    # Clean up after test
    STORAGE["oauth_clients"].clear()
    STORAGE["oauth_codes"].clear()
    STORAGE["oauth_tokens"].clear()
    STORAGE["sessions"].clear()
    STORAGE["lnurl_challenges"].clear()
    STORAGE["pof_challenges"].clear()
    STORAGE["refresh_tokens"].clear()
    STORAGE["generic_storage"].clear()


# Pytest configuration hooks
def pytest_configure(config):
    """Configure pytest with custom settings."""
    config.addinivalue_line("markers", "bitcoin: tests that require Bitcoin Core RPC connection")
    config.addinivalue_line("markers", "slow: tests that take a long time to run")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add 'unit' marker to tests in unit/ directory
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)

        # Add 'integration' marker to tests in integration/ directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Add 'e2e' marker to tests in e2e/ directory
        if "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
