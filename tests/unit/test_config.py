"""
Unit tests for configuration management.
"""

import os
from unittest.mock import patch

import pytest

from app.config import get_config, validate_config


class TestGetConfig:
    """Test configuration loading from environment variables."""

    def test_get_config_defaults(self):
        """Test that get_config returns default values when env vars not set."""
        config = get_config()

        assert config["FLASK_ENV"] == "testing"  # Set in conftest
        assert config["RPC_HOST"] == "localhost"
        assert config["RPC_PORT"] == 8332
        assert config["JWT_ALGORITHM"] == "HS256"
        assert config["APP_NAME"] == "HODLXXI"

    def test_get_config_custom_values(self):
        """Test that get_config uses environment variables when provided."""
        with patch.dict(os.environ, {"RPC_HOST": "192.168.1.100", "RPC_PORT": "18332", "APP_NAME": "CustomApp"}):
            config = get_config()

            assert config["RPC_HOST"] == "192.168.1.100"
            assert config["RPC_PORT"] == 18332
            assert config["APP_NAME"] == "CustomApp"

    def test_get_config_boolean_parsing(self):
        """Test that boolean environment variables are parsed correctly."""
        with patch.dict(os.environ, {"FLASK_DEBUG": "1", "RATE_LIMIT_ENABLED": "true", "SECURE_COOKIES": "yes"}):
            config = get_config()

            assert config["FLASK_DEBUG"] is True
            assert config["RATE_LIMIT_ENABLED"] is True
            assert config["SECURE_COOKIES"] is True

    def test_get_config_integer_parsing(self):
        """Test that integer environment variables are parsed correctly."""
        with patch.dict(
            os.environ, {"RPC_PORT": "18443", "JWT_EXPIRATION_HOURS": "48", "SESSION_LIFETIME_HOURS": "12"}
        ):
            config = get_config()

            assert config["RPC_PORT"] == 18443
            assert config["JWT_EXPIRATION_HOURS"] == 48
            assert config["SESSION_LIFETIME_HOURS"] == 12

    def test_get_config_invalid_integer_raises(self):
        """Invalid integer inputs should surface a helpful error."""
        with patch.dict(os.environ, {"RPC_PORT": "not-a-number"}):
            with pytest.raises(ValueError, match="RPC_PORT"):
                get_config()


class TestValidateConfig:
    """Test configuration validation for production."""

    def test_validate_config_development_passes(self):
        """Test that development config validation passes."""
        config = {
            "FLASK_ENV": "development",
            "JWT_SECRET": "dev-secret-CHANGE-ME-IN-PRODUCTION",
            "RPC_PASSWORD": "change-me",
            "FLASK_SECRET_KEY": None,
        }

        result = validate_config(config)
        assert result is True

    def test_validate_config_production_fails_jwt_secret(self):
        """Test that production validation fails with default JWT secret."""
        config = {
            "FLASK_ENV": "production",
            "JWT_SECRET": "dev-secret-CHANGE-ME-IN-PRODUCTION",
            "RPC_PASSWORD": "secure_password",
            "FLASK_SECRET_KEY": "some_secret",
        }

        with pytest.raises(ValueError, match="JWT_SECRET must be changed"):
            validate_config(config)

    def test_validate_config_production_fails_rpc_password(self):
        """Test that production validation fails with default RPC password."""
        config = {
            "FLASK_ENV": "production",
            "JWT_SECRET": "secure_jwt_secret",
            "RPC_PASSWORD": "change-me",
            "FLASK_SECRET_KEY": "some_secret",
        }

        with pytest.raises(ValueError, match="RPC_PASSWORD must be set"):
            validate_config(config)

    def test_validate_config_production_fails_flask_secret(self):
        """Test that production validation fails without Flask secret."""
        config = {
            "FLASK_ENV": "production",
            "JWT_SECRET": "secure_jwt_secret",
            "RPC_PASSWORD": "secure_password",
            "FLASK_SECRET_KEY": None,
        }

        with pytest.raises(ValueError, match="FLASK_SECRET_KEY must be set"):
            validate_config(config)

    def test_validate_config_production_passes(self):
        """Test that production validation passes with secure values."""
        config = {
            "FLASK_ENV": "production",
            "JWT_SECRET": "secure_jwt_secret_with_sufficient_entropy",
            "RPC_PASSWORD": "secure_rpc_password",
            "FLASK_SECRET_KEY": "secure_flask_secret_key",
        }

        result = validate_config(config)
        assert result is True
