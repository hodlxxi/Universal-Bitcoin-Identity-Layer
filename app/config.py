"""Configuration management for HODLXXI.

Centralises environment variable loading and validation logic while keeping the
public API intentionally simple.
"""

from __future__ import annotations

import os
from typing import Any, Mapping, Optional, TypedDict

_TRUTHY_VALUES = {"1", "true", "yes", "on"}


class AppConfig(TypedDict):
    """Typed representation of the application's configuration."""

    RPC_HOST: str
    RPC_PORT: int
    RPC_USER: str
    RPC_PASSWORD: str
    RPC_WALLET: str
    FLASK_SECRET_KEY: Optional[str]
    FLASK_ENV: str
    FLASK_DEBUG: bool
    JWT_SECRET: str
    JWT_ALGORITHM: str
    JWT_ISSUER: str
    JWT_AUDIENCE: str
    JWKS_DIR: str
    JWT_EXPIRATION_HOURS: int
    TOKEN_TTL: int
    LNURL_BASE_URL: str
    TURN_HOST: str
    TURN_PORT: int
    TURN_USER: str
    TURN_PASS: str
    CORS_ORIGINS: str
    SOCKETIO_CORS: str
    RATE_LIMIT_ENABLED: bool
    RATE_LIMIT_DEFAULT: str
    RATELIMIT_DEFAULT: str
    FORCE_HTTPS: bool
    LOG_LEVEL: str
    LOG_FILE: str
    DATABASE_URL: Optional[str]
    DB_HOST: str
    DB_PORT: int
    DB_USER: str
    DB_PASSWORD: Optional[str]
    DB_NAME: str
    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_PASSWORD: Optional[str]
    REDIS_DB: int
    REDIS_URL: Optional[str]
    SESSION_LIFETIME_HOURS: int
    SECURE_COOKIES: bool
    CSRF_ENABLED: bool
    APP_NAME: str
    APP_VERSION: str
    APP_HOST: str
    APP_PORT: int


def _get_env_bool(name: str, default: bool) -> bool:
    """Return an environment variable as a boolean."""

    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in _TRUTHY_VALUES


def _get_env_int(name: str, default: int) -> int:
    """Return an environment variable as an integer, raising on invalid input."""

    raw_value = os.getenv(name)
    if raw_value is None or raw_value == "":
        return default

    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer (got {raw_value!r})") from exc


def get_config() -> AppConfig:
    """Load application configuration from environment variables."""

    return {
        # Bitcoin RPC Configuration
        "RPC_HOST": os.getenv("RPC_HOST", "127.0.0.1"),
        "RPC_PORT": _get_env_int("RPC_PORT", 8332),
        "RPC_USER": os.getenv("RPC_USER", "bitcoinrpc"),
        "RPC_PASSWORD": os.getenv("RPC_PASSWORD", "change-me"),
        "RPC_WALLET": os.getenv("RPC_WALLET", ""),
        # Flask Configuration
        "FLASK_SECRET_KEY": os.getenv("FLASK_SECRET_KEY"),
        "FLASK_ENV": os.getenv("FLASK_ENV", "development"),
        "FLASK_DEBUG": _get_env_bool("FLASK_DEBUG", False),
        # JWT Configuration
        "JWT_SECRET": os.getenv("JWT_SECRET", "dev-secret-CHANGE-ME-IN-PRODUCTION"),
        "JWT_ALGORITHM": os.getenv("JWT_ALGORITHM", "HS256"),
        "JWT_ISSUER": os.getenv("JWT_ISSUER")
        or os.getenv("OIDC_ISSUER")
        or os.getenv("FLASK_SERVER_NAME")
        or "http://localhost:5000",
        "JWT_AUDIENCE": os.getenv("JWT_AUDIENCE")
        or os.getenv("OAUTH_AUDIENCE")
        or "hodlxxi",
        "JWKS_DIR": os.getenv("JWKS_DIR", "keys"),
        "JWT_EXPIRATION_HOURS": _get_env_int("JWT_EXPIRATION_HOURS", 24),
        "TOKEN_TTL": _get_env_int("TOKEN_TTL", 3600),
        # LNURL Configuration
        "LNURL_BASE_URL": os.getenv("LNURL_BASE_URL", "http://localhost:5000"),
        # TURN Server Configuration (for WebRTC)
        "TURN_HOST": os.getenv("TURN_HOST", "turn.example.com"),
        "TURN_PORT": _get_env_int("TURN_PORT", 3478),
        "TURN_USER": os.getenv("TURN_USER", "user"),
        "TURN_PASS": os.getenv("TURN_PASS", "pass"),
        # CORS Configuration
        "CORS_ORIGINS": os.getenv("CORS_ORIGINS", "*"),
        "SOCKETIO_CORS": os.getenv("SOCKETIO_CORS", "*"),
        # Rate Limiting
        "RATE_LIMIT_ENABLED": _get_env_bool("RATE_LIMIT_ENABLED", True),
        "RATE_LIMIT_DEFAULT": os.getenv("RATE_LIMIT_DEFAULT", "100/hour"),
        "RATELIMIT_DEFAULT": os.getenv("RATELIMIT_DEFAULT", os.getenv("RATE_LIMIT_DEFAULT", "100/hour")),
        "FORCE_HTTPS": _get_env_bool(
            "FORCE_HTTPS",
            os.getenv("FLASK_ENV", "development").lower() == "production",
        ),
        # Logging
        "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
        "LOG_FILE": os.getenv("LOG_FILE", "logs/app.log"),
        # Database Configuration (REQUIRED for production)
        "DATABASE_URL": os.getenv("DATABASE_URL"),
        "DB_HOST": os.getenv("DB_HOST", "localhost"),
        "DB_PORT": _get_env_int("DB_PORT", 5432),
        "DB_USER": os.getenv("DB_USER", "hodlxxi"),
        "DB_PASSWORD": os.getenv("DB_PASSWORD"),
        "DB_NAME": os.getenv("DB_NAME", "hodlxxi"),
        # Redis Configuration (REQUIRED for production)
        "REDIS_HOST": os.getenv("REDIS_HOST", "localhost"),
        "REDIS_PORT": _get_env_int("REDIS_PORT", 6379),
        "REDIS_PASSWORD": os.getenv("REDIS_PASSWORD"),
        "REDIS_DB": _get_env_int("REDIS_DB", 0),
        "REDIS_URL": os.getenv("REDIS_URL") or os.getenv("REDIS_DSN"),
        # Session Configuration
        "SESSION_LIFETIME_HOURS": _get_env_int("SESSION_LIFETIME_HOURS", 24),
        # Security Configuration
        "SECURE_COOKIES": _get_env_bool("SECURE_COOKIES", False),
        "CSRF_ENABLED": _get_env_bool("CSRF_ENABLED", False),
        # Application Settings
        "APP_NAME": os.getenv("APP_NAME", "HODLXXI"),
        "APP_VERSION": os.getenv("APP_VERSION", "1.0.0-alpha"),
        "APP_HOST": os.getenv("APP_HOST", "0.0.0.0"),
        "APP_PORT": _get_env_int("APP_PORT", 5000),
    }


def validate_config(config: Mapping[str, Any]) -> bool:
    """Validate critical configuration values.

    Args:
        config: Configuration mapping to validate.

    Returns:
        True if configuration is valid, raises ValueError otherwise.
    """

    # Check for insecure defaults in production
    flask_env = config.get("FLASK_ENV")

    if flask_env == "production":
        if config.get("JWT_SECRET") == "dev-secret-CHANGE-ME-IN-PRODUCTION":
            raise ValueError("⚠️  JWT_SECRET must be changed for production!")

        if config.get("RPC_PASSWORD") == "change-me":
            raise ValueError("⚠️  RPC_PASSWORD must be set for production!")

        if not config.get("FLASK_SECRET_KEY"):
            raise ValueError("⚠️  FLASK_SECRET_KEY must be set for production!")

        # Validate database configuration
        database_url = config.get("DATABASE_URL")
        db_password = config.get("DB_PASSWORD")

        if not database_url and not db_password:
            import warnings

            warnings.warn(
                "⚠️  DATABASE_URL or DB_PASSWORD not set - database connectivity may fail!",
                stacklevel=2,
            )

        # Warn if Redis password not set
        if not config.get("REDIS_PASSWORD"):
            import warnings

            warnings.warn("⚠️  REDIS_PASSWORD not set - Redis will be unprotected!", stacklevel=2)

    return True
