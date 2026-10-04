"""Security helpers for configuring Flask in production."""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any, Mapping

import redis
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from app.redis_contract import log_memory_fallback_warning, redis_required

try:  # pragma: no cover - optional dependency
    from flask_talisman import Talisman  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for tests
    Talisman = None  # type: ignore


logger = logging.getLogger(__name__)

REDIS_BACKED_RATE_LIMIT_SCHEMES = ("redis://", "rediss://", "unix://")
RATE_LIMIT_REDIS_REQUIRED_ENVIRONMENTS = {"production", "staging"}
_LIMITER_INITIALIZED_EXTENSION = "hodlxxi_rate_limiter_initialized"
_LIVENESS_PATHS = frozenset({"/health", "/health/live"})
_PUBLIC_STATUS_PATH = "/api/public/status"


def _is_redis_backed_storage_uri(storage_uri: object) -> bool:
    return isinstance(storage_uri, str) and storage_uri.startswith(REDIS_BACKED_RATE_LIMIT_SCHEMES)


def _redact_uri_for_log(uri: str | None) -> str:
    """Redact credentials from connection/storage URIs before logging."""
    if not uri:
        return ""
    raw = str(uri)
    try:
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(raw)
        if not parts.netloc:
            return raw

        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""

        if parts.username or "@" in parts.netloc:
            user = parts.username or "user"
            netloc = f"{user}:<redacted>@{host}{port}"
        else:
            netloc = parts.netloc

        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        if "://" in raw and "@" in raw:
            scheme, rest = raw.split("://", 1)
            return f"{scheme}://<redacted>@{rest.split('@', 1)[1]}"
        return raw


limiter = Limiter(key_func=get_remote_address)


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "on"}


def _build_redis_uri(cfg: Mapping[str, Any]) -> str:
    configured_url = cfg.get("REDIS_URL") or cfg.get("REDIS_DSN") or os.getenv("REDIS_URL") or os.getenv("REDIS_DSN")
    if configured_url:
        return str(configured_url)

    host = cfg.get("REDIS_HOST") or os.getenv("REDIS_HOST") or "127.0.0.1"
    port = cfg.get("REDIS_PORT") or os.getenv("REDIS_PORT") or 6379
    db = cfg.get("REDIS_DB") if cfg.get("REDIS_DB") is not None else os.getenv("REDIS_DB", 0)
    password = cfg.get("REDIS_PASSWORD") or os.getenv("REDIS_PASSWORD")
    if password:
        return f"redis://:{password}@{host}:{port}/{db}"
    return f"redis://{host}:{port}/{db}"


def _runtime_environment(cfg: Mapping[str, Any]) -> str:
    return str(cfg.get("FLASK_ENV") or cfg.get("ENV") or os.getenv("FLASK_ENV") or "development").strip().lower()


def _rate_limit_redis_required(cfg: Mapping[str, Any]) -> bool:
    return redis_required(cfg) or _runtime_environment(cfg) in RATE_LIMIT_REDIS_REQUIRED_ENVIRONMENTS


def _rate_limit_testing(cfg: Mapping[str, Any]) -> bool:
    return _as_bool(cfg.get("TESTING"), False) or _runtime_environment(cfg) in {"test", "testing"}


def _configured_rate_limit_storage(cfg: Mapping[str, Any]) -> str:
    configured_uri = (
        cfg.get("RATELIMIT_STORAGE_URI")
        or cfg.get("RATE_LIMIT_STORAGE_URI")
        or os.getenv("RATELIMIT_STORAGE_URL")
        or os.getenv("REDIS_URL")
        or os.getenv("REDIS_DSN")
        or cfg.get("REDIS_URL")
        or cfg.get("REDIS_DSN")
    )
    if configured_uri:
        return str(configured_uri)
    if os.getenv("REDIS_HOST") or cfg.get("REDIS_HOST_EXPLICIT"):
        return _build_redis_uri(cfg)
    return "memory://"


def _validate_rate_limit_storage(storage_uri: str, cfg: Mapping[str, Any]) -> str:
    """Return a safe rate-limit storage URI or fail closed in production."""

    if _rate_limit_redis_required(cfg) and not _is_redis_backed_storage_uri(storage_uri):
        raise RuntimeError("Redis-backed rate limiting is required in staging and production")

    if storage_uri == "memory://":
        log_memory_fallback_warning("rate_limit", "missing_storage_uri")
        return storage_uri

    if storage_uri.startswith(("redis://", "rediss://", "unix://")):
        try:
            client = redis.from_url(storage_uri, socket_connect_timeout=5, socket_timeout=5)
            client.ping()
            client.close()
        except Exception as exc:
            if _rate_limit_redis_required(cfg):
                raise RuntimeError("Redis-backed rate limiting is required but Redis ping failed") from exc
            log_memory_fallback_warning("rate_limit", exc.__class__.__name__)
            return "memory://"

    return storage_uri


def init_security(app: Flask, cfg: Mapping[str, Any]) -> Limiter:
    """Initialise standard security middleware and rate limiting."""
    # Respect reverse proxy headers for TLS detection and client IP extraction.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)  # type: ignore[assignment]

    default_force_https = (
        str(cfg.get("FLASK_ENV") or os.getenv("FLASK_ENV", "development")).strip().lower() == "production"
    )
    force_https = _as_bool(cfg.get("FORCE_HTTPS"), default_force_https)
    # Allow explicit override via environment for local debugging (DEV ONLY)
    # Set DISABLE_FORCE_HTTPS=1 in the service environment to disable HTTP->HTTPS redirects.
    if os.getenv("DISABLE_FORCE_HTTPS", "").lower() in {"1", "true", "yes", "on"}:
        force_https = False
        logger.warning("DISABLE_FORCE_HTTPS set: disabling HTTPS enforcement for local debugging.")

    if not force_https and default_force_https:
        logger.warning("FORCE_HTTPS disabled while FLASK_ENV=production – ensure this is intentional before deploying.")
    elif force_https:
        logger.debug("HTTPS enforcement enabled")
    csp = {
        "default-src": "'self'",
        "img-src": "* data:",
        "style-src": "'self' 'unsafe-inline'",
        # CRITICAL: Added cdnjs.cloudflare.com and 'unsafe-eval' for Socket.IO
        "script-src": "'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com",
        # CRITICAL: Added wss: and ws: for WebSocket connections
        "connect-src": "'self' wss: ws: https: http:",
        "font-src": "'self' https://fonts.googleapis.com https://fonts.gstatic.com",
    }
    if Talisman is not None:
        hsts_enabled = bool(force_https)
        Talisman(
            app,
            force_https=force_https,
            strict_transport_security=hsts_enabled,
            strict_transport_security_preload=hsts_enabled,
            strict_transport_security_include_subdomains=hsts_enabled,
            strict_transport_security_max_age=31536000 if hsts_enabled else 0,
            frame_options=None,
            x_xss_protection=False,
            force_file_save=False,
            content_security_policy=csp,
            session_cookie_secure=True,
            session_cookie_samesite="Lax",
            referrer_policy="no-referrer",
        )
    else:
        logger.warning("flask-talisman not installed; skipping security headers setup")

    init_rate_limiter(app, cfg)

    log_level = str(cfg.get("LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, log_level, logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    if not any(isinstance(handler, logging.StreamHandler) for handler in root_logger.handlers):
        handler = logging.StreamHandler()
        fmt = (
            '{"level":"%(levelname)s","msg":"%(message)s","name":"%(name)s","path":"%(pathname)s",'
            '"lineno":%(lineno)d}'
        )
        handler.setFormatter(logging.Formatter(fmt))
        root_logger.addHandler(handler)

    return limiter


def init_rate_limiter(app: Flask, cfg: Mapping[str, Any] | None = None) -> Limiter:
    """Configure Flask-Limiter once, before calling its 4.1 ``init_app(app)`` API."""

    if app.extensions.get(_LIMITER_INITIALIZED_EXTENSION) is not None:
        raise RuntimeError("Rate limiter is already initialized for this application")

    runtime_cfg: Mapping[str, Any] = cfg or app.config
    enabled = _as_bool(runtime_cfg.get("RATE_LIMIT_ENABLED", runtime_cfg.get("RATELIMIT_ENABLED")), True)
    default_limit = str(runtime_cfg.get("RATELIMIT_DEFAULT") or runtime_cfg.get("RATE_LIMIT_DEFAULT") or "100/hour")

    if _rate_limit_testing(runtime_cfg):
        storage_uri = "memory://"
        app.config["RATELIMIT_KEY_PREFIX"] = f"test-{uuid.uuid4()}"
    else:
        storage_uri = _configured_rate_limit_storage(runtime_cfg)
        if enabled:
            storage_uri = _validate_rate_limit_storage(storage_uri, runtime_cfg)

    app.config["RATELIMIT_ENABLED"] = enabled
    app.config["RATELIMIT_STORAGE_URI"] = storage_uri
    app.config["RATELIMIT_DEFAULT"] = default_limit
    app.config["RATELIMIT_STRATEGY"] = "fixed-window"
    app.config["RATELIMIT_IN_MEMORY_FALLBACK_ENABLED"] = False

    # Flask-Limiter 4.1 accepts only the application here. All policy is in
    # app.config before this one initialization call.
    limiter.init_app(app)
    app.extensions[_LIMITER_INITIALIZED_EXTENSION] = limiter

    logger.info(
        "Rate limiter initialized with %s storage (limit: %s), enabled=%s",
        _redact_uri_for_log(storage_uri),
        default_limit,
        enabled,
    )
    return limiter


def exempt_liveness_endpoints(app: Flask) -> dict[str, str]:
    """Exempt uniquely owned liveness routes after registration."""

    owners: dict[str, list[str]] = {path: [] for path in _LIVENESS_PATHS}
    for rule in app.url_map.iter_rules():
        if rule.rule in owners and "GET" in rule.methods:
            owners[rule.rule].append(rule.endpoint)

    invalid = {path: endpoints for path, endpoints in owners.items() if len(endpoints) != 1}
    if invalid:
        raise RuntimeError(f"Liveness route ownership must be unique: {invalid}")

    resolved: dict[str, str] = {}
    for path, endpoints in owners.items():
        endpoint = endpoints[0]
        limiter.exempt(app.view_functions[endpoint])
        resolved[path] = endpoint

    # Preserve the existing screensaver/public-status polling policy, but do
    # it only after route registration rather than during security bootstrap.
    status_owners = [
        rule.endpoint for rule in app.url_map.iter_rules() if rule.rule == _PUBLIC_STATUS_PATH and "GET" in rule.methods
    ]
    if len(status_owners) > 1:
        raise RuntimeError(f"Public status route ownership must be unique: {status_owners}")
    if status_owners:
        limiter.exempt(app.view_functions[status_owners[0]])
    return resolved
