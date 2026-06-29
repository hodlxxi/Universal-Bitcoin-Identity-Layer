import logging

import pytest
from flask import Flask

import app.database as database
import app.security as security


class FakeRedisClient:
    def __init__(self, fail=False):
        self.fail = fail
        self.closed = False

    def ping(self):
        if self.fail:
            raise RuntimeError("redis unavailable")
        return True

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def reset_redis_state(monkeypatch):
    database._redis_client = None
    for name in ("FLASK_ENV", "REDIS_URL", "REDIS_DSN", "REDIS_HOST", "RATELIMIT_STORAGE_URL"):
        monkeypatch.delenv(name, raising=False)
    yield
    database._redis_client = None


def test_production_redis_missing_config_fails_closed(monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "production")

    with pytest.raises(RuntimeError, match="no explicit Redis configuration"):
        database.init_redis()

    assert database.get_redis() is None


def test_production_redis_connection_failure_fails_closed(monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6399/0")
    monkeypatch.setattr(database.redis, "from_url", lambda *a, **k: FakeRedisClient(fail=True))

    with pytest.raises(RuntimeError, match="initialization failed"):
        database.init_redis()

    assert database.get_redis() is None


def test_non_production_redis_failure_falls_back_with_structured_warning(monkeypatch, caplog):
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6399/0")
    monkeypatch.setattr(database.redis, "from_url", lambda *a, **k: FakeRedisClient(fail=True))

    with caplog.at_level(logging.WARNING):
        database.init_redis()

    assert database.get_redis() is None
    assert any(
        record.msg == "redis.memory_fallback"
        and getattr(record, "event", None) == "redis.memory_fallback"
        and getattr(record, "surface", None) == "cache_session"
        for record in caplog.records
    )


def test_valid_redis_url_initializes_without_semantic_change(monkeypatch):
    client = FakeRedisClient()
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    monkeypatch.setattr(database.redis, "from_url", lambda *a, **k: client)

    database.init_redis()

    assert database.get_redis() is client


def test_production_rate_limiter_refuses_memory_storage(monkeypatch):
    app = Flask(__name__)
    app.config.update(FLASK_ENV="production", RATE_LIMIT_STORAGE_URI="memory://")

    with pytest.raises(RuntimeError, match="Redis-backed rate limiting is required"):
        security.init_rate_limiter(app)


def test_production_rate_limiter_refuses_redis_ping_failure(monkeypatch):
    app = Flask(__name__)
    app.config.update(FLASK_ENV="production", RATE_LIMIT_STORAGE_URI="redis://127.0.0.1:6399/0")
    monkeypatch.setattr(security.redis, "from_url", lambda *a, **k: FakeRedisClient(fail=True))

    with pytest.raises(RuntimeError, match="Redis ping failed"):
        security.init_rate_limiter(app)


def test_non_production_rate_limiter_redis_failure_uses_memory_with_warning(monkeypatch, caplog):
    app = Flask(__name__)
    app.config.update(FLASK_ENV="development", RATE_LIMIT_STORAGE_URI="redis://127.0.0.1:6399/0")
    monkeypatch.setattr(security.redis, "from_url", lambda *a, **k: FakeRedisClient(fail=True))

    with caplog.at_level(logging.WARNING):
        security.init_rate_limiter(app)

    assert any(
        record.msg == "redis.memory_fallback" and getattr(record, "surface", None) == "rate_limit"
        for record in caplog.records
    )


def test_init_security_production_allows_legacy_typeerror_after_validated_redis(monkeypatch):
    app = Flask(__name__)
    cfg = {
        "FLASK_ENV": "production",
        "RATE_LIMIT_ENABLED": True,
        "RATE_LIMIT_DEFAULT": "100/hour",
    }
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    monkeypatch.setattr(security.redis, "from_url", lambda *a, **k: FakeRedisClient())

    calls = []

    def legacy_type_error_once(*args, **kwargs):
        calls.append(kwargs)
        if kwargs:
            raise TypeError("legacy limiter signature")
        return None

    monkeypatch.setattr(security.limiter, "init_app", legacy_type_error_once)

    security.init_security(app, cfg)

    assert calls == [
        {
            "default_limits": ["100/hour"],
            "storage_uri": "redis://127.0.0.1:6379/0",
            "strategy": "fixed-window",
        },
        {},
    ]
    assert app.config["RATELIMIT_STORAGE_URI"] == "redis://127.0.0.1:6379/0"
    assert app.config["RATE_LIMIT_STORAGE_URI"] == "redis://127.0.0.1:6379/0"


@pytest.mark.parametrize("uri", ["redis://127.0.0.1:6379/0", "rediss://cache.example/0", "unix:///run/redis.sock"])
def test_rate_limit_legacy_fallback_accepts_only_redis_backed_schemes(monkeypatch, uri):
    app = Flask(__name__)
    app.config.update(FLASK_ENV="production", RATE_LIMIT_STORAGE_URI=uri)
    monkeypatch.setattr(security.redis, "from_url", lambda *a, **k: FakeRedisClient())
    calls = []

    def legacy_type_error_once(*args, **kwargs):
        calls.append(kwargs)
        if kwargs:
            raise TypeError("legacy limiter signature")
        return None

    monkeypatch.setattr(security.limiter, "init_app", legacy_type_error_once)

    security.init_rate_limiter(app)

    assert calls[-1] == {}
    assert app.config["RATELIMIT_STORAGE_URI"] == uri


@pytest.mark.parametrize("uri", ["", "memory://", "http://redis.example/0", "redis+sentinel://example/0"])
def test_rate_limit_legacy_fallback_rejects_non_redis_backed_schemes(monkeypatch, uri):
    app = Flask(__name__)
    app.config.update(FLASK_ENV="production", RATE_LIMIT_STORAGE_URI=uri)
    if uri == "":
        monkeypatch.delenv("REDIS_URL", raising=False)

    def legacy_type_error(*args, **kwargs):
        raise TypeError("legacy limiter signature")

    monkeypatch.setattr(security.limiter, "init_app", legacy_type_error)

    with pytest.raises(RuntimeError):
        security.init_rate_limiter(app)
