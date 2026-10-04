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


def test_string_false_testing_flag_cannot_bypass_production_redis_policy():
    app = Flask(__name__)
    app.config.update(
        FLASK_ENV="production",
        TESTING="false",
        RATE_LIMIT_STORAGE_URI="memory://",
    )

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


def test_testing_rate_limiter_forces_isolated_memory_without_redis_access(monkeypatch):
    apps = [Flask("testing_limiter_one"), Flask("testing_limiter_two")]
    monkeypatch.setattr(
        security.redis,
        "from_url",
        lambda *_a, **_k: pytest.fail("testing limiter contacted Redis"),
    )

    for app in apps:
        security.init_rate_limiter(
            app,
            {
                "TESTING": True,
                "FLASK_ENV": "testing",
                "RATE_LIMIT_ENABLED": True,
                "REDIS_URL": "redis://configured-but-forbidden.invalid:6379/0",
            },
        )

    assert [app.config["RATELIMIT_STORAGE_URI"] for app in apps] == ["memory://", "memory://"]
    prefixes = [app.config["RATELIMIT_KEY_PREFIX"] for app in apps]
    assert all(prefix.startswith("test-") for prefix in prefixes)
    assert prefixes[0] != prefixes[1]


def test_init_security_uses_supported_4_1_api_after_validated_redis(monkeypatch):
    app = Flask(__name__)
    cfg = {
        "FLASK_ENV": "production",
        "RATE_LIMIT_ENABLED": True,
        "RATE_LIMIT_DEFAULT": "100/hour",
    }
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    monkeypatch.setattr(security.redis, "from_url", lambda *a, **k: FakeRedisClient())

    calls = []

    def init_app(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(security.limiter, "init_app", init_app)

    security.init_security(app, cfg)

    assert calls == [((app,), {})]
    assert app.config["RATELIMIT_STORAGE_URI"] == "redis://127.0.0.1:6379/0"
    assert app.config["RATELIMIT_DEFAULT"] == "100/hour"
    assert app.config["RATELIMIT_STRATEGY"] == "fixed-window"
    assert app.config["RATELIMIT_IN_MEMORY_FALLBACK_ENABLED"] is False


@pytest.mark.parametrize("environment", ["staging", "production"])
@pytest.mark.parametrize("uri", ["redis://127.0.0.1:6379/0", "rediss://cache.example/0", "unix:///run/redis.sock"])
def test_required_environments_accept_only_validated_redis_storage(monkeypatch, environment, uri):
    app = Flask(__name__)
    app.config.update(FLASK_ENV=environment, RATE_LIMIT_STORAGE_URI=uri)
    monkeypatch.setattr(security.redis, "from_url", lambda *a, **k: FakeRedisClient())
    calls = []

    def init_app(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(security.limiter, "init_app", init_app)

    security.init_rate_limiter(app)

    assert calls == [((app,), {})]
    assert app.config["RATELIMIT_STORAGE_URI"] == uri


def test_production_rate_limiter_accepts_explicit_managed_redis_host(monkeypatch):
    app = Flask(__name__)
    app.config.update(
        FLASK_ENV="production",
        REDIS_HOST_EXPLICIT=True,
        REDIS_HOST="cache.internal",
        REDIS_PORT=6380,
        REDIS_DB=3,
        REDIS_PASSWORD="synthetic-password",
    )
    urls = []

    def from_url(url, **_kwargs):
        urls.append(url)
        return FakeRedisClient()

    monkeypatch.setattr(security.redis, "from_url", from_url)
    monkeypatch.setattr(security.limiter, "init_app", lambda app: None)

    security.init_rate_limiter(app)

    expected = "redis://:synthetic-password@cache.internal:6380/3"
    assert urls == [expected]
    assert app.config["RATELIMIT_STORAGE_URI"] == expected


def test_production_rate_limiter_accepts_redis_dsn(monkeypatch):
    app = Flask(__name__)
    app.config.update(FLASK_ENV="production")
    monkeypatch.setenv("REDIS_DSN", "redis://cache.internal:6379/4")
    urls = []

    def from_url(url, **_kwargs):
        urls.append(url)
        return FakeRedisClient()

    monkeypatch.setattr(security.redis, "from_url", from_url)
    monkeypatch.setattr(security.limiter, "init_app", lambda app: None)

    security.init_rate_limiter(app)

    assert urls == ["redis://cache.internal:6379/4"]
    assert app.config["RATELIMIT_STORAGE_URI"] == "redis://cache.internal:6379/4"


@pytest.mark.parametrize("environment", ["staging", "production"])
@pytest.mark.parametrize("uri", ["", "memory://", "http://redis.example/0", "redis+sentinel://example/0"])
def test_required_environments_reject_non_redis_backed_schemes(monkeypatch, environment, uri):
    app = Flask(__name__)
    app.config.update(FLASK_ENV=environment, RATE_LIMIT_STORAGE_URI=uri)
    if uri == "":
        monkeypatch.delenv("REDIS_URL", raising=False)

    with pytest.raises(RuntimeError):
        security.init_rate_limiter(app)


def test_rate_limiter_refuses_second_initialization(monkeypatch):
    app = Flask(__name__)
    app.config.update(FLASK_ENV="testing", TESTING=True)
    monkeypatch.setattr(security.limiter, "init_app", lambda app: None)

    security.init_rate_limiter(app)
    with pytest.raises(RuntimeError, match="already initialized"):
        security.init_rate_limiter(app)
