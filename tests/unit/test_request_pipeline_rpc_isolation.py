import builtins
import os
import socket
import subprocess
import urllib.request
from pathlib import Path

import requests
from flask import Flask, jsonify
from flask.sessions import SecureCookieSession

import app.blueprints.admin as admin
import app.blueprints.auth as auth
import app.database as database
import app.factory as factory
import app.security as security
import app.utils as utils


def _route_owners(app, path):
    return [
        (frozenset(rule.methods) - {"HEAD", "OPTIONS"}, rule.endpoint)
        for rule in app.url_map.iter_rules()
        if rule.rule == path
    ]


def _fail_on_dependency_calls(monkeypatch, *, include_limiter=True):
    calls = []

    def fail(name):
        def sentinel(*_args, **_kwargs):
            calls.append(name)
            raise AssertionError(f"unexpected dependency call: {name}")

        return sentinel

    monkeypatch.setattr(admin, "get_rpc_connection", fail("bitcoin_rpc"))
    monkeypatch.setattr(auth, "get_rpc_connection", fail("auth_bitcoin_rpc"))
    monkeypatch.setattr(utils, "get_rpc_connection", fail("utils_bitcoin_rpc"))
    monkeypatch.setattr(database, "get_db", fail("database_get_db"))
    monkeypatch.setattr(database, "get_session", fail("database_get_session"))
    monkeypatch.setattr(database.sqlite3, "connect", fail("sqlite_connect"))
    monkeypatch.setattr(builtins, "open", fail("filesystem_open"))
    monkeypatch.setattr(os, "open", fail("filesystem_os_open"))
    monkeypatch.setattr(Path, "open", fail("filesystem_path_open"))
    monkeypatch.setattr(subprocess, "run", fail("subprocess"))
    monkeypatch.setattr(socket.socket, "connect", fail("socket_connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", fail("socket_connect_ex"))
    monkeypatch.setattr(socket, "create_connection", fail("socket_create_connection"))
    monkeypatch.setattr(socket, "getaddrinfo", fail("dns_getaddrinfo"))
    monkeypatch.setattr(requests.sessions.Session, "request", fail("requests_network"))
    monkeypatch.setattr(urllib.request, "urlopen", fail("urllib_network"))

    if include_limiter:
        storage = security.limiter.storage
        for name in (
            "acquire_entry",
            "acquire_sliding_window_entry",
            "get",
            "get_moving_window",
            "get_sliding_window",
            "get_window_stats",
            "hit",
            "incr",
            "test",
        ):
            if hasattr(storage, name):
                monkeypatch.setattr(storage, name, fail(f"limiter_storage_{name}"))

    return calls


def test_single_worker_queue_precondition_removed_from_factory_liveness(client, app, monkeypatch):
    assert _route_owners(app, "/health") == [(frozenset({"GET"}), "admin.health")]
    assert _route_owners(app, "/health/live") == [(frozenset({"GET"}), "admin.liveness")]
    assert _route_owners(app, "/health/ready") == [(frozenset({"GET"}), "admin.readiness")]
    assert app.config["LIVENESS_ROUTE_OWNERS"] == {
        "/health": "admin.health",
        "/health/live": "admin.liveness",
    }

    calls = _fail_on_dependency_calls(monkeypatch, include_limiter=False)
    monkeypatch.setattr(SecureCookieSession, "get", lambda *_a, **_k: calls.append("session_get"))
    monkeypatch.setattr(
        factory,
        "log_event",
        lambda *_args, **_kwargs: calls.append("request_logging"),
    )
    health = client.get("/health")
    live = client.get("/health/live")

    assert health.status_code == live.status_code == 200
    assert health.get_json()["status"] == "healthy"
    assert live.get_json() == {"status": "alive"}
    assert "rpc" not in health.get_json()
    assert calls == []


def test_social_mobile_entrypoint_preserves_exact_health_and_login_map(monkeypatch):
    cfg = factory.get_config()
    cfg.update(
        TESTING=True,
        FLASK_ENV="testing",
        RATE_LIMIT_ENABLED=True,
        SOCIAL_MOBILE_AUTHORIZATION_ENABLED=False,
        SOCIAL_SESSION_ISSUANCE_ENABLED=False,
    )
    monkeypatch.setattr(factory, "init_all", lambda: None)
    monkeypatch.setattr(factory, "init_audit_logger", lambda: None)

    app = factory.create_social_mobile_app(cfg)

    assert len(list(app.url_map.iter_rules())) == 140
    assert _route_owners(app, "/health") == [(frozenset({"GET"}), "admin.health")]
    assert _route_owners(app, "/health/live") == [(frozenset({"GET"}), "admin.liveness")]
    assert _route_owners(app, "/health/ready") == [(frozenset({"GET"}), "admin.readiness")]
    assert _route_owners(app, "/login") == [(frozenset({"GET"}), "auth.login")]


def test_enabled_social_mobile_entrypoint_preserves_exact_health_and_login_map(monkeypatch):
    from app import database as app_database
    from app.blueprints.internal_social_mobile_authorization import internal_social_mobile_authorization_bp
    from app.blueprints.internal_social_session_issuance import internal_social_session_issuance_bp
    from app.services import social_mobile_session_runtime

    cfg = factory.get_config()
    cfg.update(
        TESTING=True,
        FLASK_ENV="testing",
        RATE_LIMIT_ENABLED=True,
        SOCIAL_MOBILE_AUTHORIZATION_ENABLED=True,
        SOCIAL_SESSION_ISSUANCE_ENABLED=True,
    )
    monkeypatch.setattr(factory, "init_all", lambda: None)
    monkeypatch.setattr(factory, "init_audit_logger", lambda: None)
    engine = type("Engine", (), {"dialect": type("Dialect", (), {"name": "postgresql"})()})()
    monkeypatch.setattr(app_database, "_engine", engine)

    def install_routes(app, _cfg, *, session_factory):
        assert session_factory is app_database.get_session
        app.register_blueprint(internal_social_mobile_authorization_bp)
        app.register_blueprint(internal_social_session_issuance_bp)

    monkeypatch.setattr(
        social_mobile_session_runtime,
        "configure_social_mobile_session",
        install_routes,
    )

    app = factory.create_social_mobile_app(cfg)

    assert len(list(app.url_map.iter_rules())) == 162
    assert _route_owners(app, "/health") == [(frozenset({"GET"}), "admin.health")]
    assert _route_owners(app, "/health/live") == [(frozenset({"GET"}), "admin.liveness")]
    assert _route_owners(app, "/health/ready") == [(frozenset({"GET"}), "admin.readiness")]
    assert _route_owners(app, "/login") == [(frozenset({"GET"}), "auth.login")]


def test_liveness_exemption_bypasses_enabled_limiter_storage(monkeypatch):
    app = Flask("liveness_limiter_isolation")
    app.config.update(TESTING=True)
    security.init_rate_limiter(
        app,
        {
            "TESTING": True,
            "FLASK_ENV": "testing",
            "RATE_LIMIT_ENABLED": True,
            "RATE_LIMIT_DEFAULT": "1/minute",
        },
    )

    app.add_url_rule("/health", "health", lambda: jsonify(status="healthy"))
    app.add_url_rule("/health/live", "liveness", lambda: jsonify(status="alive"))
    app.add_url_rule(
        "/api/public/status",
        "api_public_status",
        lambda: jsonify(status="degraded"),
    )
    assert security.exempt_liveness_endpoints(app) == {
        "/health": "health",
        "/health/live": "liveness",
    }

    calls = []

    def fail(*_args, **_kwargs):
        calls.append("limiter_storage")
        raise AssertionError("liveness reached limiter storage")

    storage = security.limiter.storage
    for name in ("get_window_stats", "hit", "test"):
        if hasattr(storage, name):
            monkeypatch.setattr(storage, name, fail)

    client = app.test_client()
    assert [client.get("/health").status_code for _ in range(3)] == [200, 200, 200]
    assert [client.get("/health/live").status_code for _ in range(3)] == [200, 200, 200]
    assert [client.get("/api/public/status").status_code for _ in range(3)] == [200, 200, 200]
    assert calls == []


def test_protected_endpoint_is_actually_limited_with_testing_backend():
    app = Flask("protected_limiter_contract")
    app.config.update(TESTING=True)
    security.init_rate_limiter(
        app,
        {
            "TESTING": True,
            "FLASK_ENV": "testing",
            "RATE_LIMIT_ENABLED": True,
            "RATE_LIMIT_DEFAULT": "100/hour",
        },
    )

    @app.get("/protected")
    @security.limiter.limit("2/minute")
    def protected():
        return jsonify(ok=True)

    client = app.test_client()
    assert [client.get("/protected").status_code for _ in range(3)] == [200, 200, 429]
    assert app.config["RATELIMIT_STORAGE_URI"] == "memory://"
    assert app.config["RATELIMIT_KEY_PREFIX"].startswith("test-")


def test_factory_initializes_limiter_exactly_once_after_configuration(monkeypatch):
    cfg = factory.get_config()
    cfg.update(TESTING=True, FLASK_ENV="testing", RATE_LIMIT_ENABLED=True)
    calls = []
    original = security.limiter.init_app

    def spy(app):
        calls.append(
            {
                "app": app,
                "storage": app.config.get("RATELIMIT_STORAGE_URI"),
                "enabled": app.config.get("RATELIMIT_ENABLED"),
            }
        )
        return original(app)

    monkeypatch.setattr(security.limiter, "init_app", spy)
    monkeypatch.setattr(factory, "init_all", lambda: None)
    monkeypatch.setattr(factory, "init_audit_logger", lambda: None)

    app = factory.create_app(cfg)

    assert calls == [{"app": app, "storage": "memory://", "enabled": True}]
    backend_calls = []

    def fail(*_args, **_kwargs):
        backend_calls.append("limiter_storage")
        raise AssertionError("factory liveness reached limiter storage")

    storage = security.limiter.storage
    for name in ("get_window_stats", "hit", "test"):
        if hasattr(storage, name):
            monkeypatch.setattr(storage, name, fail)

    client = app.test_client()
    assert client.get("/health").status_code == 200
    assert client.get("/health/live").status_code == 200
    assert backend_calls == []


def test_factory_login_remains_covered_by_default_rate_limit(monkeypatch):
    cfg = factory.get_config()
    cfg.update(
        TESTING=True,
        FLASK_ENV="testing",
        RATE_LIMIT_ENABLED=True,
        RATE_LIMIT_DEFAULT="100/hour",
        RATELIMIT_DEFAULT="100/hour",
    )
    monkeypatch.setattr(factory, "init_all", lambda: None)
    monkeypatch.setattr(factory, "init_audit_logger", lambda: None)

    app = factory.create_app(cfg)
    client = app.test_client()
    statuses = [client.get("/login").status_code for _ in range(101)]

    assert statuses[:100] == [200] * 100
    assert statuses[100] == 429


def test_login_renders_challenge_and_security_contract_without_rpc(client, monkeypatch):
    calls = []

    def unavailable_rpc(*_args, **_kwargs):
        calls.append("rpc")
        raise TimeoutError("synthetic slow or failing RPC")

    monkeypatch.setattr(auth, "get_rpc_connection", unavailable_rpc)
    monkeypatch.setattr(utils, "get_rpc_connection", unavailable_rpc)

    response = client.get("/login")

    assert response.status_code == 200
    assert calls == []
    with client.session_transaction() as browser:
        challenge = browser["challenge"]
        assert browser["challenge_timestamp"] > 0
    assert challenge.encode() in response.data
    assert b"/api/public/status" in response.data
    assert b"block_height=" not in response.data
    assert b"balance=" not in response.data
    assert b"mempool=" not in response.data
    assert b"Lightning" in response.data
    assert b"Nostr" in response.data
    assert b"apple-mobile-web-app-capable" in response.data
    assert b'fetch("/api/lnurl-auth/create"' in response.data
    assert b'fetch("/api/challenge"' in response.data
    assert b"OAuth2/OIDC" in response.data
    assert response.headers.get("Cache-Control") is None
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    cookie = response.headers["Set-Cookie"]
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_readiness_keeps_database_check_without_rpc(client, monkeypatch):
    queries = []

    class Database:
        def execute(self, query):
            queries.append(query)

    monkeypatch.setattr(database, "get_db", lambda: Database())
    monkeypatch.setattr(admin, "get_rpc_connection", lambda: (_ for _ in ()).throw(AssertionError("RPC called")))

    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ready"}
    assert queries == ["SELECT 1"]


def test_readiness_failure_remains_sanitized(client, monkeypatch):
    def unavailable_database():
        raise RuntimeError("synthetic-sensitive-database-detail")

    monkeypatch.setattr(database, "get_db", unavailable_database)
    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.get_json() == {
        "status": "not_ready",
        "error": "Internal server error",
    }
    assert b"synthetic-sensitive-database-detail" not in response.data


def test_legacy_entrypoint_liveness_and_login_ownership(monkeypatch):
    monkeypatch.setenv("SOCKETIO_ASYNC_MODE", "threading")
    import app.app as legacy

    assert len(list(legacy.app.url_map.iter_rules())) == 133
    assert _route_owners(legacy.app, "/health") == [(frozenset({"GET"}), "health")]
    assert _route_owners(legacy.app, "/health/live") == [(frozenset({"GET"}), "liveness")]
    assert _route_owners(legacy.app, "/health/ready") == []
    assert _route_owners(legacy.app, "/login") == [(frozenset({"GET"}), "login")]
    assert legacy.app.config["LIVENESS_ROUTE_OWNERS"] == {
        "/health": "health",
        "/health/live": "liveness",
    }

    calls = _fail_on_dependency_calls(monkeypatch, include_limiter=False)
    monkeypatch.setattr(
        legacy,
        "get_rpc_connection",
        lambda: calls.append("legacy_bitcoin_rpc") or (_ for _ in ()).throw(AssertionError("RPC called")),
    )
    cleanup_calls = []
    monkeypatch.setattr(legacy, "cleanup_expired_data", lambda: cleanup_calls.append("cleanup"))
    visit_logs = []
    monkeypatch.setattr(legacy.app.logger, "info", lambda *_args, **_kwargs: visit_logs.append("visit_log"))
    client = legacy.app.test_client()
    session_calls = []
    limiter_calls = []
    with monkeypatch.context() as liveness_patches:
        liveness_patches.setattr(
            SecureCookieSession,
            "get",
            lambda *_a, **_k: session_calls.append("session_get"),
        )
        storage = security.limiter.storage
        for name in ("get_window_stats", "hit", "test"):
            if hasattr(storage, name):
                liveness_patches.setattr(
                    storage,
                    name,
                    lambda *_a, _name=name, **_k: limiter_calls.append(_name),
                )
        assert client.get("/health").status_code == 200
        assert client.get("/health/live").status_code == 200
    assert visit_logs == []
    assert session_calls == []
    assert limiter_calls == []
    assert cleanup_calls == []
    login = client.get("/login")
    assert login.status_code == 200
    with client.session_transaction() as browser:
        assert browser["challenge"].encode() in login.data
    assert calls == []


def test_legacy_recurring_cleanup_does_not_hold_process_open(monkeypatch):
    import app.app as legacy

    timers = []

    class FakeTimer:
        def __init__(self, interval, callback):
            self.interval = interval
            self.callback = callback
            self.daemon = False
            self.started = False
            timers.append(self)

        def start(self):
            self.started = True

    monkeypatch.setattr(legacy.threading, "Timer", FakeTimer)
    legacy.cleanup_expired_data()

    assert len(timers) == 1
    assert timers[0].interval == 60.0
    assert timers[0].callback is legacy.cleanup_expired_data
    assert timers[0].daemon is True
    assert timers[0].started is True


def test_wsgi_aliases_preserve_factory_route_ownership():
    import wsgi

    assert wsgi.application is wsgi.app
    assert len(list(wsgi.app.url_map.iter_rules())) == 140
    assert _route_owners(wsgi.app, "/health") == [(frozenset({"GET"}), "admin.health")]
    assert _route_owners(wsgi.app, "/health/live") == [(frozenset({"GET"}), "admin.liveness")]
    assert _route_owners(wsgi.app, "/health/ready") == [(frozenset({"GET"}), "admin.readiness")]
    assert _route_owners(wsgi.app, "/login") == [(frozenset({"GET"}), "auth.login")]


def test_repository_owned_liveness_monitors_use_health_live():
    expected = {
        "Dockerfile": "http://localhost:5000/health/live",
        "QUICK_DEPLOY.sh": "https://$DOMAIN/health/live",
        "QUICK_REFERENCE.md": "localhost:5000/health/live",
        "deployment/QUICK_REFERENCE.md": "/health/live",
        "deployment/deploy-production.sh": "127.0.0.1:5000/health/live",
        "docs/DEV_ONBOARDING_CHECKLIST.md": "localhost:5000/health/live",
        "docs/ops/RUNTIME_OBSERVABILITY.md": "GET /health/live",
        "scripts/hodlxxi_diagnostics.sh": '"/health/live"',
    }
    for name, marker in expected.items():
        assert marker in Path(name).read_text()

    dockerfile = Path("Dockerfile").read_text()
    deployment = Path("deployment/deploy-production.sh").read_text()
    assert "localhost:5000/health ||" not in dockerfile
    assert "127.0.0.1:5000/health |" not in deployment
