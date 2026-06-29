import types

import pytest


@pytest.fixture()
def production_app(monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("FLASK_DEBUG", "0")
    monkeypatch.setenv("ENABLE_LEGACY_WALLET_ROUTES", "false")
    monkeypatch.setenv("ENABLE_DEV_ROUTES", "false")
    monkeypatch.setenv("ENABLE_DEBUG_ROUTES", "false")
    monkeypatch.setenv("ENABLE_PUBLIC_METRICS", "false")
    monkeypatch.setenv("ENABLE_PUBLIC_TURN_CREDENTIALS", "false")
    monkeypatch.setenv("ENABLE_TURN_CREDENTIALS", "false")
    monkeypatch.setenv("ENABLE_METRICS", "false")

    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "")
    monkeypatch.setenv("RATELIMIT_STORAGE_URL", "memory://")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RPC_USER", "test")
    monkeypatch.setenv("RPC_PASSWORD", "test")
    monkeypatch.setenv("RPC_HOST", "127.0.0.1")
    monkeypatch.setenv("RPC_PORT", "8332")

    import app.factory as factory

    monkeypatch.setattr(factory, "init_all", lambda: None)

    app = factory.create_app()
    app.config.update(TESTING=True)
    return app


def test_explorer_pubkey_resolve_exists_when_legacy_gate_closed(production_app):
    rules = {str(rule) for rule in production_app.url_map.iter_rules()}

    assert "/api/pubkey/resolve" in rules
    assert "/new-index" not in rules
    assert "/docs2" not in rules


def test_explorer_pubkey_resolve_rejects_anonymous_without_importing_legacy(production_app, monkeypatch):
    def fail_if_called():
        raise AssertionError("legacy handler must not be imported for anonymous requests")

    monkeypatch.setitem(
        __import__("sys").modules,
        "app.app",
        types.SimpleNamespace(api_pubkey_resolve=fail_if_called),
    )

    client = production_app.test_client()
    response = client.get("/api/pubkey/resolve?ref=missing")

    assert response.status_code == 401


def test_explorer_pubkey_resolve_full_user_reaches_lazy_legacy_handler(production_app, monkeypatch):
    expected_pubkey = "02" + "a" * 64

    def fake_resolve():
        return {"pubkey": expected_pubkey}

    monkeypatch.setitem(
        __import__("sys").modules,
        "app.app",
        types.SimpleNamespace(api_pubkey_resolve=fake_resolve),
    )

    client = production_app.test_client()
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "02" + "b" * 64
        sess["access_level"] = "full"

    response = client.get("/api/pubkey/resolve?ref=testref")

    assert response.status_code == 200
    assert response.get_json()["pubkey"] == expected_pubkey
