"""Production feature gates default closed for defensive runtime surfaces."""

import pytest

_FALSEY_FLAGS = [
    "ENABLE_DEBUG_ROUTES",
    "ENABLE_DEV_ROUTES",
    "ENABLE_PUBLIC_METRICS",
    "ENABLE_PUBLIC_TURN_CREDENTIALS",
    "ENABLE_LEGACY_WALLET_ROUTES",
    "ENABLE_OAUTH_DEV_ROUTES",
]


@pytest.fixture
def production_client(monkeypatch):
    for name in _FALSEY_FLAGS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("DISABLE_FORCE_HTTPS", "1")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    import app.database as database
    import app.factory as factory

    class _DummyDB:
        def execute(self, *_args, **_kwargs):
            return None

    monkeypatch.setattr(factory, "init_all", lambda: None)
    monkeypatch.setattr(factory, "init_audit_logger", lambda: None)
    monkeypatch.setattr(database, "get_db", lambda: _DummyDB())

    app = factory.create_app()
    app.config.update(TESTING=True)
    return app.test_client()


@pytest.mark.parametrize(
    "path,method",
    [
        ("/metrics", "get"),
        ("/metrics/prometheus", "get"),
        ("/dev/dashboard", "get"),
        ("/agent/jobs/test/dev/mark_paid", "post"),
        ("/api/rpc/getblockchaininfo", "get"),
        ("/api/descriptors", "get"),
    ],
)
def test_production_defensive_surfaces_default_closed(production_client, path, method):
    response = getattr(production_client, method)(path)
    assert response.status_code in {403, 404}


@pytest.mark.parametrize(
    "path",
    [
        "/health/ready",
        "/oauth/jwks.json",
        "/.well-known/openid-configuration",
        "/api/public/status",
    ],
)
def test_core_public_surfaces_remain_available(production_client, path):
    response = production_client.get(path)
    assert response.status_code == 200


def test_config_flag_accepts_only_explicit_true_values(monkeypatch):
    from app.feature_flags import config_flag

    for value in ["1", "true", "yes", "on", " TRUE "]:
        monkeypatch.setenv("TEST_BOOLEAN_FLAG", value)
        assert config_flag("TEST_BOOLEAN_FLAG") is True

    for value in ["", "0", "false", "no", "off", "enabled"]:
        monkeypatch.setenv("TEST_BOOLEAN_FLAG", value)
        assert config_flag("TEST_BOOLEAN_FLAG") is False


def test_anonymous_full_user_wallet_product_route_is_not_public(production_client):
    response = production_client.get("/rpc/getblockchaininfo")
    assert response.status_code != 200
