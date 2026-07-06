import pytest


@pytest.fixture()
def production_app(monkeypatch):
    # Production-like closed gates. These routes must not depend on broad legacy enablement.
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("FLASK_DEBUG", "0")
    monkeypatch.setenv("ENABLE_LEGACY_WALLET_ROUTES", "false")
    monkeypatch.setenv("ENABLE_DEV_ROUTES", "false")
    monkeypatch.setenv("ENABLE_DEBUG_ROUTES", "false")
    monkeypatch.setenv("ENABLE_PUBLIC_METRICS", "false")
    monkeypatch.setenv("ENABLE_PUBLIC_TURN_CREDENTIALS", "false")
    monkeypatch.setenv("ENABLE_TURN_CREDENTIALS", "false")
    monkeypatch.setenv("ENABLE_METRICS", "false")

    # Keep this test focused on route contracts, not live infrastructure.
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


def test_full_user_product_routes_exist_when_legacy_gate_closed(production_app):
    rules = {str(rule) for rule in production_app.url_map.iter_rules()}

    assert "/verify_pubkey_and_list" in rules
    assert "/rpc/<cmd>" in rules
    assert "/export_descriptors" in rules
    assert "/import_descriptor" in rules
    assert "/set_labels_from_zpub" in rules
    assert "/api/ui/hide_manifesto" in rules


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/verify_pubkey_and_list"),
        ("GET", "/rpc/listlabels"),
        ("GET", "/export_descriptors"),
        ("POST", "/import_descriptor"),
        ("POST", "/set_labels_from_zpub"),
        ("POST", "/api/ui/hide_manifesto"),
    ],
)
def test_full_user_product_routes_reject_anonymous(production_app, method, path):
    client = production_app.test_client()
    response = client.open(path, method=method)
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/metrics"),
        ("GET", "/metrics/prometheus"),
        ("GET", "/dev/dashboard"),
    ],
)
def test_dangerous_or_debug_surfaces_remain_closed(production_app, method, path):
    client = production_app.test_client()
    response = client.open(path, method=method)
    assert response.status_code == 404


def test_unsupported_browser_rpc_is_rejected_for_full_user(production_app):
    client = production_app.test_client()
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "f" * 64
        sess["access_level"] = "full"

    response = client.get("/rpc/stop")
    assert response.status_code == 400
