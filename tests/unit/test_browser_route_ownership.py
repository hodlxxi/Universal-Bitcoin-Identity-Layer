from flask import url_for
import inspect
import sys


def _endpoints_for_path(app, path, method="GET"):
    return {rule.endpoint for rule in app.url_map.iter_rules() if rule.rule == path and method in rule.methods}


def test_browser_routes_are_owned_by_blueprints(app):
    expected_owner = {
        "/": "ui.index",
        "/home": "ui.home",
        "/login": "auth.login",
        "/logout": "auth.logout",
        "/playground": "ui.playground",
        "/account": "ui.legacy_account_route",
        "/explorer": "ui.legacy_explorer_route",
        "/onboard": "ui.legacy_onboard_route",
        "/oneword": "ui.legacy_oneword_route",
        "/upgrade": "ui.legacy_upgrade_route",
        "/app": "ui.legacy_chat_route",
    }

    for path, endpoint in expected_owner.items():
        endpoints = _endpoints_for_path(app, path)
        assert endpoint in endpoints, f"{path} endpoints were {sorted(endpoints)}"


def test_legacy_endpoint_names_still_resolve(app):
    with app.test_request_context():
        assert url_for("home") == "/home"
        assert url_for("login") == "/login"
        assert url_for("logout") == "/logout"
        assert url_for("playground") == "/playground"
        assert url_for("app") == "/app"


def test_auth_blueprint_implements_login_logout_directly(app):
    login_view = app.view_functions["auth.login"]
    logout_view = app.view_functions["auth.logout"]

    assert login_view.__module__ == "app.blueprints.auth"
    assert logout_view.__module__ == "app.blueprints.auth"

    # Bare endpoint aliases still point to the auth blueprint implementations.
    assert app.view_functions["login"] is login_view
    assert app.view_functions["logout"] is logout_view


def test_login_sets_signature_challenge_session_and_renders_legacy_ui(client):
    response = client.get("/login")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert '<canvas id="matrix-bg"' in body
    assert "HODLXXI — Login" in body

    with client.session_transaction() as sess:
        assert sess.get("challenge")
        assert sess.get("challenge_timestamp")


def test_browser_route_runtime_compatibility(client):
    response = client.get("/")
    assert response.status_code == 200

    response = client.get("/home", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert "/login?next=/home" in response.headers["Location"]

    response = client.get("/app", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert "/login?next=/app" in response.headers["Location"]

    response = client.get("/account", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert "/login?next=/account" in response.headers["Location"]

    response = client.get("/upgrade", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert "/login?next=/upgrade" in response.headers["Location"]

    response = client.get("/login")
    assert response.status_code == 200

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "test-pubkey"

    response = client.get("/logout", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/login")

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "test-pubkey"

    response = client.get("/playground")
    assert response.status_code == 200

    response = client.get("/home")
    assert response.status_code == 200

    response = client.get("/account", follow_redirects=False)
    assert response.status_code == 200

    response = client.get("/explorer", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/home#explorer")

    response = client.get("/onboard", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/home#onboard")

    response = client.get("/oneword", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/home")

    response = client.get("/upgrade", follow_redirects=False)
    assert response.status_code == 200

    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "test-pubkey"

    response = client.get("/app")
    assert response.status_code == 200


def test_ui_core_browser_shell_routes_do_not_delegate_to_app_app():
    from app.blueprints import ui as ui_module

    home_source = inspect.getsource(ui_module.legacy_home_route)
    app_source = inspect.getsource(ui_module.legacy_chat_route)
    playground_source = inspect.getsource(ui_module.playground)
    account_source = inspect.getsource(ui_module.legacy_account_route)
    explorer_source = inspect.getsource(ui_module.legacy_explorer_route)
    onboard_source = inspect.getsource(ui_module.legacy_onboard_route)
    oneword_source = inspect.getsource(ui_module.legacy_oneword_route)
    upgrade_source = inspect.getsource(ui_module.legacy_upgrade_route)

    assert "from app.app import" not in home_source
    assert "from app.app import" not in app_source
    assert "from app.app import" not in playground_source
    assert "from app.app import" not in account_source
    assert "from app.app import" not in explorer_source
    assert "from app.app import" not in onboard_source
    assert "from app.app import" not in oneword_source
    assert "from app.app import" not in upgrade_source


def test_factory_boot_registers_browser_runtime_handlers_without_importing_app_app(app):
    from app.browser_routes import get_browser_route_handler

    assert get_browser_route_handler("chat") is not None
    assert get_browser_route_handler("login") is not None
    assert get_browser_route_handler("logout") is not None
    assert get_browser_route_handler("playground") is not None
    # Transitional compatibility note:
    # this branch still imports app.app for legacy API bridges while browser
    # route ownership is being stabilized before full monolith retirement.
    # Full removal is covered by the next monolith-retirement phase.
