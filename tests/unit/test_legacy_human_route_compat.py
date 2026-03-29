"""Route ownership contracts for post-bridge browser/UI handlers."""

from __future__ import annotations

from flask import url_for


def _rules_for_path(app, path: str):
    return [rule for rule in app.url_map.iter_rules() if str(rule) == path]


def _view_identity(app, endpoint: str):
    vf = app.view_functions.get(endpoint)
    if not vf:
        return None, None
    return getattr(vf, "__module__", None), getattr(vf, "__name__", None)


def test_factory_contains_key_human_routes(app):
    wanted = {
        "/",
        "/screensaver",
        "/home",
        "/app",
        "/login",
        "/logout",
        "/account",
        "/playground",
        "/explorer",
        "/onboard",
        "/oneword",
        "/upgrade",
    }
    seen = {str(r) for r in app.url_map.iter_rules()}
    missing = sorted(wanted - seen)
    assert not missing, f"Missing expected human routes: {missing}"


def test_important_paths_bound_to_ui_blueprint_handlers(app):
    expected = {
        "/": ("app.blueprints.ui", "index"),
        "/home": ("app.blueprints.ui", "home_route"),
        "/app": ("app.blueprints.ui", "app_route"),
        "/playground": ("app.blueprints.ui", "playground"),
        "/account": ("app.blueprints.ui", "account_route"),
        "/explorer": ("app.blueprints.ui", "explorer_route"),
        "/onboard": ("app.blueprints.ui", "onboard_route"),
        "/oneword": ("app.blueprints.ui", "oneword_route"),
        "/upgrade": ("app.blueprints.ui", "upgrade_route"),
    }

    for path, expected_view in expected.items():
        matched = _rules_for_path(app, path)
        assert matched, f"No rules found for {path}"

        resolved = {_view_identity(app, r.endpoint) for r in matched}
        assert expected_view in resolved, (
            f"{path} not bound to expected UI view {expected_view}. " f"Resolved={sorted(resolved)}"
        )


def test_legacy_human_routes_not_registered(app):
    assert "legacy_explorer_alias" not in app.view_functions
    assert "legacy_onboard_alias" not in app.view_functions
    assert "legacy_upgrade" not in app.view_functions
    assert not any(name.startswith("legacy_") for name in app.view_functions)


def test_legacy_home_url_for_alias_exists(app):
    # Legacy inline templates use url_for("home"). Keep this contract explicit.
    with app.test_request_context():
        assert url_for("ui.home") == "/home"


def test_lightweight_request_behavior_for_key_human_routes(client):
    for path in ["/", "/home", "/app", "/login", "/oneword"]:
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code in {200, 302, 401, 403}, f"Unexpected status for {path}: {resp.status_code}"

    app_resp = client.get("/app", follow_redirects=False)
    assert app_resp.headers.get("Location") != "/home#chat"

    oneword_resp = client.get("/oneword", follow_redirects=False)
    assert oneword_resp.status_code == 302
    assert oneword_resp.headers.get("Location") == "/home"


def test_login_flow_sets_challenge_session(client):
    resp = client.get("/login", follow_redirects=False)
    assert resp.status_code == 200

    with client.session_transaction() as sess:
        assert "challenge" in sess
        assert "challenge_timestamp" in sess


def test_app_route_usable_with_session_backed_access(client):
    with client.session_transaction() as sess:
        sess["logged_in_pubkey"] = "02" + "11" * 32
        sess["access_level"] = "limited"

    resp = client.get("/app", follow_redirects=False)
    assert resp.status_code in {200, 302}
    assert resp.headers.get("Location") != "/home#chat"
