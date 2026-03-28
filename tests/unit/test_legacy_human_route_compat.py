"""Focused contract tests for transitional legacy human-route compatibility."""

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
        "/upgrade",
    }
    seen = {str(r) for r in app.url_map.iter_rules()}
    missing = sorted(wanted - seen)
    assert not missing, f"Missing expected human routes: {missing}"


def test_important_paths_bound_to_legacy_handlers(app):
    expected = {
        "/": ("app.app", "root_redirect"),
        "/home": ("app.app", "home_page"),
        "/app": ("app.app", "chat"),
        "/login": ("app.app", "login"),
        "/playground": ("app.app", "playground"),
    }

    for path, expected_view in expected.items():
        matched = _rules_for_path(app, path)
        assert matched, f"No rules found for {path}"

        resolved = {_view_identity(app, r.endpoint) for r in matched}
        assert expected_view in resolved, (
            f"{path} not bound to expected legacy view {expected_view}. "
            f"Resolved={sorted(resolved)}"
        )


def test_legacy_home_url_for_alias_exists(app):
    # Legacy inline templates use url_for("home"). Keep this contract explicit.
    with app.test_request_context():
        assert url_for("home") == "/home"



def test_lightweight_request_behavior_for_key_human_routes(client):
    for path in ["/", "/home", "/app", "/login"]:
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code in {200, 302, 401, 403}, (
            f"Unexpected status for {path}: {resp.status_code}"
        )
