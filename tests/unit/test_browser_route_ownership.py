from flask import url_for


def _endpoints_for_path(app, path, method="GET"):
    return {
        rule.endpoint
        for rule in app.url_map.iter_rules()
        if rule.rule == path and method in rule.methods
    }


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


def test_browser_route_runtime_compatibility(client):
    response = client.get("/")
    assert response.status_code == 200

    response = client.get("/home")
    assert response.status_code == 200

    response = client.get("/login")
    assert response.status_code == 200

    response = client.get("/logout", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/login")

    response = client.get("/playground")
    assert response.status_code == 200

    response = client.get("/account", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert "/login?next=/account" in response.headers["Location"]

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
    assert response.status_code in (302, 303)
    assert "/login?next=/upgrade" in response.headers["Location"]

    response = client.get("/app")
    assert response.status_code == 200
