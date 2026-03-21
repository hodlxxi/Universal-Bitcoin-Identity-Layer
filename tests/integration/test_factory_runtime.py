from app.factory import create_app


def test_create_app_boots_successfully():
    app = create_app()
    assert app is not None
    assert app.view_functions["oauth.register_client"]


def test_wsgi_exposes_factory_created_app():
    import wsgi

    assert wsgi.app is not None
    assert wsgi.application is wsgi.app
    assert wsgi.app.import_name == create_app().import_name


def test_legacy_oauthx_routes_resolve(client):
    status = client.get("/oauthx/status")
    docs = client.get("/oauthx/docs")

    assert status.status_code == 200
    assert docs.status_code == 200
    assert status.get_json()["endpoints"]["authorize"] == "/oauth/authorize"
    assert docs.get_json()["lnurl_auth"]["POST /api/lnurl-auth/create"] == "Create LNURL session"


def test_factory_registers_legacy_compat_routes_without_duplicates(app):
    route_rules = [rule.rule for rule in app.url_map.iter_rules()]

    assert route_rules.count("/oauthx/status") == 1
    assert route_rules.count("/oauthx/docs") == 1
    assert route_rules.count("/api/account/summary") == 1
    assert route_rules.count("/api/billing/create-invoice") == 1


def test_legacy_public_status_and_docs_aliases_resolve(client):
    assert client.get("/api/public/status").status_code == 200
    assert client.get("/docs").status_code == 200
    assert client.get("/docs.json").status_code == 302
