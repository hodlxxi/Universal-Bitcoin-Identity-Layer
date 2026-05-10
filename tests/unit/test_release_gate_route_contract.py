from collections import defaultdict

CRITICAL_PUBLIC_ROUTES = {
    "/login": {"GET"},
    "/home": {"GET"},
    "/app": {"GET"},
    "/account": {"GET"},
    "/.well-known/agent.json": {"GET"},
    "/agent/capabilities": {"GET"},
    "/agent/capabilities/schema": {"GET"},
    "/agent/reputation": {"GET"},
    "/agent/attestations": {"GET"},
    "/agent/chain/health": {"GET"},
    "/agent/skills": {"GET"},
    "/agent/request": {"POST"},
    "/agent/jobs/<job_id>": {"GET"},
    "/agent/verify/<job_id>": {"GET"},
    "/api/public/status": {"GET"},
}


def _rules_for_path(app, path: str):
    return [rule for rule in app.url_map.iter_rules() if rule.rule == path]


def test_wsgi_runtime_is_factory_created_app():
    import wsgi

    from app.factory import create_app

    assert hasattr(wsgi, "app")
    assert wsgi.app.import_name == create_app().import_name


def test_factory_runtime_registers_critical_public_route_surface(app):
    missing = []
    method_mismatches = []

    for path, expected_methods in CRITICAL_PUBLIC_ROUTES.items():
        rules = _rules_for_path(app, path)
        if not rules:
            missing.append(path)
            continue

        found_methods = set()
        for rule in rules:
            found_methods.update(m for m in rule.methods if m not in {"HEAD", "OPTIONS"})

        if not expected_methods.issubset(found_methods):
            method_mismatches.append((path, sorted(expected_methods), sorted(found_methods)))

    assert not missing, f"missing critical routes: {missing}"
    assert not method_mismatches, f"critical method mismatches: {method_mismatches}"


def test_protected_browser_routes_remain_session_gated(client):
    for path in ("/home", "/app", "/account"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code in (302, 303)
        assert f"/login?next={path}" in response.headers["Location"]


def test_agent_discovery_and_capability_documents_exist(client):
    for path in (
        "/.well-known/agent.json",
        "/agent/capabilities",
        "/agent/capabilities/schema",
    ):
        response = client.get(path)
        assert response.status_code == 200, f"{path} expected 200, got {response.status_code}"


def test_no_duplicate_critical_route_ownership(app):
    route_methods = defaultdict(list)

    for rule in app.url_map.iter_rules():
        if rule.rule not in CRITICAL_PUBLIC_ROUTES:
            continue
        methods = {m for m in rule.methods if m not in {"HEAD", "OPTIONS"}}
        for method in methods:
            route_methods[(method, rule.rule)].append(rule.endpoint)

    duplicates = {(method, path): owners for (method, path), owners in route_methods.items() if len(owners) > 1}
    assert not duplicates, f"duplicate critical route ownership detected: {duplicates}"
