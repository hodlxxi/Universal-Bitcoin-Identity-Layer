"""Phase 0 NIP-17 runtime contract tests (docs + policy only)."""

CRITICAL_PHASE0_ROUTES = {
    "/health/ready": {"GET"},
    "/login": {"GET"},
    "/app": {"GET"},
    "/.well-known/agent.json": {"GET"},
    "/agent/capabilities": {"GET"},
    "/agent/message": {"POST"},
}


def _rules_for_path(app, path: str):
    return [rule for rule in app.url_map.iter_rules() if rule.rule == path]


def test_phase0_critical_routes_still_exist(app):
    missing = []
    method_mismatches = []

    for path, expected_methods in CRITICAL_PHASE0_ROUTES.items():
        rules = _rules_for_path(app, path)
        if not rules:
            missing.append(path)
            continue

        found_methods = set()
        for rule in rules:
            found_methods.update(m for m in rule.methods if m not in {"HEAD", "OPTIONS"})

        if not expected_methods.issubset(found_methods):
            method_mismatches.append((path, sorted(expected_methods), sorted(found_methods)))

    assert not missing, f"missing Phase 0 contract routes: {missing}"
    assert not method_mismatches, f"Phase 0 route method mismatches: {method_mismatches}"


def test_runtime_is_factory_created_via_wsgi_app():
    import wsgi

    from app.factory import create_app

    assert hasattr(wsgi, "app")
    assert wsgi.app.import_name == create_app().import_name


def test_phase0_requires_no_nip17_runtime_flag(app):
    # Contract declaration only: no runtime behavior gate is required in Phase 0.
    assert app.config.get("NIP17_ENABLED") in (None, False, True)


def test_capability_surface_can_later_expose_nip17_metadata(client):
    response = client.get("/agent/capabilities")
    assert response.status_code == 200

    payload = response.get_json(silent=True)
    # Contract-only assertion: placeholder or absent metadata is acceptable in Phase 0.
    if isinstance(payload, dict):
        assert "nip17" not in payload or payload["nip17"] in (None, False, True, {}, [])


def test_placeholder_policy_values_are_allowed():
    placeholder_policy = {
        "phase": "0",
        "encryption_required": False,
        "relay_discovery_kind": 10050,
        "kinds": [14, 15],
    }

    assert placeholder_policy["phase"] == "0"
    assert placeholder_policy["encryption_required"] is False
    assert placeholder_policy["relay_discovery_kind"] == 10050
    assert placeholder_policy["kinds"] == [14, 15]
