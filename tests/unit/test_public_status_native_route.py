def test_public_status_route_is_factory_native(app):
    matches = [r for r in app.url_map.iter_rules() if r.rule == "/api/public/status"]
    assert len(matches) == 1

    rule = matches[0]
    assert rule.endpoint == "public_status.api_public_status"

    view = app.view_functions[rule.endpoint]
    assert view.__module__ == "app.blueprints.public_status"


def test_lnd_status_remains_legacy_bridge_for_now(app):
    matches = [r for r in app.url_map.iter_rules() if r.rule == "/api/lnd/status"]
    assert len(matches) == 1

    rule = matches[0]
    assert rule.endpoint == "api_lnd_status"

    view = app.view_functions[rule.endpoint]
    assert view.__module__ == "app.blueprints.legacy_bridge"
