"""Dynamic confidential views must work with real, enabled Flask-Limiter."""

from unittest.mock import Mock

import pytest
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_qualified_name, get_remote_address

from app.blueprints import internal_social_mobile_authorization as mobile
from app.blueprints import internal_social_session_issuance as issuance
from app.services.social_mobile_authorization_ingress_schema import VIEWER_HEADER


@pytest.fixture(params=[mobile, issuance], ids=["mobile", "session-issuance"])
def surface(request):
    module = request.param
    blueprint = (
        mobile.internal_social_mobile_authorization_bp
        if module is mobile
        else issuance.internal_social_session_issuance_bp
    )
    app = Flask(__name__)
    app.config.update(TESTING=True, RATELIMIT_ENABLED=True)
    limiter = Limiter(get_remote_address, app=app, storage_uri="memory://", default_limits=["100/minute"])
    app.register_blueprint(blueprint)
    assert limiter.enabled
    return module, blueprint, app


def command_views(surface):
    module, blueprint, app = surface
    return {command: app.view_functions[f"{blueprint.name}.{command.replace('/', '_')}"] for command in module.COMMANDS}


def test_command_metadata_is_valid_unique_and_deterministic(surface):
    module, _, _ = surface
    views = command_views(surface)
    for command, view in views.items():
        for attribute in ("__module__", "__name__", "__qualname__"):
            value = getattr(view, attribute)
            assert isinstance(value, str) and value
        assert view.__module__ == module.__name__
        assert get_qualified_name(view) == get_qualified_name(module._command_view(command))
    for attribute in ("__name__", "__qualname__"):
        assert len({getattr(view, attribute) for view in views.values()}) == len(views)


def test_each_route_dispatches_its_own_command_with_limiter(surface, monkeypatch):
    module, _, app = surface
    dispatch = Mock(side_effect=lambda command: {"command": command})
    monkeypatch.setattr(module, "_command", dispatch)
    client = app.test_client()
    for command in module.COMMANDS:
        response = client.post(module.PREFIX + "/" + command, json={})
        assert response.status_code == 200
        assert response.get_json() == {"command": command}
        dispatch.assert_called_with(command)
    assert dispatch.call_count == len(module.COMMANDS)


def request_body(module):
    return ("qr/create", {}) if module is mobile else ("resolve", {"issuanceId": "a" * 64})


def test_missing_runtime_fails_closed_with_limiter(surface):
    module, _, app = surface
    command, body = request_body(module)
    response = app.test_client().post(module.PREFIX + "/" + command, json=body)
    assert response.status_code == 404
    assert response.get_json() == {"error": "invalid_request"}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic invalid"},
        {"Authorization": "Bearer synthetic-service"},
        {"Authorization": "Bearer synthetic-service", VIEWER_HEADER: "Basic invalid"},
    ],
    ids=["missing-service", "malformed-service", "missing-viewer", "malformed-viewer"],
)
def test_credentials_fail_closed_before_authority_with_limiter(surface, monkeypatch, headers):
    module, _, app = surface
    # Only supply the runtime boundary; real request parsing must deny before execution.
    runtime = Mock()
    monkeypatch.setattr(module, "_runtime", lambda: runtime)
    command, body = request_body(module)
    response = app.test_client().post(module.PREFIX + "/" + command, json=body, headers=headers)
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_credential"}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    runtime.execute.assert_not_called()
