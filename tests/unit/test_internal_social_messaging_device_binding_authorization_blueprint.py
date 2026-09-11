from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from flask import Flask, Request
from werkzeug.datastructures import MultiDict

from app.blueprints import internal_social_messaging_device_binding_authorization as routes
from app.services.confidential_service_credentials import CredentialDenied
from app.services.social_messaging_device_binding_authorization import DeviceBindingAuthorizationUnavailable
from app.services.social_messaging_device_binding_authorization_runtime import (
    MESSAGING_DEVICE_AUTHORIZATION_SCOPE,
    MessagingDeviceBindingAuthorizationViewerDenied,
)

SERVICE_TOKEN = "service-token"
VIEWER_TOKEN = "viewer-token"
INTENT_TOKEN = "a.b.c"
ASSERTION = "client-assertion"
PAYLOAD = json.dumps(
    {
        "operation": "register",
        "schema": "hodlxxi.social_messaging_device_binding_authorization.v1",
    },
    sort_keys=True,
    separators=(",", ":"),
)
RESULT = b'{"action":"register","schema":"hodlxxi.social_messaging_device_binding_authorization_result.v1"}'
INTENT_PROPOSAL = json.dumps(
    {
        "deviceId": "22" * 32,
        "expectedBindingId": None,
        "operation": "register",
        "publicKey": "09" + "00" * 31,
        "requestId": "33" * 32,
    },
    sort_keys=True,
    separators=(",", ":"),
)
INTENT_RESULT = b'{"schema":"hodlxxi.social_messaging_device_binding_authorization_intent.v1"}'


class Runtime:
    def __init__(self):
        self.service_config = SimpleNamespace(client_id="social-binding-authorization")
        self.service = object()
        self.calls = []
        self.error = None

    def issue_service_token(self, assertion):
        self.calls.append(("issue", assertion))
        return "issued-service-token"

    def verify_service_authority(self, token):
        self.calls.append(("service", token))
        if self.error is not None:
            raise self.error
        return self.service

    def authorize_for_service(self, service, viewer_token, payload, intent_token):
        self.calls.append(("authorize", service, viewer_token, payload, intent_token))
        if self.error is not None:
            raise self.error
        return RESULT

    def create_intent_for_service(self, service, viewer_token, payload):
        self.calls.append(("intent", service, viewer_token, payload))
        if self.error is not None:
            raise self.error
        return INTENT_RESULT


def client():
    app = Flask(__name__)
    app.config.update(TESTING=True)
    app.register_blueprint(routes.internal_social_messaging_device_binding_authorization_bp)
    return app.test_client()


def headers(*, service=SERVICE_TOKEN, viewer=VIEWER_TOKEN):
    return {
        "Authorization": f"Bearer {service}",
        routes.VIEWER_AUTHORIZATION_HEADER: f"Bearer {viewer}",
        routes.INTENT_TOKEN_HEADER: INTENT_TOKEN,
    }


def token_form(**changes):
    values = {
        "grant_type": "client_credentials",
        "client_id": "social-binding-authorization",
        "client_assertion_type": routes.CLIENT_ASSERTION_TYPE,
        "client_assertion": ASSERTION,
        "scope": MESSAGING_DEVICE_AUTHORIZATION_SCOPE,
    }
    values.update(changes)
    return values


def assert_no_store(response):
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_routes_are_absent_without_the_dedicated_runtime():
    http = client()
    for path, kwargs in (
        (routes.SERVICE_TOKEN_ROUTE, {"data": token_form()}),
        (
            routes.AUTHORIZATIONS_ROUTE,
            {"data": PAYLOAD, "content_type": "application/json", "headers": headers()},
        ),
        (
            routes.AUTHORIZATION_INTENTS_ROUTE,
            {"data": PAYLOAD, "content_type": "application/json", "headers": headers()},
        ),
    ):
        response = http.post(path, **kwargs)
        assert response.status_code == 404
        assert response.get_json() == {"error": "not_found"}
        assert_no_store(response)


def test_service_token_route_uses_exact_confidential_service_form(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    response = http.post(routes.SERVICE_TOKEN_ROUTE, data=token_form())
    assert response.status_code == 200
    assert response.get_json() == {
        "access_token": "issued-service-token",
        "token_type": "Bearer",
        "expires_in": 60,
        "scope": MESSAGING_DEVICE_AUTHORIZATION_SCOPE,
    }
    assert runtime.calls == [("issue", ASSERTION)]
    assert_no_store(response)

    bad = http.post(routes.SERVICE_TOKEN_ROUTE, data=token_form(scope="social:messaging-device:manage"))
    assert bad.status_code == 401
    assert bad.get_json() == {"error": "invalid_client"}

    extra = token_form(unexpected="value")
    bad = http.post(routes.SERVICE_TOKEN_ROUTE, data=extra)
    assert bad.status_code == 400
    assert bad.get_json() == {"error": "invalid_request"}


def test_service_token_boundary_rejects_query_and_invalid_lengths_before_form_parse(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()
    form_loads = []
    original_load_form_data = Request._load_form_data

    def track_form_load(request):
        form_loads.append(True)
        return original_load_form_data(request)

    monkeypatch.setattr(Request, "_load_form_data", track_form_load)
    cases = (
        {
            "path": routes.SERVICE_TOKEN_ROUTE + "?unexpected=value",
            "data": token_form(),
        },
        {
            "path": routes.SERVICE_TOKEN_ROUTE,
            "content_type": "application/x-www-form-urlencoded",
            "environ_overrides": {"CONTENT_LENGTH": ""},
        },
        {
            "path": routes.SERVICE_TOKEN_ROUTE,
            "content_type": "application/x-www-form-urlencoded",
            "environ_overrides": {"CONTENT_LENGTH": "0"},
        },
        {
            "path": routes.SERVICE_TOKEN_ROUTE,
            "data": b"x" * (routes.MAX_SERVICE_TOKEN_FORM_BYTES + 1),
            "content_type": "application/x-www-form-urlencoded",
        },
    )

    for case in cases:
        response = http.post(**case)
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_request"}
        assert_no_store(response)

    assert form_loads == []
    assert runtime.calls == []


def test_service_token_route_rejects_duplicate_fields(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()
    duplicate = MultiDict(token_form())
    duplicate.add("client_assertion", "second-assertion")

    response = http.post(routes.SERVICE_TOKEN_ROUTE, data=duplicate)

    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_request"}
    assert runtime.calls == []
    assert_no_store(response)


def test_operation_authenticates_service_before_forwarding_exact_ascii(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    response = http.post(
        routes.AUTHORIZATIONS_ROUTE,
        data=PAYLOAD,
        content_type="application/json",
        headers=headers(),
    )
    assert response.status_code == 200
    assert response.data == RESULT
    assert response.content_type == "application/json"
    assert runtime.calls == [
        ("service", SERVICE_TOKEN),
        ("authorize", runtime.service, VIEWER_TOKEN, PAYLOAD, INTENT_TOKEN),
    ]
    assert_no_store(response)


def test_intent_route_uses_same_authorities_and_forwards_only_exact_proposal(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    response = client().post(
        routes.AUTHORIZATION_INTENTS_ROUTE,
        data=INTENT_PROPOSAL,
        content_type="application/json",
        headers=headers(),
    )
    assert response.status_code == 200
    assert response.data == INTENT_RESULT
    assert runtime.calls == [
        ("service", SERVICE_TOKEN),
        ("intent", runtime.service, VIEWER_TOKEN, INTENT_PROPOSAL),
    ]
    assert_no_store(response)


def test_submission_requires_separate_bounded_intent_header(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    supplied = headers()
    supplied.pop(routes.INTENT_TOKEN_HEADER)
    response = client().post(
        routes.AUTHORIZATIONS_ROUTE,
        data=PAYLOAD,
        content_type="application/json",
        headers=supplied,
    )
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_request"}
    assert runtime.calls == [("service", SERVICE_TOKEN)]
    assert_no_store(response)

    for invalid in ("not-a-jwt", "a..c", "a" * (routes.MAX_INTENT_TOKEN_BYTES + 1)):
        runtime.calls.clear()
        supplied = headers()
        supplied[routes.INTENT_TOKEN_HEADER] = invalid
        response = client().post(
            routes.AUTHORIZATIONS_ROUTE,
            data=PAYLOAD,
            content_type="application/json",
            headers=supplied,
        )
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_request"}
        assert runtime.calls == [("service", SERVICE_TOKEN)]
        assert_no_store(response)


def test_missing_or_invalid_service_never_reaches_request_runtime(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    missing = http.post(
        routes.AUTHORIZATIONS_ROUTE,
        data=PAYLOAD,
        content_type="application/json",
    )
    assert missing.status_code == 401
    assert missing.get_json() == {"error": "invalid_token"}
    assert runtime.calls == []

    runtime.error = CredentialDenied("credential denied")
    denied = http.post(
        routes.AUTHORIZATIONS_ROUTE,
        data=PAYLOAD,
        content_type="application/json",
        headers=headers(),
    )
    assert denied.status_code == 401
    assert denied.get_json() == {"error": "invalid_token"}
    assert runtime.calls == [("service", SERVICE_TOKEN)]


def test_request_boundary_rejects_non_ascii_oversize_and_non_json(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    for data, content_type in (
        (b'{"x":"\xff"}', "application/json"),
        (b"x" * 8193, "application/json"),
        (PAYLOAD, "text/plain"),
    ):
        runtime.calls.clear()
        response = http.post(routes.AUTHORIZATIONS_ROUTE, data=data, content_type=content_type, headers=headers())
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_request"}
        assert runtime.calls == [("service", SERVICE_TOKEN)]


@pytest.mark.parametrize(
    ("error", "status", "body"),
    [
        (
            MessagingDeviceBindingAuthorizationViewerDenied(),
            401,
            {"error": "invalid_viewer_credential"},
        ),
        (
            DeviceBindingAuthorizationUnavailable(),
            503,
            {"error": "device_binding_authorization_unavailable"},
        ),
        (
            RuntimeError("sensitive database detail"),
            503,
            {"error": "device_binding_authorization_unavailable"},
        ),
    ],
)
def test_runtime_failures_are_generic_and_non_sensitive(monkeypatch, error, status, body):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()
    original_verify = runtime.verify_service_authority

    def verify(token):
        runtime.error = None
        return original_verify(token)

    runtime.verify_service_authority = verify

    def authorize(*_args):
        raise error

    runtime.authorize_for_service = authorize
    response = http.post(
        routes.AUTHORIZATIONS_ROUTE,
        data=PAYLOAD,
        content_type="application/json",
        headers=headers(),
    )
    assert response.status_code == status
    assert response.get_json() == body
    assert "sensitive" not in response.get_data(as_text=True)
    assert_no_store(response)
