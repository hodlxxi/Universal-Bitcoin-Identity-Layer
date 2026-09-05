from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from flask import Flask

from app.blueprints import internal_social_messaging_device as routes
from app.services.confidential_service_credentials import CredentialDenied
from app.services.social_messaging_device_contract import (
    MessagingDeviceAuthorityUnavailable,
    MessagingDeviceRequestInvalid,
)
from app.services.social_messaging_device_internal_delivery import (
    MESSAGING_DEVICE_SCOPE,
    MessagingViewerCredentialDenied,
    MessagingViewerEntitlementDenied,
    MessagingViewerEntitlementUnavailable,
)

SERVICE_TOKEN = "service-token"
VIEWER_TOKEN = "viewer-token"
ASSERTION = "client-assertion"
STATEMENT = json.dumps(
    {
        "schema": "hodlxxi.social_messaging_device_binding_command.v1",
        "version": 1,
        "operation": "register",
        "deviceId": "11" * 32,
        "algorithm": "x25519-v1",
        "publicKey": "22" * 32,
        "expectedBindingId": None,
        "requestId": "33" * 32,
    },
    separators=(",", ":"),
)

SNAPSHOT = {
    "schema": "hodlxxi.social_messaging_device_binding_snapshot.v1",
    "version": 1,
    "source": "hodlxxi-ubid",
    "snapshotId": "sha256:" + "44" * 32,
    "complete": True,
    "issuedAt": 2_000_000_000_000,
    "expiresAt": 2_000_000_300_000,
    "activeDevices": [],
}

RESULT = {
    "schema": "hodlxxi.social_messaging_device_binding_result.v1",
    "version": 1,
    "operation": "register",
    "device": {
        "deviceId": "11" * 32,
        "bindingId": "55" * 32,
        "algorithm": "x25519-v1",
        "version": 1,
        "publicKey": "22" * 32,
        "validFrom": "2033-05-18T03:33:20Z",
        "expiresAt": "2033-06-17T03:33:20Z",
    },
}


class Runtime:
    def __init__(self):
        self.service_config = SimpleNamespace(client_id="social-confidential-backend")
        self.calls = []
        self.token = "issued-service-token"
        self.service = object()
        self.current_result = SNAPSHOT
        self.apply_result = RESULT
        self.service_error = None
        self.viewer_error = None

    def issue_service_token(self, assertion):
        self.calls.append(("issue", assertion))
        return self.token

    def verify_service_authority(self, token):
        self.calls.append(("verify-service", token))
        if self.service_error is not None:
            raise self.service_error
        return self.service

    def current_for_service(self, service, viewer_token):
        self.calls.append(("current", service, viewer_token))
        if self.viewer_error is not None:
            raise self.viewer_error
        return self.current_result

    def apply_for_service(self, service, viewer_token, statement):
        self.calls.append(("apply", service, viewer_token, statement))
        if self.viewer_error is not None:
            raise self.viewer_error
        return self.apply_result


def client():
    app = Flask(__name__)
    app.config.update(TESTING=True)
    app.register_blueprint(routes.internal_social_messaging_device_bp)
    return app.test_client()


def headers(*, service=SERVICE_TOKEN, viewer=VIEWER_TOKEN):
    return {
        "Authorization": f"Bearer {service}",
        routes.VIEWER_AUTHORIZATION_HEADER: f"Bearer {viewer}",
    }


def token_form(*, scope=MESSAGING_DEVICE_SCOPE):
    return {
        "grant_type": "client_credentials",
        "client_id": "social-confidential-backend",
        "client_assertion_type": routes.CLIENT_ASSERTION_TYPE,
        "client_assertion": ASSERTION,
        "scope": scope,
    }


def assert_no_store(response):
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_routes_are_404_when_runtime_is_absent():
    http = client()
    for method, path, kwargs in (
        ("post", routes.SERVICE_TOKEN_ROUTE, {"data": token_form()}),
        ("get", routes.DEVICE_BINDINGS_ROUTE, {}),
        (
            "post",
            routes.DEVICE_BINDINGS_ROUTE,
            {"data": STATEMENT, "content_type": "application/json"},
        ),
    ):
        response = getattr(http, method)(path, **kwargs)
        assert response.status_code == 404
        assert response.get_json() == {"error": "not_found"}
        assert_no_store(response)


def test_service_token_route_requires_exact_form_and_scope(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    response = http.post(routes.SERVICE_TOKEN_ROUTE, data=token_form())
    assert response.status_code == 200
    assert response.get_json() == {
        "access_token": "issued-service-token",
        "token_type": "Bearer",
        "expires_in": 60,
        "scope": MESSAGING_DEVICE_SCOPE,
    }
    assert runtime.calls == [("issue", ASSERTION)]
    assert_no_store(response)

    bad = http.post(
        routes.SERVICE_TOKEN_ROUTE,
        data=token_form(scope="social:full-directory:read"),
    )
    assert bad.status_code == 401
    assert bad.get_json() == {"error": "invalid_client"}

    extra = token_form()
    extra["unexpected"] = "value"
    bad = http.post(routes.SERVICE_TOKEN_ROUTE, data=extra)
    assert bad.status_code == 400
    assert bad.get_json() == {"error": "invalid_request"}


def test_get_requires_service_then_viewer_and_returns_snapshot(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    missing_service = http.get(routes.DEVICE_BINDINGS_ROUTE)
    assert missing_service.status_code == 401
    assert missing_service.get_json() == {"error": "invalid_token"}
    assert runtime.calls == []

    missing_viewer = http.get(
        routes.DEVICE_BINDINGS_ROUTE,
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
    )
    assert missing_viewer.status_code == 401
    assert missing_viewer.get_json() == {"error": "invalid_viewer_credential"}
    assert runtime.calls == [("verify-service", SERVICE_TOKEN)]

    runtime.calls.clear()
    response = http.get(routes.DEVICE_BINDINGS_ROUTE, headers=headers())
    assert response.status_code == 200
    assert response.get_json() == SNAPSHOT
    assert runtime.calls == [
        ("verify-service", SERVICE_TOKEN),
        ("current", runtime.service, VIEWER_TOKEN),
    ]
    assert_no_store(response)


def test_post_forwards_exact_ascii_statement_after_both_credentials(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    response = http.post(
        routes.DEVICE_BINDINGS_ROUTE,
        data=STATEMENT,
        content_type="application/json",
        headers=headers(),
    )
    assert response.status_code == 200
    assert response.get_json() == RESULT
    assert runtime.calls == [
        ("verify-service", SERVICE_TOKEN),
        ("apply", runtime.service, VIEWER_TOKEN, STATEMENT),
    ]
    assert_no_store(response)


@pytest.mark.parametrize(
    ("error", "status", "body"),
    [
        (
            MessagingDeviceRequestInvalid(),
            400,
            {"error": "invalid_request"},
        ),
        (
            MessagingDeviceAuthorityUnavailable(),
            503,
            {"error": "device_authority_unavailable"},
        ),
    ],
)
def test_post_distinguishes_invalid_request_from_authority_unavailable(
    monkeypatch,
    error,
    status,
    body,
):
    runtime = Runtime()
    runtime.viewer_error = error
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    response = http.post(
        routes.DEVICE_BINDINGS_ROUTE,
        data=STATEMENT,
        content_type="application/json",
        headers=headers(),
    )

    assert response.status_code == status
    assert response.get_json() == body
    assert_no_store(response)


@pytest.mark.parametrize(
    ("error", "status", "body"),
    [
        (
            MessagingViewerCredentialDenied(),
            401,
            {"error": "invalid_viewer_credential"},
        ),
        (
            MessagingViewerEntitlementDenied(),
            403,
            {"error": "insufficient_entitlement"},
        ),
        (
            MessagingViewerEntitlementUnavailable(),
            503,
            {"error": "device_authority_unavailable"},
        ),
        (
            MessagingDeviceAuthorityUnavailable(),
            503,
            {"error": "device_authority_unavailable"},
        ),
    ],
)
def test_viewer_and_authority_failures_are_fail_closed(
    monkeypatch,
    error,
    status,
    body,
):
    runtime = Runtime()
    runtime.viewer_error = error
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    response = http.get(routes.DEVICE_BINDINGS_ROUTE, headers=headers())
    assert response.status_code == status
    assert response.get_json() == body
    assert_no_store(response)


def test_service_verification_failure_never_reaches_viewer(monkeypatch):
    runtime = Runtime()
    runtime.service_error = CredentialDenied("credential denied")
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    response = http.get(routes.DEVICE_BINDINGS_ROUTE, headers=headers())
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_token"}
    assert runtime.calls == [("verify-service", SERVICE_TOKEN)]


def test_post_rejects_non_ascii_or_oversized_body_before_authority(monkeypatch):
    runtime = Runtime()
    monkeypatch.setattr(routes, "_runtime", lambda: runtime)
    http = client()

    non_ascii = http.post(
        routes.DEVICE_BINDINGS_ROUTE,
        data=b'{"x":"\xff"}',
        content_type="application/json",
        headers=headers(),
    )
    assert non_ascii.status_code == 400
    assert non_ascii.get_json() == {"error": "invalid_request"}

    oversized = http.post(
        routes.DEVICE_BINDINGS_ROUTE,
        data="x" * 8193,
        content_type="application/json",
        headers=headers(),
    )
    assert oversized.status_code == 400
    assert oversized.get_json() == {"error": "invalid_request"}

    assert not any(call[0] == "apply" for call in runtime.calls)
