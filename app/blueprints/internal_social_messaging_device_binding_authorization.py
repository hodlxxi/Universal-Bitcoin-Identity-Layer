"""Private Social routes for identity-authorized device-binding operations."""

from __future__ import annotations

from flask import Blueprint, Response, current_app, jsonify, request

from app.services.bearer_credentials import (
    DEFAULT_MAX_BEARER_LENGTH,
    BearerHeaderError,
    has_compact_jwt_shape,
    parse_bearer_authorization_header,
)
from app.services.confidential_service_credentials import (
    GRANT_TYPE,
    MAX_LIFETIME_SECONDS,
    CredentialDenied,
    CredentialUnavailable,
)
from app.services.social_messaging_device_binding_authorization import (
    MAX_AUTHORIZATION_BYTES,
    DeviceBindingAuthorizationUnavailable,
)
from app.services.social_messaging_device_binding_authorization_intent import (
    MAX_INTENT_REQUEST_BYTES,
    MAX_INTENT_TOKEN_BYTES,
)
from app.services.social_messaging_device_binding_authorization_runtime import (
    MESSAGING_DEVICE_AUTHORIZATION_SCOPE,
    MessagingDeviceBindingAuthorizationRuntime,
    MessagingDeviceBindingAuthorizationViewerDenied,
    configured_messaging_device_binding_authorization_runtime,
)

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
SERVICE_TOKEN_ROUTE = "/internal/v1/social/messaging/device-binding-authorization-service-token"
AUTHORIZATIONS_ROUTE = "/internal/v1/social/messaging/device-binding-authorizations"
AUTHORIZATION_INTENTS_ROUTE = "/internal/v1/social/messaging/device-binding-authorization-intents"
VIEWER_AUTHORIZATION_HEADER = "X-HODLXXI-Viewer-Authorization"
INTENT_TOKEN_HEADER = "X-HODLXXI-Device-Binding-Intent"
# Preserve the credential layer's 16-KiB assertion limit while allowing a
# finite envelope for the other four URL-encoded form fields.
MAX_SERVICE_TOKEN_FORM_BYTES = DEFAULT_MAX_BEARER_LENGTH + (8 * 1024)

internal_social_messaging_device_binding_authorization_bp = Blueprint(
    "internal_social_messaging_device_binding_authorization",
    __name__,
)


def _runtime() -> MessagingDeviceBindingAuthorizationRuntime | None:
    return configured_messaging_device_binding_authorization_runtime(current_app)


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _json_error(error: str, status: int):
    response = jsonify({"error": error})
    response.status_code = status
    return _no_store(response)


def _service_and_viewer(runtime: MessagingDeviceBindingAuthorizationRuntime):
    try:
        service_token = parse_bearer_authorization_header(request.headers.get("Authorization", ""))
        service = runtime.verify_service_authority(service_token)
    except (BearerHeaderError, CredentialDenied):
        return None, None, _json_error("invalid_token", 401)
    except Exception:
        return None, None, _json_error("invalid_token", 401)
    try:
        viewer_token = parse_bearer_authorization_header(request.headers.get(VIEWER_AUTHORIZATION_HEADER, ""))
    except BearerHeaderError:
        return None, None, _json_error("invalid_viewer_credential", 401)
    return service, viewer_token, None


def _canonical_ascii_body(maximum: int) -> str:
    content_length = request.content_length
    if (
        request.args
        or request.mimetype != "application/json"
        or type(content_length) is not int
        or not 1 <= content_length <= maximum
    ):
        raise ValueError
    body = request.get_data(cache=False, as_text=False)
    if type(body) is not bytes or len(body) != content_length or any(byte < 0x20 or byte > 0x7E for byte in body):
        raise ValueError
    return body.decode("ascii")


@internal_social_messaging_device_binding_authorization_bp.post(SERVICE_TOKEN_ROUTE)
def issue_internal_social_messaging_device_binding_authorization_token():
    runtime = _runtime()
    if runtime is None:
        return _json_error("not_found", 404)
    content_length = request.content_length
    if (
        request.args
        or request.mimetype != "application/x-www-form-urlencoded"
        or type(content_length) is not int
        or not 1 <= content_length <= MAX_SERVICE_TOKEN_FORM_BYTES
    ):
        return _json_error("invalid_request", 400)
    required = {
        "grant_type",
        "client_id",
        "client_assertion_type",
        "client_assertion",
        "scope",
    }
    form = request.form
    if set(form) != required or any(len(form.getlist(name)) != 1 for name in required):
        return _json_error("invalid_request", 400)
    if (
        form["grant_type"] != GRANT_TYPE
        or form["client_id"] != runtime.service_config.client_id
        or form["client_assertion_type"] != CLIENT_ASSERTION_TYPE
        or form["scope"] != MESSAGING_DEVICE_AUTHORIZATION_SCOPE
    ):
        return _json_error("invalid_client", 401)
    try:
        token = runtime.issue_service_token(form["client_assertion"])
    except CredentialDenied:
        return _json_error("invalid_client", 401)
    except Exception:
        return _json_error("temporarily_unavailable", 503)
    response = jsonify(
        {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": MAX_LIFETIME_SECONDS,
            "scope": MESSAGING_DEVICE_AUTHORIZATION_SCOPE,
        }
    )
    return _no_store(response)


@internal_social_messaging_device_binding_authorization_bp.post(AUTHORIZATIONS_ROUTE)
def authorize_internal_social_messaging_device_binding():
    runtime = _runtime()
    if runtime is None:
        return _json_error("not_found", 404)

    service, viewer_token, error = _service_and_viewer(runtime)
    if error is not None:
        return error
    try:
        payload = _canonical_ascii_body(MAX_AUTHORIZATION_BYTES)
        intent_token = request.headers.get(INTENT_TOKEN_HEADER, "")
        if (
            type(intent_token) is not str
            or not 1 <= len(intent_token) <= MAX_INTENT_TOKEN_BYTES
            or not has_compact_jwt_shape(intent_token)
        ):
            raise ValueError
    except Exception:
        return _json_error("invalid_request", 400)

    try:
        result = runtime.authorize_for_service(service, viewer_token, payload, intent_token)
    except CredentialDenied:
        return _json_error("invalid_token", 401)
    except MessagingDeviceBindingAuthorizationViewerDenied:
        return _json_error("invalid_viewer_credential", 401)
    except DeviceBindingAuthorizationUnavailable:
        return _json_error("device_binding_authorization_unavailable", 503)
    except Exception:
        return _json_error("device_binding_authorization_unavailable", 503)

    if type(result) is not bytes:
        return _json_error("device_binding_authorization_unavailable", 503)
    return _no_store(Response(result, status=200, mimetype="application/json"))


@internal_social_messaging_device_binding_authorization_bp.post(AUTHORIZATION_INTENTS_ROUTE)
def create_internal_social_messaging_device_binding_authorization_intent():
    runtime = _runtime()
    if runtime is None:
        return _json_error("not_found", 404)
    service, viewer_token, error = _service_and_viewer(runtime)
    if error is not None:
        return error
    try:
        payload = _canonical_ascii_body(MAX_INTENT_REQUEST_BYTES)
    except Exception:
        return _json_error("invalid_request", 400)
    try:
        result = runtime.create_intent_for_service(service, viewer_token, payload)
    except CredentialDenied:
        return _json_error("invalid_token", 401)
    except MessagingDeviceBindingAuthorizationViewerDenied:
        return _json_error("invalid_viewer_credential", 401)
    except DeviceBindingAuthorizationUnavailable:
        return _json_error("device_binding_authorization_unavailable", 503)
    except Exception:
        return _json_error("device_binding_authorization_unavailable", 503)
    if type(result) is not bytes:
        return _json_error("device_binding_authorization_unavailable", 503)
    return _no_store(Response(result, status=200, mimetype="application/json"))


__all__ = [
    "AUTHORIZATIONS_ROUTE",
    "AUTHORIZATION_INTENTS_ROUTE",
    "CLIENT_ASSERTION_TYPE",
    "MAX_SERVICE_TOKEN_FORM_BYTES",
    "INTENT_TOKEN_HEADER",
    "SERVICE_TOKEN_ROUTE",
    "VIEWER_AUTHORIZATION_HEADER",
    "internal_social_messaging_device_binding_authorization_bp",
]
