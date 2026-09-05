"""Private Social messaging-device authority routes.

The blueprint is inert unless the messaging-device runtime has been explicitly
installed in ``app.extensions``. Factory registration is handled separately.
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.services.bearer_credentials import (
    BearerHeaderError,
    parse_bearer_authorization_header,
)
from app.services.confidential_service_credentials import (
    GRANT_TYPE,
    MAX_LIFETIME_SECONDS,
    CredentialDenied,
    CredentialUnavailable,
)
from app.services.social_messaging_device_contract import (
    MAX_COMMAND_BYTES,
    MessagingDeviceAuthorityUnavailable,
    MessagingDeviceRequestInvalid,
)
from app.services.social_messaging_device_internal_delivery import (
    MESSAGING_DEVICE_SCOPE,
    MessagingDeviceInternalDeliveryRuntime,
    MessagingViewerCredentialDenied,
    MessagingViewerEntitlementDenied,
    MessagingViewerEntitlementUnavailable,
)

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
MESSAGING_DEVICE_INTERNAL_EXTENSION = "social_messaging_device_internal_delivery_v1"
SERVICE_TOKEN_ROUTE = "/internal/v1/social/messaging/service-token"
DEVICE_BINDINGS_ROUTE = "/internal/v1/social/messaging/device-bindings"
VIEWER_AUTHORIZATION_HEADER = "X-HODLXXI-Viewer-Authorization"

internal_social_messaging_device_bp = Blueprint(
    "internal_social_messaging_device",
    __name__,
)


def _runtime() -> MessagingDeviceInternalDeliveryRuntime | None:
    runtime = current_app.extensions.get(MESSAGING_DEVICE_INTERNAL_EXTENSION)
    return runtime if type(runtime) is MessagingDeviceInternalDeliveryRuntime else None


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _json_error(error: str, status: int):
    response = jsonify({"error": error})
    response.status_code = status
    return _no_store(response)


def _service_authority(runtime: MessagingDeviceInternalDeliveryRuntime):
    try:
        token = parse_bearer_authorization_header(request.headers.get("Authorization", ""))
        return runtime.verify_service_authority(token)
    except (BearerHeaderError, CredentialDenied):
        return None
    except Exception:
        return None


def _viewer_token() -> str | None:
    try:
        return parse_bearer_authorization_header(request.headers.get(VIEWER_AUTHORIZATION_HEADER, ""))
    except BearerHeaderError:
        return None


def _map_viewer_error(exc: Exception):
    if isinstance(exc, MessagingViewerCredentialDenied):
        return _json_error("invalid_viewer_credential", 401)
    if isinstance(exc, MessagingViewerEntitlementDenied):
        return _json_error("insufficient_entitlement", 403)
    return _json_error("device_authority_unavailable", 503)


@internal_social_messaging_device_bp.post(SERVICE_TOKEN_ROUTE)
def issue_internal_social_messaging_service_token():
    runtime = _runtime()
    if runtime is None:
        return _json_error("not_found", 404)
    if request.mimetype != "application/x-www-form-urlencoded":
        return _json_error("invalid_request", 400)

    required = {
        "grant_type",
        "client_id",
        "client_assertion_type",
        "client_assertion",
        "scope",
    }
    if set(request.form) != required or any(len(request.form.getlist(name)) != 1 for name in required):
        return _json_error("invalid_request", 400)
    if (
        request.form["grant_type"] != GRANT_TYPE
        or request.form["client_id"] != runtime.service_config.client_id
        or request.form["client_assertion_type"] != CLIENT_ASSERTION_TYPE
        or request.form["scope"] != MESSAGING_DEVICE_SCOPE
    ):
        return _json_error("invalid_client", 401)

    try:
        token = runtime.issue_service_token(request.form["client_assertion"])
    except CredentialDenied:
        return _json_error("invalid_client", 401)
    except CredentialUnavailable:
        return _json_error("temporarily_unavailable", 503)
    except Exception:
        return _json_error("temporarily_unavailable", 503)

    response = jsonify(
        {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": MAX_LIFETIME_SECONDS,
            "scope": MESSAGING_DEVICE_SCOPE,
        }
    )
    return _no_store(response)


@internal_social_messaging_device_bp.get(DEVICE_BINDINGS_ROUTE)
def read_internal_social_messaging_device_bindings():
    runtime = _runtime()
    if runtime is None:
        return _json_error("not_found", 404)
    if request.args or request.content_length not in (None, 0):
        return _json_error("invalid_request", 400)

    service = _service_authority(runtime)
    if service is None:
        return _json_error("invalid_token", 401)

    viewer_token = _viewer_token()
    if viewer_token is None:
        return _json_error("invalid_viewer_credential", 401)

    try:
        result = runtime.current_for_service(service, viewer_token)
    except CredentialDenied:
        return _json_error("invalid_token", 401)
    except (
        MessagingViewerCredentialDenied,
        MessagingViewerEntitlementDenied,
        MessagingViewerEntitlementUnavailable,
    ) as exc:
        return _map_viewer_error(exc)
    except MessagingDeviceAuthorityUnavailable:
        return _json_error("device_authority_unavailable", 503)
    except Exception:
        return _json_error("device_authority_unavailable", 503)

    return _no_store(jsonify(result))


@internal_social_messaging_device_bp.post(DEVICE_BINDINGS_ROUTE)
def mutate_internal_social_messaging_device_bindings():
    runtime = _runtime()
    if runtime is None:
        return _json_error("not_found", 404)
    if request.args or request.mimetype != "application/json":
        return _json_error("invalid_request", 400)

    content_length = request.content_length
    if type(content_length) is not int or not 1 <= content_length <= MAX_COMMAND_BYTES:
        return _json_error("invalid_request", 400)

    service = _service_authority(runtime)
    if service is None:
        return _json_error("invalid_token", 401)

    viewer_token = _viewer_token()
    if viewer_token is None:
        return _json_error("invalid_viewer_credential", 401)

    try:
        body = request.get_data(cache=False, as_text=False)
        if type(body) is not bytes or len(body) != content_length or any(byte < 0x20 or byte > 0x7E for byte in body):
            raise ValueError
        statement = body.decode("ascii")
    except Exception:
        return _json_error("invalid_request", 400)

    try:
        result = runtime.apply_for_service(
            service,
            viewer_token,
            statement,
        )
    except CredentialDenied:
        return _json_error("invalid_token", 401)
    except (
        MessagingViewerCredentialDenied,
        MessagingViewerEntitlementDenied,
        MessagingViewerEntitlementUnavailable,
    ) as exc:
        return _map_viewer_error(exc)
    except MessagingDeviceRequestInvalid:
        return _json_error("invalid_request", 400)
    except MessagingDeviceAuthorityUnavailable:
        return _json_error("device_authority_unavailable", 503)
    except Exception:
        return _json_error("device_authority_unavailable", 503)

    return _no_store(jsonify(result))


__all__ = [
    "CLIENT_ASSERTION_TYPE",
    "DEVICE_BINDINGS_ROUTE",
    "MESSAGING_DEVICE_INTERNAL_EXTENSION",
    "SERVICE_TOKEN_ROUTE",
    "VIEWER_AUTHORIZATION_HEADER",
    "internal_social_messaging_device_bp",
]
