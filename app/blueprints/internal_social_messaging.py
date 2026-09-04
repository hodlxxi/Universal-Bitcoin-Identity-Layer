"""Private, disabled-by-default Social messaging device-key routes."""

from __future__ import annotations

from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
)

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
from app.services.social_messaging_device_binding_registry import (
    DeviceBindingRegistryUnavailable,
)
from app.services.social_messaging_internal_delivery import (
    MESSAGING_SERVICE_SCOPE,
    MessagingEntitlementDenied,
    MessagingEntitlementUnavailable,
    MessagingViewerCredentialDenied,
    configured_social_messaging_internal_delivery_runtime,
)


CLIENT_ASSERTION_TYPE = (
    "urn:ietf:params:oauth:"
    "client-assertion-type:jwt-bearer"
)

SERVICE_TOKEN_ROUTE = (
    "/internal/v1/social/messaging/service-token"
)

DEVICE_BINDINGS_ROUTE = (
    "/internal/v1/social/messaging/device-bindings"
)

VIEWER_AUTHORIZATION_HEADER = (
    "X-HODLXXI-Viewer-Authorization"
)

MAX_STATEMENT_BYTES = 8192


internal_social_messaging_bp = Blueprint(
    "internal_social_messaging",
    __name__,
)


def _runtime():
    return (
        configured_social_messaging_internal_delivery_runtime(
            current_app
        )
    )


def _no_store(response):
    response.headers[
        "Cache-Control"
    ] = "no-store"

    response.headers[
        "Pragma"
    ] = "no-cache"

    return response


def _json_error(
    error: str,
    status: int,
):
    response = jsonify(
        {"error": error}
    )

    response.status_code = status

    return _no_store(response)


def _service(runtime):
    try:
        token = parse_bearer_authorization_header(
            request.headers.get(
                "Authorization",
                "",
            )
        )

        return runtime.verify_service_authority(
            token
        )

    except (
        BearerHeaderError,
        CredentialDenied,
    ):
        raise CredentialDenied(
            "credential denied"
        ) from None


def _viewer_token():
    try:
        return parse_bearer_authorization_header(
            request.headers.get(
                VIEWER_AUTHORIZATION_HEADER,
                "",
            )
        )

    except BearerHeaderError:
        raise MessagingViewerCredentialDenied() from None


@internal_social_messaging_bp.post(
    SERVICE_TOKEN_ROUTE
)
def issue_internal_social_messaging_service_token():
    runtime = _runtime()

    if runtime is None:
        return _json_error(
            "not_found",
            404,
        )

    if (
        request.mimetype
        != "application/x-www-form-urlencoded"
    ):
        return _json_error(
            "invalid_request",
            400,
        )

    required = {
        "grant_type",
        "client_id",
        "client_assertion_type",
        "client_assertion",
        "scope",
    }

    if (
        set(request.form) != required
        or any(
            len(
                request.form.getlist(name)
            ) != 1
            for name in required
        )
    ):
        return _json_error(
            "invalid_request",
            400,
        )

    if (
        request.form["grant_type"]
        != GRANT_TYPE
        or request.form["client_id"]
        != runtime.service_config.client_id
        or request.form[
            "client_assertion_type"
        ]
        != CLIENT_ASSERTION_TYPE
        or request.form["scope"]
        != MESSAGING_SERVICE_SCOPE
    ):
        return _json_error(
            "invalid_client",
            401,
        )

    try:
        token = runtime.issue_service_token(
            request.form[
                "client_assertion"
            ]
        )

    except CredentialDenied:
        return _json_error(
            "invalid_client",
            401,
        )

    except CredentialUnavailable:
        return _json_error(
            "temporarily_unavailable",
            503,
        )

    except Exception:
        return _json_error(
            "temporarily_unavailable",
            503,
        )

    response = jsonify(
        {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": (
                MAX_LIFETIME_SECONDS
            ),
            "scope": (
                MESSAGING_SERVICE_SCOPE
            ),
        }
    )

    return _no_store(response)


@internal_social_messaging_bp.get(
    DEVICE_BINDINGS_ROUTE
)
def read_own_social_messaging_device_bindings():
    runtime = _runtime()

    if runtime is None:
        return _json_error(
            "not_found",
            404,
        )

    if (
        request.args
        or request.content_length
        not in (None, 0)
    ):
        return _json_error(
            "invalid_request",
            400,
        )

    try:
        service = _service(runtime)

    except CredentialDenied:
        return _json_error(
            "invalid_token",
            401,
        )

    try:
        viewer_token = _viewer_token()

        result = (
            runtime.current_devices_for_service(
                service,
                viewer_token,
            )
        )

    except MessagingViewerCredentialDenied:
        return _json_error(
            "invalid_viewer_credential",
            401,
        )

    except MessagingEntitlementDenied:
        return _json_error(
            "insufficient_entitlement",
            403,
        )

    except MessagingEntitlementUnavailable:
        return _json_error(
            "entitlement_unavailable",
            503,
        )

    except DeviceBindingRegistryUnavailable:
        return _json_error(
            "device_binding_unavailable",
            503,
        )

    except Exception:
        return _json_error(
            "device_binding_unavailable",
            503,
        )

    return _no_store(
        jsonify(result)
    )


@internal_social_messaging_bp.post(
    DEVICE_BINDINGS_ROUTE
)
def apply_own_social_messaging_device_binding():
    runtime = _runtime()

    if runtime is None:
        return _json_error(
            "not_found",
            404,
        )

    try:
        service = _service(runtime)

    except CredentialDenied:
        return _json_error(
            "invalid_token",
            401,
        )

    try:
        viewer_token = _viewer_token()

    except MessagingViewerCredentialDenied:
        return _json_error(
            "invalid_viewer_credential",
            401,
        )

    if (
        request.args
        or request.mimetype
        != "application/json"
    ):
        return _json_error(
            "invalid_request",
            400,
        )

    raw = request.get_data(
        cache=False
    )

    if (
        not raw
        or len(raw)
        > MAX_STATEMENT_BYTES
    ):
        return _json_error(
            "invalid_request",
            400,
        )

    try:
        payload = raw.decode(
            "ascii",
            errors="strict",
        )

    except UnicodeDecodeError:
        return _json_error(
            "invalid_request",
            400,
        )

    try:
        result = (
            runtime.apply_device_statement_for_service(
                service,
                viewer_token,
                payload,
            )
        )

    except MessagingViewerCredentialDenied:
        return _json_error(
            "invalid_viewer_credential",
            401,
        )

    except MessagingEntitlementDenied:
        return _json_error(
            "insufficient_entitlement",
            403,
        )

    except MessagingEntitlementUnavailable:
        return _json_error(
            "entitlement_unavailable",
            503,
        )

    except DeviceBindingRegistryUnavailable:
        return _json_error(
            "device_binding_unavailable",
            503,
        )

    except Exception:
        return _json_error(
            "device_binding_unavailable",
            503,
        )

    return _no_store(
        jsonify(result)
    )


__all__ = [
    "CLIENT_ASSERTION_TYPE",
    "DEVICE_BINDINGS_ROUTE",
    "SERVICE_TOKEN_ROUTE",
    "VIEWER_AUTHORIZATION_HEADER",
    "internal_social_messaging_bp",
]
