"""Private, disabled-by-default Social Full-directory delivery routes."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.services.bearer_credentials import BearerHeaderError, parse_bearer_authorization_header
from app.services.confidential_service_credentials import (
    GRANT_TYPE,
    MAX_LIFETIME_SECONDS,
    SERVICE_SCOPE,
    CredentialDenied,
    CredentialUnavailable,
)
from app.services.privacy_full_directory_internal_delivery import (
    ViewerCredentialDenied,
    configured_internal_delivery_runtime,
)
from app.services.privacy_safe_full_directory import (
    PrivacySafeFullDirectoryDenied,
    PrivacySafeFullDirectoryUnavailable,
)

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
SERVICE_TOKEN_ROUTE = "/internal/v1/social/service-token"
PRIVATE_DIRECTORY_ROUTE = "/internal/v1/social/full-directory"
VIEWER_AUTHORIZATION_HEADER = "X-HODLXXI-Viewer-Authorization"

internal_privacy_full_directory_bp = Blueprint(
    "internal_privacy_full_directory",
    __name__,
)


def _runtime():
    return configured_internal_delivery_runtime(current_app)


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _json_error(error: str, status: int):
    response = jsonify({"error": error})
    response.status_code = status
    return _no_store(response)


@internal_privacy_full_directory_bp.post(SERVICE_TOKEN_ROUTE)
def issue_internal_social_service_token():
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
        or request.form["scope"] != SERVICE_SCOPE
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
            "scope": SERVICE_SCOPE,
        }
    )
    return _no_store(response)


@internal_privacy_full_directory_bp.get(PRIVATE_DIRECTORY_ROUTE)
def read_internal_social_full_directory():
    runtime = _runtime()
    if runtime is None:
        return _json_error("not_found", 404)
    if request.args or request.content_length not in (None, 0):
        return _json_error("invalid_request", 400)

    try:
        service_token = parse_bearer_authorization_header(request.headers.get("Authorization", ""))
        service = runtime.verify_service_authority(service_token)
    except (BearerHeaderError, CredentialDenied):
        return _json_error("invalid_token", 401)
    except Exception:
        return _json_error("invalid_token", 401)

    try:
        viewer_token = parse_bearer_authorization_header(request.headers.get(VIEWER_AUTHORIZATION_HEADER, ""))
        directory = runtime.current_directory_for_service(service, viewer_token)
    except (BearerHeaderError, ViewerCredentialDenied):
        return _json_error("invalid_viewer_credential", 401)
    except CredentialDenied:
        return _json_error("invalid_token", 401)
    except PrivacySafeFullDirectoryDenied:
        return _json_error("insufficient_entitlement", 403)
    except PrivacySafeFullDirectoryUnavailable:
        return _json_error("directory_unavailable", 503)
    except Exception:
        return _json_error("directory_unavailable", 503)

    response = jsonify(directory)
    return _no_store(response)


__all__ = [
    "CLIENT_ASSERTION_TYPE",
    "PRIVATE_DIRECTORY_ROUTE",
    "SERVICE_TOKEN_ROUTE",
    "VIEWER_AUTHORIZATION_HEADER",
    "internal_privacy_full_directory_bp",
]
