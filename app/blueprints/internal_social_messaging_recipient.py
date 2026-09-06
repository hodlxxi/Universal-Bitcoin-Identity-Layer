"""Private HTTP boundary for Social recipient-device resolution.

This blueprint is inert unless an exact MessagingRecipientInternalDeliveryRuntime
has been installed in ``app.extensions``. It never accepts a canonical target
subject from the caller and never projects raw device or binding identifiers.
"""

from __future__ import annotations

import hashlib
import json
import re

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
from app.services.full_recipient_directory_provider import validate_x25519_public_key
from app.services.recipient_device_resolver import (
    PACKAGE_SCHEMA,
    SOURCE as RECIPIENT_SOURCE,
    VERSION as RECIPIENT_VERSION,
    RecipientAliasInvalid,
    RecipientDeviceResolverDenied,
    RecipientDeviceResolverUnavailable,
)
from app.services.social_messaging_device_contract import (
    ALGORITHM,
    MAX_ACTIVE_DEVICES,
    MAX_BINDING_VERSION,
)
from app.services.social_messaging_recipient_internal_delivery import (
    MESSAGING_RECIPIENT_INTERNAL_EXTENSION,
    MESSAGING_RECIPIENT_SCOPE,
    MessagingRecipientInternalDeliveryRuntime,
    MessagingRecipientViewerCredentialDenied,
    MessagingRecipientViewerEntitlementDenied,
    MessagingRecipientViewerEntitlementUnavailable,
)

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
SERVICE_TOKEN_ROUTE = "/internal/v1/social/messaging/recipient-service-token"
RECIPIENT_DEVICES_ROUTE = "/internal/v1/social/messaging/recipient-devices"
VIEWER_AUTHORIZATION_HEADER = "X-HODLXXI-Viewer-Authorization"
MAX_RECIPIENT_REQUEST_BYTES = 256

_ALIAS = re.compile(r"p_[A-Za-z0-9_-]{22}\Z").fullmatch
_DEVICE_HANDLE = re.compile(r"d_[A-Za-z0-9_-]{22}\Z").fullmatch
_SNAPSHOT_ID = re.compile(r"sha256:[0-9a-f]{64}\Z").fullmatch
_PACKAGE_FIELDS = {
    "schema",
    "version",
    "source",
    "snapshotId",
    "complete",
    "alias",
    "issuedAt",
    "expiresAt",
    "devices",
}
_DEVICE_FIELDS = {
    "deviceHandle",
    "algorithm",
    "version",
    "publicKey",
    "validFrom",
    "expiresAt",
}

internal_social_messaging_recipient_bp = Blueprint(
    "internal_social_messaging_recipient",
    __name__,
)


def _runtime() -> MessagingRecipientInternalDeliveryRuntime | None:
    runtime = current_app.extensions.get(MESSAGING_RECIPIENT_INTERNAL_EXTENSION)
    return runtime if type(runtime) is MessagingRecipientInternalDeliveryRuntime else None


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _json_error(error: str, status: int):
    response = jsonify({"error": error})
    response.status_code = status
    return _no_store(response)


def _service_authority(runtime: MessagingRecipientInternalDeliveryRuntime):
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


def _closed_json_object(source: str) -> dict[str, object]:
    def pairs(values):
        result = {}
        for key, item in values:
            if type(key) is not str or key in result:
                raise ValueError
            result[key] = item
        return result

    decoded = json.loads(source, object_pairs_hook=pairs)
    if type(decoded) is not dict:
        raise ValueError
    return decoded


def _recipient_alias_from_request() -> str:
    try:
        content_length = request.content_length
        if (
            request.args
            or request.mimetype != "application/json"
            or type(content_length) is not int
            or not 1 <= content_length <= MAX_RECIPIENT_REQUEST_BYTES
        ):
            raise ValueError

        body = request.get_data(cache=False, as_text=False)
        if type(body) is not bytes or len(body) != content_length or any(byte < 0x20 or byte > 0x7E for byte in body):
            raise ValueError

        data = _closed_json_object(body.decode("ascii"))
        if set(data) != {"recipientAlias"}:
            raise ValueError
        alias = data["recipientAlias"]
        if type(alias) is not str or _ALIAS(alias) is None:
            raise ValueError
        return alias
    except Exception:
        raise RecipientAliasInvalid() from None


def _normalize_recipient_package(
    value: object,
    *,
    expected_alias: str,
) -> dict[str, object] | None:
    try:
        if type(value) is not dict or set(value) != _PACKAGE_FIELDS:
            raise ValueError
        if (
            value["schema"] != PACKAGE_SCHEMA
            or type(value["version"]) is not int
            or value["version"] != RECIPIENT_VERSION
            or value["source"] != RECIPIENT_SOURCE
            or value["complete"] is not True
            or value["alias"] != expected_alias
            or type(value["alias"]) is not str
            or _ALIAS(value["alias"]) is None
            or type(value["snapshotId"]) is not str
            or _SNAPSHOT_ID(value["snapshotId"]) is None
        ):
            raise ValueError

        issued_at = value["issuedAt"]
        expires_at = value["expiresAt"]
        if type(issued_at) is not int or type(expires_at) is not int or issued_at < 0 or expires_at <= issued_at:
            raise ValueError

        raw_devices = value["devices"]
        if type(raw_devices) is not list or not 1 <= len(raw_devices) <= MAX_ACTIVE_DEVICES:
            raise ValueError

        devices = []
        handles = set()
        public_keys = set()
        for raw in raw_devices:
            if type(raw) is not dict or set(raw) != _DEVICE_FIELDS:
                raise ValueError

            handle = raw["deviceHandle"]
            algorithm = raw["algorithm"]
            version = raw["version"]
            public_key = raw["publicKey"]
            valid_from = raw["validFrom"]
            device_expires_at = raw["expiresAt"]

            if (
                type(handle) is not str
                or _DEVICE_HANDLE(handle) is None
                or handle in handles
                or algorithm != ALGORITHM
                or type(version) is not int
                or not 1 <= version <= MAX_BINDING_VERSION
                or type(public_key) is not str
                or validate_x25519_public_key(public_key) != public_key
                or public_key in public_keys
                or type(valid_from) is not int
                or type(device_expires_at) is not int
                or valid_from < 0
                or valid_from > issued_at
                or device_expires_at < expires_at
                or valid_from >= device_expires_at
            ):
                raise ValueError

            handles.add(handle)
            public_keys.add(public_key)
            devices.append(
                {
                    "deviceHandle": handle,
                    "algorithm": algorithm,
                    "version": version,
                    "publicKey": public_key,
                    "validFrom": valid_from,
                    "expiresAt": device_expires_at,
                }
            )

        devices.sort(key=lambda item: item["deviceHandle"])
        evidence = {
            "schema": PACKAGE_SCHEMA,
            "version": RECIPIENT_VERSION,
            "source": RECIPIENT_SOURCE,
            "alias": expected_alias,
            "complete": True,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "devices": devices,
        }
        canonical = json.dumps(
            evidence,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        snapshot_id = "sha256:" + hashlib.sha256(canonical).hexdigest()
        if value["snapshotId"] != snapshot_id:
            raise ValueError

        return {
            "schema": PACKAGE_SCHEMA,
            "version": RECIPIENT_VERSION,
            "source": RECIPIENT_SOURCE,
            "snapshotId": snapshot_id,
            "complete": True,
            "alias": expected_alias,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "devices": devices,
        }
    except Exception:
        return None


@internal_social_messaging_recipient_bp.post(SERVICE_TOKEN_ROUTE)
def issue_internal_social_messaging_recipient_service_token():
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
        or request.form["scope"] != MESSAGING_RECIPIENT_SCOPE
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
            "scope": MESSAGING_RECIPIENT_SCOPE,
        }
    )
    return _no_store(response)


@internal_social_messaging_recipient_bp.post(RECIPIENT_DEVICES_ROUTE)
def read_internal_social_messaging_recipient_devices():
    runtime = _runtime()
    if runtime is None:
        return _json_error("not_found", 404)

    try:
        recipient_alias = _recipient_alias_from_request()
    except RecipientAliasInvalid:
        return _json_error("invalid_request", 400)

    service = _service_authority(runtime)
    if service is None:
        return _json_error("invalid_token", 401)

    viewer_token = _viewer_token()
    if viewer_token is None:
        return _json_error("invalid_viewer_credential", 401)

    try:
        raw = runtime.resolve_for_service(
            service,
            viewer_token,
            recipient_alias,
        )
    except CredentialDenied:
        return _json_error("invalid_token", 401)
    except MessagingRecipientViewerCredentialDenied:
        return _json_error("invalid_viewer_credential", 401)
    except MessagingRecipientViewerEntitlementDenied:
        return _json_error("insufficient_entitlement", 403)
    except MessagingRecipientViewerEntitlementUnavailable:
        return _json_error("recipient_authority_unavailable", 503)
    except RecipientAliasInvalid:
        return _json_error("invalid_request", 400)
    except (RecipientDeviceResolverDenied, RecipientDeviceResolverUnavailable):
        return _json_error("recipient_authority_unavailable", 503)
    except Exception:
        return _json_error("recipient_authority_unavailable", 503)

    package = _normalize_recipient_package(
        raw,
        expected_alias=recipient_alias,
    )
    if package is None:
        return _json_error("recipient_authority_unavailable", 503)

    return _no_store(jsonify(package))


__all__ = [
    "CLIENT_ASSERTION_TYPE",
    "MAX_RECIPIENT_REQUEST_BYTES",
    "MESSAGING_RECIPIENT_INTERNAL_EXTENSION",
    "RECIPIENT_DEVICES_ROUTE",
    "SERVICE_TOKEN_ROUTE",
    "VIEWER_AUTHORIZATION_HEADER",
    "internal_social_messaging_recipient_bp",
]
