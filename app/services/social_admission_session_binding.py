"""Pure commitments for frozen Social device-admission session bindings.

This module canonicalizes immutable, non-secret authority identifiers and
derives the two role-separated hashes carried by VerificationContextV1.  It
does not load, validate, or claim current durable authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import NoReturn, cast

VERSION = 1
MAX_PREIMAGE_BYTES = 2_048

SESSION_BINDING_PREIMAGE_SCHEMA = "hodlxxi.social_admission_session_binding_preimage.v1"
APPROVER_SESSION_BINDING_PREIMAGE_SCHEMA = "hodlxxi.social_admission_approver_session_binding_preimage.v1"
SESSION_BINDING_DOMAIN = "HODLXXI_SOCIAL_ADMISSION_SESSION_BINDING_V1"
APPROVER_SESSION_BINDING_DOMAIN = "HODLXXI_SOCIAL_ADMISSION_APPROVER_SESSION_BINDING_V1"
UNAVAILABLE_MESSAGE = "social admission session binding unavailable"

_HEX32 = re.compile(r"[0-9a-f]{32}\Z").fullmatch
_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_CLIENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z").fullmatch

_SESSION_BINDING_FIELDS = frozenset(
    (
        "clientId",
        "deviceId",
        "parentOAuthBrowserGenerationId",
        "parentOAuthSessionId",
        "parentOAuthTokenId",
        "schema",
        "socialSessionIssuanceId",
        "socialSessionTokenId",
        "subject",
        "version",
        "x25519BindingId",
    )
)
_APPROVER_SESSION_BINDING_FIELDS = frozenset(
    (
        "clientId",
        "oauthBrowserGenerationId",
        "oauthSessionId",
        "oauthTokenId",
        "schema",
        "subject",
        "version",
    )
)


class SocialAdmissionSessionBindingUnavailable(ValueError):
    """The only failure exposed by this pure contract boundary."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True, slots=True)
class SessionBindingInputsV1:
    preimage: str
    subject: str
    device_id: str
    x25519_binding_id: str
    social_session_issuance_id: str
    social_session_token_id: str
    parent_oauth_token_id: str
    parent_oauth_session_id: str
    parent_oauth_browser_generation_id: str
    client_id: str


@dataclass(frozen=True, slots=True)
class ApproverSessionBindingInputsV1:
    preimage: str
    subject: str
    oauth_token_id: str
    oauth_session_id: str
    oauth_browser_generation_id: str
    client_id: str


def _deny() -> NoReturn:
    raise SocialAdmissionSessionBindingUnavailable()


def _canonical(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _hex32(value: object) -> str:
    if type(value) is not str or _HEX32(value) is None:
        _deny()
    return cast(str, value)


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64(value) is None:
        _deny()
    return cast(str, value)


def _client_id(value: object) -> str:
    if type(value) is not str or _CLIENT_ID(value) is None:
        _deny()
    return cast(str, value)


def _closed_json(source: object, fields: frozenset[str]) -> dict[str, object]:
    try:
        if type(source) is not str:
            raise ValueError
        encoded = source.encode("ascii")
        if not 1 <= len(encoded) <= MAX_PREIMAGE_BYTES or any(byte < 0x20 or byte > 0x7E for byte in encoded):
            raise ValueError

        def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if type(key) is not str or key in result:
                    raise ValueError
                result[key] = value
            return result

        def invalid_constant(_value: str) -> NoReturn:
            raise ValueError

        value = json.loads(
            source,
            object_pairs_hook=unique_pairs,
            parse_constant=invalid_constant,
        )
        if type(value) is not dict or set(value) != fields or _canonical(value) != source:
            raise ValueError
        return cast(dict[str, object], value)
    except Exception:
        _deny()


def canonical_session_binding_preimage_v1_bytes(
    *,
    subject: object,
    device_id: object,
    x25519_binding_id: object,
    social_session_issuance_id: object,
    social_session_token_id: object,
    parent_oauth_token_id: object,
    parent_oauth_session_id: object,
    parent_oauth_browser_generation_id: object,
    client_id: object,
) -> bytes:
    """Canonical immutable inputs for one Social device session generation."""

    wire = _canonical(
        {
            "clientId": _client_id(client_id),
            "deviceId": _hex64(device_id),
            "parentOAuthBrowserGenerationId": _hex64(parent_oauth_browser_generation_id),
            "parentOAuthSessionId": _hex64(parent_oauth_session_id),
            "parentOAuthTokenId": _hex32(parent_oauth_token_id),
            "schema": SESSION_BINDING_PREIMAGE_SCHEMA,
            "socialSessionIssuanceId": _hex64(social_session_issuance_id),
            "socialSessionTokenId": _hex32(social_session_token_id),
            "subject": _hex64(subject),
            "version": VERSION,
            "x25519BindingId": _hex64(x25519_binding_id),
        }
    )
    if len(wire) > MAX_PREIMAGE_BYTES:
        _deny()
    return wire.encode("ascii")


def canonical_approver_session_binding_preimage_v1_bytes(
    *,
    subject: object,
    oauth_token_id: object,
    oauth_session_id: object,
    oauth_browser_generation_id: object,
    client_id: object,
) -> bytes:
    """Canonical immutable inputs for one desktop approver OAuth generation."""

    wire = _canonical(
        {
            "clientId": _client_id(client_id),
            "oauthBrowserGenerationId": _hex64(oauth_browser_generation_id),
            "oauthSessionId": _hex64(oauth_session_id),
            "oauthTokenId": _hex32(oauth_token_id),
            "schema": APPROVER_SESSION_BINDING_PREIMAGE_SCHEMA,
            "subject": _hex64(subject),
            "version": VERSION,
        }
    )
    if len(wire) > MAX_PREIMAGE_BYTES:
        _deny()
    return wire.encode("ascii")


def parse_session_binding_preimage_v1(source: object) -> SessionBindingInputsV1:
    value = _closed_json(source, _SESSION_BINDING_FIELDS)
    if (
        value["schema"] != SESSION_BINDING_PREIMAGE_SCHEMA
        or type(value["version"]) is not int
        or value["version"] != VERSION
    ):
        _deny()
    result = SessionBindingInputsV1(
        preimage=cast(str, source),
        subject=_hex64(value["subject"]),
        device_id=_hex64(value["deviceId"]),
        x25519_binding_id=_hex64(value["x25519BindingId"]),
        social_session_issuance_id=_hex64(value["socialSessionIssuanceId"]),
        social_session_token_id=_hex32(value["socialSessionTokenId"]),
        parent_oauth_token_id=_hex32(value["parentOAuthTokenId"]),
        parent_oauth_session_id=_hex64(value["parentOAuthSessionId"]),
        parent_oauth_browser_generation_id=_hex64(value["parentOAuthBrowserGenerationId"]),
        client_id=_client_id(value["clientId"]),
    )
    if (
        canonical_session_binding_preimage_v1_bytes(
            subject=result.subject,
            device_id=result.device_id,
            x25519_binding_id=result.x25519_binding_id,
            social_session_issuance_id=result.social_session_issuance_id,
            social_session_token_id=result.social_session_token_id,
            parent_oauth_token_id=result.parent_oauth_token_id,
            parent_oauth_session_id=result.parent_oauth_session_id,
            parent_oauth_browser_generation_id=result.parent_oauth_browser_generation_id,
            client_id=result.client_id,
        ).decode("ascii")
        != source
    ):
        _deny()
    return result


def parse_approver_session_binding_preimage_v1(source: object) -> ApproverSessionBindingInputsV1:
    value = _closed_json(source, _APPROVER_SESSION_BINDING_FIELDS)
    if (
        value["schema"] != APPROVER_SESSION_BINDING_PREIMAGE_SCHEMA
        or type(value["version"]) is not int
        or value["version"] != VERSION
    ):
        _deny()
    result = ApproverSessionBindingInputsV1(
        preimage=cast(str, source),
        subject=_hex64(value["subject"]),
        oauth_token_id=_hex32(value["oauthTokenId"]),
        oauth_session_id=_hex64(value["oauthSessionId"]),
        oauth_browser_generation_id=_hex64(value["oauthBrowserGenerationId"]),
        client_id=_client_id(value["clientId"]),
    )
    if (
        canonical_approver_session_binding_preimage_v1_bytes(
            subject=result.subject,
            oauth_token_id=result.oauth_token_id,
            oauth_session_id=result.oauth_session_id,
            oauth_browser_generation_id=result.oauth_browser_generation_id,
            client_id=result.client_id,
        ).decode("ascii")
        != source
    ):
        _deny()
    return result


def _derive(domain: str, preimage: str) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + preimage.encode("ascii")).hexdigest()


def derive_session_binding_v1(preimage: object) -> str:
    inputs = parse_session_binding_preimage_v1(preimage)
    return _derive(SESSION_BINDING_DOMAIN, inputs.preimage)


def derive_approver_session_binding_v1(preimage: object) -> str:
    inputs = parse_approver_session_binding_preimage_v1(preimage)
    return _derive(APPROVER_SESSION_BINDING_DOMAIN, inputs.preimage)


def require_session_binding_match_v1(preimage: object, presented_binding: object) -> str:
    """Compare only after the caller has established locked current authority."""

    expected = derive_session_binding_v1(preimage)
    presented = _hex64(presented_binding)
    if not hmac.compare_digest(expected, presented):
        _deny()
    return expected


def require_approver_session_binding_match_v1(preimage: object, presented_binding: object) -> str:
    """Compare an independently authorized desktop approver generation."""

    expected = derive_approver_session_binding_v1(preimage)
    presented = _hex64(presented_binding)
    if not hmac.compare_digest(expected, presented):
        _deny()
    return expected


__all__ = [
    "APPROVER_SESSION_BINDING_DOMAIN",
    "APPROVER_SESSION_BINDING_PREIMAGE_SCHEMA",
    "MAX_PREIMAGE_BYTES",
    "SESSION_BINDING_DOMAIN",
    "SESSION_BINDING_PREIMAGE_SCHEMA",
    "ApproverSessionBindingInputsV1",
    "SessionBindingInputsV1",
    "SocialAdmissionSessionBindingUnavailable",
    "canonical_approver_session_binding_preimage_v1_bytes",
    "canonical_session_binding_preimage_v1_bytes",
    "derive_approver_session_binding_v1",
    "derive_session_binding_v1",
    "parse_approver_session_binding_preimage_v1",
    "parse_session_binding_preimage_v1",
    "require_approver_session_binding_match_v1",
    "require_session_binding_match_v1",
]
