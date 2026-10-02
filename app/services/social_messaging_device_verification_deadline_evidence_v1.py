"""Dormant authenticated deadline evidence for one exact Social V2 input.

The module freezes public bytes and a dedicated public-key trust lifecycle.  It
does not read authority rows, reserve anything, sign, persist, or grant final
admission.  A future PostgreSQL reservation owner must create the payload only
from its locked authority readers; this module intentionally exposes no
raw-field payload constructor.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import uuid
import weakref
from dataclasses import FrozenInstanceError, dataclass, field
from functools import wraps
from types import MappingProxyType
from typing import Callable, Mapping, NamedTuple, NoReturn, ParamSpec, TypeVar, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services import social_messaging_mobile_pre_enrollment_v2 as preacceptance

VERSION = 1
EVIDENCE_SCHEMA = "hodlxxi.social_messaging_device_verification_deadline_evidence.v1"
EVIDENCE_ALGORITHM = "RS256"
EVIDENCE_TYPE = "hodlxxi-social-messaging-device-verification-deadline-evidence-v1+jws"
EVIDENCE_PURPOSE = "social_messaging_device_verification_deadline_evidence_v1"
EVIDENCE_AUDIENCE_PATH = "/internal/v1/social/messaging-device-verification/deadline-evidence/consume"
EVIDENCE_JTI_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_EVIDENCE_JTI_V1"
RESERVATION_ID_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_RESERVATION_ID_V1"
RESERVATION_ID_PREIMAGE_SCHEMA = "hodlxxi.social_messaging_device_verification_deadline_reservation_id_preimage.v1"
INPUT_PAYLOAD_DIGEST_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_INPUT_PAYLOAD_V1"
INPUT_PAYLOAD_DIGEST_PREFIX = "hodlxxi-social-messaging-device-verification-deadline-input-payload-v1-sha256:"
TRUST_RECORD_ID_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_VERIFICATION_DEADLINE_TRUST_RECORD_ID_V1"
TRUST_RECORD_SCHEMA = "hodlxxi.social_messaging_device_verification_deadline_trust_record.v1"

MAX_EVIDENCE_BYTES = 16_384
MAX_PROTECTED_HEADER_BYTES = 1_024
MAX_PAYLOAD_BYTES = 12_288
MAX_EVIDENCE_LIFETIME_MS = 10_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991

RUNTIME_ENABLED = False
RESERVATION_PERSISTENCE = "not_implemented"
PRIVATE_KEY_CUSTODY = "not_provisioned"
AUTHORITY = "not_granted"
FINAL_ADMISSION = "denied"
DENIED_MESSAGE = "social messaging device verification deadline evidence denied"

_PUBLIC_JWK_FIELDS = frozenset(("kty", "use", "alg", "kid", "n", "e"))
_HEADER_FIELDS = {"alg", "kid", "typ"}
_PAYLOAD_WITHOUT_JTI_FIELDS = {
    "acceptanceId",
    "approvalEventId",
    "approverOAuthBrowserGenerationId",
    "approverOAuthSessionId",
    "approverOAuthTokenId",
    "approverSessionExpiresAt",
    "associationId",
    "associationVersion",
    "attemptId",
    "aud",
    "authorizationDigest",
    "clientId",
    "deviceId",
    "enrollmentChallengeId",
    "expiresAt",
    "fullEvidenceId",
    "fullEvidenceVersion",
    "fullExpiresAt",
    "fullProofId",
    "fullSourceEvidenceSha256",
    "inputDigest",
    "inputPayloadDigest",
    "iss",
    "observedAt",
    "operation",
    "operationId",
    "parentOAuthBrowserGenerationId",
    "parentOAuthSessionId",
    "parentOAuthTokenId",
    "phoneSessionExpiresAt",
    "purpose",
    "requestId",
    "reservationId",
    "reservationRevision",
    "schema",
    "servicePrincipal",
    "socialSessionIssuanceId",
    "socialSessionIssuanceRevision",
    "socialSessionTokenId",
    "subject",
    "version",
    "x25519BindingExpiresAt",
    "x25519BindingId",
    "x25519BindingVersion",
    "x25519PublicKeyCommitment",
}
_PAYLOAD_FIELDS = _PAYLOAD_WITHOUT_JTI_FIELDS | {"jti"}
_RESERVATION_PREIMAGE_FIELDS = {
    "acceptanceId",
    "associationId",
    "deviceId",
    "enrollmentChallengeId",
    "inputDigest",
    "operation",
    "operationId",
    "requestId",
    "schema",
    "subject",
    "version",
}
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z").fullmatch
_HEX32 = re.compile(r"[0-9a-f]{32}\Z").fullmatch
_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_CONFIGURED_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z").fullmatch
_BOUNDED_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z").fullmatch
_INPUT_DIGEST = re.compile(
    r"hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:[0-9a-f]{64}\Z"
).fullmatch
_INPUT_PAYLOAD_DIGEST = re.compile(re.escape(INPUT_PAYLOAD_DIGEST_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_FULL_PROOF_ID = re.compile(r"hodlxxi-full-entitlement-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_X25519_COMMITMENT = re.compile(r"hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_P = ParamSpec("_P")
_T = TypeVar("_T")


class SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied(ValueError):
    """The sole bounded, non-sensitive public failure."""

    def __init__(self) -> None:
        super().__init__(DENIED_MESSAGE)


def _deny() -> NoReturn:
    raise SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied() from None


def _sanitize_public_failure(function: Callable[_P, _T]) -> Callable[_P, _T]:
    """Replace every internal failure after leaving its exception context."""

    @wraps(function)
    def guarded(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        try:
            return function(*args, **kwargs)
        except Exception:
            pass
        _deny()

    return guarded


def _canonical(value: Mapping[str, object]) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    except Exception:
        _deny()


def _closed_json(source: object, fields: set[str] | frozenset[str], maximum: int) -> dict[str, object]:
    try:
        if type(source) is not str:
            raise ValueError
        encoded = source.encode("ascii")
        if not 1 <= len(encoded) <= maximum or any(byte < 0x20 or byte > 0x7E for byte in encoded):
            raise ValueError

        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in items:
                if type(key) is not str or key in result:
                    raise ValueError
                result[key] = value
            return result

        def invalid_constant(_value: str) -> NoReturn:
            raise ValueError

        value = json.loads(source, object_pairs_hook=pairs, parse_constant=invalid_constant)
        if type(value) is not dict or set(value) != set(fields) or _canonical(value) != source:
            raise ValueError
        return cast(dict[str, object], value)
    except Exception:
        pass
    _deny()


def _integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER or positive and value == 0:
        _deny()
    return cast(int, value)


def _hex32(value: object) -> str:
    if type(value) is not str or _HEX32(value) is None:
        _deny()
    return cast(str, value)


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64(value) is None:
        _deny()
    return cast(str, value)


def _configured_identifier(value: object) -> str:
    if type(value) is not str or _CONFIGURED_IDENTIFIER(value) is None:
        _deny()
    return cast(str, value)


def _bounded_version(value: object) -> str:
    if type(value) is not str or _BOUNDED_VERSION(value) is None:
        _deny()
    return cast(str, value)


def _matching(value: object, matcher) -> str:
    if type(value) is not str or matcher(value) is None:
        _deny()
    return cast(str, value)


def _uuid(value: object) -> str:
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError
        return cast(str, value)
    except Exception:
        _deny()


def _canonical_ipv6_hex(address: ipaddress.IPv6Address) -> str:
    raw = int(address)
    groups = [(raw >> shift) & 0xFFFF for shift in range(112, -1, -16)]
    best_start = best_length = run_start = run_length = 0
    for index, group in enumerate(groups):
        if group == 0:
            if run_length == 0:
                run_start = index
            run_length += 1
            if run_length > best_length:
                best_start, best_length = run_start, run_length
        else:
            run_length = 0
    encoded = [format(group, "x") for group in groups]
    if best_length < 2:
        return ":".join(encoded)
    return ":".join(encoded[:best_start]) + "::" + ":".join(encoded[best_start + best_length :])


def _https_origin(value: object) -> str:
    try:
        if type(value) is not str or not value.isascii() or not 1 <= len(value) <= 255:
            raise ValueError
        match = re.fullmatch(r"https://(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::([0-9]+))?", value)
        if match is None:
            raise ValueError
        host, port = match.groups()
        if port is not None and (re.fullmatch(r"[1-9][0-9]{0,4}", port) is None or int(port) > 65535 or port == "443"):
            raise ValueError
        if host.startswith("["):
            if _canonical_ipv6_hex(ipaddress.IPv6Address(host[1:-1])) != host[1:-1]:
                raise ValueError
        else:
            labels = host.split(".")
            if len(labels) == 4 and all(re.fullmatch(r"[0-9]+", label) for label in labels):
                if str(ipaddress.IPv4Address(host)) != host:
                    raise ValueError
            elif re.fullmatch(r"[0-9]+|0x[0-9a-f]*", labels[-1]) or any(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None or label.startswith("xn--")
                for label in labels
            ):
                raise ValueError
        return cast(str, value)
    except Exception:
        pass
    _deny()


def _evidence_audience(value: object) -> str:
    if type(value) is not str or not value.endswith(EVIDENCE_AUDIENCE_PATH):
        _deny()
    _https_origin(value[: -len(EVIDENCE_AUDIENCE_PATH)])
    return cast(str, value)


def _base64url_encode(source: bytes) -> str:
    return base64.urlsafe_b64encode(source).decode("ascii").rstrip("=")


def _base64url_decode(source: object) -> bytes:
    try:
        if type(source) is not str or _BASE64URL(source) is None or "=" in source:
            raise ValueError
        decoded = base64.urlsafe_b64decode(source + "=" * ((4 - len(source) % 4) % 4))
        if not decoded or _base64url_encode(decoded) != source:
            raise ValueError
        return decoded
    except Exception:
        pass
    _deny()


@dataclass(frozen=True, slots=True, repr=False)
class _TrustedRSAKeyV1:
    kid: str
    public_key: rsa.RSAPublicKey
    fingerprint: str
    jwk: Mapping[str, str]


def _public_key(value: Mapping[str, object]) -> _TrustedRSAKeyV1:
    try:
        if set(value) != _PUBLIC_JWK_FIELDS or any(type(item) is not str for item in value.values()):
            raise ValueError
        if value["kty"] != "RSA" or value["use"] != "sig" or value["alg"] != EVIDENCE_ALGORITHM:
            raise ValueError
        kid = _configured_identifier(value["kid"])
        integers: dict[str, int] = {}
        for name, maximum in (("n", 1_366), ("e", 16)):
            encoded = cast(str, value[name])
            if not 1 <= len(encoded) <= maximum:
                raise ValueError
            raw = _base64url_decode(encoded)
            if raw[0] == 0:
                raise ValueError
            integers[name] = int.from_bytes(raw, "big")
        modulus, exponent = integers["n"], integers["e"]
        if (
            not 2_048 <= modulus.bit_length() <= 8_192
            or modulus % 2 != 1
            or exponent < 65_537
            or exponent % 2 != 1
            or exponent >= modulus
        ):
            raise ValueError
        key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size != modulus.bit_length():
            raise ValueError
        spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        copied = MappingProxyType({name: cast(str, value[name]) for name in sorted(_PUBLIC_JWK_FIELDS)})
        return _TrustedRSAKeyV1(kid, key, "sha256:" + hashlib.sha256(spki).hexdigest(), copied)
    except Exception:
        pass
    _deny()


@dataclass(frozen=True, slots=True, repr=False)
class DeadlineEvidenceTrustRecordV1:
    """One dedicated public JWK registration and bounded trust generation."""

    public_jwk: Mapping[str, object] = field(repr=False)
    trust_revision: int
    not_before: int
    not_after: int
    revoked_at: int | None = None
    _key: _TrustedRSAKeyV1 = field(init=False, repr=False, compare=False)
    _record_id: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        try:
            if type(self.public_jwk) not in (dict, MappingProxyType):
                raise ValueError
            key = _public_key(dict(self.public_jwk))
            revision = _integer(self.trust_revision, positive=True)
            not_before = _integer(self.not_before)
            not_after = _integer(self.not_after, positive=True)
            revoked = None if self.revoked_at is None else _integer(self.revoked_at)
            if not_before >= not_after or revoked is not None and not not_before <= revoked < not_after:
                raise ValueError
            values: dict[str, object] = {
                "jwk": dict(key.jwk),
                "notAfter": not_after,
                "notBefore": not_before,
                "revokedAt": revoked,
                "schema": TRUST_RECORD_SCHEMA,
                "trustRevision": revision,
                "version": VERSION,
            }
            record_id = hashlib.sha256(
                TRUST_RECORD_ID_DOMAIN.encode("ascii") + b"\0" + _canonical(values).encode("ascii")
            ).hexdigest()
            object.__setattr__(self, "public_jwk", key.jwk)
            object.__setattr__(self, "_key", key)
            object.__setattr__(self, "_record_id", record_id)
            return
        except Exception:
            pass
        _deny()

    @property
    def key_id(self) -> str:
        return self._key.kid

    @property
    def key_fingerprint(self) -> str:
        return self._key.fingerprint

    @property
    def trust_record_id(self) -> str:
        return self._record_id


@dataclass(frozen=True, slots=True, repr=False)
class MessagingDeviceVerificationDeadlineEvidenceV1Config:
    """Dedicated empty-by-default deadline-evidence public trust."""

    enabled: bool = False
    issuer: str = ""
    audience: str = ""
    client_id: str = ""
    service_principal: str = ""
    purpose: str = EVIDENCE_PURPOSE
    trust_records: tuple[DeadlineEvidenceTrustRecordV1, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        try:
            if type(self.enabled) is not bool or type(self.trust_records) is not tuple:
                raise ValueError
            if self.purpose != EVIDENCE_PURPOSE or type(self.purpose) is not str:
                raise ValueError
            identities = (self.issuer, self.audience, self.client_id, self.service_principal)
            if any(type(value) is not str for value in identities):
                raise ValueError
            if not self.enabled and identities == ("", "", "", "") and not self.trust_records:
                return
            _https_origin(self.issuer)
            _evidence_audience(self.audience)
            _configured_identifier(self.client_id)
            _configured_identifier(self.service_principal)
            if not self.trust_records or any(
                type(item) is not DeadlineEvidenceTrustRecordV1 for item in self.trust_records
            ):
                raise ValueError
            pairs = {(item.key_id, item.trust_revision) for item in self.trust_records}
            kids = {item.key_id for item in self.trust_records}
            if len(pairs) != len(self.trust_records) or len(kids) != len(self.trust_records):
                raise ValueError
            return
        except Exception:
            pass
        _deny()


@dataclass(frozen=True, slots=True, repr=False)
class DeadlineEvidenceClaimsV1:
    payload_wire: str
    acceptance_id: str
    approval_event_id: str
    approver_oauth_browser_generation_id: str
    approver_oauth_session_id: str
    approver_oauth_token_id: str
    approver_session_expires_at: int
    association_id: str
    association_version: int
    attempt_id: str
    audience: str
    authorization_digest: str
    client_id: str
    device_id: str
    enrollment_challenge_id: str
    expires_at: int
    full_evidence_id: str
    full_evidence_version: str
    full_expires_at: int
    full_proof_id: str
    full_source_evidence_sha256: str
    input_digest: str
    input_payload_digest: str
    issuer: str
    observed_at: int
    operation: str
    operation_id: str
    parent_oauth_browser_generation_id: str
    parent_oauth_session_id: str
    parent_oauth_token_id: str
    phone_session_expires_at: int
    request_id: str
    reservation_id: str
    reservation_revision: int
    service_principal: str
    social_session_issuance_id: str
    social_session_issuance_revision: str
    social_session_token_id: str
    subject: str
    token_id: str
    x25519_binding_expires_at: int
    x25519_binding_id: str
    x25519_binding_version: int
    x25519_public_key_commitment: str


@_sanitize_public_failure
def deadline_evidence_input_payload_digest_v1(expected_input_wire: object) -> str:
    try:
        parsed = preacceptance.parse_preaccepted_enrollment_verification_input_v2(expected_input_wire)
        return (
            INPUT_PAYLOAD_DIGEST_PREFIX
            + hashlib.sha256(
                INPUT_PAYLOAD_DIGEST_DOMAIN.encode("ascii") + b"\0" + parsed.wire.encode("ascii")
            ).hexdigest()
        )
    except Exception:
        _deny()


def _reservation_id_from_values(value: Mapping[str, object]) -> str:
    preimage = {
        "acceptanceId": value["acceptanceId"],
        "associationId": value["associationId"],
        "deviceId": value["deviceId"],
        "enrollmentChallengeId": value["enrollmentChallengeId"],
        "inputDigest": value["inputDigest"],
        "operation": value["operation"],
        "operationId": value["operationId"],
        "requestId": value["requestId"],
        "schema": RESERVATION_ID_PREIMAGE_SCHEMA,
        "subject": value["subject"],
        "version": VERSION,
    }
    if set(preimage) != _RESERVATION_PREIMAGE_FIELDS:
        _deny()
    return hashlib.sha256(
        RESERVATION_ID_DOMAIN.encode("ascii") + b"\0" + _canonical(preimage).encode("ascii")
    ).hexdigest()


def _jti_from_values(value: Mapping[str, object]) -> str:
    return hashlib.sha256(EVIDENCE_JTI_DOMAIN.encode("ascii") + b"\0" + _canonical(value).encode("ascii")).hexdigest()


def _parse_payload_values(value: Mapping[str, object], source: str) -> DeadlineEvidenceClaimsV1:
    if (
        value["schema"] != EVIDENCE_SCHEMA
        or type(value["version"]) is not int
        or value["version"] != VERSION
        or value["purpose"] != EVIDENCE_PURPOSE
        or type(value["reservationRevision"]) is not int
        or value["reservationRevision"] != VERSION
        or type(value["operation"]) is not str
        or value["operation"] != "register"
    ):
        _deny()
    without_jti = {name: value[name] for name in _PAYLOAD_WITHOUT_JTI_FIELDS}
    if _hex64(value["jti"]) != _jti_from_values(without_jti):
        _deny()
    observed = _integer(value["observedAt"])
    expires = _integer(value["expiresAt"], positive=True)
    deadlines = (
        _integer(value["phoneSessionExpiresAt"], positive=True),
        _integer(value["approverSessionExpiresAt"], positive=True),
        _integer(value["fullExpiresAt"], positive=True),
        _integer(value["x25519BindingExpiresAt"], positive=True),
    )
    if (
        observed >= expires
        or expires - observed > MAX_EVIDENCE_LIFETIME_MS
        or expires > min(deadlines)
        or _hex64(value["reservationId"]) != _reservation_id_from_values(value)
    ):
        _deny()
    association_version = _integer(value["associationVersion"], positive=True)
    binding_version = _integer(value["x25519BindingVersion"], positive=True)
    if association_version != 1 or binding_version > 1_024:
        _deny()
    return DeadlineEvidenceClaimsV1(
        payload_wire=source,
        acceptance_id=_hex64(value["acceptanceId"]),
        approval_event_id=_hex64(value["approvalEventId"]),
        approver_oauth_browser_generation_id=_hex64(value["approverOAuthBrowserGenerationId"]),
        approver_oauth_session_id=_hex64(value["approverOAuthSessionId"]),
        approver_oauth_token_id=_hex32(value["approverOAuthTokenId"]),
        approver_session_expires_at=deadlines[1],
        association_id=_hex64(value["associationId"]),
        association_version=association_version,
        attempt_id=_hex64(value["attemptId"]),
        audience=_evidence_audience(value["aud"]),
        authorization_digest=_hex64(value["authorizationDigest"]),
        client_id=_configured_identifier(value["clientId"]),
        device_id=_hex64(value["deviceId"]),
        enrollment_challenge_id=_hex64(value["enrollmentChallengeId"]),
        expires_at=expires,
        full_evidence_id=_uuid(value["fullEvidenceId"]),
        full_evidence_version=_bounded_version(value["fullEvidenceVersion"]),
        full_expires_at=deadlines[2],
        full_proof_id=_matching(value["fullProofId"], _FULL_PROOF_ID),
        full_source_evidence_sha256=_hex64(value["fullSourceEvidenceSha256"]),
        input_digest=_matching(value["inputDigest"], _INPUT_DIGEST),
        input_payload_digest=_matching(value["inputPayloadDigest"], _INPUT_PAYLOAD_DIGEST),
        issuer=_https_origin(value["iss"]),
        observed_at=observed,
        operation="register",
        operation_id=_hex64(value["operationId"]),
        parent_oauth_browser_generation_id=_hex64(value["parentOAuthBrowserGenerationId"]),
        parent_oauth_session_id=_hex64(value["parentOAuthSessionId"]),
        parent_oauth_token_id=_hex32(value["parentOAuthTokenId"]),
        phone_session_expires_at=deadlines[0],
        request_id=_hex64(value["requestId"]),
        reservation_id=cast(str, value["reservationId"]),
        reservation_revision=VERSION,
        service_principal=_configured_identifier(value["servicePrincipal"]),
        social_session_issuance_id=_hex64(value["socialSessionIssuanceId"]),
        social_session_issuance_revision=_hex64(value["socialSessionIssuanceRevision"]),
        social_session_token_id=_hex32(value["socialSessionTokenId"]),
        subject=_hex64(value["subject"]),
        token_id=cast(str, value["jti"]),
        x25519_binding_expires_at=deadlines[3],
        x25519_binding_id=_hex64(value["x25519BindingId"]),
        x25519_binding_version=binding_version,
        x25519_public_key_commitment=_matching(value["x25519PublicKeyCommitment"], _X25519_COMMITMENT),
    )


@_sanitize_public_failure
def parse_messaging_device_verification_deadline_evidence_payload_v1(
    source: object,
    *,
    expected_input_wire: object | None = None,
) -> DeadlineEvidenceClaimsV1:
    """Strictly parse claims; parsing alone never authenticates authority."""

    try:
        value = _closed_json(source, _PAYLOAD_FIELDS, MAX_PAYLOAD_BYTES)
        claims = _parse_payload_values(value, cast(str, source))
        if expected_input_wire is not None:
            parsed = preacceptance.parse_preaccepted_enrollment_verification_input_v2(expected_input_wire)
            envelope = parsed.approval.envelope
            pre_enrollment = envelope.pre_enrollment
            context = parsed.context
            if (
                claims.acceptance_id != parsed.acceptance_id
                or claims.approval_event_id != parsed.approval.event_id
                or claims.authorization_digest != preacceptance.authorization_v2_digest(envelope.wire)
                or claims.association_id != parsed.association_id
                or claims.association_version != context.association_version
                or claims.attempt_id != context.attempt_id
                or claims.device_id != pre_enrollment.device_id
                or claims.enrollment_challenge_id != parsed.enrollment.enrollment_challenge_id
                or claims.input_digest != preacceptance.preaccepted_enrollment_verification_input_v2_digest(parsed.wire)
                or claims.input_payload_digest != deadline_evidence_input_payload_digest_v1(parsed.wire)
                or claims.operation != envelope.semantic.operation
                or claims.request_id != pre_enrollment.request_id
                or claims.subject != pre_enrollment.subject
                or claims.x25519_binding_id != pre_enrollment.x25519_binding_id
                or claims.x25519_binding_version != pre_enrollment.x25519_binding_version
                or claims.x25519_public_key_commitment != pre_enrollment.x25519_public_key_commitment
                or claims.x25519_binding_expires_at != envelope.x25519_binding_expires_at_ms
                or not parsed.enrollment.issued_at <= claims.observed_at < parsed.enrollment.expires_at
                or claims.expires_at > min(parsed.enrollment.expires_at, pre_enrollment.expires_at)
            ):
                _deny()
        return claims
    except SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied:
        raise
    except Exception:
        _deny()


@_sanitize_public_failure
def canonical_messaging_device_verification_deadline_evidence_protected_header_v1_bytes(*, kid: object) -> bytes:
    try:
        source = _canonical({"alg": EVIDENCE_ALGORITHM, "kid": _configured_identifier(kid), "typ": EVIDENCE_TYPE})
        _parse_protected_header(source)
        return source.encode("ascii")
    except Exception:
        _deny()


def _parse_protected_header(source: object) -> dict[str, object]:
    value = _closed_json(source, _HEADER_FIELDS, MAX_PROTECTED_HEADER_BYTES)
    if (
        value["alg"] != EVIDENCE_ALGORITHM
        or value["typ"] != EVIDENCE_TYPE
        or _configured_identifier(value["kid"]) != value["kid"]
    ):
        _deny()
    return value


@_sanitize_public_failure
def messaging_device_verification_deadline_evidence_signing_input_v1(
    *, protected_header_wire: object, payload_wire: object
) -> bytes:
    """Return the exact compact-JWS signing input; no signing capability exists."""

    try:
        if type(protected_header_wire) is not str or type(payload_wire) is not str:
            raise ValueError
        _parse_protected_header(protected_header_wire)
        parse_messaging_device_verification_deadline_evidence_payload_v1(payload_wire)
        return (
            _base64url_encode(protected_header_wire.encode("ascii"))
            + "."
            + _base64url_encode(payload_wire.encode("ascii"))
        ).encode("ascii")
    except Exception:
        _deny()


@_sanitize_public_failure
def compact_messaging_device_verification_deadline_evidence_v1(
    *, protected_header_wire: object, payload_wire: object, signature: object
) -> str:
    try:
        if type(signature) is not bytes or not signature:
            raise ValueError
        signing_input = messaging_device_verification_deadline_evidence_signing_input_v1(
            protected_header_wire=protected_header_wire,
            payload_wire=payload_wire,
        )
        evidence = signing_input.decode("ascii") + "." + _base64url_encode(signature)
        if len(evidence.encode("ascii")) > MAX_EVIDENCE_BYTES:
            raise ValueError
        return evidence
    except Exception:
        _deny()


class _AuthenticatedSnapshotV1(NamedTuple):
    claims: DeadlineEvidenceClaimsV1
    key_id: str
    key_fingerprint: str
    trust_record_id: str
    trust_revision: int


class AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1:
    """Unforgeable process-local view of one successfully verified evidence JWS."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *args: object, **kwargs: object) -> AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1:
        _deny()

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise FrozenInstanceError(f"cannot assign to field {name!r}")

    def __init_subclass__(cls, **kwargs: object) -> None:
        _deny()

    def __copy__(self) -> NoReturn:
        _deny()

    def __deepcopy__(self, memo: object) -> NoReturn:
        _deny()

    def __reduce__(self) -> NoReturn:
        _deny()

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        _deny()

    @property
    def claims(self) -> DeadlineEvidenceClaimsV1:
        return _authenticated_snapshot(self).claims

    @property
    def key_id(self) -> str:
        return _authenticated_snapshot(self).key_id

    @property
    def key_fingerprint(self) -> str:
        return _authenticated_snapshot(self).key_fingerprint

    @property
    def trust_record_id(self) -> str:
        return _authenticated_snapshot(self).trust_record_id

    @property
    def trust_revision(self) -> int:
        return _authenticated_snapshot(self).trust_revision


_AUTHENTIC_RESULTS: dict[
    int,
    tuple[
        weakref.ReferenceType[AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1],
        _AuthenticatedSnapshotV1,
    ],
] = {}


def _register_authenticated(
    value: AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1,
    snapshot: _AuthenticatedSnapshotV1,
) -> None:
    identity = id(value)

    def remove(
        reference: weakref.ReferenceType[AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1],
    ) -> None:
        registered = _AUTHENTIC_RESULTS.get(identity)
        if registered is not None and registered[0] is reference:
            _AUTHENTIC_RESULTS.pop(identity, None)

    _AUTHENTIC_RESULTS[identity] = (weakref.ref(value, remove), snapshot)


def _authenticated_snapshot(value: object) -> _AuthenticatedSnapshotV1:
    if type(value) is not AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1:
        _deny()
    registered = _AUTHENTIC_RESULTS.get(id(value))
    if registered is None or registered[0]() is not value:
        _deny()
    return registered[1]


@_sanitize_public_failure
def project_authenticated_messaging_device_verification_deadline_evidence_v1(
    value: object,
) -> Mapping[str, object]:
    """Project only registry-backed facts; the projection grants no authority."""

    try:
        snapshot = _authenticated_snapshot(value)
        claims = snapshot.claims
        return MappingProxyType(
            {
                "authority": AUTHORITY,
                "claims": claims,
                "finalAdmission": FINAL_ADMISSION,
                "keyFingerprint": snapshot.key_fingerprint,
                "keyId": snapshot.key_id,
                "privateKeyCustody": PRIVATE_KEY_CUSTODY,
                "reservationPersistence": RESERVATION_PERSISTENCE,
                "runtimeEnabled": RUNTIME_ENABLED,
                "trustRecordId": snapshot.trust_record_id,
                "trustRevision": snapshot.trust_revision,
            }
        )
    except Exception:
        _deny()


@_sanitize_public_failure
def verify_messaging_device_verification_deadline_evidence_v1(
    evidence: object,
    *,
    config: MessagingDeviceVerificationDeadlineEvidenceV1Config = (
        MessagingDeviceVerificationDeadlineEvidenceV1Config()
    ),
    expected_input_wire: object,
    now: object,
) -> AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1:
    """Authenticate one exact evidence JWS against one exact V2 input."""

    try:
        if type(config) is not MessagingDeviceVerificationDeadlineEvidenceV1Config or config.enabled is not True:
            raise ValueError
        if type(evidence) is not str:
            raise ValueError
        encoded = evidence.encode("ascii")
        if (
            not 1 <= len(encoded) <= MAX_EVIDENCE_BYTES
            or any(byte < 0x20 or byte > 0x7E for byte in encoded)
            or evidence.count(".") != 2
        ):
            raise ValueError
        protected_segment, payload_segment, signature_segment = evidence.split(".")
        protected_wire = _base64url_decode(protected_segment).decode("ascii")
        header = _parse_protected_header(protected_wire)
        matches = [record for record in config.trust_records if record.key_id == header["kid"]]
        if len(matches) != 1:
            raise ValueError
        record = matches[0]
        payload_wire = _base64url_decode(payload_segment).decode("ascii")
        claims = parse_messaging_device_verification_deadline_evidence_payload_v1(
            payload_wire,
            expected_input_wire=expected_input_wire,
        )
        current = _integer(now)
        if (
            claims.issuer != config.issuer
            or claims.audience != config.audience
            or claims.client_id != config.client_id
            or claims.service_principal != config.service_principal
            or not claims.observed_at <= current < claims.expires_at
            or not record.not_before <= claims.observed_at < record.not_after
            or claims.expires_at > record.not_after
            or record.revoked_at is not None
        ):
            raise ValueError
        signature = _base64url_decode(signature_segment)
        if len(signature) != (record._key.public_key.key_size + 7) // 8:
            raise ValueError
        signing_input = (protected_segment + "." + payload_segment).encode("ascii")
        record._key.public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        result = object.__new__(AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1)
        _register_authenticated(
            result,
            _AuthenticatedSnapshotV1(
                claims=claims,
                key_id=record.key_id,
                key_fingerprint=record.key_fingerprint,
                trust_record_id=record.trust_record_id,
                trust_revision=record.trust_revision,
            ),
        )
        return result
    except Exception:
        pass
    _deny()


__all__ = [
    "AUTHORITY",
    "AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1",
    "DENIED_MESSAGE",
    "DeadlineEvidenceClaimsV1",
    "DeadlineEvidenceTrustRecordV1",
    "EVIDENCE_ALGORITHM",
    "EVIDENCE_AUDIENCE_PATH",
    "EVIDENCE_JTI_DOMAIN",
    "EVIDENCE_PURPOSE",
    "EVIDENCE_SCHEMA",
    "EVIDENCE_TYPE",
    "FINAL_ADMISSION",
    "INPUT_PAYLOAD_DIGEST_DOMAIN",
    "INPUT_PAYLOAD_DIGEST_PREFIX",
    "MAX_EVIDENCE_BYTES",
    "MAX_EVIDENCE_LIFETIME_MS",
    "MessagingDeviceVerificationDeadlineEvidenceV1Config",
    "PRIVATE_KEY_CUSTODY",
    "RESERVATION_ID_DOMAIN",
    "RESERVATION_PERSISTENCE",
    "RUNTIME_ENABLED",
    "SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied",
    "canonical_messaging_device_verification_deadline_evidence_protected_header_v1_bytes",
    "compact_messaging_device_verification_deadline_evidence_v1",
    "deadline_evidence_input_payload_digest_v1",
    "messaging_device_verification_deadline_evidence_signing_input_v1",
    "parse_messaging_device_verification_deadline_evidence_payload_v1",
    "project_authenticated_messaging_device_verification_deadline_evidence_v1",
    "verify_messaging_device_verification_deadline_evidence_v1",
]
