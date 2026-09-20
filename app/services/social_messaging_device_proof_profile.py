"""Dormant canonical shape contracts for Social device proof and Enrollment V2.

UBID deliberately does not verify Ed25519. The current strict primitive is in
Social, but no atomic final-admission owner has been selected. This module
validates exact shared bytes and returns only shape results; it never accepts a
Social assertion or reports association, consumption, or admission.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import NoReturn, cast

from app.services.full_recipient_directory_provider import validate_x25519_public_key

DEVICE_PROOF_PROFILE = "hodlxxi.social_messaging_device_proof.ed25519_webcrypto.v1"
DEVICE_PROOF_ALGORITHM = "Ed25519"
DEVICE_PROOF_SCHEMA = "hodlxxi.social_messaging_device_proof.v1"
DEVICE_PROOF_PREIMAGE_SCHEMA = "hodlxxi.social_messaging_device_proof_preimage.v1"
DEVICE_PROOF_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_PROOF_ED25519_WEBCRYPTO_V1"
DEVICE_PROOF_RUNTIME_ENABLED = False
FINAL_AUTHORITY_MODEL = "ATOMIC_OWNER_PENDING"
ATOMIC_CHALLENGE_OWNER = "PENDING"
FINAL_ADMISSION_OWNER = "PENDING"

DEVICE_REQUEST_SCHEMA = "hodlxxi.social_messaging_device_request_candidate.v1"
DEVICE_CHALLENGE_SCHEMA = "hodlxxi.social_messaging_device_challenge_candidate.v1"
DEVICE_CHALLENGE_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_REQUEST_CHALLENGE_V1"
RECIPIENT_SELF_SCHEMA = "hodlxxi.social_messaging_recipient_self_request.v1"
MAX_CHALLENGE_LIFETIME_MS = 60_000

ENROLLMENT_V2_SCHEMA = "hodlxxi.social_messaging_device_enrollment.v2"
ENROLLMENT_V2_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_V2"
ENROLLMENT_V2_PROOF_SCHEMA = "hodlxxi.social_messaging_device_enrollment_proof.v2"
ENROLLMENT_V2_PROOF_PREIMAGE_SCHEMA = "hodlxxi.social_messaging_device_enrollment_proof_preimage.v2"
ENROLLMENT_V2_PROOF_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_PROOF_V2"
ENROLLMENT_V2_APPROVAL_PURPOSE = "hodlxxi-social-messaging-device-enrollment-v2"
ENROLLMENT_V2_RUNTIME_ENABLED = False
ENROLLMENT_V2_EXISTING_DEVICES_REQUIRE_REENROLLMENT = True
AUTH_KEY_ROTATION_INVALIDATES_PREDECESSOR = True
AUTH_KEY_ROTATION_INVALIDATES_OUTSTANDING_CHALLENGES = True
MAX_ENROLLMENT_LIFETIME_MS = 60_000

MAX_SAFE_INTEGER = 9_007_199_254_740_991
UNAVAILABLE_MESSAGE = "social messaging device proof unavailable"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_HEX128 = re.compile(r"[0-9a-f]{128}\Z").fullmatch
_BODY_DIGEST = re.compile(r"hodlxxi-social-device-request-body-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_ENROLLMENT_DIGEST = re.compile(r"hodlxxi-social-messaging-device-enrollment-v2-sha256:[0-9a-f]{64}\Z").fullmatch
_X25519_COMMITMENT = re.compile(r"hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_PATH = re.compile(r"/[a-z0-9]+(?:[/-][a-z0-9]+)*\Z").fullmatch
_HANDLE = re.compile(r"d_[A-Za-z0-9_-]{22}\Z").fullmatch

_REQUEST_FIELDS = {
    "audience",
    "bindingId",
    "bindingVersion",
    "bodyDigest",
    "deviceId",
    "method",
    "operation",
    "path",
    "recipientHandle",
    "schema",
    "sessionBinding",
    "subject",
    "version",
}
_CHALLENGE_FIELDS = {"challengeId", "domain", "expiresAt", "issuedAt", "request", "schema", "version"}
_PROOF_FIELDS = {"algorithm", "challengeId", "profile", "publicKey", "schema", "signature", "version"}
_ENROLLMENT_FIELDS = {
    "audience",
    "deviceId",
    "domain",
    "ed25519PublicKey",
    "enrollmentChallengeId",
    "expiresAt",
    "issuedAt",
    "profile",
    "schema",
    "subject",
    "version",
    "x25519BindingId",
    "x25519BindingVersion",
    "x25519PublicKeyCommitment",
}
_ENROLLMENT_PROOF_FIELDS = {
    "algorithm",
    "enrollmentChallengeId",
    "enrollmentDigest",
    "profile",
    "publicKey",
    "schema",
    "signature",
    "version",
}


class SocialMessagingDeviceProofUnavailable(ValueError):
    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True)
class DeviceProofShapeResult:
    canonical_structure_validity: str
    strict_ed25519_cryptographic_validity: str
    current_device_key_association_validity: str
    atomic_challenge_consumption: str
    final_admission: str
    proof_profile: str
    challenge_id: str
    public_key: str


@dataclass(frozen=True)
class EnrollmentV2Record:
    audience: str
    device_id: str
    ed25519_public_key: str
    enrollment_challenge_id: str
    expires_at: int
    issued_at: int
    subject: str
    x25519_binding_id: str
    x25519_binding_version: int
    x25519_public_key_commitment: str


@dataclass(frozen=True)
class EnrollmentProofV2Record:
    enrollment_challenge_id: str
    enrollment_digest: str
    public_key: str
    signature: str


def _deny() -> NoReturn:
    raise SocialMessagingDeviceProofUnavailable()


def _canonical(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _closed_json(source: object, fields: set[str], maximum: int) -> dict[str, object]:
    try:
        if type(source) is not str or not 1 <= len(source.encode("ascii")) <= maximum:
            raise ValueError
        source = cast(str, source)
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in source):
            raise ValueError

        def pairs(values):
            result = {}
            for key, item in values:
                if type(key) is not str or key in result:
                    raise ValueError
                result[key] = item
            return result

        value = json.loads(source, object_pairs_hook=pairs)
        if type(value) is not dict or set(value) != fields or _canonical(value) != source:
            raise ValueError
        return cast(dict[str, object], value)
    except Exception:
        _deny()


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64(value) is None:
        _deny()
    return cast(str, value)


def _hex128(value: object) -> str:
    if type(value) is not str or _HEX128(value) is None:
        _deny()
    return cast(str, value)


def _integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER or positive and value == 0:
        _deny()
    return cast(int, value)


def _version(value: object, expected: int) -> int:
    normalized = _integer(value, positive=True)
    if normalized != expected:
        _deny()
    return normalized


def _subject(value: object) -> str:
    # The canonical participant form used by this cross-repository wire is
    # exactly 32 lowercase hexadecimal x-only bytes.
    return _hex64(value)


def _canonical_ipv6_hex(address: ipaddress.IPv6Address) -> str:
    # Freeze pure-hex RFC 5952 spelling, including IPv4-mapped addresses.
    value = int(address)
    groups = [(value >> shift) & 0xFFFF for shift in range(112, -1, -16)]
    best_start = best_length = run_start = run_length = 0
    for index, group in enumerate(groups):
        if group == 0:
            if run_length == 0:
                run_start = index
            run_length += 1
            # Strictly longer preserves the first run when lengths tie.
            if run_length > best_length:
                best_start, best_length = run_start, run_length
        else:
            run_length = 0
    encoded = [format(group, "x") for group in groups]
    if best_length < 2:
        return ":".join(encoded)
    return ":".join(encoded[:best_start]) + "::" + ":".join(encoded[best_start + best_length :])


def _audience(value: object) -> str:
    # Frozen HTTPS-origin grammar shared with Social; no URL/IDNA normalization.
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
            # No zone identifiers or dotted IPv4 tails; compare canonical hex.
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
        _deny()


def _canonical_handle(value: object) -> str:
    try:
        if type(value) is not str or _HANDLE(value) is None:
            raise ValueError
        raw = base64.urlsafe_b64decode(value[2:] + "==")
        if len(raw) != 16 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value[2:]:
            raise ValueError
        return cast(str, value)
    except Exception:
        _deny()


def _digest(domain: str, source: str) -> str:
    return hashlib.sha256((domain + "\0" + source).encode("ascii")).hexdigest()


def _request(source: object) -> dict[str, object]:
    value = _closed_json(source, _REQUEST_FIELDS, 2048)
    _version(value["version"], 1)
    _audience(value["audience"])
    for field in ("bindingId", "deviceId", "sessionBinding"):
        _hex64(value[field])
    _subject(value["subject"])
    binding_version = _integer(value["bindingVersion"], positive=True)
    if binding_version > 1024:
        _deny()
    if (
        value["schema"] != DEVICE_REQUEST_SCHEMA
        or value["version"] != 1
        or value["method"] != "POST"
        or type(value["path"]) is not str
        or len(value["path"]) > 160
        or _PATH(value["path"]) is None
        or type(value["bodyDigest"]) is not str
        or _BODY_DIGEST(value["bodyDigest"]) is None
    ):
        _deny()
    if value["operation"] == "ciphertext-submit":
        if value["recipientHandle"] is not None:
            _deny()
    elif value["operation"] == "recipient-self-read":
        _canonical_handle(value["recipientHandle"])
    else:
        _deny()
    return value


def _challenge(source: object) -> dict[str, object]:
    value = _closed_json(source, _CHALLENGE_FIELDS, 4096)
    _version(value["version"], 1)
    issued_at = _integer(value["issuedAt"])
    expires_at = _integer(value["expiresAt"])
    if (
        value["schema"] != DEVICE_CHALLENGE_SCHEMA
        or value["version"] != 1
        or value["domain"] != DEVICE_CHALLENGE_DOMAIN
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_CHALLENGE_LIFETIME_MS
    ):
        _deny()
    _hex64(value["challengeId"])
    _request(value["request"])
    return value


def parse_device_proof_v1(source: object) -> dict[str, object]:
    value = _closed_json(source, _PROOF_FIELDS, 1024)
    _version(value["version"], 1)
    if (
        value["algorithm"] != DEVICE_PROOF_ALGORITHM
        or value["profile"] != DEVICE_PROOF_PROFILE
        or value["schema"] != DEVICE_PROOF_SCHEMA
        or value["version"] != 1
    ):
        _deny()
    _hex64(value["challengeId"])
    _hex64(value["publicKey"])
    _hex128(value["signature"])
    return value


def canonical_device_proof_v1_bytes(
    *,
    challenge_id: object,
    public_key: object,
    signature: object,
) -> bytes:
    source = _canonical(
        {
            "algorithm": DEVICE_PROOF_ALGORITHM,
            "challengeId": challenge_id,
            "profile": DEVICE_PROOF_PROFILE,
            "publicKey": public_key,
            "schema": DEVICE_PROOF_SCHEMA,
            "signature": signature,
            "version": 1,
        }
    )
    parse_device_proof_v1(source)
    return source.encode("ascii")


def canonical_device_proof_signing_preimage_v1(
    stored_challenge_wire: object,
    public_key: object,
) -> bytes:
    _challenge(stored_challenge_wire)
    normalized_key = _hex64(public_key)
    return _canonical(
        {
            "challenge": stored_challenge_wire,
            "domain": DEVICE_PROOF_DOMAIN,
            "profile": DEVICE_PROOF_PROFILE,
            "publicKey": normalized_key,
            "schema": DEVICE_PROOF_PREIMAGE_SCHEMA,
            "version": 1,
        }
    ).encode("ascii")


def inspect_device_proof_shape_v1(
    *,
    stored_challenge_wire: object,
    actual_request_wire: object,
    proof_wire: object,
    expected_public_key: object,
    now: object,
) -> DeviceProofShapeResult:
    challenge = _challenge(stored_challenge_wire)
    _request(actual_request_wire)
    normalized_now = _integer(now)
    proof = parse_device_proof_v1(proof_wire)
    expected_key = _hex64(expected_public_key)
    challenge_issued_at = _integer(challenge["issuedAt"])
    challenge_expires_at = _integer(challenge["expiresAt"])
    challenge_id = _hex64(challenge["challengeId"])
    proof_challenge_id = _hex64(proof["challengeId"])
    proof_public_key = _hex64(proof["publicKey"])
    if (
        challenge["request"] != actual_request_wire
        or normalized_now < challenge_issued_at
        or normalized_now >= challenge_expires_at
        or proof_challenge_id != challenge_id
        or proof_public_key != expected_key
    ):
        _deny()
    return DeviceProofShapeResult(
        canonical_structure_validity="valid",
        strict_ed25519_cryptographic_validity="not_evaluated_by_ubid",
        current_device_key_association_validity="not_evaluated",
        atomic_challenge_consumption="not_implemented",
        final_admission="denied",
        proof_profile=DEVICE_PROOF_PROFILE,
        challenge_id=proof_challenge_id,
        public_key=proof_public_key,
    )


def x25519_public_key_commitment_v1(public_key: object) -> str:
    try:
        normalized = validate_x25519_public_key(public_key)
    except Exception:
        _deny()
    return "hodlxxi-social-messaging-x25519-public-key-v1-sha256:" + _digest(
        "HODLXXI_SOCIAL_MESSAGING_X25519_PUBLIC_KEY_COMMITMENT_V1",
        normalized,
    )


def parse_enrollment_v2(source: object) -> EnrollmentV2Record:
    value = _closed_json(source, _ENROLLMENT_FIELDS, 4096)
    _version(value["version"], 2)
    issued_at = _integer(value["issuedAt"])
    expires_at = _integer(value["expiresAt"])
    binding_version = _integer(value["x25519BindingVersion"], positive=True)
    subject = _subject(value["subject"])
    public_key = _hex64(value["ed25519PublicKey"])
    commitment_value = value["x25519PublicKeyCommitment"]
    if (
        value["schema"] != ENROLLMENT_V2_SCHEMA
        or value["version"] != 2
        or value["domain"] != ENROLLMENT_V2_DOMAIN
        or value["profile"] != DEVICE_PROOF_PROFILE
        or binding_version > 1024
        or type(commitment_value) is not str
        or _X25519_COMMITMENT(commitment_value) is None
        or public_key == subject
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_ENROLLMENT_LIFETIME_MS
    ):
        _deny()
    return EnrollmentV2Record(
        audience=_audience(value["audience"]),
        device_id=_hex64(value["deviceId"]),
        ed25519_public_key=public_key,
        enrollment_challenge_id=_hex64(value["enrollmentChallengeId"]),
        expires_at=expires_at,
        issued_at=issued_at,
        subject=subject,
        x25519_binding_id=_hex64(value["x25519BindingId"]),
        x25519_binding_version=binding_version,
        x25519_public_key_commitment=cast(str, commitment_value),
    )


def canonical_enrollment_v2_bytes(
    *,
    audience: object,
    device_id: object,
    ed25519_public_key: object,
    enrollment_challenge_id: object,
    expires_at: object,
    issued_at: object,
    subject: object,
    x25519_binding_id: object,
    x25519_binding_version: object,
    x25519_public_key_commitment: object,
) -> bytes:
    source = _canonical(
        {
            "audience": audience,
            "deviceId": device_id,
            "domain": ENROLLMENT_V2_DOMAIN,
            "ed25519PublicKey": ed25519_public_key,
            "enrollmentChallengeId": enrollment_challenge_id,
            "expiresAt": expires_at,
            "issuedAt": issued_at,
            "profile": DEVICE_PROOF_PROFILE,
            "schema": ENROLLMENT_V2_SCHEMA,
            "subject": subject,
            "version": 2,
            "x25519BindingId": x25519_binding_id,
            "x25519BindingVersion": x25519_binding_version,
            "x25519PublicKeyCommitment": x25519_public_key_commitment,
        }
    )
    parse_enrollment_v2(source)
    return source.encode("ascii")


def enrollment_v2_digest(source: object) -> str:
    parse_enrollment_v2(source)
    source = cast(str, source)
    return "hodlxxi-social-messaging-device-enrollment-v2-sha256:" + _digest(
        "HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2",
        source,
    )


def canonical_enrollment_proof_signing_preimage_v2(source: object) -> bytes:
    value = parse_enrollment_v2(source)
    source = cast(str, source)
    return _canonical(
        {
            "domain": ENROLLMENT_V2_PROOF_DOMAIN,
            "enrollment": source,
            "profile": DEVICE_PROOF_PROFILE,
            "publicKey": value.ed25519_public_key,
            "schema": ENROLLMENT_V2_PROOF_PREIMAGE_SCHEMA,
            "version": 2,
        }
    ).encode("ascii")


def parse_enrollment_proof_v2(source: object) -> EnrollmentProofV2Record:
    value = _closed_json(source, _ENROLLMENT_PROOF_FIELDS, 1024)
    _version(value["version"], 2)
    digest_value = value["enrollmentDigest"]
    if (
        value["algorithm"] != DEVICE_PROOF_ALGORITHM
        or value["profile"] != DEVICE_PROOF_PROFILE
        or value["schema"] != ENROLLMENT_V2_PROOF_SCHEMA
        or value["version"] != 2
        or type(digest_value) is not str
        or _ENROLLMENT_DIGEST(digest_value) is None
    ):
        _deny()
    return EnrollmentProofV2Record(
        enrollment_challenge_id=_hex64(value["enrollmentChallengeId"]),
        enrollment_digest=cast(str, digest_value),
        public_key=_hex64(value["publicKey"]),
        signature=_hex128(value["signature"]),
    )


def canonical_enrollment_proof_v2_bytes(
    *,
    enrollment_challenge_id: object,
    enrollment_digest: object,
    public_key: object,
    signature: object,
) -> bytes:
    source = _canonical(
        {
            "algorithm": DEVICE_PROOF_ALGORITHM,
            "enrollmentChallengeId": enrollment_challenge_id,
            "enrollmentDigest": enrollment_digest,
            "profile": DEVICE_PROOF_PROFILE,
            "publicKey": public_key,
            "schema": ENROLLMENT_V2_PROOF_SCHEMA,
            "signature": signature,
            "version": 2,
        }
    )
    parse_enrollment_proof_v2(source)
    return source.encode("ascii")


def enrollment_approval_unsigned_event_v2(source: object) -> dict[str, object]:
    value = parse_enrollment_v2(source)
    return {
        "content": source,
        "created_at": value.issued_at // 1000,
        "kind": 27236,
        "tags": [
            ["purpose", ENROLLMENT_V2_APPROVAL_PURPOSE],
            ["enrollment-digest", enrollment_v2_digest(source)],
            ["challenge-id", value.enrollment_challenge_id],
            ["device-id", value.device_id],
        ],
    }


__all__ = [
    "ATOMIC_CHALLENGE_OWNER",
    "AUTH_KEY_ROTATION_INVALIDATES_OUTSTANDING_CHALLENGES",
    "AUTH_KEY_ROTATION_INVALIDATES_PREDECESSOR",
    "DEVICE_PROOF_ALGORITHM",
    "DEVICE_PROOF_PROFILE",
    "DEVICE_PROOF_RUNTIME_ENABLED",
    "ENROLLMENT_V2_EXISTING_DEVICES_REQUIRE_REENROLLMENT",
    "ENROLLMENT_V2_RUNTIME_ENABLED",
    "FINAL_ADMISSION_OWNER",
    "FINAL_AUTHORITY_MODEL",
    "DeviceProofShapeResult",
    "EnrollmentProofV2Record",
    "EnrollmentV2Record",
    "SocialMessagingDeviceProofUnavailable",
    "canonical_device_proof_signing_preimage_v1",
    "canonical_device_proof_v1_bytes",
    "canonical_enrollment_proof_v2_bytes",
    "canonical_enrollment_proof_signing_preimage_v2",
    "canonical_enrollment_v2_bytes",
    "enrollment_approval_unsigned_event_v2",
    "enrollment_v2_digest",
    "inspect_device_proof_shape_v1",
    "parse_device_proof_v1",
    "parse_enrollment_proof_v2",
    "parse_enrollment_v2",
    "x25519_public_key_commitment_v1",
]
