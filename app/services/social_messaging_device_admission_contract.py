"""Dormant pure contracts for final Social messaging device admission.

This module freezes canonical bytes, state vocabulary, and typed future ports.
It performs no I/O, verifies no RSA or participant signature, consumes no
challenge, applies no operation effect, and never grants final admission.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, NoReturn, Protocol, cast

from app.services.social_messaging_device_proof_profile import (
    DEVICE_PROOF_PROFILE,
    EnrollmentProofV2Record,
    EnrollmentV2Record,
    enrollment_approval_unsigned_event_v2,
    enrollment_v2_digest,
    parse_device_proof_v1,
    parse_enrollment_proof_v2,
    parse_enrollment_v2,
)

VERSION = 1
MAX_SAFE_INTEGER = 9_007_199_254_740_991

VERIFICATION_CONTEXT_SCHEMA = "hodlxxi.social_device_verification_context.v1"
VERIFICATION_INPUT_SCHEMA = "hodlxxi.social_device_verification_input.v1"
VERIFICATION_STATEMENT_SCHEMA = "hodlxxi.social_device_verification_statement.v1"
ADMISSION_RECEIPT_SCHEMA = "hodlxxi.social_device_admission_receipt.v1"
COMMAND_SCHEMA = "hodlxxi.social_device_admission_command.v1"
RESPONSE_SCHEMA = "hodlxxi.social_device_admission_response.v1"

CONTEXT_DIGEST_PREFIX = "hodlxxi-social-device-verification-context-v1-sha256:"
CONTEXT_DIGEST_DOMAIN = "HODLXXI_SOCIAL_DEVICE_VERIFICATION_CONTEXT_V1"
INPUT_DIGEST_PREFIX = "hodlxxi-social-device-verification-input-v1-sha256:"
INPUT_DIGEST_DOMAIN = "HODLXXI_SOCIAL_DEVICE_VERIFICATION_INPUT_V1"

STATEMENT_ALGORITHM = "RS256"
STATEMENT_TYPE = "hodlxxi-social-device-verification+jws"
STATEMENT_PURPOSE = "social_device_cryptographic_verification_v1"
STRICT_ED25519_RESULT = "strict-ed25519-valid"
ENROLLMENT_V2_RESULT = "enrollment-v2-ed25519-and-nostr-valid"

MAX_CONTEXT_BYTES = 4_096
MAX_INPUT_BYTES = 24_576
MAX_STATEMENT_BYTES = 4_096
MAX_CHALLENGE_BYTES = 4_096
MAX_PROOF_BYTES = 1_024
MAX_APPROVAL_EVENT_BYTES = 8_192
MAX_ACTUAL_REQUEST_BYTES = 2_048
MAX_ROUTING_REQUEST_BYTES = 2_048
MAX_STATEMENT_LIFETIME_MS = 10_000

ADMISSION_PREFIX = "/internal/v1/social/device-admission"
CONSUME_PATH = ADMISSION_PREFIX + "/consume"
RUNTIME_ENABLED = False
CRYPTOGRAPHIC_VERIFICATION = "not_evaluated"
CURRENT_AUTHORITY = "not_evaluated"
CHALLENGE_CONSUMPTION = "not_implemented"
OPERATION_EFFECT = "not_implemented"
FINAL_ADMISSION = "denied"
ATOMIC_OWNER = "ubid_selected_not_implemented"
UNAVAILABLE_MESSAGE = "social messaging device admission unavailable"

CHALLENGE_KINDS = ("enrollment-v2", "device-request-v1")
OPERATIONS = ("enrollment-activate", "ciphertext-submit", "recipient-self-read")
ENROLLMENT_STATES = ("prepared", "challenged", "consumed", "cancelled", "expired", "invalidated")
CHALLENGE_STATES = ("issued", "consumed", "expired", "invalidated", "cancelled")
ASSOCIATION_STATES = ("active", "rotated", "revoked", "expired")
RECEIPT_STATES = ("committed",)
ENROLLMENT_TERMINAL_STATES = frozenset(("consumed", "cancelled", "expired", "invalidated"))
CHALLENGE_TERMINAL_STATES = frozenset(("consumed", "expired", "invalidated", "cancelled"))
ASSOCIATION_TERMINAL_STATES = frozenset(("rotated", "revoked", "expired"))

ENROLLMENT_TRANSITIONS = MappingProxyType(
    {
        "prepared": frozenset(("challenged", "cancelled", "expired", "invalidated")),
        "challenged": frozenset(("consumed", "cancelled", "expired", "invalidated")),
        "consumed": frozenset(),
        "cancelled": frozenset(),
        "expired": frozenset(),
        "invalidated": frozenset(),
    }
)
CHALLENGE_TRANSITIONS = MappingProxyType(
    {
        "issued": frozenset(("consumed", "expired", "invalidated", "cancelled")),
        "consumed": frozenset(),
        "expired": frozenset(),
        "invalidated": frozenset(),
        "cancelled": frozenset(),
    }
)
ASSOCIATION_TRANSITIONS = MappingProxyType(
    {
        "active": frozenset(("rotated", "revoked", "expired")),
        "rotated": frozenset(),
        "revoked": frozenset(),
        "expired": frozenset(),
    }
)
RECEIPT_TRANSITIONS = MappingProxyType({None: frozenset(("committed",)), "committed": frozenset()})

_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_HEX128 = re.compile(r"[0-9a-f]{128}\Z").fullmatch
_CONFIGURED_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z").fullmatch
_CONTEXT_DIGEST = re.compile(r"hodlxxi-social-device-verification-context-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_INPUT_DIGEST = re.compile(r"hodlxxi-social-device-verification-input-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_X25519_COMMITMENT = re.compile(r"hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_FULL_PROOF_ID = re.compile(r"hodlxxi-full-entitlement-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_BODY_DIGEST = re.compile(r"hodlxxi-social-device-request-body-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_HANDLE = re.compile(r"d_[A-Za-z0-9_-]{22}\Z").fullmatch
_MESSAGE_ID = re.compile(r"m_[A-Za-z0-9_-]{43}\Z").fullmatch
_ENVELOPE_DIGEST = re.compile(r"hodlxxi-social-message-envelope-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_SNAPSHOT_ID = re.compile(r"sha256:[0-9a-f]{64}\Z").fullmatch
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z").fullmatch

_CONTEXT_FIELDS = {
    "approverFullProofId",
    "approverSessionBinding",
    "associationId",
    "associationVersion",
    "attemptId",
    "audience",
    "authorityEpoch",
    "bindingId",
    "bindingVersion",
    "challengeId",
    "challengeKind",
    "deviceId",
    "ed25519PublicKey",
    "fullProofId",
    "predecessorAssociationId",
    "profile",
    "schema",
    "sessionBinding",
    "subject",
    "version",
    "x25519PublicKeyCommitment",
}
_INPUT_FIELDS = {
    "actualRequest",
    "approvalEvent",
    "challenge",
    "context",
    "proof",
    "routingRequest",
    "schema",
    "version",
}
_HEADER_FIELDS = {"alg", "kid", "typ"}
_STATEMENT_FIELDS = {
    "aud",
    "attemptId",
    "challengeId",
    "challengeKind",
    "clientId",
    "contextDigest",
    "expiresAt",
    "inputDigest",
    "iss",
    "issuedAt",
    "jti",
    "purpose",
    "result",
    "schema",
    "servicePrincipal",
    "version",
}
_RECEIPT_FIELDS = {"challengeId", "decidedAt", "operation", "receiptId", "schema", "status", "version"}
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
_ROUTING_FIELDS = {
    "envelopeDigest",
    "messageId",
    "recipientDeviceHandles",
    "recipientPackageSnapshotId",
    "schema",
    "version",
}
_APPROVAL_FIELDS = {"content", "created_at", "id", "kind", "pubkey", "sig", "tags"}


class SocialMessagingDeviceAdmissionUnavailable(ValueError):
    """The only failure exposed by this pure contract boundary."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True, slots=True)
class VerificationContextV1:
    wire: str
    challenge_kind: str
    challenge_id: str
    attempt_id: str
    audience: str
    subject: str
    device_id: str
    binding_id: str
    binding_version: int
    x25519_public_key_commitment: str
    profile: str
    ed25519_public_key: str
    association_id: str
    association_version: int
    predecessor_association_id: str | None
    authority_epoch: int
    session_binding: str
    approver_session_binding: str | None
    full_proof_id: str
    approver_full_proof_id: str | None


@dataclass(frozen=True, slots=True)
class VerificationInputV1:
    wire: str
    context: VerificationContextV1
    challenge_wire: str
    proof_wire: str
    approval_event_wire: str | None
    actual_request_wire: str | None
    routing_request_wire: str | None
    operation: str


@dataclass(frozen=True, slots=True)
class VerificationStatementClaimsV1:
    issuer: str
    audience: str
    client_id: str
    service_principal: str
    result: str
    challenge_kind: str
    challenge_id: str
    attempt_id: str
    context_digest: str
    input_digest: str
    issued_at: int
    expires_at: int
    token_id: str


@dataclass(frozen=True, slots=True)
class VerificationStatementInspectionV1:
    protected_header_wire: str
    payload_wire: str
    signing_input: bytes
    signature: bytes
    claims: VerificationStatementClaimsV1
    canonical_structure: str = field(default="valid", init=False)
    rsa_signature_verification: str = field(default=CRYPTOGRAPHIC_VERIFICATION, init=False)
    cryptographic_verification: str = field(default=CRYPTOGRAPHIC_VERIFICATION, init=False)
    current_authority: str = field(default=CURRENT_AUTHORITY, init=False)
    challenge_consumption: str = field(default=CHALLENGE_CONSUMPTION, init=False)
    operation_effect: str = field(default=OPERATION_EFFECT, init=False)
    final_admission: str = field(default=FINAL_ADMISSION, init=False)
    runtime_enabled: bool = field(default=RUNTIME_ENABLED, init=False)
    atomic_owner: str = field(default=ATOMIC_OWNER, init=False)


@dataclass(frozen=True, slots=True)
class AdmissionReceiptV1:
    receipt_id: str
    challenge_id: str
    operation: str
    decided_at: int
    status: str = "committed"


@dataclass(frozen=True, slots=True)
class ReceiptInspectionV1:
    receipt: AdmissionReceiptV1
    bearer_authority: str = field(default="none", init=False)
    reexecution_authority: str = field(default="none", init=False)
    final_admission: str = field(default=FINAL_ADMISSION, init=False)


@dataclass(frozen=True, slots=True)
class StateTransitionV1:
    machine: str
    previous_state: str | None
    next_state: str
    terminal_after_transition: bool
    commit_claim: str = field(default="not_evaluated", init=False)
    rollback_claim: str = field(default="not_evaluated", init=False)


@dataclass(frozen=True, slots=True)
class ExclusiveDeadlineInspectionV1:
    issued_at: int
    expires_at: int
    observed_at: int
    disposition: str
    expiry_semantics: str = field(default="exclusive_no_skew", init=False)


@dataclass(frozen=True, slots=True)
class AtomicOwnerInspectionV1:
    owner: str = field(default="ubid", init=False)
    implementation: str = field(default="selected_not_implemented", init=False)
    transaction_effect: str = field(default=OPERATION_EFFECT, init=False)
    challenge_consumption: str = field(default=CHALLENGE_CONSUMPTION, init=False)
    final_admission: str = field(default=FINAL_ADMISSION, init=False)
    rollback_claim: str = field(default="no_effect_or_receipt_or_consumption_commit", init=False)
    commit_claim: str = field(default="durable_publication_not_implemented", init=False)
    deadlock_outcome: str = field(default="deny_and_roll_back", init=False)
    lock_timeout_outcome: str = field(default="deny_and_roll_back", init=False)
    uncertain_commit_outcome: str = field(default="reconcile_history_never_reexecute", init=False)


@dataclass(frozen=True, slots=True)
class AdmissionRouteContractV1:
    path: str
    command: str
    command_fields: tuple[str, ...]
    response_kind: str
    response_fields: tuple[str, ...]
    response_maximum: int


@dataclass(frozen=True, slots=True)
class ParsedAdmissionCommandV1:
    route: AdmissionRouteContractV1
    values: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class ParsedAdmissionResponseV1:
    route: AdmissionRouteContractV1
    values: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class StoredAdmissionChallengeV1:
    context: VerificationContextV1
    challenge_wire: str
    state: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True, slots=True)
class AuthenticatedVerificationStatementV1:
    """Future verifier output; shape inspection cannot construct authority."""

    claims: VerificationStatementClaimsV1
    statement_digest: str
    trust_registration_id: str


@dataclass(frozen=True, slots=True)
class CurrentAdmissionAuthorityV1:
    context_digest: str
    authority_epoch: int
    locked_deadline_ms: int
    full_proof_id: str
    approver_full_proof_id: str | None


@dataclass(frozen=True, slots=True)
class PreparedAdmissionEffectV1:
    operation: str
    effect_id: str
    effect_digest: str


class ChallengeStorageOwner(Protocol):
    def lock_issued_challenge_for_consumption(self, challenge_id: str) -> StoredAdmissionChallengeV1: ...

    def record_consumed_challenge_transition(
        self,
        challenge: StoredAdmissionChallengeV1,
        transition: StateTransitionV1,
        receipt: AdmissionReceiptV1,
    ) -> StoredAdmissionChallengeV1: ...

    def record_non_consumed_terminal_challenge_transition(
        self,
        challenge: StoredAdmissionChallengeV1,
        transition: StateTransitionV1,
    ) -> StoredAdmissionChallengeV1: ...


class AuthenticatedSocialVerificationStatementVerifier(Protocol):
    def authenticate_for_consumption(
        self,
        statement: str,
        *,
        expected_context_digest: str,
        expected_input_digest: str,
        observed_at: int,
    ) -> AuthenticatedVerificationStatementV1: ...


class TransactionBoundAdmissionAuthority(Protocol):
    def lock_current_authority(
        self,
        context: VerificationContextV1,
        *,
        observed_at: int,
    ) -> CurrentAdmissionAuthorityV1: ...


class ExactAtomicOperationEffectPort(Protocol):
    def prepare_exact_effect_in_transaction(
        self,
        value: VerificationInputV1,
        authority: CurrentAdmissionAuthorityV1,
        statement: AuthenticatedVerificationStatementV1,
    ) -> PreparedAdmissionEffectV1: ...


class ReceiptHistoryProjection(Protocol):
    def read_committed_receipt(self, challenge_id: str) -> AdmissionReceiptV1 | None: ...


def _deny() -> NoReturn:
    raise SocialMessagingDeviceAdmissionUnavailable()


def _canonical(value: Mapping[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _closed_json(source: object, fields: set[str], maximum: int) -> dict[str, object]:
    try:
        if type(source) is not str:
            raise ValueError
        encoded = source.encode("ascii")
        if not 1 <= len(encoded) <= maximum or any(byte < 0x20 or byte > 0x7E for byte in encoded):
            raise ValueError

        def pairs(items):
            result = {}
            for key, value in items:
                if type(key) is not str or key in result:
                    raise ValueError
                result[key] = value
            return result

        def invalid_constant(_value):
            raise ValueError

        value = json.loads(source, object_pairs_hook=pairs, parse_constant=invalid_constant)
        if type(value) is not dict or set(value) != fields or _canonical(value) != source:
            raise ValueError
        return cast(dict[str, object], value)
    except Exception:
        _deny()


def _ascii_string(value: object, *, maximum: int, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    try:
        if type(value) is not str:
            raise ValueError
        encoded = value.encode("ascii")
        if not 1 <= len(encoded) <= maximum or any(byte < 0x20 or byte > 0x7E for byte in encoded):
            raise ValueError
        return value
    except Exception:
        _deny()


def _integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER or positive and value == 0:
        _deny()
    return cast(int, value)


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64(value) is None:
        _deny()
    return cast(str, value)


def _hex128(value: object) -> str:
    if type(value) is not str or _HEX128(value) is None:
        _deny()
    return cast(str, value)


def _configured_identifier(value: object) -> str:
    if type(value) is not str or _CONFIGURED_IDENTIFIER(value) is None:
        _deny()
    return cast(str, value)


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


def _audience(value: object) -> str:
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
        _deny()


def _statement_audience(value: object) -> str:
    if type(value) is not str or not value.endswith(CONSUME_PATH):
        _deny()
    origin = value[: -len(CONSUME_PATH)]
    _audience(origin)
    return value


def _canonical_token(value: object, *, prefix: str, encoded_length: int, decoded_length: int) -> str:
    try:
        if type(value) is not str or not value.startswith(prefix):
            raise ValueError
        encoded = value[len(prefix) :]
        if len(encoded) != encoded_length or _BASE64URL(encoded) is None:
            raise ValueError
        raw = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        if len(raw) != decoded_length or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != encoded:
            raise ValueError
        return value
    except Exception:
        _deny()


def _digest(prefix: str, domain: str, source: str) -> str:
    return prefix + hashlib.sha256(domain.encode("ascii") + b"\0" + source.encode("ascii")).hexdigest()


def verification_context_digest_v1(context_wire: object) -> str:
    parse_verification_context_v1(context_wire)
    return _digest(CONTEXT_DIGEST_PREFIX, CONTEXT_DIGEST_DOMAIN, cast(str, context_wire))


def verification_input_digest_v1(input_wire: object) -> str:
    parse_verification_input_v1(input_wire)
    return _digest(INPUT_DIGEST_PREFIX, INPUT_DIGEST_DOMAIN, cast(str, input_wire))


def parse_verification_context_v1(source: object) -> VerificationContextV1:
    value = _closed_json(source, _CONTEXT_FIELDS, MAX_CONTEXT_BYTES)
    if (
        value["schema"] != VERIFICATION_CONTEXT_SCHEMA
        or value["version"] != VERSION
        or type(value["version"]) is not int
    ):
        _deny()
    challenge_kind = value["challengeKind"]
    if type(challenge_kind) is not str or challenge_kind not in CHALLENGE_KINDS:
        _deny()
    binding_version = _integer(value["bindingVersion"], positive=True)
    association_version = _integer(value["associationVersion"], positive=True)
    authority_epoch = _integer(value["authorityEpoch"], positive=True)
    if binding_version > 1_024:
        _deny()
    commitment = value["x25519PublicKeyCommitment"]
    full_proof = value["fullProofId"]
    if (
        type(commitment) is not str
        or _X25519_COMMITMENT(commitment) is None
        or value["profile"] != DEVICE_PROOF_PROFILE
        or type(full_proof) is not str
        or _FULL_PROOF_ID(full_proof) is None
    ):
        _deny()
    predecessor = value["predecessorAssociationId"]
    approver_session = value["approverSessionBinding"]
    approver_full = value["approverFullProofId"]
    if challenge_kind == "device-request-v1":
        if predecessor is not None or approver_session is not None or approver_full is not None:
            _deny()
    else:
        if (predecessor is None and association_version != 1) or (predecessor is not None and association_version <= 1):
            _deny()
        if predecessor is None and authority_epoch != 1:
            _deny()
        predecessor = None if predecessor is None else _hex64(predecessor)
        approver_session = _hex64(approver_session)
        if type(approver_full) is not str or _FULL_PROOF_ID(approver_full) is None:
            _deny()
    return VerificationContextV1(
        wire=cast(str, source),
        challenge_kind=challenge_kind,
        challenge_id=_hex64(value["challengeId"]),
        attempt_id=_hex64(value["attemptId"]),
        audience=_audience(value["audience"]),
        subject=_hex64(value["subject"]),
        device_id=_hex64(value["deviceId"]),
        binding_id=_hex64(value["bindingId"]),
        binding_version=binding_version,
        x25519_public_key_commitment=cast(str, commitment),
        profile=DEVICE_PROOF_PROFILE,
        ed25519_public_key=_hex64(value["ed25519PublicKey"]),
        association_id=_hex64(value["associationId"]),
        association_version=association_version,
        predecessor_association_id=cast(str | None, predecessor),
        authority_epoch=authority_epoch,
        session_binding=_hex64(value["sessionBinding"]),
        approver_session_binding=cast(str | None, approver_session),
        full_proof_id=cast(str, full_proof),
        approver_full_proof_id=cast(str | None, approver_full),
    )


def canonical_verification_context_v1_bytes(
    *,
    challenge_kind: object,
    challenge_id: object,
    attempt_id: object,
    audience: object,
    subject: object,
    device_id: object,
    binding_id: object,
    binding_version: object,
    x25519_public_key_commitment: object,
    profile: object,
    ed25519_public_key: object,
    association_id: object,
    association_version: object,
    predecessor_association_id: object,
    authority_epoch: object,
    session_binding: object,
    approver_session_binding: object,
    full_proof_id: object,
    approver_full_proof_id: object,
) -> bytes:
    source = _canonical(
        {
            "approverFullProofId": approver_full_proof_id,
            "approverSessionBinding": approver_session_binding,
            "associationId": association_id,
            "associationVersion": association_version,
            "attemptId": attempt_id,
            "audience": audience,
            "authorityEpoch": authority_epoch,
            "bindingId": binding_id,
            "bindingVersion": binding_version,
            "challengeId": challenge_id,
            "challengeKind": challenge_kind,
            "deviceId": device_id,
            "ed25519PublicKey": ed25519_public_key,
            "fullProofId": full_proof_id,
            "predecessorAssociationId": predecessor_association_id,
            "profile": profile,
            "schema": VERIFICATION_CONTEXT_SCHEMA,
            "sessionBinding": session_binding,
            "subject": subject,
            "version": VERSION,
            "x25519PublicKeyCommitment": x25519_public_key_commitment,
        }
    )
    parse_verification_context_v1(source)
    return source.encode("ascii")


def _parse_request(source: object) -> dict[str, object]:
    value = _closed_json(source, _REQUEST_FIELDS, MAX_ACTUAL_REQUEST_BYTES)
    if (
        value["schema"] != "hodlxxi.social_messaging_device_request_candidate.v1"
        or value["version"] != VERSION
        or type(value["version"]) is not int
        or value["method"] != "POST"
        or type(value["bodyDigest"]) is not str
        or _BODY_DIGEST(value["bodyDigest"]) is None
    ):
        _deny()
    _audience(value["audience"])
    for field_name in ("bindingId", "deviceId", "sessionBinding", "subject"):
        _hex64(value[field_name])
    binding_version = _integer(value["bindingVersion"], positive=True)
    if binding_version > 1_024:
        _deny()
    if value["operation"] == "ciphertext-submit":
        if value["path"] != "/messaging/v1/ciphertext-submit" or value["recipientHandle"] is not None:
            _deny()
    elif value["operation"] == "recipient-self-read":
        if value["path"] != "/messaging/v1/recipient-self-read":
            _deny()
        _canonical_token(value["recipientHandle"], prefix="d_", encoded_length=22, decoded_length=16)
    else:
        _deny()
    return value


def _parse_request_challenge(source: object) -> tuple[dict[str, object], dict[str, object]]:
    value = _closed_json(source, _CHALLENGE_FIELDS, MAX_CHALLENGE_BYTES)
    issued_at = _integer(value["issuedAt"])
    expires_at = _integer(value["expiresAt"])
    if (
        value["schema"] != "hodlxxi.social_messaging_device_challenge_candidate.v1"
        or value["version"] != VERSION
        or type(value["version"]) is not int
        or value["domain"] != "HODLXXI_SOCIAL_MESSAGING_DEVICE_REQUEST_CHALLENGE_V1"
        or expires_at <= issued_at
        or expires_at - issued_at > 60_000
    ):
        _deny()
    _hex64(value["challengeId"])
    request = _parse_request(value["request"])
    return value, request


def _validate_enrollment_challenge_context_binding(
    challenge_wire: object,
    context: VerificationContextV1,
) -> EnrollmentV2Record:
    enrollment = parse_enrollment_v2(challenge_wire)
    if (
        context.challenge_kind != "enrollment-v2"
        or enrollment.enrollment_challenge_id != context.challenge_id
        or enrollment.audience != context.audience
        or enrollment.subject != context.subject
        or enrollment.device_id != context.device_id
        or enrollment.x25519_binding_id != context.binding_id
        or enrollment.x25519_binding_version != context.binding_version
        or enrollment.x25519_public_key_commitment != context.x25519_public_key_commitment
        or enrollment.ed25519_public_key != context.ed25519_public_key
    ):
        _deny()
    return enrollment


def _validate_request_challenge_context_binding(
    challenge_wire: object,
    context: VerificationContextV1,
) -> tuple[dict[str, object], dict[str, object]]:
    challenge, request = _parse_request_challenge(challenge_wire)
    if (
        context.challenge_kind != "device-request-v1"
        or challenge["challengeId"] != context.challenge_id
        or request["audience"] != context.audience
        or request["subject"] != context.subject
        or request["deviceId"] != context.device_id
        or request["bindingId"] != context.binding_id
        or request["bindingVersion"] != context.binding_version
        or request["sessionBinding"] != context.session_binding
    ):
        _deny()
    return challenge, request


def _validate_challenge_context_binding(challenge_wire: object, context: VerificationContextV1) -> None:
    if context.challenge_kind == "enrollment-v2":
        _validate_enrollment_challenge_context_binding(challenge_wire, context)
    else:
        _validate_request_challenge_context_binding(challenge_wire, context)


def _validate_enrollment_proof_binding(
    proof_wire: object,
    *,
    enrollment: EnrollmentV2Record,
    context: VerificationContextV1,
    challenge_wire: str,
) -> EnrollmentProofV2Record:
    proof = parse_enrollment_proof_v2(proof_wire)
    if (
        proof.enrollment_challenge_id != enrollment.enrollment_challenge_id
        or proof.enrollment_challenge_id != context.challenge_id
        or proof.enrollment_digest != enrollment_v2_digest(challenge_wire)
        or proof.public_key != context.ed25519_public_key
    ):
        _deny()
    return proof


def _parse_routing_request(source: object) -> dict[str, object]:
    value = _closed_json(source, _ROUTING_FIELDS, MAX_ROUTING_REQUEST_BYTES)
    handles = value["recipientDeviceHandles"]
    if (
        value["schema"] != "hodlxxi.social_messaging_recipient_routing_request.v1"
        or value["version"] != VERSION
        or type(value["version"]) is not int
        or type(value["envelopeDigest"]) is not str
        or _ENVELOPE_DIGEST(value["envelopeDigest"]) is None
        or type(value["recipientPackageSnapshotId"]) is not str
        or _SNAPSHOT_ID(value["recipientPackageSnapshotId"]) is None
        or type(handles) is not list
        or not 1 <= len(handles) <= 16
    ):
        _deny()
    _canonical_token(value["messageId"], prefix="m_", encoded_length=43, decoded_length=32)
    normalized = tuple(_canonical_token(item, prefix="d_", encoded_length=22, decoded_length=16) for item in handles)
    if tuple(sorted(set(normalized))) != normalized:
        _deny()
    return value


def _parse_approval_event(source: object, *, context: VerificationContextV1, challenge_wire: str) -> dict[str, object]:
    value = _closed_json(source, _APPROVAL_FIELDS, MAX_APPROVAL_EVENT_BYTES)
    expected_unsigned = enrollment_approval_unsigned_event_v2(challenge_wire)
    unsigned = {field: value[field] for field in ("content", "created_at", "kind", "tags")}
    if (
        unsigned != expected_unsigned
        or value["pubkey"] != context.subject
        or type(value["created_at"]) is not int
        or type(value["kind"]) is not int
    ):
        _deny()
    event_id = _hex64(value["id"])
    _hex128(value["sig"])
    preimage = json.dumps(
        [0, value["pubkey"], value["created_at"], value["kind"], value["tags"], value["content"]],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    if hashlib.sha256(preimage.encode("ascii")).hexdigest() != event_id:
        _deny()
    return value


def _parse_verification_input_v1(source: object) -> VerificationInputV1:
    value = _closed_json(source, _INPUT_FIELDS, MAX_INPUT_BYTES)
    if value["schema"] != VERIFICATION_INPUT_SCHEMA or value["version"] != VERSION or type(value["version"]) is not int:
        _deny()
    context_wire = _ascii_string(value["context"], maximum=MAX_CONTEXT_BYTES)
    challenge_wire = _ascii_string(value["challenge"], maximum=MAX_CHALLENGE_BYTES)
    proof_wire = _ascii_string(value["proof"], maximum=MAX_PROOF_BYTES)
    approval_wire = _ascii_string(value["approvalEvent"], maximum=MAX_APPROVAL_EVENT_BYTES, nullable=True)
    actual_wire = _ascii_string(value["actualRequest"], maximum=MAX_ACTUAL_REQUEST_BYTES, nullable=True)
    routing_wire = _ascii_string(value["routingRequest"], maximum=MAX_ROUTING_REQUEST_BYTES, nullable=True)
    context = parse_verification_context_v1(context_wire)

    if context.challenge_kind == "enrollment-v2":
        if approval_wire is None or actual_wire is not None or routing_wire is not None:
            _deny()
        enrollment = _validate_enrollment_challenge_context_binding(challenge_wire, context)
        _validate_enrollment_proof_binding(
            proof_wire,
            enrollment=enrollment,
            context=context,
            challenge_wire=cast(str, challenge_wire),
        )
        _parse_approval_event(approval_wire, context=context, challenge_wire=challenge_wire)
        operation = "enrollment-activate"
    else:
        if approval_wire is not None or actual_wire is None:
            _deny()
        challenge, request = _validate_request_challenge_context_binding(challenge_wire, context)
        proof = parse_device_proof_v1(proof_wire)
        if (
            challenge["request"] != actual_wire
            or proof["challengeId"] != context.challenge_id
            or proof["profile"] != context.profile
            or proof["publicKey"] != context.ed25519_public_key
        ):
            _deny()
        operation = cast(str, request["operation"])
        if operation == "ciphertext-submit":
            if routing_wire is None:
                _deny()
            _parse_routing_request(routing_wire)
        elif routing_wire is not None:
            _deny()
    return VerificationInputV1(
        wire=cast(str, source),
        context=context,
        challenge_wire=cast(str, challenge_wire),
        proof_wire=cast(str, proof_wire),
        approval_event_wire=cast(str | None, approval_wire),
        actual_request_wire=cast(str | None, actual_wire),
        routing_request_wire=cast(str | None, routing_wire),
        operation=operation,
    )


def parse_verification_input_v1(source: object) -> VerificationInputV1:
    try:
        return _parse_verification_input_v1(source)
    except SocialMessagingDeviceAdmissionUnavailable:
        raise
    except Exception:
        _deny()


def canonical_verification_input_v1_bytes(
    *,
    context: object,
    challenge: object,
    proof: object,
    approval_event: object,
    actual_request: object,
    routing_request: object,
) -> bytes:
    source = _canonical(
        {
            "actualRequest": actual_request,
            "approvalEvent": approval_event,
            "challenge": challenge,
            "context": context,
            "proof": proof,
            "routingRequest": routing_request,
            "schema": VERIFICATION_INPUT_SCHEMA,
            "version": VERSION,
        }
    )
    parse_verification_input_v1(source)
    return source.encode("ascii")


def canonical_verification_statement_protected_header_v1_bytes(*, kid: object) -> bytes:
    source = _canonical({"alg": STATEMENT_ALGORITHM, "kid": _configured_identifier(kid), "typ": STATEMENT_TYPE})
    _parse_protected_header(source, expected_kid=cast(str, kid))
    return source.encode("ascii")


def _parse_protected_header(source: object, *, expected_kid: str) -> dict[str, object]:
    value = _closed_json(source, _HEADER_FIELDS, 1_024)
    if (
        value["alg"] != STATEMENT_ALGORITHM
        or value["typ"] != STATEMENT_TYPE
        or _configured_identifier(value["kid"]) != _configured_identifier(expected_kid)
    ):
        _deny()
    return value


def _statement_claims(value: dict[str, object]) -> VerificationStatementClaimsV1:
    if (
        value["schema"] != VERIFICATION_STATEMENT_SCHEMA
        or value["version"] != VERSION
        or type(value["version"]) is not int
        or value["purpose"] != STATEMENT_PURPOSE
        or value["challengeKind"] not in CHALLENGE_KINDS
    ):
        _deny()
    challenge_kind = cast(str, value["challengeKind"])
    result = value["result"]
    expected_result = ENROLLMENT_V2_RESULT if challenge_kind == "enrollment-v2" else STRICT_ED25519_RESULT
    if result != expected_result:
        _deny()
    context_digest = value["contextDigest"]
    input_digest = value["inputDigest"]
    if (
        type(context_digest) is not str
        or _CONTEXT_DIGEST(context_digest) is None
        or type(input_digest) is not str
        or _INPUT_DIGEST(input_digest) is None
    ):
        _deny()
    issued_at = _integer(value["issuedAt"])
    expires_at = _integer(value["expiresAt"])
    if expires_at <= issued_at or expires_at - issued_at > MAX_STATEMENT_LIFETIME_MS:
        _deny()
    return VerificationStatementClaimsV1(
        issuer=_audience(value["iss"]),
        audience=_statement_audience(value["aud"]),
        client_id=_configured_identifier(value["clientId"]),
        service_principal=_configured_identifier(value["servicePrincipal"]),
        result=cast(str, result),
        challenge_kind=challenge_kind,
        challenge_id=_hex64(value["challengeId"]),
        attempt_id=_hex64(value["attemptId"]),
        context_digest=cast(str, context_digest),
        input_digest=cast(str, input_digest),
        issued_at=issued_at,
        expires_at=expires_at,
        token_id=_hex64(value["jti"]),
    )


def canonical_verification_statement_payload_v1_bytes(
    *,
    issuer: object,
    audience: object,
    client_id: object,
    service_principal: object,
    result: object,
    challenge_kind: object,
    challenge_id: object,
    attempt_id: object,
    context_digest: object,
    input_digest: object,
    issued_at: object,
    expires_at: object,
    token_id: object,
) -> bytes:
    source = _canonical(
        {
            "aud": audience,
            "attemptId": attempt_id,
            "challengeId": challenge_id,
            "challengeKind": challenge_kind,
            "clientId": client_id,
            "contextDigest": context_digest,
            "expiresAt": expires_at,
            "inputDigest": input_digest,
            "iss": issuer,
            "issuedAt": issued_at,
            "jti": token_id,
            "purpose": STATEMENT_PURPOSE,
            "result": result,
            "schema": VERIFICATION_STATEMENT_SCHEMA,
            "servicePrincipal": service_principal,
            "version": VERSION,
        }
    )
    _statement_claims(_closed_json(source, _STATEMENT_FIELDS, 3_072))
    return source.encode("ascii")


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
        _deny()


def compact_verification_statement_v1(
    *,
    protected_header_wire: object,
    payload_wire: object,
    signature: object,
) -> str:
    try:
        if type(protected_header_wire) is not str or type(payload_wire) is not str or type(signature) is not bytes:
            raise ValueError
        if not signature:
            raise ValueError
        header = _closed_json(protected_header_wire, _HEADER_FIELDS, 1_024)
        _parse_protected_header(protected_header_wire, expected_kid=_configured_identifier(header["kid"]))
        _statement_claims(_closed_json(payload_wire, _STATEMENT_FIELDS, 3_072))
        statement = ".".join(
            (
                _base64url_encode(protected_header_wire.encode("ascii")),
                _base64url_encode(payload_wire.encode("ascii")),
                _base64url_encode(signature),
            )
        )
        if len(statement.encode("ascii")) > MAX_STATEMENT_BYTES:
            raise ValueError
        return statement
    except Exception:
        _deny()


def inspect_verification_statement_shape_v1(
    statement: object,
    *,
    expected_kid: object,
    expected_issuer: object,
    expected_audience: object,
    expected_client_id: object,
    expected_service_principal: object,
    expected_context_wire: object,
    expected_input_wire: object,
    now: object,
    challenge_expires_at: object,
    session_expires_at: object,
    approver_session_expires_at: object = None,
) -> VerificationStatementInspectionV1:
    try:
        if type(statement) is not str:
            raise ValueError
        encoded_statement = statement.encode("ascii")
        if not 1 <= len(encoded_statement) <= MAX_STATEMENT_BYTES or statement.count(".") != 2:
            raise ValueError
        protected_segment, payload_segment, signature_segment = statement.split(".")
        protected_wire = _base64url_decode(protected_segment).decode("ascii")
        payload_wire = _base64url_decode(payload_segment).decode("ascii")
        signature = _base64url_decode(signature_segment)
        _parse_protected_header(protected_wire, expected_kid=_configured_identifier(expected_kid))
        claims = _statement_claims(_closed_json(payload_wire, _STATEMENT_FIELDS, 3_072))
        context = parse_verification_context_v1(expected_context_wire)
        input_value = parse_verification_input_v1(expected_input_wire)
        configured_issuer = _audience(expected_issuer)
        current = _integer(now)
        challenge_deadline = _integer(challenge_expires_at, positive=True)
        session_deadline = _integer(session_expires_at, positive=True)
        deadlines = [challenge_deadline, session_deadline]
        if context.challenge_kind == "enrollment-v2":
            deadlines.append(_integer(approver_session_expires_at, positive=True))
        elif approver_session_expires_at is not None:
            _deny()
        if (
            input_value.context != context
            or claims.issuer != configured_issuer
            or context.audience != configured_issuer
            or claims.audience != _statement_audience(expected_audience)
            or claims.client_id != _configured_identifier(expected_client_id)
            or claims.service_principal != _configured_identifier(expected_service_principal)
            or claims.challenge_kind != context.challenge_kind
            or claims.challenge_id != context.challenge_id
            or claims.attempt_id != context.attempt_id
            or claims.context_digest != verification_context_digest_v1(context.wire)
            or claims.input_digest != verification_input_digest_v1(input_value.wire)
            or current < claims.issued_at
            or current >= claims.expires_at
            or claims.expires_at > min(deadlines)
        ):
            raise ValueError
        return VerificationStatementInspectionV1(
            protected_header_wire=protected_wire,
            payload_wire=payload_wire,
            signing_input=(protected_segment + "." + payload_segment).encode("ascii"),
            signature=signature,
            claims=claims,
        )
    except SocialMessagingDeviceAdmissionUnavailable:
        raise
    except Exception:
        _deny()


def parse_admission_receipt_v1(source: object) -> AdmissionReceiptV1:
    value = _closed_json(source, _RECEIPT_FIELDS, 2_048)
    if (
        value["schema"] != ADMISSION_RECEIPT_SCHEMA
        or value["version"] != VERSION
        or type(value["version"]) is not int
        or value["operation"] not in OPERATIONS
        or value["status"] != "committed"
    ):
        _deny()
    return AdmissionReceiptV1(
        receipt_id=_hex64(value["receiptId"]),
        challenge_id=_hex64(value["challengeId"]),
        operation=cast(str, value["operation"]),
        decided_at=_integer(value["decidedAt"]),
    )


def canonical_admission_receipt_v1_bytes(
    *, receipt_id: object, challenge_id: object, operation: object, decided_at: object
) -> bytes:
    source = _canonical(
        {
            "challengeId": challenge_id,
            "decidedAt": decided_at,
            "operation": operation,
            "receiptId": receipt_id,
            "schema": ADMISSION_RECEIPT_SCHEMA,
            "status": "committed",
            "version": VERSION,
        }
    )
    parse_admission_receipt_v1(source)
    return source.encode("ascii")


def inspect_admission_receipt_v1(source: object) -> ReceiptInspectionV1:
    return ReceiptInspectionV1(parse_admission_receipt_v1(source))


_ROUTE_SPECS = (
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/session-bind",
        "session-bind",
        ("presentationId",),
        "session-binding",
        ("sessionBinding", "expiresAt"),
        2_048,
    ),
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/enrollment-prepare",
        "enrollment-prepare",
        ("presentationId", "deviceId"),
        "enrollment-prepared",
        ("enrollmentId", "expiresAt"),
        2_048,
    ),
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/enrollment-challenge",
        "enrollment-challenge",
        ("presentationId", "enrollmentId", "ed25519PublicKey"),
        "challenge",
        ("challengeId", "challengeWire", "contextWire"),
        12_288,
    ),
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/enrollment-read",
        "enrollment-read",
        ("presentationId", "enrollmentId"),
        "enrollment-state",
        (
            "enrollmentId",
            "state",
            "challengeWire",
            "contextWire",
            "phoneProofWire",
            "approvalEventWire",
            "receipt",
        ),
        24_576,
    ),
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/enrollment-phone-proof",
        "enrollment-phone-proof",
        ("presentationId", "enrollmentId", "proofWire"),
        "enrollment-state",
        (
            "enrollmentId",
            "state",
            "challengeWire",
            "contextWire",
            "phoneProofWire",
            "approvalEventWire",
            "receipt",
        ),
        24_576,
    ),
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/enrollment-approval",
        "enrollment-approval",
        ("presentationId", "enrollmentId", "approvalEventWire"),
        "enrollment-state",
        (
            "enrollmentId",
            "state",
            "challengeWire",
            "contextWire",
            "phoneProofWire",
            "approvalEventWire",
            "receipt",
        ),
        24_576,
    ),
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/enrollment-cancel",
        "enrollment-cancel",
        ("presentationId", "enrollmentId"),
        "enrollment-terminal",
        ("enrollmentId", "state"),
        2_048,
    ),
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/challenge",
        "challenge",
        ("presentationId", "deviceId", "actualRequestWire", "routingRequestWire"),
        "challenge",
        ("challengeId", "challengeWire", "contextWire"),
        12_288,
    ),
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/challenge-read",
        "challenge-read",
        ("presentationId", "challengeId"),
        "challenge",
        ("challengeId", "challengeWire", "contextWire"),
        12_288,
    ),
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/consume",
        "consume",
        ("presentationId", "challengeId", "inputWire", "statement"),
        "receipt",
        ("receipt",),
        2_048,
    ),
    AdmissionRouteContractV1(
        ADMISSION_PREFIX + "/recover",
        "recover",
        ("presentationId", "challengeId"),
        "receipt-history",
        ("receipt",),
        2_048,
    ),
)
ADMISSION_ROUTES = MappingProxyType({item.path: item for item in _ROUTE_SPECS})
ADMISSION_ROUTE_TUPLES = tuple((item.path, item.command, item.response_kind) for item in _ROUTE_SPECS)


def _route(path: object) -> AdmissionRouteContractV1:
    if type(path) is not str or path not in ADMISSION_ROUTES:
        _deny()
    return ADMISSION_ROUTES[path]


def _validate_command_values(route: AdmissionRouteContractV1, value: dict[str, object]) -> None:
    for field_name in ("presentationId", "deviceId", "enrollmentId", "challengeId"):
        if field_name in value:
            _hex64(value[field_name])
    if "ed25519PublicKey" in value:
        _hex64(value["ed25519PublicKey"])
    if "proofWire" in value:
        parse_enrollment_proof_v2(value["proofWire"])
    if "approvalEventWire" in value:
        _ascii_string(value["approvalEventWire"], maximum=MAX_APPROVAL_EVENT_BYTES)
    if "actualRequestWire" in value:
        request = _parse_request(value["actualRequestWire"])
        if route.command == "challenge" and request["deviceId"] != value["deviceId"]:
            _deny()
        routing = value["routingRequestWire"]
        if request["operation"] == "ciphertext-submit":
            if routing is None:
                _deny()
            _parse_routing_request(routing)
        elif routing is not None:
            _deny()
    if "inputWire" in value:
        parsed = parse_verification_input_v1(value["inputWire"])
        if parsed.context.challenge_id != value["challengeId"]:
            _deny()
        _ascii_string(value["statement"], maximum=MAX_STATEMENT_BYTES)


def _parse_admission_command_v1(path: object, source: object) -> ParsedAdmissionCommandV1:
    route = _route(path)
    fields = {"schema", "version", "command", *route.command_fields}
    value = _closed_json(source, fields, 40_960)
    if (
        value["schema"] != COMMAND_SCHEMA
        or value["version"] != VERSION
        or type(value["version"]) is not int
        or value["command"] != route.command
    ):
        _deny()
    _validate_command_values(route, value)
    return ParsedAdmissionCommandV1(route, MappingProxyType(dict(value)))


def parse_admission_command_v1(path: object, source: object) -> ParsedAdmissionCommandV1:
    try:
        return _parse_admission_command_v1(path, source)
    except SocialMessagingDeviceAdmissionUnavailable:
        raise
    except Exception:
        _deny()


def canonical_admission_command_v1_bytes(path: object, **fields: object) -> bytes:
    route = _route(path)
    source = _canonical({"schema": COMMAND_SCHEMA, "version": VERSION, "command": route.command, **fields})
    parse_admission_command_v1(route.path, source)
    return source.encode("ascii")


def _receipt_from_object(value: object) -> AdmissionReceiptV1:
    if type(value) is not dict:
        _deny()
    return parse_admission_receipt_v1(_canonical(value))


def _validate_response_values(route: AdmissionRouteContractV1, value: dict[str, object]) -> None:
    for field_name in ("sessionBinding", "enrollmentId", "challengeId"):
        if field_name in value:
            _hex64(value[field_name])
    if "expiresAt" in value:
        _integer(value["expiresAt"], positive=True)
    if route.response_kind == "challenge":
        context = parse_verification_context_v1(value["contextWire"])
        if context.challenge_id != value["challengeId"]:
            _deny()
        if route.command == "enrollment-challenge":
            if context.challenge_kind != "enrollment-v2":
                _deny()
        elif context.challenge_kind != "device-request-v1":
            _deny()
        _validate_challenge_context_binding(value["challengeWire"], context)
    elif route.response_kind == "enrollment-state":
        state = value["state"]
        if type(state) is not str or state not in ENROLLMENT_STATES:
            _deny()
        challenge_wire = value["challengeWire"]
        context_wire = value["contextWire"]
        if (challenge_wire is None) != (context_wire is None):
            _deny()
        if state == "prepared":
            if any(
                value[field] is not None
                for field in ("challengeWire", "contextWire", "phoneProofWire", "approvalEventWire", "receipt")
            ):
                _deny()
            return
        if state in {"cancelled", "expired", "invalidated"} and challenge_wire is None:
            if (
                value["phoneProofWire"] is not None
                or value["approvalEventWire"] is not None
                or value["receipt"] is not None
            ):
                _deny()
            return
        if challenge_wire is None:
            _deny()
        context = parse_verification_context_v1(context_wire)
        enrollment = _validate_enrollment_challenge_context_binding(challenge_wire, context)
        phone_proof_wire = value["phoneProofWire"]
        approval_event_wire = value["approvalEventWire"]
        if state == "consumed" and (
            phone_proof_wire is None or approval_event_wire is None or value["receipt"] is None
        ):
            _deny()
        if phone_proof_wire is not None:
            _validate_enrollment_proof_binding(
                phone_proof_wire,
                enrollment=enrollment,
                context=context,
                challenge_wire=cast(str, challenge_wire),
            )
        if approval_event_wire is not None:
            _parse_approval_event(
                approval_event_wire,
                context=context,
                challenge_wire=cast(str, challenge_wire),
            )
        if state == "consumed":
            receipt = _receipt_from_object(value["receipt"])
            if receipt.challenge_id != context.challenge_id or receipt.operation != "enrollment-activate":
                _deny()
        elif value["receipt"] is not None:
            _deny()
    elif route.response_kind == "enrollment-terminal":
        if value["state"] not in {"cancelled", "expired", "invalidated"}:
            _deny()
    elif route.response_kind in {"receipt", "receipt-history"}:
        receipt = _receipt_from_object(value["receipt"])
        if route.response_kind == "receipt-history" and receipt.challenge_id == "":
            _deny()


def _parse_admission_response_v1(path: object, source: object) -> ParsedAdmissionResponseV1:
    route = _route(path)
    fields = {"schema", "version", "kind", *route.response_fields}
    value = _closed_json(source, fields, route.response_maximum)
    if (
        value["schema"] != RESPONSE_SCHEMA
        or value["version"] != VERSION
        or type(value["version"]) is not int
        or value["kind"] != route.response_kind
    ):
        _deny()
    _validate_response_values(route, value)
    return ParsedAdmissionResponseV1(route, MappingProxyType(dict(value)))


def parse_admission_response_v1(path: object, source: object) -> ParsedAdmissionResponseV1:
    try:
        return _parse_admission_response_v1(path, source)
    except SocialMessagingDeviceAdmissionUnavailable:
        raise
    except Exception:
        _deny()


def canonical_admission_response_v1_bytes(path: object, **fields: object) -> bytes:
    route = _route(path)
    source = _canonical({"schema": RESPONSE_SCHEMA, "version": VERSION, "kind": route.response_kind, **fields})
    parse_admission_response_v1(route.path, source)
    return source.encode("ascii")


def validate_state_transition_v1(
    machine: object,
    previous_state: object,
    next_state: object,
) -> StateTransitionV1:
    tables = {
        "enrollment": ENROLLMENT_TRANSITIONS,
        "challenge": CHALLENGE_TRANSITIONS,
        "association": ASSOCIATION_TRANSITIONS,
        "receipt": RECEIPT_TRANSITIONS,
    }
    terminal = {
        "enrollment": ENROLLMENT_TERMINAL_STATES,
        "challenge": CHALLENGE_TERMINAL_STATES,
        "association": ASSOCIATION_TERMINAL_STATES,
        "receipt": frozenset(("committed",)),
    }
    if type(machine) is not str or machine not in tables or type(next_state) is not str:
        _deny()
    table = tables[machine]
    if previous_state not in table or next_state not in table[previous_state]:
        _deny()
    return StateTransitionV1(machine, cast(str | None, previous_state), next_state, next_state in terminal[machine])


def inspect_exclusive_deadline_v1(
    *, issued_at: object, expires_at: object, observed_at: object
) -> ExclusiveDeadlineInspectionV1:
    issued = _integer(issued_at)
    expires = _integer(expires_at)
    observed = _integer(observed_at)
    if expires <= issued:
        _deny()
    disposition = "not_yet_valid" if observed < issued else "current" if observed < expires else "expired"
    return ExclusiveDeadlineInspectionV1(issued, expires, observed, disposition)


def inspect_atomic_owner_v1() -> AtomicOwnerInspectionV1:
    return AtomicOwnerInspectionV1()


__all__ = [
    "ADMISSION_PREFIX",
    "ADMISSION_RECEIPT_SCHEMA",
    "ADMISSION_ROUTES",
    "ADMISSION_ROUTE_TUPLES",
    "ASSOCIATION_STATES",
    "ASSOCIATION_TERMINAL_STATES",
    "ATOMIC_OWNER",
    "AdmissionReceiptV1",
    "AdmissionRouteContractV1",
    "AtomicOwnerInspectionV1",
    "AuthenticatedSocialVerificationStatementVerifier",
    "AuthenticatedVerificationStatementV1",
    "CHALLENGE_CONSUMPTION",
    "CHALLENGE_KINDS",
    "CHALLENGE_STATES",
    "CHALLENGE_TERMINAL_STATES",
    "COMMAND_SCHEMA",
    "CONTEXT_DIGEST_DOMAIN",
    "CONTEXT_DIGEST_PREFIX",
    "CRYPTOGRAPHIC_VERIFICATION",
    "CURRENT_AUTHORITY",
    "ChallengeStorageOwner",
    "CurrentAdmissionAuthorityV1",
    "ENROLLMENT_STATES",
    "ENROLLMENT_TERMINAL_STATES",
    "ExactAtomicOperationEffectPort",
    "ExclusiveDeadlineInspectionV1",
    "FINAL_ADMISSION",
    "INPUT_DIGEST_DOMAIN",
    "INPUT_DIGEST_PREFIX",
    "MAX_ACTUAL_REQUEST_BYTES",
    "MAX_APPROVAL_EVENT_BYTES",
    "MAX_CHALLENGE_BYTES",
    "MAX_CONTEXT_BYTES",
    "MAX_INPUT_BYTES",
    "MAX_PROOF_BYTES",
    "MAX_ROUTING_REQUEST_BYTES",
    "MAX_STATEMENT_BYTES",
    "MAX_STATEMENT_LIFETIME_MS",
    "OPERATION_EFFECT",
    "OPERATIONS",
    "ParsedAdmissionCommandV1",
    "ParsedAdmissionResponseV1",
    "PreparedAdmissionEffectV1",
    "RECEIPT_STATES",
    "RESPONSE_SCHEMA",
    "RUNTIME_ENABLED",
    "ReceiptHistoryProjection",
    "ReceiptInspectionV1",
    "STATEMENT_ALGORITHM",
    "STATEMENT_PURPOSE",
    "STATEMENT_TYPE",
    "SocialMessagingDeviceAdmissionUnavailable",
    "StateTransitionV1",
    "StoredAdmissionChallengeV1",
    "TransactionBoundAdmissionAuthority",
    "VERIFICATION_CONTEXT_SCHEMA",
    "VERIFICATION_INPUT_SCHEMA",
    "VERIFICATION_STATEMENT_SCHEMA",
    "VerificationContextV1",
    "VerificationInputV1",
    "VerificationStatementClaimsV1",
    "VerificationStatementInspectionV1",
    "canonical_admission_command_v1_bytes",
    "canonical_admission_receipt_v1_bytes",
    "canonical_admission_response_v1_bytes",
    "canonical_verification_context_v1_bytes",
    "canonical_verification_input_v1_bytes",
    "canonical_verification_statement_payload_v1_bytes",
    "canonical_verification_statement_protected_header_v1_bytes",
    "compact_verification_statement_v1",
    "inspect_admission_receipt_v1",
    "inspect_atomic_owner_v1",
    "inspect_exclusive_deadline_v1",
    "inspect_verification_statement_shape_v1",
    "parse_admission_command_v1",
    "parse_admission_receipt_v1",
    "parse_admission_response_v1",
    "parse_verification_context_v1",
    "parse_verification_input_v1",
    "validate_state_transition_v1",
    "verification_context_digest_v1",
    "verification_input_digest_v1",
]
