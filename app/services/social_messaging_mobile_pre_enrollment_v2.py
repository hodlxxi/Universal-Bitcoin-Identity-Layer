"""Dormant pure Social pre-enrollment V2 canonical contract.

This module freezes only the deterministic preacceptance-through-candidate-
association-link boundary.  It performs no I/O, persistence, session issuance,
routing, or runtime composition.  Ed25519 verification remains Social's
responsibility; UBID only preserves and cross-checks the existing Enrollment V2
proof bytes.  Its serializers do not grant acceptance or association authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import NoReturn, cast

from app.services.social_messaging_device_admission_contract import VerificationContextV1, parse_verification_context_v1
from app.services.social_messaging_device_binding_authorization import (
    NOSTR_EVENT_KIND,
    Bip340IdentitySignatureVerifier,
    _parse_timestamp,
)
from app.services.social_messaging_device_ed25519_association_lifecycle import (
    association_id_v1,
    canonical_association_creation_v1_bytes,
)
from app.services.social_messaging_device_proof_profile import (
    DEVICE_PROOF_PROFILE,
    MAX_SAFE_INTEGER,
    EnrollmentProofV2Record,
    EnrollmentV2Record,
    enrollment_v2_digest,
    parse_enrollment_proof_v2,
    parse_enrollment_v2,
    x25519_public_key_commitment_v1,
)
from app.services.social_messaging_mobile_authorization import SemanticProposal, inspect_claim
from app.services.social_messaging_mobile_authorization import parse_json as parse_v1_json

PRE_ENROLLMENT_SCHEMA = "hodlxxi.social_messaging_device_pre_enrollment.v2"
PRE_ENROLLMENT_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_PRE_ENROLLMENT_V2"
PRE_ENROLLMENT_DIGEST_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_PRE_ENROLLMENT_DIGEST_V2"
PRE_ENROLLMENT_DIGEST_PREFIX = "hodlxxi-social-messaging-device-pre-enrollment-v2-sha256:"

AUTHORIZATION_SCHEMA = "hodlxxi.social_messaging_device_authorization_method.v2"
AUTHORIZATION_DOMAIN = "HODLXXI_SOCIAL_MESSAGING_DEVICE_AUTHORIZATION_METHOD_V2"
AUTHORIZATION_METHOD = "qr_desktop_pre_enrollment_v2"
PAIRING_SECRET_DOMAIN = "HODLXXI_SOCIAL_PAIRING_SECRET_V2"
PHONE_EXCHANGE_DOMAIN = "HODLXXI_SOCIAL_PHONE_EXCHANGE_V2"
PAIRING_POSSESSION_DOMAIN = "HODLXXI_SOCIAL_PAIRING_POSSESSION_V2"

APPROVAL_EVENT_PURPOSE = "hodlxxi-social-messaging-device-qr-pre-enrollment-approval-v2"

ACCEPTANCE_ID_PREIMAGE_SCHEMA = "hodlxxi.social_mobile_pre_enrollment_acceptance_id_preimage.v2"
ACCEPTANCE_ID_DOMAIN = "HODLXXI_SOCIAL_MOBILE_PRE_ENROLLMENT_ACCEPTANCE_ID_V2"
ACCEPTANCE_SCHEMA = "hodlxxi.social_mobile_authorization_acceptance.v2"

VERIFICATION_INPUT_SCHEMA = "hodlxxi.social_preaccepted_enrollment_verification_input.v2"
VERIFICATION_INPUT_DIGEST_DOMAIN = "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_INPUT_V2"
VERIFICATION_INPUT_DIGEST_PREFIX = "hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:"

ASSOCIATION_LINK_SCHEMA = "hodlxxi.social_pre_enrollment_association_link.v2"

VERSION = 2
MAX_PRE_ENROLLMENT_LIFETIME_MS = 600_000
MAX_PAIRING_LIFETIME_SECONDS = 300
MAX_PRE_ENROLLMENT_BYTES = 8_192
MAX_AUTHORIZATION_BYTES = 16_384
MAX_APPROVAL_EVENT_BYTES = 24_576
MAX_ACCEPTANCE_BYTES = 4_096
MAX_VERIFICATION_INPUT_BYTES = 24_576
MAX_ASSOCIATION_LINK_BYTES = 4_096
UNAVAILABLE_MESSAGE = "social messaging mobile pre-enrollment unavailable"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_HEX128 = re.compile(r"[0-9a-f]{128}\Z").fullmatch
_X25519_COMMITMENT = re.compile(r"hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_PRE_ENROLLMENT_DIGEST = re.compile(
    r"hodlxxi-social-messaging-device-pre-enrollment-v2-sha256:[0-9a-f]{64}\Z"
).fullmatch
_ENROLLMENT_DIGEST = re.compile(r"hodlxxi-social-messaging-device-enrollment-v2-sha256:[0-9a-f]{64}\Z").fullmatch

_PRE_ENROLLMENT_FIELDS = {
    "bindingAuthorizationDigest",
    "deviceId",
    "domain",
    "ed25519PublicKey",
    "expiresAt",
    "issuedAt",
    "pairingId",
    "preEffectAssociationId",
    "preEffectAssociationState",
    "preEffectAssociationVersion",
    "preEffectAuthorityEpoch",
    "profile",
    "proposedAssociationVersion",
    "proposedAuthorityEpoch",
    "proposedPredecessorAssociationId",
    "requestId",
    "schema",
    "subject",
    "transitionKind",
    "version",
    "x25519BindingId",
    "x25519BindingVersion",
    "x25519PublicKeyCommitment",
}
_PAIRING_CONTEXT_FIELDS = {
    "createdAt",
    "desktopContext",
    "exchangeCommitment",
    "expiresAt",
    "pairingId",
    "secretCommitment",
}
_AUTHORIZATION_FIELDS = {"content", "context", "domain", "method", "preEnrollment", "schema", "version"}
_APPROVAL_EVENT_FIELDS = {"content", "created_at", "id", "kind", "pubkey", "sig", "tags"}
_ACCEPTANCE_FIELDS = {
    "acceptanceId",
    "approvalEventId",
    "authorizationDigest",
    "bindingId",
    "deviceId",
    "ed25519PublicKey",
    "pairingId",
    "preEnrollmentDigest",
    "profile",
    "requestId",
    "schema",
    "subject",
    "version",
    "x25519BindingVersion",
    "x25519PublicKeyCommitment",
}
_VERIFICATION_INPUT_FIELDS = {
    "acceptanceId",
    "approvalEvent",
    "context",
    "enrollment",
    "phoneProof",
    "schema",
    "version",
}
_ASSOCIATION_LINK_FIELDS = {
    "acceptanceId",
    "associationId",
    "associationVersion",
    "authorityEpoch",
    "enrollmentChallengeId",
    "enrollmentDigest",
    "preEnrollmentDigest",
    "schema",
    "version",
}


class SocialMessagingMobilePreEnrollmentV2Unavailable(ValueError):
    """The sole non-sensitive failure exposed by this pure boundary."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True, slots=True)
class PairingContextV2:
    created_at: int
    desktop_context: str
    exchange_commitment: str
    expires_at: int
    pairing_id: str
    secret_commitment: str


@dataclass(frozen=True, slots=True)
class PreEnrollmentV2:
    wire: str
    binding_authorization_digest: str
    device_id: str
    ed25519_public_key: str
    expires_at: int
    issued_at: int
    pairing_id: str
    request_id: str
    subject: str
    x25519_binding_id: str
    x25519_binding_version: int
    x25519_public_key_commitment: str


@dataclass(frozen=True, slots=True)
class AuthorizationEnvelopeV2:
    wire: str
    content: str
    semantic: SemanticProposal
    context: PairingContextV2
    pre_enrollment: PreEnrollmentV2
    x25519_public_key: str
    x25519_binding_valid_from_ms: int
    x25519_binding_expires_at_ms: int


@dataclass(frozen=True, slots=True)
class ApprovalEventV2:
    wire: str
    event_id: str
    signature: str
    envelope: AuthorizationEnvelopeV2


@dataclass(frozen=True, slots=True)
class AcceptanceV2:
    wire: str
    acceptance_id: str
    approval: ApprovalEventV2


@dataclass(frozen=True, slots=True)
class PreacceptedEnrollmentVerificationInputV2:
    wire: str
    acceptance_id: str
    approval: ApprovalEventV2
    context: VerificationContextV1
    enrollment_wire: str
    enrollment: EnrollmentV2Record
    phone_proof_wire: str
    phone_proof: EnrollmentProofV2Record
    association_id: str


@dataclass(frozen=True, slots=True)
class AssociationLinkV2:
    wire: str
    acceptance_id: str
    association_id: str
    enrollment_challenge_id: str
    enrollment_digest: str
    pre_enrollment_digest: str


def _deny() -> NoReturn:
    raise SocialMessagingMobilePreEnrollmentV2Unavailable() from None


def _canonical(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    except Exception:
        _deny()


def _closed_json(source: object, fields: set[str], maximum: int) -> dict[str, object]:
    try:
        if type(source) is not str or not 1 <= len(source.encode("ascii")) <= maximum:
            raise ValueError
        source = cast(str, source)
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in source):
            raise ValueError

        def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in values:
                if type(key) is not str or key in result:
                    raise ValueError
                result[key] = value
            return result

        def invalid_constant(_value: str) -> NoReturn:
            raise ValueError

        value = json.loads(source, object_pairs_hook=pairs, parse_constant=invalid_constant)
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
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER or (positive and value == 0):
        _deny()
    return cast(int, value)


def _milliseconds_from_timestamp(value: object) -> int:
    try:
        parsed = _parse_timestamp(value)
        return int(parsed.timestamp()) * 1000
    except Exception:
        _deny()


def _seconds_from_timestamp(value: object) -> int:
    return _milliseconds_from_timestamp(value) // 1000


def _sha256_ascii(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _domain_digest(domain: str, source: str) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + source.encode("ascii")).hexdigest()


def _parse_pairing_context(value: object) -> PairingContextV2:
    try:
        if type(value) is not dict or set(value) != _PAIRING_CONTEXT_FIELDS:
            raise ValueError
        created_at = _seconds_from_timestamp(value["createdAt"])
        expires_at = _seconds_from_timestamp(value["expiresAt"])
        if not created_at < expires_at <= created_at + MAX_PAIRING_LIFETIME_SECONDS:
            raise ValueError
        return PairingContextV2(
            created_at=created_at,
            desktop_context=_hex64(value["desktopContext"]),
            exchange_commitment=_hex64(value["exchangeCommitment"]),
            expires_at=expires_at,
            pairing_id=_hex64(value["pairingId"]),
            secret_commitment=_hex64(value["secretCommitment"]),
        )
    except Exception:
        _deny()


def canonical_pre_enrollment_v2_bytes(
    *,
    binding_authorization_digest: object,
    device_id: object,
    ed25519_public_key: object,
    expires_at: object,
    issued_at: object,
    pairing_id: object,
    pre_effect_association_id: object,
    pre_effect_association_state: object,
    pre_effect_association_version: object,
    pre_effect_authority_epoch: object,
    proposed_association_version: object,
    proposed_authority_epoch: object,
    proposed_predecessor_association_id: object,
    request_id: object,
    subject: object,
    transition_kind: object,
    x25519_binding_id: object,
    x25519_binding_version: object,
    x25519_public_key_commitment: object,
) -> bytes:
    source = _canonical(
        {
            "bindingAuthorizationDigest": binding_authorization_digest,
            "deviceId": device_id,
            "domain": PRE_ENROLLMENT_DOMAIN,
            "ed25519PublicKey": ed25519_public_key,
            "expiresAt": expires_at,
            "issuedAt": issued_at,
            "pairingId": pairing_id,
            "preEffectAssociationId": pre_effect_association_id,
            "preEffectAssociationState": pre_effect_association_state,
            "preEffectAssociationVersion": pre_effect_association_version,
            "preEffectAuthorityEpoch": pre_effect_authority_epoch,
            "profile": DEVICE_PROOF_PROFILE,
            "proposedAssociationVersion": proposed_association_version,
            "proposedAuthorityEpoch": proposed_authority_epoch,
            "proposedPredecessorAssociationId": proposed_predecessor_association_id,
            "requestId": request_id,
            "schema": PRE_ENROLLMENT_SCHEMA,
            "subject": subject,
            "transitionKind": transition_kind,
            "version": VERSION,
            "x25519BindingId": x25519_binding_id,
            "x25519BindingVersion": x25519_binding_version,
            "x25519PublicKeyCommitment": x25519_public_key_commitment,
        }
    )
    parse_pre_enrollment_v2(source)
    return source.encode("ascii")


def parse_pre_enrollment_v2(source: object) -> PreEnrollmentV2:
    value = _closed_json(source, _PRE_ENROLLMENT_FIELDS, MAX_PRE_ENROLLMENT_BYTES)
    issued_at = _integer(value["issuedAt"])
    expires_at = _integer(value["expiresAt"])
    subject = _hex64(value["subject"])
    public_key = _hex64(value["ed25519PublicKey"])
    binding_version = _integer(value["x25519BindingVersion"], positive=True)
    commitment = value["x25519PublicKeyCommitment"]
    digest_value = value["bindingAuthorizationDigest"]
    if (
        value["schema"] != PRE_ENROLLMENT_SCHEMA
        or type(value["version"]) is not int
        or value["version"] != VERSION
        or value["domain"] != PRE_ENROLLMENT_DOMAIN
        or value["profile"] != DEVICE_PROOF_PROFILE
        or type(digest_value) is not str
        or _HEX64(digest_value) is None
        or type(commitment) is not str
        or _X25519_COMMITMENT(commitment) is None
        or public_key == subject
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_PRE_ENROLLMENT_LIFETIME_MS
        or binding_version != 1
        or value["transitionKind"] != "initial"
        or value["preEffectAssociationState"] != "absent"
        or value["preEffectAssociationId"] is not None
        or value["preEffectAssociationVersion"] is not None
        or type(value["preEffectAuthorityEpoch"]) is not int
        or value["preEffectAuthorityEpoch"] != 0
        or type(value["proposedAssociationVersion"]) is not int
        or value["proposedAssociationVersion"] != 1
        or type(value["proposedAuthorityEpoch"]) is not int
        or value["proposedAuthorityEpoch"] != 1
        or value["proposedPredecessorAssociationId"] is not None
    ):
        _deny()
    return PreEnrollmentV2(
        wire=cast(str, source),
        binding_authorization_digest=cast(str, digest_value),
        device_id=_hex64(value["deviceId"]),
        ed25519_public_key=public_key,
        expires_at=expires_at,
        issued_at=issued_at,
        pairing_id=_hex64(value["pairingId"]),
        request_id=_hex64(value["requestId"]),
        subject=subject,
        x25519_binding_id=_hex64(value["x25519BindingId"]),
        x25519_binding_version=binding_version,
        x25519_public_key_commitment=cast(str, commitment),
    )


def pre_enrollment_v2_digest(source: object) -> str:
    parsed = parse_pre_enrollment_v2(source)
    return PRE_ENROLLMENT_DIGEST_PREFIX + _domain_digest(PRE_ENROLLMENT_DIGEST_DOMAIN, parsed.wire)


def canonical_authorization_envelope_v2_bytes(
    *, content: object, context_wire: object, pre_enrollment_wire: object
) -> bytes:
    try:
        if type(content) is not str or type(context_wire) is not str or type(pre_enrollment_wire) is not str:
            raise ValueError
        context = _closed_json(context_wire, _PAIRING_CONTEXT_FIELDS, 2_048)
        source = _canonical(
            {
                "content": content,
                "context": context,
                "domain": AUTHORIZATION_DOMAIN,
                "method": AUTHORIZATION_METHOD,
                "preEnrollment": pre_enrollment_wire,
                "schema": AUTHORIZATION_SCHEMA,
                "version": VERSION,
            }
        )
        parse_authorization_envelope_v2(source)
        return source.encode("ascii")
    except Exception:
        _deny()


def parse_authorization_envelope_v2(source: object) -> AuthorizationEnvelopeV2:
    value = _closed_json(source, _AUTHORIZATION_FIELDS, MAX_AUTHORIZATION_BYTES)
    if (
        value["schema"] != AUTHORIZATION_SCHEMA
        or type(value["version"]) is not int
        or value["version"] != VERSION
        or value["domain"] != AUTHORIZATION_DOMAIN
        or value["method"] != AUTHORIZATION_METHOD
        or type(value["content"]) is not str
        or type(value["preEnrollment"]) is not str
    ):
        _deny()
    try:
        pre_enrollment = parse_pre_enrollment_v2(value["preEnrollment"])
        context = _parse_pairing_context(value["context"])
        semantic = inspect_claim(value["content"], pre_enrollment.subject)
        binding_record = parse_v1_json(semantic.binding_record)
        binding_valid_from_ms = _milliseconds_from_timestamp(binding_record["validFrom"])
        binding_expires_at_ms = _milliseconds_from_timestamp(binding_record["expiresAt"])
        commitment = x25519_public_key_commitment_v1(binding_record["publicKey"])
        if (
            semantic.operation != "register"
            or semantic.subject != pre_enrollment.subject
            or semantic.request_id != pre_enrollment.request_id
            or semantic.binding_id != pre_enrollment.x25519_binding_id
            or binding_record["deviceId"] != pre_enrollment.device_id
            or binding_record["bindingVersion"] != pre_enrollment.x25519_binding_version
            or binding_record["operation"] != "register"
            or binding_record["priorBindingId"] is not None
            or pre_enrollment.x25519_binding_version != 1
            or _sha256_ascii(value["content"]) != pre_enrollment.binding_authorization_digest
            or commitment != pre_enrollment.x25519_public_key_commitment
            or binding_record["publicKey"] == pre_enrollment.ed25519_public_key
            or pre_enrollment.pairing_id != context.pairing_id
            or pre_enrollment.issued_at != semantic.issued_at * 1000
            or not context.created_at <= semantic.issued_at < semantic.expires_at <= context.expires_at
            or pre_enrollment.expires_at > binding_expires_at_ms
        ):
            raise ValueError
        return AuthorizationEnvelopeV2(
            wire=cast(str, source),
            content=cast(str, value["content"]),
            semantic=semantic,
            context=context,
            pre_enrollment=pre_enrollment,
            x25519_public_key=cast(str, binding_record["publicKey"]),
            x25519_binding_valid_from_ms=binding_valid_from_ms,
            x25519_binding_expires_at_ms=binding_expires_at_ms,
        )
    except Exception:
        _deny()


def authorization_v2_digest(source: object) -> str:
    return _sha256_ascii(parse_authorization_envelope_v2(source).wire)


def _acceptance_time(envelope: AuthorizationEnvelopeV2, now_ms: object) -> int:
    now = _integer(now_ms)
    if not (
        envelope.context.created_at * 1000 <= now < envelope.context.expires_at * 1000
        and envelope.semantic.issued_at * 1000 <= now < envelope.semantic.expires_at * 1000
        and envelope.pre_enrollment.issued_at <= now < envelope.pre_enrollment.expires_at
        and envelope.x25519_binding_valid_from_ms <= now < envelope.x25519_binding_expires_at_ms
    ):
        _deny()
    return now


def validate_acceptance_time_v2(source: object, *, now_ms: object) -> AuthorizationEnvelopeV2:
    envelope = parse_authorization_envelope_v2(source)
    _acceptance_time(envelope, now_ms)
    return envelope


def pairing_secret_commitment_v2(secret: object) -> str:
    return _domain_digest(PAIRING_SECRET_DOMAIN, _hex64(secret))


def phone_exchange_commitment_v2(verifier: object) -> str:
    return _domain_digest(PHONE_EXCHANGE_DOMAIN, _hex64(verifier))


def pairing_possession_proof_v2(secret: object, authorization_digest: object) -> str:
    normalized_secret = _hex64(secret)
    normalized_digest = _hex64(authorization_digest)
    return hmac.new(
        bytes.fromhex(normalized_secret),
        PAIRING_POSSESSION_DOMAIN.encode("ascii") + b"\0" + normalized_digest.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def verify_pairing_possession_v2(
    source: object, *, secret: object, possession_proof: object, now_ms: object
) -> AuthorizationEnvelopeV2:
    envelope = validate_acceptance_time_v2(source, now_ms=now_ms)
    proof = _hex64(possession_proof)
    if not hmac.compare_digest(
        pairing_secret_commitment_v2(secret), envelope.context.secret_commitment
    ) or not hmac.compare_digest(pairing_possession_proof_v2(secret, authorization_v2_digest(envelope.wire)), proof):
        _deny()
    return envelope


def _approval_tags(envelope: AuthorizationEnvelopeV2) -> list[list[str]]:
    return [
        ["purpose", APPROVAL_EVENT_PURPOSE],
        ["authorization-digest", authorization_v2_digest(envelope.wire)],
        ["pre-enrollment-digest", pre_enrollment_v2_digest(envelope.pre_enrollment.wire)],
        ["request-id", envelope.pre_enrollment.request_id],
        ["action", "register"],
        ["pairing-id", envelope.pre_enrollment.pairing_id],
    ]


def canonical_approval_event_id_input_v2(source: object) -> bytes:
    envelope = parse_authorization_envelope_v2(source)
    return json.dumps(
        [
            0,
            envelope.pre_enrollment.subject,
            envelope.semantic.issued_at,
            NOSTR_EVENT_KIND,
            _approval_tags(envelope),
            envelope.wire,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


def approval_event_id_v2(source: object) -> str:
    return hashlib.sha256(canonical_approval_event_id_input_v2(source)).hexdigest()


def canonical_approval_event_v2_bytes(source: object, *, signature: object) -> bytes:
    envelope = parse_authorization_envelope_v2(source)
    event = _canonical(
        {
            "content": envelope.wire,
            "created_at": envelope.semantic.issued_at,
            "id": approval_event_id_v2(envelope.wire),
            "kind": NOSTR_EVENT_KIND,
            "pubkey": envelope.pre_enrollment.subject,
            "sig": _hex128(signature),
            "tags": _approval_tags(envelope),
        }
    )
    parse_approval_event_v2(event)
    return event.encode("ascii")


def parse_approval_event_v2(source: object) -> ApprovalEventV2:
    value = _closed_json(source, _APPROVAL_EVENT_FIELDS, MAX_APPROVAL_EVENT_BYTES)
    try:
        envelope = parse_authorization_envelope_v2(value["content"])
        expected_id = approval_event_id_v2(envelope.wire)
        signature = _hex128(value["sig"])
        if (
            value["content"] != envelope.wire
            or type(value["created_at"]) is not int
            or value["created_at"] != envelope.semantic.issued_at
            or type(value["kind"]) is not int
            or value["kind"] != NOSTR_EVENT_KIND
            or value["pubkey"] != envelope.pre_enrollment.subject
            or value["id"] != expected_id
            or value["tags"] != _approval_tags(envelope)
            or Bip340IdentitySignatureVerifier().verify(
                subject=envelope.pre_enrollment.subject,
                signature=bytes.fromhex(signature),
                digest=bytes.fromhex(expected_id),
            )
            is not True
        ):
            raise ValueError
        return ApprovalEventV2(cast(str, source), expected_id, signature, envelope)
    except Exception:
        _deny()


def canonical_acceptance_id_preimage_v2_bytes(approval_event_wire: object) -> bytes:
    approval = parse_approval_event_v2(approval_event_wire)
    envelope = approval.envelope
    return _canonical(
        {
            "approvalEventId": approval.event_id,
            "authorizationDigest": authorization_v2_digest(envelope.wire),
            "bindingId": envelope.pre_enrollment.x25519_binding_id,
            "pairingId": envelope.pre_enrollment.pairing_id,
            "preEnrollmentDigest": pre_enrollment_v2_digest(envelope.pre_enrollment.wire),
            "requestId": envelope.pre_enrollment.request_id,
            "schema": ACCEPTANCE_ID_PREIMAGE_SCHEMA,
            "subject": envelope.pre_enrollment.subject,
            "version": VERSION,
        }
    ).encode("ascii")


def acceptance_id_v2(approval_event_wire: object) -> str:
    preimage = canonical_acceptance_id_preimage_v2_bytes(approval_event_wire)
    return hashlib.sha256(ACCEPTANCE_ID_DOMAIN.encode("ascii") + b"\0" + preimage).hexdigest()


def _acceptance_wire(approval: ApprovalEventV2) -> str:
    envelope = approval.envelope
    pre_enrollment = envelope.pre_enrollment
    return _canonical(
        {
            "acceptanceId": acceptance_id_v2(approval.wire),
            "approvalEventId": approval.event_id,
            "authorizationDigest": authorization_v2_digest(envelope.wire),
            "bindingId": pre_enrollment.x25519_binding_id,
            "deviceId": pre_enrollment.device_id,
            "ed25519PublicKey": pre_enrollment.ed25519_public_key,
            "pairingId": pre_enrollment.pairing_id,
            "preEnrollmentDigest": pre_enrollment_v2_digest(pre_enrollment.wire),
            "profile": DEVICE_PROOF_PROFILE,
            "requestId": pre_enrollment.request_id,
            "schema": ACCEPTANCE_SCHEMA,
            "subject": pre_enrollment.subject,
            "version": VERSION,
            "x25519BindingVersion": pre_enrollment.x25519_binding_version,
            "x25519PublicKeyCommitment": pre_enrollment.x25519_public_key_commitment,
        }
    )


def canonical_acceptance_v2_bytes(approval_event_wire: object, *, now_ms: object) -> bytes:
    approval = parse_approval_event_v2(approval_event_wire)
    _acceptance_time(approval.envelope, now_ms)
    wire = _acceptance_wire(approval)
    _closed_json(wire, _ACCEPTANCE_FIELDS, MAX_ACCEPTANCE_BYTES)
    return wire.encode("ascii")


def parse_acceptance_v2(source: object, *, approval_event_wire: object) -> AcceptanceV2:
    _closed_json(source, _ACCEPTANCE_FIELDS, MAX_ACCEPTANCE_BYTES)
    approval = parse_approval_event_v2(approval_event_wire)
    expected = _acceptance_wire(approval)
    if source != expected:
        _deny()
    return AcceptanceV2(cast(str, source), acceptance_id_v2(approval.wire), approval)


def _validate_input_cross_contract(
    approval: ApprovalEventV2,
    context: VerificationContextV1,
    enrollment_wire: str,
    enrollment: EnrollmentV2Record,
    phone_proof: EnrollmentProofV2Record,
) -> str:
    pre_enrollment = approval.envelope.pre_enrollment
    association_id = association_id_v1(enrollment_wire, 1, None)
    if (
        context.challenge_kind != "enrollment-v2"
        or context.challenge_id != enrollment.enrollment_challenge_id
        or context.audience != enrollment.audience
        or context.subject != pre_enrollment.subject
        or context.device_id != pre_enrollment.device_id
        or context.binding_id != pre_enrollment.x25519_binding_id
        or context.binding_version != pre_enrollment.x25519_binding_version
        or context.x25519_public_key_commitment != pre_enrollment.x25519_public_key_commitment
        or context.profile != DEVICE_PROOF_PROFILE
        or context.ed25519_public_key != pre_enrollment.ed25519_public_key
        or context.association_id != association_id
        or context.association_version != 1
        or context.predecessor_association_id is not None
        or context.authority_epoch != 1
        or enrollment.subject != pre_enrollment.subject
        or enrollment.device_id != pre_enrollment.device_id
        or enrollment.ed25519_public_key != pre_enrollment.ed25519_public_key
        or enrollment.x25519_binding_id != pre_enrollment.x25519_binding_id
        or enrollment.x25519_binding_version != pre_enrollment.x25519_binding_version
        or enrollment.x25519_public_key_commitment != pre_enrollment.x25519_public_key_commitment
        or enrollment.issued_at < pre_enrollment.issued_at
        or enrollment.expires_at > pre_enrollment.expires_at
        or phone_proof.enrollment_challenge_id != enrollment.enrollment_challenge_id
        or phone_proof.enrollment_digest != enrollment_v2_digest(enrollment_wire)
        or phone_proof.public_key != enrollment.ed25519_public_key
    ):
        _deny()
    return association_id


def canonical_preaccepted_enrollment_verification_input_v2_bytes(
    *, approval_event_wire: object, context_wire: object, enrollment_wire: object, phone_proof_wire: object
) -> bytes:
    try:
        approval = parse_approval_event_v2(approval_event_wire)
        context = parse_verification_context_v1(context_wire)
        enrollment = parse_enrollment_v2(enrollment_wire)
        proof = parse_enrollment_proof_v2(phone_proof_wire)
        _validate_input_cross_contract(
            approval,
            context,
            cast(str, enrollment_wire),
            enrollment,
            proof,
        )
        source = _canonical(
            {
                "acceptanceId": acceptance_id_v2(approval.wire),
                "approvalEvent": approval.wire,
                "context": context.wire,
                "enrollment": enrollment_wire,
                "phoneProof": phone_proof_wire,
                "schema": VERIFICATION_INPUT_SCHEMA,
                "version": VERSION,
            }
        )
        parse_preaccepted_enrollment_verification_input_v2(source)
        return source.encode("ascii")
    except Exception:
        _deny()


def parse_preaccepted_enrollment_verification_input_v2(
    source: object,
) -> PreacceptedEnrollmentVerificationInputV2:
    value = _closed_json(source, _VERIFICATION_INPUT_FIELDS, MAX_VERIFICATION_INPUT_BYTES)
    if (
        value["schema"] != VERIFICATION_INPUT_SCHEMA
        or type(value["version"]) is not int
        or value["version"] != VERSION
        or type(value["approvalEvent"]) is not str
        or type(value["context"]) is not str
        or type(value["enrollment"]) is not str
        or type(value["phoneProof"]) is not str
    ):
        _deny()
    try:
        approval = parse_approval_event_v2(value["approvalEvent"])
        expected_acceptance_id = acceptance_id_v2(approval.wire)
        if value["acceptanceId"] != expected_acceptance_id:
            raise ValueError
        context = parse_verification_context_v1(value["context"])
        enrollment = parse_enrollment_v2(value["enrollment"])
        proof = parse_enrollment_proof_v2(value["phoneProof"])
        association_id = _validate_input_cross_contract(
            approval,
            context,
            cast(str, value["enrollment"]),
            enrollment,
            proof,
        )
        return PreacceptedEnrollmentVerificationInputV2(
            wire=cast(str, source),
            acceptance_id=expected_acceptance_id,
            approval=approval,
            context=context,
            enrollment_wire=cast(str, value["enrollment"]),
            enrollment=enrollment,
            phone_proof_wire=cast(str, value["phoneProof"]),
            phone_proof=proof,
            association_id=association_id,
        )
    except Exception:
        _deny()


def preaccepted_enrollment_verification_input_v2_digest(source: object) -> str:
    parsed = parse_preaccepted_enrollment_verification_input_v2(source)
    return VERIFICATION_INPUT_DIGEST_PREFIX + _domain_digest(VERIFICATION_INPUT_DIGEST_DOMAIN, parsed.wire)


def validate_preaccepted_enrollment_time_v2(
    value: object,
    *,
    now_ms: object,
    phone_session_expires_at_ms: object,
    approver_session_expires_at_ms: object,
    full_expires_at_ms: object,
    x25519_binding_expires_at_ms: object,
) -> PreacceptedEnrollmentVerificationInputV2:
    parsed = parse_preaccepted_enrollment_verification_input_v2(value)
    now = _integer(now_ms)
    phone_deadline = _integer(phone_session_expires_at_ms, positive=True)
    approver_deadline = _integer(approver_session_expires_at_ms, positive=True)
    full_deadline = _integer(full_expires_at_ms, positive=True)
    binding_deadline = _integer(x25519_binding_expires_at_ms, positive=True)
    pre_enrollment = parsed.approval.envelope.pre_enrollment
    enrollment = parsed.enrollment
    if (
        binding_deadline != parsed.approval.envelope.x25519_binding_expires_at_ms
        or not pre_enrollment.issued_at <= now < pre_enrollment.expires_at
        or not enrollment.issued_at <= now < enrollment.expires_at
        or any(now >= deadline for deadline in (phone_deadline, approver_deadline, full_deadline, binding_deadline))
        or enrollment.expires_at
        > min(
            pre_enrollment.expires_at,
            phone_deadline,
            approver_deadline,
            full_deadline,
            binding_deadline,
        )
    ):
        _deny()
    return parsed


def _association_link_wire(value: PreacceptedEnrollmentVerificationInputV2) -> str:
    pre_enrollment = value.approval.envelope.pre_enrollment
    return _canonical(
        {
            "acceptanceId": value.acceptance_id,
            "associationId": value.association_id,
            "associationVersion": 1,
            "authorityEpoch": 1,
            "enrollmentChallengeId": value.enrollment.enrollment_challenge_id,
            "enrollmentDigest": enrollment_v2_digest(value.enrollment_wire),
            "preEnrollmentDigest": pre_enrollment_v2_digest(pre_enrollment.wire),
            "schema": ASSOCIATION_LINK_SCHEMA,
            "version": VERSION,
        }
    )


def canonical_association_link_v2_bytes(
    verification_input_wire: object,
    *,
    now_ms: object,
    phone_session_expires_at_ms: object,
    approver_session_expires_at_ms: object,
    full_expires_at_ms: object,
    x25519_binding_expires_at_ms: object,
) -> bytes:
    parsed = validate_preaccepted_enrollment_time_v2(
        verification_input_wire,
        now_ms=now_ms,
        phone_session_expires_at_ms=phone_session_expires_at_ms,
        approver_session_expires_at_ms=approver_session_expires_at_ms,
        full_expires_at_ms=full_expires_at_ms,
        x25519_binding_expires_at_ms=x25519_binding_expires_at_ms,
    )
    wire = _association_link_wire(parsed)
    _closed_json(wire, _ASSOCIATION_LINK_FIELDS, MAX_ASSOCIATION_LINK_BYTES)
    return wire.encode("ascii")


def parse_association_link_v2(source: object, *, verification_input_wire: object) -> AssociationLinkV2:
    value = _closed_json(source, _ASSOCIATION_LINK_FIELDS, MAX_ASSOCIATION_LINK_BYTES)
    parsed = parse_preaccepted_enrollment_verification_input_v2(verification_input_wire)
    expected = _association_link_wire(parsed)
    if (
        source != expected
        or value["schema"] != ASSOCIATION_LINK_SCHEMA
        or type(value["version"]) is not int
        or value["version"] != VERSION
        or type(value["associationVersion"]) is not int
        or value["associationVersion"] != 1
        or type(value["authorityEpoch"]) is not int
        or value["authorityEpoch"] != 1
        or type(value["preEnrollmentDigest"]) is not str
        or _PRE_ENROLLMENT_DIGEST(value["preEnrollmentDigest"]) is None
        or type(value["enrollmentDigest"]) is not str
        or _ENROLLMENT_DIGEST(value["enrollmentDigest"]) is None
    ):
        _deny()
    return AssociationLinkV2(
        wire=cast(str, source),
        acceptance_id=_hex64(value["acceptanceId"]),
        association_id=_hex64(value["associationId"]),
        enrollment_challenge_id=_hex64(value["enrollmentChallengeId"]),
        enrollment_digest=cast(str, value["enrollmentDigest"]),
        pre_enrollment_digest=cast(str, value["preEnrollmentDigest"]),
    )


def association_creation_preimage_v1_bytes(verification_input_wire: object) -> bytes:
    parsed = parse_preaccepted_enrollment_verification_input_v2(verification_input_wire)
    return canonical_association_creation_v1_bytes(parsed.enrollment_wire, 1, None)


def epoch_milliseconds_from_utc_second(value: str) -> int:
    """Expose the exact whole-second conversion used at the V1/V2 boundary."""

    return _milliseconds_from_timestamp(value)


def utc_second_from_epoch_milliseconds(value: object) -> str:
    """Return canonical UTC-Z only when ``value`` is an exact whole second."""

    milliseconds = _integer(value)
    if milliseconds % 1000:
        _deny()
    try:
        return datetime.fromtimestamp(milliseconds // 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        _deny()


__all__ = [
    "ACCEPTANCE_SCHEMA",
    "APPROVAL_EVENT_PURPOSE",
    "ASSOCIATION_LINK_SCHEMA",
    "AUTHORIZATION_DOMAIN",
    "AUTHORIZATION_METHOD",
    "AUTHORIZATION_SCHEMA",
    "PRE_ENROLLMENT_DOMAIN",
    "PRE_ENROLLMENT_SCHEMA",
    "VERIFICATION_INPUT_SCHEMA",
    "AcceptanceV2",
    "ApprovalEventV2",
    "AssociationLinkV2",
    "AuthorizationEnvelopeV2",
    "PairingContextV2",
    "PreEnrollmentV2",
    "PreacceptedEnrollmentVerificationInputV2",
    "SocialMessagingMobilePreEnrollmentV2Unavailable",
    "acceptance_id_v2",
    "approval_event_id_v2",
    "association_creation_preimage_v1_bytes",
    "authorization_v2_digest",
    "canonical_acceptance_id_preimage_v2_bytes",
    "canonical_acceptance_v2_bytes",
    "canonical_approval_event_id_input_v2",
    "canonical_approval_event_v2_bytes",
    "canonical_association_link_v2_bytes",
    "canonical_authorization_envelope_v2_bytes",
    "canonical_pre_enrollment_v2_bytes",
    "canonical_preaccepted_enrollment_verification_input_v2_bytes",
    "epoch_milliseconds_from_utc_second",
    "pairing_possession_proof_v2",
    "pairing_secret_commitment_v2",
    "parse_acceptance_v2",
    "parse_approval_event_v2",
    "parse_association_link_v2",
    "parse_authorization_envelope_v2",
    "parse_pre_enrollment_v2",
    "parse_preaccepted_enrollment_verification_input_v2",
    "phone_exchange_commitment_v2",
    "pre_enrollment_v2_digest",
    "preaccepted_enrollment_verification_input_v2_digest",
    "utc_second_from_epoch_milliseconds",
    "validate_acceptance_time_v2",
    "validate_preaccepted_enrollment_time_v2",
    "verify_pairing_possession_v2",
]
