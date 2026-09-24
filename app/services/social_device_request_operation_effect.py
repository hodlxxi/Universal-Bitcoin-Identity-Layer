"""Pure identity for dormant Social ``device-request-v1`` effects.

This module reparses the frozen admission input and accepts only the concrete
authenticated Social statement plus the already-selected current authority.
It describes deterministic request effects and receipt identity.  It performs
no I/O, executes no effect, consumes no challenge, stores no receipt, resolves
no recipient, and grants no admission.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping, NoReturn, TypeAlias, cast

from app.services import social_messaging_device_admission_contract as admission
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1

VERSION = 1
CHALLENGE_KIND = "device-request-v1"
CIPHERTEXT_SUBMIT = "ciphertext-submit"
RECIPIENT_SELF_READ = "recipient-self-read"
OPERATIONS = (CIPHERTEXT_SUBMIT, RECIPIENT_SELF_READ)

EFFECT_ID_PREIMAGE_SCHEMA = "hodlxxi.social_device_request_effect_id_preimage.v1"
CIPHERTEXT_SUBMIT_EFFECT_SCHEMA = "hodlxxi.social_device_request_ciphertext_submit_effect.v1"
RECIPIENT_SELF_READ_EFFECT_SCHEMA = "hodlxxi.social_device_request_recipient_self_read_effect.v1"
RECEIPT_ID_PREIMAGE_SCHEMA = "hodlxxi.social_device_request_receipt_id_preimage.v1"
PREPARED_EFFECT_SCHEMA = "hodlxxi.social_device_request_prepared_effect.v1"

EFFECT_ID_DOMAIN = "HODLXXI_SOCIAL_DEVICE_REQUEST_EFFECT_ID_V1"
EFFECT_DIGEST_DOMAIN = "HODLXXI_SOCIAL_DEVICE_REQUEST_EFFECT_DIGEST_V1"
RECEIPT_ID_DOMAIN = "HODLXXI_SOCIAL_DEVICE_REQUEST_RECEIPT_ID_V1"

RUNTIME_ENABLED = False
EFFECT_EXECUTION = "not_implemented"
CHALLENGE_CONSUMPTION = "not_implemented"
RECEIPT_STORAGE = "not_implemented"
ROUTING_DECISION = "not_implemented"
RECIPIENT_RESOLUTION = "not_implemented"
FINAL_ADMISSION = "denied"
UNAVAILABLE_MESSAGE = "social device request operation effect unavailable"

_KEY_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}\Z").fullmatch


class SocialDeviceRequestOperationEffectUnavailable(ValueError):
    """The one non-sensitive failure exposed by this pure contract."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class CiphertextSubmitPromisedEffectV1:
    """Frozen facts available before any routing decision or persistence."""

    actual_request_wire: str
    routing_request_wire: str
    body_digest: str
    message_id: str
    envelope_digest: str
    recipient_package_snapshot_id: str
    recipient_device_handles: tuple[str, ...]

    def __new__(cls, *args: object, **kwargs: object) -> CiphertextSubmitPromisedEffectV1:
        _deny()

    def __init_subclass__(cls, **kwargs: object) -> None:
        _deny()


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RecipientSelfReadPromisedEffectV1:
    """Frozen self-read request only; no resolution, selection, or pagination."""

    actual_request_wire: str
    body_digest: str
    recipient_handle: str

    def __new__(cls, *args: object, **kwargs: object) -> RecipientSelfReadPromisedEffectV1:
        _deny()

    def __init_subclass__(cls, **kwargs: object) -> None:
        _deny()


PromisedDeviceRequestEffectV1: TypeAlias = CiphertextSubmitPromisedEffectV1 | RecipientSelfReadPromisedEffectV1


@dataclass(frozen=True, slots=True, init=False, repr=False)
class PreparedDeviceRequestOperationEffectV1:
    """Typed non-authoritative identity for one exact prepared request effect."""

    challenge_kind: str
    challenge_id: str
    operation: str
    subject: str
    device_id: str
    binding_id: str
    binding_version: int
    association_id: str
    association_version: int
    context_digest: str
    input_digest: str
    authority_epoch: int
    locked_deadline_ms: int
    full_proof_id: str
    approver_full_proof_id: None
    statement_token_id: str
    statement_attempt_id: str
    promised_effect: PromisedDeviceRequestEffectV1
    effect_id: str
    effect_digest: str
    receipt_id: str

    def __new__(cls, *args: object, **kwargs: object) -> PreparedDeviceRequestOperationEffectV1:
        _deny()

    def __init_subclass__(cls, **kwargs: object) -> None:
        _deny()


def _deny() -> NoReturn:
    raise SocialDeviceRequestOperationEffectUnavailable()


def _canonical(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    except Exception:
        pass
    _deny()


def _hash(domain: str, preimage: bytes) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + preimage).hexdigest()


def _time(value: object) -> int:
    if type(value) is not int or value < 0 or value > admission.MAX_SAFE_INTEGER:
        _deny()
    return cast(int, value)


def _exact_input(value: object) -> admission.VerificationInputV1:
    if type(value) is not admission.VerificationInputV1:
        _deny()
    parsed = admission.parse_verification_input_v1(value.wire)
    if parsed != value or parsed.context.challenge_kind != CHALLENGE_KIND or parsed.operation not in OPERATIONS:
        _deny()
    return parsed


def _exact_authority(
    value: object,
    input_value: admission.VerificationInputV1,
    *,
    observed_at: int,
) -> admission.CurrentAdmissionAuthorityV1:
    if type(value) is not admission.CurrentAdmissionAuthorityV1:
        _deny()
    authority = cast(admission.CurrentAdmissionAuthorityV1, value)
    context = input_value.context
    if (
        authority.context_digest != admission.verification_context_digest_v1(context.wire)
        or type(authority.authority_epoch) is not int
        or authority.authority_epoch != context.authority_epoch
        or type(authority.locked_deadline_ms) is not int
        or not 0 < authority.locked_deadline_ms <= admission.MAX_SAFE_INTEGER
        or observed_at >= authority.locked_deadline_ms
        or authority.full_proof_id != context.full_proof_id
        or authority.approver_full_proof_id is not None
        or context.approver_full_proof_id is not None
    ):
        _deny()
    return authority


def _authenticated_statement(
    value: object,
    input_value: admission.VerificationInputV1,
    *,
    observed_at: int,
    challenge_issued_at: int,
    challenge_expires_at: int,
) -> AuthenticatedSocialDeviceVerificationStatementV1:
    try:
        if type(value) is not AuthenticatedSocialDeviceVerificationStatementV1:
            _deny()
        statement = cast(AuthenticatedSocialDeviceVerificationStatementV1, value)
        context = input_value.context
        context_digest = admission.verification_context_digest_v1(context.wire)
        input_digest = admission.verification_input_digest_v1(input_value.wire)
        if (
            statement.result != admission.STRICT_ED25519_RESULT
            or statement.purpose != admission.STATEMENT_PURPOSE
            or statement.issuer != context.audience
            or admission._statement_audience(statement.audience) != statement.audience
            or admission._configured_identifier(statement.client_id) != statement.client_id
            or admission._configured_identifier(statement.service_principal) != statement.service_principal
            or statement.challenge_kind != CHALLENGE_KIND
            or statement.challenge_id != context.challenge_id
            or statement.attempt_id != context.attempt_id
            or statement.context_digest != context_digest
            or statement.input_digest != input_digest
            or admission._hex64(statement.token_id) != statement.token_id
            or admission._configured_identifier(statement.key_id) != statement.key_id
            or type(statement.key_fingerprint) is not str
            or _KEY_FINGERPRINT(statement.key_fingerprint) is None
            or type(statement.issued_at) is not int
            or type(statement.expires_at) is not int
            or not challenge_issued_at <= statement.issued_at <= observed_at < statement.expires_at
            or statement.expires_at > challenge_expires_at
        ):
            _deny()
        return statement
    except Exception:
        pass
    _deny()


def _make_ciphertext_promise(
    actual_request_wire: str,
    request: Mapping[str, object],
    routing_request_wire: str,
    routing: Mapping[str, object],
) -> CiphertextSubmitPromisedEffectV1:
    promised = object.__new__(CiphertextSubmitPromisedEffectV1)
    values = {
        "actual_request_wire": actual_request_wire,
        "routing_request_wire": routing_request_wire,
        "body_digest": request["bodyDigest"],
        "message_id": routing["messageId"],
        "envelope_digest": routing["envelopeDigest"],
        "recipient_package_snapshot_id": routing["recipientPackageSnapshotId"],
        "recipient_device_handles": tuple(cast(list[str], routing["recipientDeviceHandles"])),
    }
    for name, item in values.items():
        object.__setattr__(promised, name, item)
    return promised


def _make_self_read_promise(
    actual_request_wire: str,
    request: Mapping[str, object],
) -> RecipientSelfReadPromisedEffectV1:
    promised = object.__new__(RecipientSelfReadPromisedEffectV1)
    values = {
        "actual_request_wire": actual_request_wire,
        "body_digest": request["bodyDigest"],
        "recipient_handle": request["recipientHandle"],
    }
    for name, item in values.items():
        object.__setattr__(promised, name, item)
    return promised


def _effect_id_preimage(value: PreparedDeviceRequestOperationEffectV1) -> bytes:
    return _canonical(
        {
            "approverFullProofId": value.approver_full_proof_id,
            "authorityEpoch": value.authority_epoch,
            "challengeId": value.challenge_id,
            "challengeKind": value.challenge_kind,
            "contextDigest": value.context_digest,
            "deviceId": value.device_id,
            "fullProofId": value.full_proof_id,
            "inputDigest": value.input_digest,
            "lockedDeadlineMs": value.locked_deadline_ms,
            "operation": value.operation,
            "schema": EFFECT_ID_PREIMAGE_SCHEMA,
            "statementAttemptId": value.statement_attempt_id,
            "statementTokenId": value.statement_token_id,
            "subject": value.subject,
            "version": VERSION,
        }
    )


def _effect_digest_values(value: PreparedDeviceRequestOperationEffectV1) -> dict[str, object]:
    promised = value.promised_effect
    common: dict[str, object] = {
        "actualRequestWire": promised.actual_request_wire,
        "associationId": value.association_id,
        "associationVersion": value.association_version,
        "authorityEpoch": value.authority_epoch,
        "bindingId": value.binding_id,
        "bindingVersion": value.binding_version,
        "bodyDigest": promised.body_digest,
        "challengeId": value.challenge_id,
        "challengeKind": value.challenge_kind,
        "contextDigest": value.context_digest,
        "deviceId": value.device_id,
        "fullProofId": value.full_proof_id,
        "lockedDeadlineMs": value.locked_deadline_ms,
        "operation": value.operation,
        "subject": value.subject,
        "version": VERSION,
    }
    if type(promised) is CiphertextSubmitPromisedEffectV1:
        common.update(
            {
                "envelopeDigest": promised.envelope_digest,
                "messageId": promised.message_id,
                "recipientDeviceHandles": promised.recipient_device_handles,
                "recipientPackageSnapshotId": promised.recipient_package_snapshot_id,
                "routingRequestWire": promised.routing_request_wire,
                "schema": CIPHERTEXT_SUBMIT_EFFECT_SCHEMA,
            }
        )
    elif type(promised) is RecipientSelfReadPromisedEffectV1:
        common.update(
            {
                "recipientHandle": promised.recipient_handle,
                "schema": RECIPIENT_SELF_READ_EFFECT_SCHEMA,
            }
        )
    else:
        _deny()
    return common


def _effect_digest_preimage(value: PreparedDeviceRequestOperationEffectV1) -> bytes:
    return _canonical(_effect_digest_values(value))


def _receipt_id_preimage(value: PreparedDeviceRequestOperationEffectV1) -> bytes:
    return _canonical(
        {
            "approverFullProofId": value.approver_full_proof_id,
            "authorityEpoch": value.authority_epoch,
            "challengeId": value.challenge_id,
            "challengeKind": value.challenge_kind,
            "contextDigest": value.context_digest,
            "deviceId": value.device_id,
            "effectDigest": value.effect_digest,
            "effectId": value.effect_id,
            "fullProofId": value.full_proof_id,
            "inputDigest": value.input_digest,
            "lockedDeadlineMs": value.locked_deadline_ms,
            "operation": value.operation,
            "schema": RECEIPT_ID_PREIMAGE_SCHEMA,
            "statementAttemptId": value.statement_attempt_id,
            "statementTokenId": value.statement_token_id,
            "subject": value.subject,
            "version": VERSION,
        }
    )


def _validate_promise(value: PreparedDeviceRequestOperationEffectV1) -> None:
    promised = value.promised_effect
    if type(promised) is CiphertextSubmitPromisedEffectV1:
        if value.operation != CIPHERTEXT_SUBMIT:
            _deny()
        request = admission._parse_request(promised.actual_request_wire)
        routing = admission._parse_routing_request(promised.routing_request_wire)
        if (
            request["operation"] != CIPHERTEXT_SUBMIT
            or request["recipientHandle"] is not None
            or request["bodyDigest"] != promised.body_digest
            or routing["messageId"] != promised.message_id
            or routing["envelopeDigest"] != promised.envelope_digest
            or routing["recipientPackageSnapshotId"] != promised.recipient_package_snapshot_id
            or tuple(cast(list[str], routing["recipientDeviceHandles"])) != promised.recipient_device_handles
        ):
            _deny()
    elif type(promised) is RecipientSelfReadPromisedEffectV1:
        if value.operation != RECIPIENT_SELF_READ:
            _deny()
        request = admission._parse_request(promised.actual_request_wire)
        if (
            request["operation"] != RECIPIENT_SELF_READ
            or request["bodyDigest"] != promised.body_digest
            or request["recipientHandle"] != promised.recipient_handle
        ):
            _deny()
    else:
        _deny()
    if (
        request["subject"] != value.subject
        or request["deviceId"] != value.device_id
        or request["bindingId"] != value.binding_id
        or request["bindingVersion"] != value.binding_version
    ):
        _deny()


def _exact_prepared(value: object) -> PreparedDeviceRequestOperationEffectV1:
    if type(value) is not PreparedDeviceRequestOperationEffectV1:
        _deny()
    prepared = cast(PreparedDeviceRequestOperationEffectV1, value)
    if (
        prepared.challenge_kind != CHALLENGE_KIND
        or prepared.operation not in OPERATIONS
        or admission._hex64(prepared.challenge_id) != prepared.challenge_id
        or admission._hex64(prepared.subject) != prepared.subject
        or admission._hex64(prepared.device_id) != prepared.device_id
        or admission._hex64(prepared.binding_id) != prepared.binding_id
        or admission._integer(prepared.binding_version, positive=True) > 1_024
        or admission._hex64(prepared.association_id) != prepared.association_id
        or admission._integer(prepared.association_version, positive=True) != prepared.association_version
        or type(prepared.context_digest) is not str
        or admission._CONTEXT_DIGEST(prepared.context_digest) is None
        or type(prepared.input_digest) is not str
        or admission._INPUT_DIGEST(prepared.input_digest) is None
        or admission._integer(prepared.authority_epoch, positive=True) != prepared.authority_epoch
        or admission._integer(prepared.locked_deadline_ms, positive=True) != prepared.locked_deadline_ms
        or type(prepared.full_proof_id) is not str
        or admission._FULL_PROOF_ID(prepared.full_proof_id) is None
        or prepared.approver_full_proof_id is not None
        or admission._hex64(prepared.statement_token_id) != prepared.statement_token_id
        or admission._hex64(prepared.statement_attempt_id) != prepared.statement_attempt_id
    ):
        _deny()
    _validate_promise(prepared)
    if (
        _hash(EFFECT_ID_DOMAIN, _effect_id_preimage(prepared)) != prepared.effect_id
        or _hash(EFFECT_DIGEST_DOMAIN, _effect_digest_preimage(prepared)) != prepared.effect_digest
        or _hash(RECEIPT_ID_DOMAIN, _receipt_id_preimage(prepared)) != prepared.receipt_id
    ):
        _deny()
    return prepared


def prepare_device_request_operation_effect_v1(
    value: object,
    authority: object,
    statement: object,
    *,
    observed_at: object,
) -> PreparedDeviceRequestOperationEffectV1:
    """Prepare deterministic identities from exact already-authoritative inputs."""

    try:
        input_value = _exact_input(value)
        now = _time(observed_at)
        context = input_value.context
        challenge = cast(dict[str, object], json.loads(input_value.challenge_wire))
        challenge_issued_at = _time(challenge["issuedAt"])
        challenge_expires_at = _time(challenge["expiresAt"])
        if not challenge_issued_at <= now < challenge_expires_at:
            _deny()
        current = _exact_authority(authority, input_value, observed_at=now)
        authenticated = _authenticated_statement(
            statement,
            input_value,
            observed_at=now,
            challenge_issued_at=challenge_issued_at,
            challenge_expires_at=challenge_expires_at,
        )
        actual_wire = input_value.actual_request_wire
        if actual_wire is None:
            _deny()
        request = admission._parse_request(actual_wire)
        if input_value.operation == CIPHERTEXT_SUBMIT:
            routing_wire = input_value.routing_request_wire
            if routing_wire is None:
                _deny()
            promised: PromisedDeviceRequestEffectV1 = _make_ciphertext_promise(
                actual_wire,
                request,
                routing_wire,
                admission._parse_routing_request(routing_wire),
            )
        elif input_value.operation == RECIPIENT_SELF_READ:
            if input_value.routing_request_wire is not None:
                _deny()
            promised = _make_self_read_promise(actual_wire, request)
        else:
            _deny()

        prepared = object.__new__(PreparedDeviceRequestOperationEffectV1)
        values = {
            "challenge_kind": CHALLENGE_KIND,
            "challenge_id": context.challenge_id,
            "operation": input_value.operation,
            "subject": context.subject,
            "device_id": context.device_id,
            "binding_id": context.binding_id,
            "binding_version": context.binding_version,
            "association_id": context.association_id,
            "association_version": context.association_version,
            "context_digest": current.context_digest,
            "input_digest": authenticated.input_digest,
            "authority_epoch": current.authority_epoch,
            "locked_deadline_ms": current.locked_deadline_ms,
            "full_proof_id": current.full_proof_id,
            "approver_full_proof_id": current.approver_full_proof_id,
            "statement_token_id": authenticated.token_id,
            "statement_attempt_id": authenticated.attempt_id,
            "promised_effect": promised,
        }
        for name, item in values.items():
            object.__setattr__(prepared, name, item)
        object.__setattr__(prepared, "effect_id", _hash(EFFECT_ID_DOMAIN, _effect_id_preimage(prepared)))
        object.__setattr__(
            prepared,
            "effect_digest",
            _hash(EFFECT_DIGEST_DOMAIN, _effect_digest_preimage(prepared)),
        )
        object.__setattr__(prepared, "receipt_id", _hash(RECEIPT_ID_DOMAIN, _receipt_id_preimage(prepared)))
        return _exact_prepared(prepared)
    except Exception:
        pass
    _deny()


def canonical_request_effect_id_preimage_v1_bytes(value: object) -> bytes:
    """Identify one request authorization instance; no completion time enters."""

    return _effect_id_preimage(_exact_prepared(value))


def request_effect_id_v1(value: object) -> str:
    prepared = _exact_prepared(value)
    return _hash(EFFECT_ID_DOMAIN, _effect_id_preimage(prepared))


def canonical_request_effect_digest_preimage_v1_bytes(value: object) -> bytes:
    """Commit only to the frozen pre-routing/pre-read promised effect facts."""

    return _effect_digest_preimage(_exact_prepared(value))


def request_effect_digest_v1(value: object) -> str:
    prepared = _exact_prepared(value)
    return _hash(EFFECT_DIGEST_DOMAIN, _effect_digest_preimage(prepared))


def canonical_request_receipt_id_preimage_v1_bytes(value: object) -> bytes:
    """Freeze future receipt identity without ``decidedAt`` or commit claims."""

    return _receipt_id_preimage(_exact_prepared(value))


def request_receipt_id_v1(value: object) -> str:
    prepared = _exact_prepared(value)
    return _hash(RECEIPT_ID_DOMAIN, _receipt_id_preimage(prepared))


def canonical_prepared_request_operation_effect_v1_bytes(value: object) -> bytes:
    """Project the exact typed preparation as canonical non-authoritative JSON."""

    prepared = _exact_prepared(value)
    return _canonical(
        {
            "approverFullProofId": prepared.approver_full_proof_id,
            "authorityEpoch": prepared.authority_epoch,
            "challengeId": prepared.challenge_id,
            "challengeKind": prepared.challenge_kind,
            "contextDigest": prepared.context_digest,
            "deviceId": prepared.device_id,
            "effectDigest": prepared.effect_digest,
            "effectId": prepared.effect_id,
            "fullProofId": prepared.full_proof_id,
            "inputDigest": prepared.input_digest,
            "lockedDeadlineMs": prepared.locked_deadline_ms,
            "operation": prepared.operation,
            "promisedEffect": _effect_digest_values(prepared),
            "receiptId": prepared.receipt_id,
            "schema": PREPARED_EFFECT_SCHEMA,
            "statementAttemptId": prepared.statement_attempt_id,
            "statementTokenId": prepared.statement_token_id,
            "subject": prepared.subject,
            "version": VERSION,
        }
    )


def prepared_admission_effect_v1(value: object) -> admission.PreparedAdmissionEffectV1:
    """Return the generic interface projection without granting it authority."""

    prepared = _exact_prepared(value)
    return admission.PreparedAdmissionEffectV1(
        operation=prepared.operation,
        effect_id=prepared.effect_id,
        effect_digest=prepared.effect_digest,
    )


__all__ = [
    "CHALLENGE_CONSUMPTION",
    "CHALLENGE_KIND",
    "CIPHERTEXT_SUBMIT",
    "CIPHERTEXT_SUBMIT_EFFECT_SCHEMA",
    "CiphertextSubmitPromisedEffectV1",
    "EFFECT_DIGEST_DOMAIN",
    "EFFECT_EXECUTION",
    "EFFECT_ID_DOMAIN",
    "EFFECT_ID_PREIMAGE_SCHEMA",
    "FINAL_ADMISSION",
    "PREPARED_EFFECT_SCHEMA",
    "PreparedDeviceRequestOperationEffectV1",
    "RECEIPT_ID_DOMAIN",
    "RECEIPT_ID_PREIMAGE_SCHEMA",
    "RECEIPT_STORAGE",
    "RECIPIENT_RESOLUTION",
    "RECIPIENT_SELF_READ",
    "RECIPIENT_SELF_READ_EFFECT_SCHEMA",
    "ROUTING_DECISION",
    "RUNTIME_ENABLED",
    "RecipientSelfReadPromisedEffectV1",
    "SocialDeviceRequestOperationEffectUnavailable",
    "canonical_prepared_request_operation_effect_v1_bytes",
    "canonical_request_effect_digest_preimage_v1_bytes",
    "canonical_request_effect_id_preimage_v1_bytes",
    "canonical_request_receipt_id_preimage_v1_bytes",
    "prepare_device_request_operation_effect_v1",
    "prepared_admission_effect_v1",
    "request_effect_digest_v1",
    "request_effect_id_v1",
    "request_receipt_id_v1",
]
