"""Pure pre-effect authority and identity for one enrollment transition.

This module describes, but never executes, the exact ``enrollment-activate``
effect.  Durable callers must construct its authority from locked state in the
caller-owned transaction.  There is no database, clock, receipt, challenge
consumption, runtime wiring, or final-admission capability here.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import NoReturn, cast

from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1
from app.services.social_messaging_device_proof_profile import (
    MAX_SAFE_INTEGER,
    enrollment_v2_digest,
    parse_enrollment_v2,
)

VERSION = 1
OPERATION = "enrollment-activate"
CHALLENGE_KIND = "enrollment-v2"
PROPOSED_STATE = "active"
TRANSITION_KINDS = ("initial", "rotate", "reenroll")

AUTHORITY_SCHEMA = "hodlxxi.social_enrollment_transition_authority.v1"
EFFECT_ID_PREIMAGE_SCHEMA = "hodlxxi.social_enrollment_effect_id_preimage.v1"
EFFECT_TRANSITION_SCHEMA = "hodlxxi.social_enrollment_effect_transition.v1"
EFFECT_ID_DOMAIN = "HODLXXI_SOCIAL_ENROLLMENT_EFFECT_ID_V1"
EFFECT_DIGEST_DOMAIN = "HODLXXI_SOCIAL_ENROLLMENT_EFFECT_DIGEST_V1"
MAX_AUTHORITY_BYTES = 8_192

RUNTIME_ENABLED = False
EFFECT_EXECUTION = "not_implemented"
CHALLENGE_CONSUMPTION = "not_implemented"
RECEIPT_ISSUANCE = "not_implemented"
FINAL_ADMISSION = "denied"
UNAVAILABLE_MESSAGE = "social enrollment transition authority unavailable"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_CONTEXT_DIGEST = re.compile(r"hodlxxi-social-device-verification-context-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_INPUT_DIGEST = re.compile(r"hodlxxi-social-device-verification-input-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_ENROLLMENT_DIGEST = re.compile(r"hodlxxi-social-messaging-device-enrollment-v2-sha256:[0-9a-f]{64}\Z").fullmatch
_FULL_PROOF_ID = re.compile(r"hodlxxi-full-entitlement-v1-sha256:[0-9a-f]{64}\Z").fullmatch
_KEY_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}\Z").fullmatch

_AUTHORITY_FIELDS = frozenset(
    (
        "approverFullProofId",
        "challengeId",
        "challengeKind",
        "contextDigest",
        "deviceId",
        "enrollmentDigest",
        "fullProofId",
        "inputDigest",
        "lockedDeadlineMs",
        "observedAt",
        "operation",
        "preEffectAssociationId",
        "preEffectAssociationState",
        "preEffectAssociationVersion",
        "preEffectAuthorityEpoch",
        "proposedAssociationId",
        "proposedAssociationVersion",
        "proposedAuthorityEpoch",
        "proposedEd25519PublicKey",
        "proposedPredecessorAssociationId",
        "schema",
        "statementTokenId",
        "subject",
        "transitionKind",
        "version",
    )
)


class SocialEnrollmentTransitionAuthorityUnavailable(ValueError):
    """The one non-sensitive failure exposed by this pure contract."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class EnrollmentTransitionAuthorityV1:
    """Exact locked pre-effect evidence for one proposed successor.

    This record is neither final admission nor proof that an effect executed.
    Only a future durable adapter may establish that its fields came from the
    required locked PostgreSQL state.
    """

    wire: str
    transition_kind: str
    challenge_id: str
    subject: str
    device_id: str
    context_digest: str
    input_digest: str
    enrollment_digest: str
    statement_token_id: str
    observed_at: int
    locked_deadline_ms: int
    full_proof_id: str
    approver_full_proof_id: str
    pre_effect_association_state: str
    pre_effect_association_id: str | None
    pre_effect_association_version: int | None
    pre_effect_authority_epoch: int
    proposed_ed25519_public_key: str
    proposed_association_id: str
    proposed_association_version: int
    proposed_predecessor_association_id: str | None
    proposed_authority_epoch: int
    operation: str = OPERATION
    challenge_kind: str = CHALLENGE_KIND

    def __new__(cls, *args: object, **kwargs: object) -> EnrollmentTransitionAuthorityV1:
        _deny()

    def __init_subclass__(cls, **kwargs: object) -> None:
        _deny()


def _deny() -> NoReturn:
    raise SocialEnrollmentTransitionAuthorityUnavailable()


def _canonical(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _closed_json(source: object) -> dict[str, object]:
    try:
        if type(source) is not str:
            raise ValueError
        encoded = source.encode("ascii")
        if not 1 <= len(encoded) <= MAX_AUTHORITY_BYTES or any(byte < 0x20 or byte > 0x7E for byte in encoded):
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

        value = json.loads(source, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)
        if type(value) is not dict or set(value) != _AUTHORITY_FIELDS or _canonical(value) != source:
            raise ValueError
        return cast(dict[str, object], value)
    except Exception:
        pass
    _deny()


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64(value) is None:
        _deny()
    return cast(str, value)


def _integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER or positive and value == 0:
        _deny()
    return cast(int, value)


def _matching(value: object, matcher) -> str:
    if type(value) is not str or matcher(value) is None:
        _deny()
    return cast(str, value)


def _transition_matrix(
    *,
    transition_kind: object,
    pre_effect_association_state: object,
    pre_effect_association_id: object,
    pre_effect_association_version: object,
    pre_effect_authority_epoch: object,
    proposed_predecessor_association_id: object,
    proposed_association_version: object,
    proposed_authority_epoch: object,
) -> tuple[str, str, str | None, int | None, int, str | None, int, int]:
    if type(transition_kind) is not str or transition_kind not in TRANSITION_KINDS:
        _deny()
    transition = cast(str, transition_kind)
    expected_state = {"initial": "absent", "rotate": "active", "reenroll": "revoked"}[transition]
    if pre_effect_association_state != expected_state:
        _deny()
    pre_epoch = _integer(pre_effect_authority_epoch)
    proposed_version = _integer(proposed_association_version, positive=True)
    proposed_epoch = _integer(proposed_authority_epoch, positive=True)
    if transition == "initial":
        if (
            pre_effect_association_id is not None
            or pre_effect_association_version is not None
            or proposed_predecessor_association_id is not None
            or pre_epoch != 0
            or proposed_version != 1
            or proposed_epoch != 1
        ):
            _deny()
        return transition, expected_state, None, None, 0, None, 1, 1
    pre_id = _hex64(pre_effect_association_id)
    pre_version = _integer(pre_effect_association_version, positive=True)
    predecessor = _hex64(proposed_predecessor_association_id)
    if (
        predecessor != pre_id
        or pre_version == MAX_SAFE_INTEGER
        or pre_epoch == 0
        or pre_epoch == MAX_SAFE_INTEGER
        or proposed_version != pre_version + 1
        or proposed_epoch != pre_epoch + 1
    ):
        _deny()
    return (
        transition,
        expected_state,
        pre_id,
        pre_version,
        pre_epoch,
        predecessor,
        proposed_version,
        proposed_epoch,
    )


def _parse_enrollment_transition_authority_v1(source: object) -> EnrollmentTransitionAuthorityV1:
    """Internally reconstruct one closed canonical authority record."""

    try:
        value = _closed_json(source)
        if (
            value["schema"] != AUTHORITY_SCHEMA
            or type(value["version"]) is not int
            or value["version"] != VERSION
            or value["operation"] != OPERATION
            or value["challengeKind"] != CHALLENGE_KIND
        ):
            _deny()
        matrix = _transition_matrix(
            transition_kind=value["transitionKind"],
            pre_effect_association_state=value["preEffectAssociationState"],
            pre_effect_association_id=value["preEffectAssociationId"],
            pre_effect_association_version=value["preEffectAssociationVersion"],
            pre_effect_authority_epoch=value["preEffectAuthorityEpoch"],
            proposed_predecessor_association_id=value["proposedPredecessorAssociationId"],
            proposed_association_version=value["proposedAssociationVersion"],
            proposed_authority_epoch=value["proposedAuthorityEpoch"],
        )
        observed_at = _integer(value["observedAt"])
        locked_deadline = _integer(value["lockedDeadlineMs"], positive=True)
        if observed_at >= locked_deadline:
            _deny()
        subject = _hex64(value["subject"])
        device_id = _hex64(value["deviceId"])
        proposed_key = _hex64(value["proposedEd25519PublicKey"])
        proposed_id = _hex64(value["proposedAssociationId"])
        if proposed_id in (subject, device_id, proposed_key):
            _deny()
        authority = object.__new__(EnrollmentTransitionAuthorityV1)
        attributes = {
            "wire": cast(str, source),
            "transition_kind": matrix[0],
            "challenge_id": _hex64(value["challengeId"]),
            "subject": subject,
            "device_id": device_id,
            "context_digest": _matching(value["contextDigest"], _CONTEXT_DIGEST),
            "input_digest": _matching(value["inputDigest"], _INPUT_DIGEST),
            "enrollment_digest": _matching(value["enrollmentDigest"], _ENROLLMENT_DIGEST),
            "statement_token_id": _hex64(value["statementTokenId"]),
            "observed_at": observed_at,
            "locked_deadline_ms": locked_deadline,
            "full_proof_id": _matching(value["fullProofId"], _FULL_PROOF_ID),
            "approver_full_proof_id": _matching(value["approverFullProofId"], _FULL_PROOF_ID),
            "pre_effect_association_state": matrix[1],
            "pre_effect_association_id": matrix[2],
            "pre_effect_association_version": matrix[3],
            "pre_effect_authority_epoch": matrix[4],
            "proposed_ed25519_public_key": proposed_key,
            "proposed_association_id": proposed_id,
            "proposed_association_version": matrix[6],
            "proposed_predecessor_association_id": matrix[5],
            "proposed_authority_epoch": matrix[7],
            "operation": OPERATION,
            "challenge_kind": CHALLENGE_KIND,
        }
        for name, item in attributes.items():
            object.__setattr__(authority, name, item)
        return authority
    except Exception:
        pass
    _deny()


def validate_enrollment_transition_authority_v1_bytes(source: object) -> bytes:
    """Validate a wire without granting typed transition authority."""

    authority = _parse_enrollment_transition_authority_v1(source)
    return authority.wire.encode("ascii")


def canonical_enrollment_transition_authority_v1_bytes(
    *,
    transition_kind: object,
    challenge_id: object,
    subject: object,
    device_id: object,
    context_digest: object,
    input_digest: object,
    enrollment_digest: object,
    statement_token_id: object,
    observed_at: object,
    locked_deadline_ms: object,
    full_proof_id: object,
    approver_full_proof_id: object,
    pre_effect_association_state: object,
    pre_effect_association_id: object,
    pre_effect_association_version: object,
    pre_effect_authority_epoch: object,
    proposed_ed25519_public_key: object,
    proposed_association_id: object,
    proposed_association_version: object,
    proposed_predecessor_association_id: object,
    proposed_authority_epoch: object,
) -> bytes:
    wire = _canonical(
        {
            "approverFullProofId": approver_full_proof_id,
            "challengeId": challenge_id,
            "challengeKind": CHALLENGE_KIND,
            "contextDigest": context_digest,
            "deviceId": device_id,
            "enrollmentDigest": enrollment_digest,
            "fullProofId": full_proof_id,
            "inputDigest": input_digest,
            "lockedDeadlineMs": locked_deadline_ms,
            "observedAt": observed_at,
            "operation": OPERATION,
            "preEffectAssociationId": pre_effect_association_id,
            "preEffectAssociationState": pre_effect_association_state,
            "preEffectAssociationVersion": pre_effect_association_version,
            "preEffectAuthorityEpoch": pre_effect_authority_epoch,
            "proposedAssociationId": proposed_association_id,
            "proposedAssociationVersion": proposed_association_version,
            "proposedAuthorityEpoch": proposed_authority_epoch,
            "proposedEd25519PublicKey": proposed_ed25519_public_key,
            "proposedPredecessorAssociationId": proposed_predecessor_association_id,
            "schema": AUTHORITY_SCHEMA,
            "statementTokenId": statement_token_id,
            "subject": subject,
            "transitionKind": transition_kind,
            "version": VERSION,
        }
    )
    validate_enrollment_transition_authority_v1_bytes(wire)
    return wire.encode("ascii")


def _exact_input(value: object) -> admission.VerificationInputV1:
    if type(value) is not admission.VerificationInputV1 or admission.parse_verification_input_v1(value.wire) != value:
        _deny()
    return cast(admission.VerificationInputV1, value)


def _authenticated_statement(
    value: admission.VerificationInputV1,
    statement: object,
    *,
    observed_at: int,
) -> AuthenticatedSocialDeviceVerificationStatementV1:
    try:
        if type(statement) is not AuthenticatedSocialDeviceVerificationStatementV1:
            _deny()
        statement = cast(AuthenticatedSocialDeviceVerificationStatementV1, statement)
        context = value.context
        enrollment = parse_enrollment_v2(value.challenge_wire)
        context_digest = admission.verification_context_digest_v1(context.wire)
        input_digest = admission.verification_input_digest_v1(value.wire)
        if (
            statement.result != admission.ENROLLMENT_V2_RESULT
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
            or _hex64(statement.token_id) != statement.token_id
            or admission._configured_identifier(statement.key_id) != statement.key_id
            or _matching(statement.key_fingerprint, _KEY_FINGERPRINT) != statement.key_fingerprint
            or type(statement.issued_at) is not int
            or type(statement.expires_at) is not int
            or not enrollment.issued_at <= observed_at < enrollment.expires_at
            or not statement.issued_at <= observed_at < statement.expires_at
            or statement.issued_at < enrollment.issued_at
            or statement.expires_at > enrollment.expires_at
        ):
            _deny()
        return statement
    except Exception:
        pass
    _deny()


def authorize_enrollment_transition_v1(
    value: object,
    statement: object,
    association_lifecycle: object,
    *,
    observed_at: object,
    locked_deadline_ms: object,
    full_proof_id: object,
    approver_full_proof_id: object,
) -> EnrollmentTransitionAuthorityV1:
    """Describe one lifecycle-permitted transition from locked pre-effect state.

    ``association_lifecycle`` is pure evidence.  A future adapter must load it
    under the established pair lock after independently validating Full,
    device/approver sessions, X25519 binding, and challenge state.
    """

    try:
        value = _exact_input(value)
        context = value.context
        now = _integer(observed_at)
        deadline = _integer(locked_deadline_ms, positive=True)
        if (
            value.operation != OPERATION
            or context.challenge_kind != CHALLENGE_KIND
            or now >= deadline
            or _matching(full_proof_id, _FULL_PROOF_ID) != context.full_proof_id
            or _matching(approver_full_proof_id, _FULL_PROOF_ID) != context.approver_full_proof_id
        ):
            _deny()
        authenticated = _authenticated_statement(value, statement, observed_at=now)
        snapshot = lifecycle.association_snapshot_v1(association_lifecycle)
        if not snapshot.history:
            transition = "initial"
            pre_state = "absent"
            pre_id = None
            pre_version = None
            updated = lifecycle.initial_association_v1(association_lifecycle, value.challenge_wire)
        elif snapshot.current is not None:
            transition = "rotate"
            pre_state = "active"
            pre_id = snapshot.current.association_id
            pre_version = snapshot.current.association_version
            updated = lifecycle.rotate_association_v1(
                association_lifecycle,
                value.challenge_wire,
                expected_predecessor_association_id=pre_id,
                expected_authority_epoch=snapshot.authority_epoch,
            )
        else:
            previous = snapshot.history[-1]
            if previous.state != "revoked":
                _deny()
            transition = "reenroll"
            pre_state = "revoked"
            pre_id = previous.association_id
            pre_version = previous.association_version
            updated = lifecycle.reenroll_association_v1(
                association_lifecycle,
                value.challenge_wire,
                expected_predecessor_association_id=pre_id,
                expected_authority_epoch=snapshot.authority_epoch,
            )
        if not lifecycle.current_association_matches_v1(updated, context):
            _deny()
        wire = canonical_enrollment_transition_authority_v1_bytes(
            transition_kind=transition,
            challenge_id=context.challenge_id,
            subject=context.subject,
            device_id=context.device_id,
            context_digest=authenticated.context_digest,
            input_digest=authenticated.input_digest,
            enrollment_digest=enrollment_v2_digest(value.challenge_wire),
            statement_token_id=authenticated.token_id,
            observed_at=now,
            locked_deadline_ms=deadline,
            full_proof_id=full_proof_id,
            approver_full_proof_id=approver_full_proof_id,
            pre_effect_association_state=pre_state,
            pre_effect_association_id=pre_id,
            pre_effect_association_version=pre_version,
            pre_effect_authority_epoch=snapshot.authority_epoch,
            proposed_ed25519_public_key=context.ed25519_public_key,
            proposed_association_id=context.association_id,
            proposed_association_version=context.association_version,
            proposed_predecessor_association_id=context.predecessor_association_id,
            proposed_authority_epoch=context.authority_epoch,
        )
        return _parse_enrollment_transition_authority_v1(wire.decode("ascii"))
    except Exception:
        pass
    _deny()


def _exact_authority(value: object) -> EnrollmentTransitionAuthorityV1:
    if (
        type(value) is not EnrollmentTransitionAuthorityV1
        or _parse_enrollment_transition_authority_v1(value.wire) != value
    ):
        _deny()
    return cast(EnrollmentTransitionAuthorityV1, value)


def canonical_enrollment_effect_id_preimage_v1_bytes(authority: object) -> bytes:
    """Identify the exact authenticated enrollment operation instance."""

    value = _exact_authority(authority)
    return _canonical(
        {
            "challengeId": value.challenge_id,
            "challengeKind": value.challenge_kind,
            "contextDigest": value.context_digest,
            "deviceId": value.device_id,
            "inputDigest": value.input_digest,
            "operation": value.operation,
            "schema": EFFECT_ID_PREIMAGE_SCHEMA,
            "statementTokenId": value.statement_token_id,
            "subject": value.subject,
            "version": VERSION,
        }
    ).encode("ascii")


def enrollment_effect_id_v1(authority: object) -> str:
    preimage = canonical_enrollment_effect_id_preimage_v1_bytes(authority)
    return hashlib.sha256(EFFECT_ID_DOMAIN.encode("ascii") + b"\0" + preimage).hexdigest()


def canonical_enrollment_effect_transition_v1_bytes(authority: object) -> bytes:
    """Describe the exact deterministic lifecycle transition, not its commit."""

    value = _exact_authority(authority)
    return _canonical(
        {
            "challengeId": value.challenge_id,
            "challengeKind": value.challenge_kind,
            "deviceId": value.device_id,
            "enrollmentDigest": value.enrollment_digest,
            "operation": value.operation,
            "preEffectAssociationId": value.pre_effect_association_id,
            "preEffectAssociationState": value.pre_effect_association_state,
            "preEffectAssociationVersion": value.pre_effect_association_version,
            "preEffectAuthorityEpoch": value.pre_effect_authority_epoch,
            "proposedAssociationId": value.proposed_association_id,
            "proposedAssociationVersion": value.proposed_association_version,
            "proposedAuthorityEpoch": value.proposed_authority_epoch,
            "proposedEd25519PublicKey": value.proposed_ed25519_public_key,
            "proposedPredecessorAssociationId": value.proposed_predecessor_association_id,
            "proposedState": PROPOSED_STATE,
            "schema": EFFECT_TRANSITION_SCHEMA,
            "subject": value.subject,
            "transitionKind": value.transition_kind,
            "version": VERSION,
        }
    ).encode("ascii")


def enrollment_effect_digest_v1(authority: object) -> str:
    preimage = canonical_enrollment_effect_transition_v1_bytes(authority)
    return hashlib.sha256(EFFECT_DIGEST_DOMAIN.encode("ascii") + b"\0" + preimage).hexdigest()


def prepared_enrollment_effect_v1(authority: object) -> admission.PreparedAdmissionEffectV1:
    """Return a deterministic description; execute and commit nothing."""

    value = _exact_authority(authority)
    return admission.PreparedAdmissionEffectV1(
        operation=OPERATION,
        effect_id=enrollment_effect_id_v1(value),
        effect_digest=enrollment_effect_digest_v1(value),
    )


__all__ = [
    "AUTHORITY_SCHEMA",
    "CHALLENGE_CONSUMPTION",
    "EFFECT_DIGEST_DOMAIN",
    "EFFECT_EXECUTION",
    "EFFECT_ID_DOMAIN",
    "EFFECT_ID_PREIMAGE_SCHEMA",
    "EFFECT_TRANSITION_SCHEMA",
    "EnrollmentTransitionAuthorityV1",
    "FINAL_ADMISSION",
    "MAX_AUTHORITY_BYTES",
    "RECEIPT_ISSUANCE",
    "RUNTIME_ENABLED",
    "SocialEnrollmentTransitionAuthorityUnavailable",
    "TRANSITION_KINDS",
    "authorize_enrollment_transition_v1",
    "canonical_enrollment_effect_id_preimage_v1_bytes",
    "canonical_enrollment_effect_transition_v1_bytes",
    "canonical_enrollment_transition_authority_v1_bytes",
    "enrollment_effect_digest_v1",
    "enrollment_effect_id_v1",
    "prepared_enrollment_effect_v1",
    "validate_enrollment_transition_authority_v1_bytes",
]
