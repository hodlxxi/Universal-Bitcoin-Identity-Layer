"""Dormant pure freeze for V2 reservation, final acceptance, CAS, and retry.

Every value returned here is a deterministic plan or inspection result.  It is
not evidence that PostgreSQL locks, persistence, an association effect, a
challenge consumption, a receipt publication, or a commit occurred.  The
future durable owner must perform those operations in one caller-owned UBID
transaction and may use these bytes only after reconstructing them from the
exact locked rows.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from functools import wraps
from types import MappingProxyType
from typing import Callable, Mapping, NoReturn, ParamSpec, TypeVar, cast

from app.services import social_messaging_device_verification_deadline_evidence_v1 as deadline
from app.services import social_messaging_mobile_pre_enrollment_v2 as preacceptance
from app.services import social_preaccepted_enrollment_verification_statement_v2 as verification

VERSION = 1
RESERVATION_SCHEMA = "hodlxxi.social_preaccepted_enrollment_v2_acceptance_reservation.v1"
AUTHORITY_SNAPSHOT_SCHEMA = "hodlxxi.social_preaccepted_enrollment_v2_current_authority_snapshot.v1"
FINALIZATION_OBSERVATION_SCHEMA = "hodlxxi.social_preaccepted_enrollment_v2_finalization_observation.v1"
EFFECT_ID_PREIMAGE_SCHEMA = "hodlxxi.social_preaccepted_enrollment_v2_effect_id_preimage.v1"
EFFECT_SCHEMA = "hodlxxi.social_preaccepted_enrollment_v2_acceptance_effect.v1"
RECEIPT_ID_PREIMAGE_SCHEMA = "hodlxxi.social_preaccepted_enrollment_v2_receipt_id_preimage.v1"
RECEIPT_SCHEMA = "hodlxxi.social_preaccepted_enrollment_v2_acceptance_receipt.v1"

EVIDENCE_DIGEST_DOMAIN = "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_DEADLINE_EVIDENCE_V1"
EVIDENCE_PAYLOAD_DIGEST_DOMAIN = "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_DEADLINE_PAYLOAD_V1"
STATEMENT_DIGEST_DOMAIN = "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_VERIFICATION_STATEMENT_V1"
AUTHORITY_SNAPSHOT_DIGEST_DOMAIN = "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_AUTHORITY_SNAPSHOT_V1"
FINALIZATION_REQUEST_DIGEST_DOMAIN = "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_FINALIZATION_REQUEST_V1"
EFFECT_ID_DOMAIN = "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_EFFECT_ID_V1"
EFFECT_DIGEST_DOMAIN = "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_EFFECT_DIGEST_V1"
RECEIPT_ID_DOMAIN = "HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_RECEIPT_ID_V1"

EVIDENCE_DIGEST_PREFIX = "hodlxxi-social-preaccepted-enrollment-v2-deadline-evidence-v1-sha256:"
EVIDENCE_PAYLOAD_DIGEST_PREFIX = "hodlxxi-social-preaccepted-enrollment-v2-deadline-payload-v1-sha256:"
STATEMENT_DIGEST_PREFIX = "hodlxxi-social-preaccepted-enrollment-v2-verification-statement-v1-sha256:"
AUTHORITY_SNAPSHOT_DIGEST_PREFIX = "hodlxxi-social-preaccepted-enrollment-v2-authority-snapshot-v1-sha256:"
FINALIZATION_REQUEST_DIGEST_PREFIX = "hodlxxi-social-preaccepted-enrollment-v2-finalization-request-v1-sha256:"
EFFECT_DIGEST_PREFIX = "hodlxxi-social-preaccepted-enrollment-v2-effect-v1-sha256:"

MAX_RESERVATION_BYTES = 8_192
MAX_AUTHORITY_SNAPSHOT_BYTES = 12_288
MAX_FINALIZATION_OBSERVATION_BYTES = 16_384
MAX_EFFECT_BYTES = 8_192
MAX_RECEIPT_BYTES = 8_192
MAX_SAFE_INTEGER = 9_007_199_254_740_991

RUNTIME_ENABLED = False
TRANSACTION_OWNER = "caller_owned_ubid_postgresql"
LOCKING = "not_performed_by_pure_contract"
PERSISTENCE = "not_performed_by_pure_contract"
COMMIT = "not_performed_by_pure_contract"
FINAL_ADMISSION = "denied"
DENIED_MESSAGE = "social preaccepted enrollment v2 atomic acceptance denied"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z").fullmatch
_BOUNDED_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z").fullmatch
_INPUT_DIGEST = re.compile(
    r"hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:[0-9a-f]{64}\Z"
).fullmatch
_INPUT_PAYLOAD_DIGEST = re.compile(re.escape(deadline.INPUT_PAYLOAD_DIGEST_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_EVIDENCE_DIGEST = re.compile(re.escape(EVIDENCE_DIGEST_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_EVIDENCE_PAYLOAD_DIGEST = re.compile(re.escape(EVIDENCE_PAYLOAD_DIGEST_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_STATEMENT_DIGEST = re.compile(re.escape(STATEMENT_DIGEST_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_AUTHORITY_DIGEST = re.compile(re.escape(AUTHORITY_SNAPSHOT_DIGEST_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_FINALIZATION_REQUEST_DIGEST = re.compile(re.escape(FINALIZATION_REQUEST_DIGEST_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_EFFECT_DIGEST = re.compile(re.escape(EFFECT_DIGEST_PREFIX) + r"[0-9a-f]{64}\Z").fullmatch
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z").fullmatch
_P = ParamSpec("_P")
_T = TypeVar("_T")

_RESERVATION_FIELDS = {
    "acceptanceId",
    "associationExpectedState",
    "associationExpectedVersion",
    "associationId",
    "challengeId",
    "challengeRevision",
    "createdAt",
    "decidedAt",
    "deviceId",
    "effectDigest",
    "effectId",
    "evidenceDigest",
    "evidencePayloadDigest",
    "evidenceTokenId",
    "expiresAt",
    "inputDigest",
    "inputPayloadDigest",
    "operation",
    "operationId",
    "receiptId",
    "requestId",
    "reservationId",
    "reservationRevision",
    "schema",
    "state",
    "statementDigest",
    "subject",
    "terminalReason",
    "version",
}
_AUTHORITY_FIELDS = {
    "acceptanceId",
    "approvalEventId",
    "approverOAuthBrowserGenerationId",
    "approverOAuthSessionId",
    "approverOAuthTokenId",
    "approverSessionExpiresAt",
    "associationId",
    "associationVersion",
    "attemptId",
    "authorizationDigest",
    "deviceId",
    "enrollmentChallengeId",
    "fullEvidenceId",
    "fullEvidenceVersion",
    "fullExpiresAt",
    "fullProofId",
    "fullSourceEvidenceSha256",
    "inputDigest",
    "inputPayloadDigest",
    "observedAt",
    "operation",
    "operationId",
    "parentOAuthBrowserGenerationId",
    "parentOAuthSessionId",
    "parentOAuthTokenId",
    "phoneSessionExpiresAt",
    "requestId",
    "schema",
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
_OBSERVATION_FIELDS = {
    "associationAuthorityEpoch",
    "associationCurrentId",
    "associationState",
    "associationVersion",
    "authoritySnapshot",
    "authoritySnapshotDigest",
    "challengeId",
    "challengeRevision",
    "challengeState",
    "observedAt",
    "reservationId",
    "reservationRevision",
    "schema",
    "version",
}
_EFFECT_ID_PREIMAGE_FIELDS = {
    "acceptanceId",
    "associationId",
    "authoritySnapshotDigest",
    "challengeId",
    "finalizationRequestDigest",
    "reservationId",
    "reservationRevision",
    "schema",
    "version",
}
_EFFECT_FIELDS = {
    "acceptanceId",
    "associationId",
    "associationVersion",
    "authorityEpoch",
    "challengeId",
    "effectId",
    "finalizationRequestDigest",
    "operation",
    "reservationId",
    "reservationRevision",
    "schema",
    "version",
}
_RECEIPT_ID_PREIMAGE_FIELDS = {
    "effectDigest",
    "effectId",
    "finalizationRequestDigest",
    "reservationId",
    "reservationRevision",
    "schema",
    "version",
}
_RECEIPT_FIELDS = {
    "acceptanceId",
    "associationId",
    "challengeId",
    "decidedAt",
    "effectDigest",
    "effectId",
    "evidenceDigest",
    "finalizationRequestDigest",
    "inputDigest",
    "receiptId",
    "reservationId",
    "reservationRevision",
    "schema",
    "statementDigest",
    "status",
    "version",
}


class SocialPreacceptedEnrollmentV2AtomicAcceptanceDenied(ValueError):
    """The one bounded, non-sensitive public failure for this contract."""

    def __init__(self) -> None:
        super().__init__(DENIED_MESSAGE)


def _deny() -> NoReturn:
    raise SocialPreacceptedEnrollmentV2AtomicAcceptanceDenied() from None


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


def _closed_json(source: object, fields: set[str], maximum: int) -> dict[str, object]:
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
        if type(value) is not dict or set(value) != fields or _canonical(value) != source:
            raise ValueError
        return cast(dict[str, object], value)
    except Exception:
        pass
    _deny()


def _integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER or positive and value == 0:
        _deny()
    return cast(int, value)


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64(value) is None:
        _deny()
    return cast(str, value)


def _matching(value: object, matcher) -> str:
    if type(value) is not str or matcher(value) is None:
        _deny()
    return cast(str, value)


def _digest(prefix: str, domain: str, source: str) -> str:
    try:
        encoded = source.encode("ascii")
        if not encoded:
            raise ValueError
        return prefix + hashlib.sha256(domain.encode("ascii") + b"\0" + encoded).hexdigest()
    except Exception:
        _deny()


@_sanitize_public_failure
def deadline_evidence_digest_v1(source: object) -> str:
    try:
        if type(source) is not str or not 1 <= len(source.encode("ascii")) <= deadline.MAX_EVIDENCE_BYTES:
            raise ValueError
    except Exception:
        _deny()
    return _digest(EVIDENCE_DIGEST_PREFIX, EVIDENCE_DIGEST_DOMAIN, cast(str, source))


@_sanitize_public_failure
def deadline_evidence_payload_digest_v1(source: object) -> str:
    try:
        deadline.parse_messaging_device_verification_deadline_evidence_payload_v1(source)
        return _digest(EVIDENCE_PAYLOAD_DIGEST_PREFIX, EVIDENCE_PAYLOAD_DIGEST_DOMAIN, cast(str, source))
    except Exception:
        _deny()


@_sanitize_public_failure
def verification_statement_digest_v1(source: object) -> str:
    try:
        if type(source) is not str or not 1 <= len(source.encode("ascii")) <= verification.MAX_STATEMENT_BYTES:
            raise ValueError
    except Exception:
        _deny()
    return _digest(STATEMENT_DIGEST_PREFIX, STATEMENT_DIGEST_DOMAIN, cast(str, source))


@dataclass(frozen=True, slots=True, repr=False)
class AtomicAcceptanceReservationV1:
    wire: str
    reservation_id: str
    reservation_revision: int
    state: str
    subject: str
    device_id: str
    request_id: str
    operation_id: str
    acceptance_id: str
    challenge_id: str
    challenge_revision: int
    association_id: str
    input_digest: str
    input_payload_digest: str
    evidence_token_id: str
    evidence_digest: str
    evidence_payload_digest: str
    created_at: int
    expires_at: int
    statement_digest: str | None
    effect_id: str | None
    effect_digest: str | None
    receipt_id: str | None
    decided_at: int | None
    terminal_reason: str | None


@_sanitize_public_failure
def parse_atomic_acceptance_reservation_v1(source: object) -> AtomicAcceptanceReservationV1:
    value = _closed_json(source, _RESERVATION_FIELDS, MAX_RESERVATION_BYTES)
    try:
        if (
            value["schema"] != RESERVATION_SCHEMA
            or type(value["version"]) is not int
            or value["version"] != VERSION
            or type(value["reservationRevision"]) is not int
            or value["reservationRevision"] != VERSION
            or value["operation"] != "register"
            or value["associationExpectedState"] != "absent"
            or type(value["associationExpectedVersion"]) is not int
            or value["associationExpectedVersion"] != 0
        ):
            raise ValueError
        raw_state = value["state"]
        if type(raw_state) is not str or raw_state not in {
            "pending",
            "accepted",
            "rejected",
            "expired",
            "cancelled",
        }:
            raise ValueError
        state = cast(str, raw_state)
        created = _integer(value["createdAt"])
        expires = _integer(value["expiresAt"], positive=True)
        challenge_revision = _integer(value["challengeRevision"], positive=True)
        if created >= expires:
            raise ValueError
        statement_digest = value["statementDigest"]
        effect_id = value["effectId"]
        effect_digest = value["effectDigest"]
        receipt_id = value["receiptId"]
        decided_at = value["decidedAt"]
        terminal_reason = value["terminalReason"]
        if state == "pending":
            if any(
                item is not None
                for item in (statement_digest, effect_id, effect_digest, receipt_id, decided_at, terminal_reason)
            ):
                raise ValueError
        elif state == "accepted":
            statement_digest = _matching(statement_digest, _STATEMENT_DIGEST)
            effect_id = _hex64(effect_id)
            effect_digest = _matching(effect_digest, _EFFECT_DIGEST)
            receipt_id = _hex64(receipt_id)
            decided_at = _integer(decided_at)
            if terminal_reason is not None or not created <= decided_at < expires:
                raise ValueError
        else:
            decided_at = _integer(decided_at)
            expected_reason = {
                "rejected": "verification_denied",
                "expired": "evidence_expired",
                "cancelled": "explicitly_cancelled",
            }[state]
            if (
                terminal_reason != expected_reason
                or any(item is not None for item in (statement_digest, effect_id, effect_digest, receipt_id))
                or decided_at < created
                or (state == "expired" and decided_at < expires)
                or (state in {"rejected", "cancelled"} and decided_at >= expires)
            ):
                raise ValueError
        return AtomicAcceptanceReservationV1(
            wire=cast(str, source),
            reservation_id=_hex64(value["reservationId"]),
            reservation_revision=VERSION,
            state=state,
            subject=_hex64(value["subject"]),
            device_id=_hex64(value["deviceId"]),
            request_id=_hex64(value["requestId"]),
            operation_id=_hex64(value["operationId"]),
            acceptance_id=_hex64(value["acceptanceId"]),
            challenge_id=_hex64(value["challengeId"]),
            challenge_revision=challenge_revision,
            association_id=_hex64(value["associationId"]),
            input_digest=_matching(value["inputDigest"], _INPUT_DIGEST),
            input_payload_digest=_matching(value["inputPayloadDigest"], _INPUT_PAYLOAD_DIGEST),
            evidence_token_id=_hex64(value["evidenceTokenId"]),
            evidence_digest=_matching(value["evidenceDigest"], _EVIDENCE_DIGEST),
            evidence_payload_digest=_matching(value["evidencePayloadDigest"], _EVIDENCE_PAYLOAD_DIGEST),
            created_at=created,
            expires_at=expires,
            statement_digest=cast(str | None, statement_digest),
            effect_id=cast(str | None, effect_id),
            effect_digest=cast(str | None, effect_digest),
            receipt_id=cast(str | None, receipt_id),
            decided_at=cast(int | None, decided_at),
            terminal_reason=cast(str | None, terminal_reason),
        )
    except Exception:
        _deny()


def _reservation_values_from_claims(
    claims: deadline.DeadlineEvidenceClaimsV1,
    *,
    challenge_revision: int,
    evidence_digest: str,
    evidence_payload_digest: str,
) -> dict[str, object]:
    return {
        "acceptanceId": claims.acceptance_id,
        "associationExpectedState": "absent",
        "associationExpectedVersion": 0,
        "associationId": claims.association_id,
        "challengeId": claims.enrollment_challenge_id,
        "challengeRevision": challenge_revision,
        "createdAt": claims.observed_at,
        "decidedAt": None,
        "deviceId": claims.device_id,
        "effectDigest": None,
        "effectId": None,
        "evidenceDigest": evidence_digest,
        "evidencePayloadDigest": evidence_payload_digest,
        "evidenceTokenId": claims.token_id,
        "expiresAt": claims.expires_at,
        "inputDigest": claims.input_digest,
        "inputPayloadDigest": claims.input_payload_digest,
        "operation": "register",
        "operationId": claims.operation_id,
        "receiptId": None,
        "requestId": claims.request_id,
        "reservationId": claims.reservation_id,
        "reservationRevision": claims.reservation_revision,
        "schema": RESERVATION_SCHEMA,
        "state": "pending",
        "statementDigest": None,
        "subject": claims.subject,
        "terminalReason": None,
        "version": VERSION,
    }


@_sanitize_public_failure
def canonical_pending_atomic_acceptance_reservation_v1_bytes(
    *,
    evidence_compact_jws: object,
    evidence_config: deadline.MessagingDeviceVerificationDeadlineEvidenceV1Config,
    expected_input_wire: object,
    observed_at: object,
    challenge_revision: object,
) -> bytes:
    """Build candidate bytes only after verifying the exact compact evidence."""

    try:
        authenticated_evidence = deadline.verify_messaging_device_verification_deadline_evidence_v1(
            evidence_compact_jws,
            config=evidence_config,
            expected_input_wire=expected_input_wire,
            now=observed_at,
        )
        projection = deadline.project_authenticated_messaging_device_verification_deadline_evidence_v1(
            authenticated_evidence
        )
        claims = projection["claims"]
        if type(claims) is not deadline.DeadlineEvidenceClaimsV1:
            raise ValueError
        observed = _integer(observed_at)
        if observed != claims.observed_at:
            raise ValueError
        revision = _integer(challenge_revision, positive=True)
        evidence_digest = deadline_evidence_digest_v1(evidence_compact_jws)
        payload_digest = deadline_evidence_payload_digest_v1(claims.payload_wire)
        wire = _canonical(
            _reservation_values_from_claims(
                claims,
                challenge_revision=revision,
                evidence_digest=evidence_digest,
                evidence_payload_digest=payload_digest,
            )
        )
        parse_atomic_acceptance_reservation_v1(wire)
        return wire.encode("ascii")
    except Exception:
        _deny()


def _authority_expected(claims: deadline.DeadlineEvidenceClaimsV1, observed_at: int) -> dict[str, object]:
    return {
        "acceptanceId": claims.acceptance_id,
        "approvalEventId": claims.approval_event_id,
        "approverOAuthBrowserGenerationId": claims.approver_oauth_browser_generation_id,
        "approverOAuthSessionId": claims.approver_oauth_session_id,
        "approverOAuthTokenId": claims.approver_oauth_token_id,
        "approverSessionExpiresAt": claims.approver_session_expires_at,
        "associationId": claims.association_id,
        "associationVersion": claims.association_version,
        "attemptId": claims.attempt_id,
        "authorizationDigest": claims.authorization_digest,
        "deviceId": claims.device_id,
        "enrollmentChallengeId": claims.enrollment_challenge_id,
        "fullEvidenceId": claims.full_evidence_id,
        "fullEvidenceVersion": claims.full_evidence_version,
        "fullExpiresAt": claims.full_expires_at,
        "fullProofId": claims.full_proof_id,
        "fullSourceEvidenceSha256": claims.full_source_evidence_sha256,
        "inputDigest": claims.input_digest,
        "inputPayloadDigest": claims.input_payload_digest,
        "observedAt": observed_at,
        "operation": claims.operation,
        "operationId": claims.operation_id,
        "parentOAuthBrowserGenerationId": claims.parent_oauth_browser_generation_id,
        "parentOAuthSessionId": claims.parent_oauth_session_id,
        "parentOAuthTokenId": claims.parent_oauth_token_id,
        "phoneSessionExpiresAt": claims.phone_session_expires_at,
        "requestId": claims.request_id,
        "schema": AUTHORITY_SNAPSHOT_SCHEMA,
        "socialSessionIssuanceId": claims.social_session_issuance_id,
        "socialSessionIssuanceRevision": claims.social_session_issuance_revision,
        "socialSessionTokenId": claims.social_session_token_id,
        "subject": claims.subject,
        "version": VERSION,
        "x25519BindingExpiresAt": claims.x25519_binding_expires_at,
        "x25519BindingId": claims.x25519_binding_id,
        "x25519BindingVersion": claims.x25519_binding_version,
        "x25519PublicKeyCommitment": claims.x25519_public_key_commitment,
    }


def _authority_wire_from_authenticated_claims(
    claims: deadline.DeadlineEvidenceClaimsV1,
    observed_at: int,
) -> str:
    return _canonical(_authority_expected(claims, observed_at))


@_sanitize_public_failure
def parse_current_authority_snapshot_v1(source: object) -> Mapping[str, object]:
    """Validate shape only; the returned mapping is never current authority."""

    value = _closed_json(source, _AUTHORITY_FIELDS, MAX_AUTHORITY_SNAPSHOT_BYTES)
    try:
        if (
            value["schema"] != AUTHORITY_SNAPSHOT_SCHEMA
            or type(value["version"]) is not int
            or value["version"] != VERSION
            or value["operation"] != "register"
            or type(value["fullEvidenceVersion"]) is not str
            or _BOUNDED_VERSION(value["fullEvidenceVersion"]) is None
        ):
            raise ValueError
        integers = {}
        for name in (
            "acceptanceId",
            "approvalEventId",
            "approverOAuthBrowserGenerationId",
            "approverOAuthSessionId",
            "associationId",
            "attemptId",
            "authorizationDigest",
            "deviceId",
            "enrollmentChallengeId",
            "fullSourceEvidenceSha256",
            "operationId",
            "parentOAuthBrowserGenerationId",
            "parentOAuthSessionId",
            "requestId",
            "socialSessionIssuanceId",
            "socialSessionIssuanceRevision",
            "subject",
            "x25519BindingId",
        ):
            _hex64(value[name])
        for name in ("approverOAuthTokenId", "parentOAuthTokenId", "socialSessionTokenId"):
            if type(value[name]) is not str or re.fullmatch(r"[0-9a-f]{32}", cast(str, value[name])) is None:
                raise ValueError
        for name in (
            "approverSessionExpiresAt",
            "associationVersion",
            "fullExpiresAt",
            "observedAt",
            "phoneSessionExpiresAt",
            "x25519BindingExpiresAt",
            "x25519BindingVersion",
        ):
            integers[name] = _integer(value[name], positive=True)
        if (
            integers["associationVersion"] != 1
            or integers["x25519BindingVersion"] > 1_024
            or integers["observedAt"]
            >= min(
                integers["phoneSessionExpiresAt"],
                integers["approverSessionExpiresAt"],
                integers["fullExpiresAt"],
                integers["x25519BindingExpiresAt"],
            )
        ):
            raise ValueError
        _matching(value["inputDigest"], _INPUT_DIGEST)
        _matching(value["inputPayloadDigest"], _INPUT_PAYLOAD_DIGEST)
        if (
            type(value["fullProofId"]) is not str
            or re.fullmatch(r"hodlxxi-full-entitlement-v1-sha256:[0-9a-f]{64}", cast(str, value["fullProofId"])) is None
        ):
            raise ValueError
        if (
            type(value["fullEvidenceId"]) is not str
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                cast(str, value["fullEvidenceId"]),
            )
            is None
        ):
            raise ValueError
        if (
            type(value["x25519PublicKeyCommitment"]) is not str
            or re.fullmatch(
                r"hodlxxi-social-messaging-x25519-public-key-v1-sha256:[0-9a-f]{64}",
                cast(str, value["x25519PublicKeyCommitment"]),
            )
            is None
        ):
            raise ValueError
        return MappingProxyType(value)
    except Exception:
        _deny()


@_sanitize_public_failure
def current_authority_snapshot_digest_v1(source: object) -> str:
    parse_current_authority_snapshot_v1(source)
    return _digest(AUTHORITY_SNAPSHOT_DIGEST_PREFIX, AUTHORITY_SNAPSHOT_DIGEST_DOMAIN, cast(str, source))


@dataclass(frozen=True, slots=True, repr=False)
class FinalizationObservationV1:
    wire: str
    authority_snapshot_wire: str
    authority_snapshot_digest: str
    reservation_id: str
    reservation_revision: int
    challenge_id: str
    challenge_revision: int
    observed_at: int


@_sanitize_public_failure
def parse_finalization_observation_v1(source: object) -> FinalizationObservationV1:
    value = _closed_json(source, _OBSERVATION_FIELDS, MAX_FINALIZATION_OBSERVATION_BYTES)
    try:
        if (
            value["schema"] != FINALIZATION_OBSERVATION_SCHEMA
            or type(value["version"]) is not int
            or value["version"] != VERSION
            or type(value["reservationRevision"]) is not int
            or value["reservationRevision"] != VERSION
            or value["challengeState"] != "issued"
            or value["associationState"] != "absent"
            or value["associationCurrentId"] is not None
            or type(value["associationVersion"]) is not int
            or value["associationVersion"] != 0
            or type(value["associationAuthorityEpoch"]) is not int
            or value["associationAuthorityEpoch"] != 0
            or type(value["authoritySnapshot"]) is not str
        ):
            raise ValueError
        authority_wire = cast(str, value["authoritySnapshot"])
        authority = parse_current_authority_snapshot_v1(authority_wire)
        digest = current_authority_snapshot_digest_v1(authority_wire)
        observed = _integer(value["observedAt"])
        if value["authoritySnapshotDigest"] != digest or authority["observedAt"] != observed:
            raise ValueError
        return FinalizationObservationV1(
            wire=cast(str, source),
            authority_snapshot_wire=authority_wire,
            authority_snapshot_digest=digest,
            reservation_id=_hex64(value["reservationId"]),
            reservation_revision=VERSION,
            challenge_id=_hex64(value["challengeId"]),
            challenge_revision=_integer(value["challengeRevision"], positive=True),
            observed_at=observed,
        )
    except Exception:
        _deny()


@_sanitize_public_failure
def parse_evidence_bound_finalization_observation_v1(
    source: object,
    *,
    authenticated_evidence: object,
    expected_reservation_id: object,
    expected_reservation_revision: object,
    expected_challenge_id: object,
    expected_challenge_revision: object,
    expected_observed_at: object,
) -> FinalizationObservationV1:
    """Bind one canonical observation to signed evidence and accepted history."""

    try:
        projection = deadline.project_authenticated_messaging_device_verification_deadline_evidence_v1(
            authenticated_evidence
        )
        claims = projection["claims"]
        if type(claims) is not deadline.DeadlineEvidenceClaimsV1:
            raise ValueError
        reservation_id = _hex64(expected_reservation_id)
        reservation_revision = _integer(expected_reservation_revision, positive=True)
        challenge_id = _hex64(expected_challenge_id)
        challenge_revision = _integer(expected_challenge_revision, positive=True)
        observed_at = _integer(expected_observed_at)
        observation = parse_finalization_observation_v1(source)
        expected_authority_wire = _authority_wire_from_authenticated_claims(
            claims,
            observed_at,
        )
        expected_authority_digest = current_authority_snapshot_digest_v1(expected_authority_wire)
        if (
            observation.reservation_id != reservation_id
            or observation.reservation_revision != reservation_revision
            or observation.challenge_id != challenge_id
            or observation.challenge_revision != challenge_revision
            or observation.observed_at != observed_at
            or observation.authority_snapshot_wire != expected_authority_wire
            or observation.authority_snapshot_digest != expected_authority_digest
        ):
            raise ValueError
        return observation
    except Exception:
        _deny()


@dataclass(frozen=True, slots=True, repr=False)
class AtomicAcceptanceReceiptV1:
    wire: str
    receipt_id: str
    reservation_id: str
    reservation_revision: int
    acceptance_id: str
    association_id: str
    challenge_id: str
    evidence_digest: str
    input_digest: str
    statement_digest: str
    effect_id: str
    effect_digest: str
    finalization_request_digest: str
    decided_at: int


@dataclass(frozen=True, slots=True, repr=False)
class AtomicAcceptanceEffectV1:
    wire: str
    effect_id: str
    effect_digest: str
    reservation_id: str
    reservation_revision: int
    acceptance_id: str
    association_id: str
    challenge_id: str
    finalization_request_digest: str


@_sanitize_public_failure
def parse_atomic_acceptance_effect_v1(
    source: object,
    *,
    finalization_observation_wire: object,
    authenticated_evidence: object,
    expected_reservation_id: object,
    expected_reservation_revision: object,
    expected_acceptance_id: object,
    expected_association_id: object,
    expected_challenge_id: object,
    expected_challenge_revision: object,
    expected_observed_at: object,
    expected_finalization_request_digest: object,
) -> AtomicAcceptanceEffectV1:
    """Parse an effect only through authenticated, expected accepted history."""

    value = _closed_json(source, _EFFECT_FIELDS, MAX_EFFECT_BYTES)
    try:
        reservation_id = _hex64(expected_reservation_id)
        reservation_revision = _integer(expected_reservation_revision, positive=True)
        acceptance_id = _hex64(expected_acceptance_id)
        association_id = _hex64(expected_association_id)
        challenge_id = _hex64(expected_challenge_id)
        finalization_request_digest = _matching(
            expected_finalization_request_digest,
            _FINALIZATION_REQUEST_DIGEST,
        )
        observation = parse_evidence_bound_finalization_observation_v1(
            finalization_observation_wire,
            authenticated_evidence=authenticated_evidence,
            expected_reservation_id=reservation_id,
            expected_reservation_revision=reservation_revision,
            expected_challenge_id=challenge_id,
            expected_challenge_revision=expected_challenge_revision,
            expected_observed_at=expected_observed_at,
        )
        if (
            value["schema"] != EFFECT_SCHEMA
            or type(value["version"]) is not int
            or value["version"] != VERSION
            or type(value["reservationRevision"]) is not int
            or value["reservationRevision"] != VERSION
            or value["operation"] != "preaccepted-enrollment-v2-accept"
            or type(value["associationVersion"]) is not int
            or value["associationVersion"] != VERSION
            or type(value["authorityEpoch"]) is not int
            or value["authorityEpoch"] != VERSION
        ):
            raise ValueError
        if (
            _hex64(value["reservationId"]) != reservation_id
            or value["reservationRevision"] != reservation_revision
            or _hex64(value["acceptanceId"]) != acceptance_id
            or _hex64(value["associationId"]) != association_id
            or _hex64(value["challengeId"]) != challenge_id
            or _matching(value["finalizationRequestDigest"], _FINALIZATION_REQUEST_DIGEST)
            != finalization_request_digest
        ):
            raise ValueError
        authority_digest = observation.authority_snapshot_digest
        preimage = _canonical(
            {
                "acceptanceId": acceptance_id,
                "associationId": association_id,
                "authoritySnapshotDigest": authority_digest,
                "challengeId": challenge_id,
                "finalizationRequestDigest": finalization_request_digest,
                "reservationId": reservation_id,
                "reservationRevision": VERSION,
                "schema": EFFECT_ID_PREIMAGE_SCHEMA,
                "version": VERSION,
            }
        )
        expected_effect_id = hashlib.sha256(
            EFFECT_ID_DOMAIN.encode("ascii") + b"\0" + preimage.encode("ascii")
        ).hexdigest()
        if value["effectId"] != expected_effect_id:
            raise ValueError
        wire = cast(str, source)
        return AtomicAcceptanceEffectV1(
            wire=wire,
            effect_id=expected_effect_id,
            effect_digest=_digest(EFFECT_DIGEST_PREFIX, EFFECT_DIGEST_DOMAIN, wire),
            reservation_id=reservation_id,
            reservation_revision=VERSION,
            acceptance_id=acceptance_id,
            association_id=association_id,
            challenge_id=challenge_id,
            finalization_request_digest=finalization_request_digest,
        )
    except Exception:
        _deny()


@_sanitize_public_failure
def parse_atomic_acceptance_receipt_v1(source: object) -> AtomicAcceptanceReceiptV1:
    value = _closed_json(source, _RECEIPT_FIELDS, MAX_RECEIPT_BYTES)
    try:
        if (
            value["schema"] != RECEIPT_SCHEMA
            or type(value["version"]) is not int
            or value["version"] != VERSION
            or type(value["reservationRevision"]) is not int
            or value["reservationRevision"] != VERSION
            or value["status"] != "committed"
        ):
            raise ValueError
        receipt_id = _hex64(value["receiptId"])
        reservation_id = _hex64(value["reservationId"])
        effect_id = _hex64(value["effectId"])
        effect_digest = _matching(value["effectDigest"], _EFFECT_DIGEST)
        finalization_request_digest = _matching(value["finalizationRequestDigest"], _FINALIZATION_REQUEST_DIGEST)
        acceptance_id = _hex64(value["acceptanceId"])
        association_id = _hex64(value["associationId"])
        challenge_id = _hex64(value["challengeId"])
        evidence_digest = _matching(value["evidenceDigest"], _EVIDENCE_DIGEST)
        input_digest = _matching(value["inputDigest"], _INPUT_DIGEST)
        statement_digest = _matching(value["statementDigest"], _STATEMENT_DIGEST)
        preimage = _canonical(
            {
                "effectDigest": effect_digest,
                "effectId": effect_id,
                "finalizationRequestDigest": finalization_request_digest,
                "reservationId": reservation_id,
                "reservationRevision": VERSION,
                "schema": RECEIPT_ID_PREIMAGE_SCHEMA,
                "version": VERSION,
            }
        )
        expected_receipt_id = hashlib.sha256(
            RECEIPT_ID_DOMAIN.encode("ascii") + b"\0" + preimage.encode("ascii")
        ).hexdigest()
        if receipt_id != expected_receipt_id:
            raise ValueError
        return AtomicAcceptanceReceiptV1(
            wire=cast(str, source),
            receipt_id=receipt_id,
            reservation_id=reservation_id,
            reservation_revision=VERSION,
            acceptance_id=acceptance_id,
            association_id=association_id,
            challenge_id=challenge_id,
            evidence_digest=evidence_digest,
            input_digest=input_digest,
            statement_digest=statement_digest,
            effect_id=effect_id,
            effect_digest=effect_digest,
            finalization_request_digest=finalization_request_digest,
            decided_at=_integer(value["decidedAt"]),
        )
    except Exception:
        _deny()


@dataclass(frozen=True, slots=True, repr=False)
class ProvisionalAtomicAcceptanceV1:
    reservation_before: AtomicAcceptanceReservationV1
    observation: FinalizationObservationV1
    effect_wire: str
    effect_id: str
    effect_digest: str
    receipt: AtomicAcceptanceReceiptV1
    reservation_after_wire: str
    finalization_request_digest: str
    publication_status: str = field(default="provisional_until_caller_commit", init=False)
    locks_proven: bool = field(default=False, init=False)
    persistence_proven: bool = field(default=False, init=False)
    commit_proven: bool = field(default=False, init=False)
    final_admission: str = field(default=FINAL_ADMISSION, init=False)
    runtime_enabled: bool = field(default=RUNTIME_ENABLED, init=False)


def _finalization_request_digest(
    reservation: AtomicAcceptanceReservationV1,
    *,
    statement_digest: str,
) -> str:
    preimage = _canonical(
        {
            "evidenceDigest": reservation.evidence_digest,
            "inputDigest": reservation.input_digest,
            "inputPayloadDigest": reservation.input_payload_digest,
            "reservationId": reservation.reservation_id,
            "reservationRevision": reservation.reservation_revision,
            "statementDigest": statement_digest,
        }
    )
    return _digest(
        FINALIZATION_REQUEST_DIGEST_PREFIX,
        FINALIZATION_REQUEST_DIGEST_DOMAIN,
        preimage,
    )


def _effect(
    reservation: AtomicAcceptanceReservationV1,
    observation: FinalizationObservationV1,
    finalization_request_digest: str,
    *,
    authenticated_evidence: object,
) -> tuple[str, str, str]:
    preimage_values = {
        "acceptanceId": reservation.acceptance_id,
        "associationId": reservation.association_id,
        "authoritySnapshotDigest": observation.authority_snapshot_digest,
        "challengeId": reservation.challenge_id,
        "finalizationRequestDigest": finalization_request_digest,
        "reservationId": reservation.reservation_id,
        "reservationRevision": reservation.reservation_revision,
        "schema": EFFECT_ID_PREIMAGE_SCHEMA,
        "version": VERSION,
    }
    if set(preimage_values) != _EFFECT_ID_PREIMAGE_FIELDS:
        _deny()
    effect_id = hashlib.sha256(
        EFFECT_ID_DOMAIN.encode("ascii") + b"\0" + _canonical(preimage_values).encode("ascii")
    ).hexdigest()
    effect_values = {
        "acceptanceId": reservation.acceptance_id,
        "associationId": reservation.association_id,
        "associationVersion": 1,
        "authorityEpoch": 1,
        "challengeId": reservation.challenge_id,
        "effectId": effect_id,
        "finalizationRequestDigest": finalization_request_digest,
        "operation": "preaccepted-enrollment-v2-accept",
        "reservationId": reservation.reservation_id,
        "reservationRevision": reservation.reservation_revision,
        "schema": EFFECT_SCHEMA,
        "version": VERSION,
    }
    if set(effect_values) != _EFFECT_FIELDS:
        _deny()
    effect_wire = _canonical(effect_values)
    parsed = parse_atomic_acceptance_effect_v1(
        effect_wire,
        finalization_observation_wire=observation.wire,
        authenticated_evidence=authenticated_evidence,
        expected_reservation_id=reservation.reservation_id,
        expected_reservation_revision=reservation.reservation_revision,
        expected_acceptance_id=reservation.acceptance_id,
        expected_association_id=reservation.association_id,
        expected_challenge_id=reservation.challenge_id,
        expected_challenge_revision=reservation.challenge_revision,
        expected_observed_at=observation.observed_at,
        expected_finalization_request_digest=finalization_request_digest,
    )
    return parsed.wire, parsed.effect_id, parsed.effect_digest


def _receipt(
    reservation: AtomicAcceptanceReservationV1,
    *,
    statement_digest: str,
    finalization_request_digest: str,
    effect_id: str,
    effect_digest: str,
    decided_at: int,
) -> AtomicAcceptanceReceiptV1:
    preimage_values = {
        "effectDigest": effect_digest,
        "effectId": effect_id,
        "finalizationRequestDigest": finalization_request_digest,
        "reservationId": reservation.reservation_id,
        "reservationRevision": reservation.reservation_revision,
        "schema": RECEIPT_ID_PREIMAGE_SCHEMA,
        "version": VERSION,
    }
    if set(preimage_values) != _RECEIPT_ID_PREIMAGE_FIELDS:
        _deny()
    receipt_id = hashlib.sha256(
        RECEIPT_ID_DOMAIN.encode("ascii") + b"\0" + _canonical(preimage_values).encode("ascii")
    ).hexdigest()
    values = {
        "acceptanceId": reservation.acceptance_id,
        "associationId": reservation.association_id,
        "challengeId": reservation.challenge_id,
        "decidedAt": decided_at,
        "effectDigest": effect_digest,
        "effectId": effect_id,
        "evidenceDigest": reservation.evidence_digest,
        "finalizationRequestDigest": finalization_request_digest,
        "inputDigest": reservation.input_digest,
        "receiptId": receipt_id,
        "reservationId": reservation.reservation_id,
        "reservationRevision": reservation.reservation_revision,
        "schema": RECEIPT_SCHEMA,
        "statementDigest": statement_digest,
        "status": "committed",
        "version": VERSION,
    }
    if set(values) != _RECEIPT_FIELDS:
        _deny()
    return parse_atomic_acceptance_receipt_v1(_canonical(values))


def _accepted_reservation_wire(
    reservation: AtomicAcceptanceReservationV1,
    *,
    statement_digest: str,
    effect_id: str,
    effect_digest: str,
    receipt: AtomicAcceptanceReceiptV1,
    decided_at: int,
) -> str:
    values = _closed_json(reservation.wire, _RESERVATION_FIELDS, MAX_RESERVATION_BYTES)
    values.update(
        {
            "decidedAt": decided_at,
            "effectDigest": effect_digest,
            "effectId": effect_id,
            "receiptId": receipt.receipt_id,
            "state": "accepted",
            "statementDigest": statement_digest,
        }
    )
    wire = _canonical(values)
    parse_atomic_acceptance_reservation_v1(wire)
    return wire


@_sanitize_public_failure
def model_atomic_acceptance_and_cas_v1(
    *,
    reservation_wire: object,
    finalization_observation_wire: object,
    expected_input_wire: object,
    expected_context_wire: object,
    evidence_compact_jws: object,
    evidence_config: deadline.MessagingDeviceVerificationDeadlineEvidenceV1Config,
    statement_compact_jws: object,
    statement_config: verification.SocialPreacceptedEnrollmentVerificationStatementV2Config,
    decided_at: object,
) -> ProvisionalAtomicAcceptanceV1:
    """Model exact checks and output bytes; perform no lock, write, or commit."""

    try:
        reservation = parse_atomic_acceptance_reservation_v1(reservation_wire)
        if reservation.state != "pending":
            raise ValueError
        observation = parse_finalization_observation_v1(finalization_observation_wire)
        decided = _integer(decided_at)
        authenticated_evidence = deadline.verify_messaging_device_verification_deadline_evidence_v1(
            evidence_compact_jws,
            config=evidence_config,
            expected_input_wire=expected_input_wire,
            now=decided,
        )
        evidence_projection = deadline.project_authenticated_messaging_device_verification_deadline_evidence_v1(
            authenticated_evidence
        )
        claims = evidence_projection["claims"]
        if type(claims) is not deadline.DeadlineEvidenceClaimsV1:
            raise ValueError
        observation = parse_evidence_bound_finalization_observation_v1(
            finalization_observation_wire,
            authenticated_evidence=authenticated_evidence,
            expected_reservation_id=reservation.reservation_id,
            expected_reservation_revision=reservation.reservation_revision,
            expected_challenge_id=reservation.challenge_id,
            expected_challenge_revision=reservation.challenge_revision,
            expected_observed_at=decided,
        )
        authenticated_statement = verification.verify_social_preaccepted_enrollment_verification_statement_v2(
            statement_compact_jws,
            config=statement_config,
            expected_context_wire=expected_context_wire,
            expected_input_wire=expected_input_wire,
            now=decided,
            phone_session_expires_at_ms=claims.phone_session_expires_at,
            approver_session_expires_at_ms=claims.approver_session_expires_at,
            full_expires_at_ms=claims.full_expires_at,
            x25519_binding_expires_at_ms=claims.x25519_binding_expires_at,
        )
        statement_projection = (
            verification.project_authenticated_social_preaccepted_enrollment_verification_statement_v2(
                authenticated_statement
            )
        )
        parsed_input = preacceptance.parse_preaccepted_enrollment_verification_input_v2(expected_input_wire)
        evidence_digest = deadline_evidence_digest_v1(evidence_compact_jws)
        payload_digest = deadline_evidence_payload_digest_v1(claims.payload_wire)
        statement_digest = verification_statement_digest_v1(statement_compact_jws)
        if (
            reservation.reservation_id != claims.reservation_id
            or reservation.reservation_revision != claims.reservation_revision
            or reservation.subject != claims.subject
            or reservation.device_id != claims.device_id
            or reservation.request_id != claims.request_id
            or reservation.operation_id != claims.operation_id
            or reservation.acceptance_id != claims.acceptance_id
            or reservation.challenge_id != claims.enrollment_challenge_id
            or reservation.association_id != claims.association_id
            or reservation.input_digest != claims.input_digest
            or reservation.input_payload_digest != claims.input_payload_digest
            or reservation.evidence_token_id != claims.token_id
            or reservation.evidence_digest != evidence_digest
            or reservation.evidence_payload_digest != payload_digest
            or reservation.created_at != claims.observed_at
            or reservation.expires_at != claims.expires_at
            or parsed_input.acceptance_id != claims.acceptance_id
            or parsed_input.association_id != claims.association_id
            or statement_projection["acceptanceId"] != claims.acceptance_id
            or statement_projection["associationId"] != claims.association_id
            or statement_projection["enrollmentChallengeId"] != claims.enrollment_challenge_id
            or statement_projection["attemptId"] != claims.attempt_id
            or statement_projection["inputDigest"] != claims.input_digest
            or type(statement_projection["issuedAt"]) is not int
            or type(statement_projection["expiresAt"]) is not int
            or not claims.observed_at <= statement_projection["issuedAt"] <= decided
            or not decided < statement_projection["expiresAt"] <= claims.expires_at
            or observation.reservation_id != reservation.reservation_id
            or observation.reservation_revision != reservation.reservation_revision
            or observation.challenge_id != reservation.challenge_id
            or observation.challenge_revision != reservation.challenge_revision
            or observation.observed_at != decided
            or not claims.observed_at <= decided < claims.expires_at
        ):
            raise ValueError
        finalization_request_digest = _finalization_request_digest(
            reservation,
            statement_digest=statement_digest,
        )
        effect_wire, effect_id, effect_digest = _effect(
            reservation,
            observation,
            finalization_request_digest,
            authenticated_evidence=authenticated_evidence,
        )
        receipt = _receipt(
            reservation,
            statement_digest=statement_digest,
            finalization_request_digest=finalization_request_digest,
            effect_id=effect_id,
            effect_digest=effect_digest,
            decided_at=decided,
        )
        reservation_after = _accepted_reservation_wire(
            reservation,
            statement_digest=statement_digest,
            effect_id=effect_id,
            effect_digest=effect_digest,
            receipt=receipt,
            decided_at=decided,
        )
        return ProvisionalAtomicAcceptanceV1(
            reservation_before=reservation,
            observation=observation,
            effect_wire=effect_wire,
            effect_id=effect_id,
            effect_digest=effect_digest,
            receipt=receipt,
            reservation_after_wire=reservation_after,
            finalization_request_digest=finalization_request_digest,
        )
    except Exception:
        _deny()


@_sanitize_public_failure
def transition_pending_reservation_terminal_v1_bytes(
    reservation_wire: object,
    *,
    state: object,
    decided_at: object,
) -> bytes:
    """Model one terminal non-accepting transition without reopening evidence."""

    try:
        reservation = parse_atomic_acceptance_reservation_v1(reservation_wire)
        if (
            reservation.state != "pending"
            or type(state) is not str
            or state
            not in {
                "rejected",
                "expired",
                "cancelled",
            }
        ):
            raise ValueError
        normalized_state = cast(str, state)
        decided = _integer(decided_at)
        reasons = {
            "rejected": "verification_denied",
            "expired": "evidence_expired",
            "cancelled": "explicitly_cancelled",
        }
        values = _closed_json(reservation.wire, _RESERVATION_FIELDS, MAX_RESERVATION_BYTES)
        values.update(
            {
                "decidedAt": decided,
                "state": normalized_state,
                "terminalReason": reasons[normalized_state],
            }
        )
        wire = _canonical(values)
        parse_atomic_acceptance_reservation_v1(wire)
        return wire.encode("ascii")
    except Exception:
        _deny()


@dataclass(frozen=True, slots=True, repr=False)
class ReservationRetryDispositionV1:
    outcome: str
    reservation_id: str
    state: str
    device_id_reuse: str
    effect_execution: str = field(default="none", init=False)
    automatic_resigning: str = field(default="forbidden", init=False)
    final_admission: str = field(default=FINAL_ADMISSION, init=False)


def _base64url_decode_strict(source: object) -> bytes:
    try:
        if type(source) is not str or _BASE64URL(source) is None or "=" in source:
            raise ValueError
        decoded = base64.urlsafe_b64decode(source + "=" * ((4 - len(source) % 4) % 4))
        encoded = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
        if not decoded or encoded != source:
            raise ValueError
        return decoded
    except Exception:
        pass
    _deny()


def _strict_non_authoritative_historical_evidence_claims_v1(
    evidence_compact_jws: object,
    *,
    expected_input_wire: object,
) -> deadline.DeadlineEvidenceClaimsV1:
    """Extract exact stored bytes without asserting current key trust or authority."""

    try:
        if type(evidence_compact_jws) is not str:
            raise ValueError
        encoded = evidence_compact_jws.encode("ascii")
        if (
            not 1 <= len(encoded) <= deadline.MAX_EVIDENCE_BYTES
            or any(byte < 0x20 or byte > 0x7E for byte in encoded)
            or evidence_compact_jws.count(".") != 2
        ):
            raise ValueError
        protected_segment, payload_segment, signature_segment = evidence_compact_jws.split(".")
        protected_wire = _base64url_decode_strict(protected_segment).decode("ascii")
        payload_wire = _base64url_decode_strict(payload_segment).decode("ascii")
        _base64url_decode_strict(signature_segment)
        signing_input = deadline.messaging_device_verification_deadline_evidence_signing_input_v1(
            protected_header_wire=protected_wire,
            payload_wire=payload_wire,
        )
        if signing_input != (protected_segment + "." + payload_segment).encode("ascii"):
            raise ValueError
        return deadline.parse_messaging_device_verification_deadline_evidence_payload_v1(
            payload_wire,
            expected_input_wire=expected_input_wire,
        )
    except Exception:
        pass
    _deny()


def _reservation_matches_exact_retry_evidence(
    reservation: AtomicAcceptanceReservationV1,
    claims: deadline.DeadlineEvidenceClaimsV1,
    evidence_compact_jws: str,
) -> bool:
    return (
        reservation.reservation_id == claims.reservation_id
        and reservation.reservation_revision == claims.reservation_revision
        and reservation.subject == claims.subject
        and reservation.device_id == claims.device_id
        and reservation.request_id == claims.request_id
        and reservation.operation_id == claims.operation_id
        and reservation.acceptance_id == claims.acceptance_id
        and reservation.challenge_id == claims.enrollment_challenge_id
        and reservation.association_id == claims.association_id
        and reservation.input_digest == claims.input_digest
        and reservation.input_payload_digest == claims.input_payload_digest
        and reservation.evidence_token_id == claims.token_id
        and reservation.evidence_digest == deadline_evidence_digest_v1(evidence_compact_jws)
        and reservation.evidence_payload_digest == deadline_evidence_payload_digest_v1(claims.payload_wire)
        and reservation.created_at == claims.observed_at
        and reservation.expires_at == claims.expires_at
    )


@_sanitize_public_failure
def validate_reservation_historical_identity_v1(
    reservation_wire: object,
    *,
    expected_input_wire: object,
    evidence_compact_jws: object,
) -> AtomicAcceptanceReservationV1:
    """Validate exact stored identity without asserting present authority."""

    try:
        reservation = parse_atomic_acceptance_reservation_v1(reservation_wire)
        claims = _strict_non_authoritative_historical_evidence_claims_v1(
            evidence_compact_jws,
            expected_input_wire=expected_input_wire,
        )
        if type(evidence_compact_jws) is not str or not _reservation_matches_exact_retry_evidence(
            reservation,
            claims,
            evidence_compact_jws,
        ):
            raise ValueError
        return reservation
    except Exception:
        _deny()


@_sanitize_public_failure
def reservation_retry_disposition_v1(
    reservation_wire: object,
    *,
    expected_input_wire: object,
    evidence_compact_jws: object,
    now: object,
    statement_compact_jws: object | None = None,
    receipt_wire: object | None = None,
) -> ReservationRetryDispositionV1:
    """Resolve only exact-byte retry; changed or terminal reuse always denies."""

    try:
        reservation = validate_reservation_historical_identity_v1(
            reservation_wire,
            expected_input_wire=expected_input_wire,
            evidence_compact_jws=evidence_compact_jws,
        )
        current = _integer(now)
        if reservation.state == "pending":
            if (
                statement_compact_jws is not None
                or receipt_wire is not None
                or not reservation.created_at <= current < reservation.expires_at
            ):
                raise ValueError
            return ReservationRetryDispositionV1(
                outcome="return_existing_pending_evidence_without_resigning",
                reservation_id=reservation.reservation_id,
                state=reservation.state,
                device_id_reuse="reserved_by_exact_pending_request",
            )
        if reservation.state == "accepted":
            if statement_compact_jws is None or receipt_wire is None:
                raise ValueError
            receipt = parse_atomic_acceptance_receipt_v1(receipt_wire)
            if (
                reservation.decided_at is None
                or current < reservation.decided_at
                or reservation.statement_digest != verification_statement_digest_v1(statement_compact_jws)
                or reservation.receipt_id != receipt.receipt_id
                or reservation.effect_id != receipt.effect_id
                or reservation.effect_digest != receipt.effect_digest
                or reservation.reservation_id != receipt.reservation_id
                or reservation.reservation_revision != receipt.reservation_revision
                or reservation.acceptance_id != receipt.acceptance_id
                or reservation.association_id != receipt.association_id
                or reservation.challenge_id != receipt.challenge_id
                or reservation.evidence_digest != receipt.evidence_digest
                or reservation.input_digest != receipt.input_digest
                or reservation.statement_digest != receipt.statement_digest
                or reservation.decided_at != receipt.decided_at
                or receipt.finalization_request_digest
                != _finalization_request_digest(
                    reservation,
                    statement_digest=receipt.statement_digest,
                )
            ):
                raise ValueError
            return ReservationRetryDispositionV1(
                outcome="return_immutable_receipt_without_effect",
                reservation_id=reservation.reservation_id,
                state=reservation.state,
                device_id_reuse="denied_association_committed",
            )
        raise ValueError
    except Exception:
        _deny()


@_sanitize_public_failure
def terminal_device_id_reuse_semantics_v1(reservation_wire: object) -> str:
    """Expose the fixed fail-closed rule for non-accepted terminal rows."""

    try:
        reservation = parse_atomic_acceptance_reservation_v1(reservation_wire)
        if reservation.state not in {"rejected", "expired", "cancelled"}:
            raise ValueError
        return (
            "new_reservation_only_after_locked_no_effect_no_receipt_no_association_proof;"
            "new_request_challenge_input_and_reservation_required"
        )
    except Exception:
        _deny()


__all__ = [
    "AUTHORITY_SNAPSHOT_SCHEMA",
    "AtomicAcceptanceEffectV1",
    "AtomicAcceptanceReceiptV1",
    "AtomicAcceptanceReservationV1",
    "COMMIT",
    "DENIED_MESSAGE",
    "EFFECT_SCHEMA",
    "FINALIZATION_OBSERVATION_SCHEMA",
    "FINAL_ADMISSION",
    "FinalizationObservationV1",
    "LOCKING",
    "PERSISTENCE",
    "ProvisionalAtomicAcceptanceV1",
    "RECEIPT_SCHEMA",
    "RESERVATION_SCHEMA",
    "RUNTIME_ENABLED",
    "ReservationRetryDispositionV1",
    "SocialPreacceptedEnrollmentV2AtomicAcceptanceDenied",
    "TRANSACTION_OWNER",
    "canonical_pending_atomic_acceptance_reservation_v1_bytes",
    "current_authority_snapshot_digest_v1",
    "deadline_evidence_digest_v1",
    "deadline_evidence_payload_digest_v1",
    "model_atomic_acceptance_and_cas_v1",
    "parse_atomic_acceptance_receipt_v1",
    "parse_atomic_acceptance_effect_v1",
    "parse_atomic_acceptance_reservation_v1",
    "parse_current_authority_snapshot_v1",
    "parse_evidence_bound_finalization_observation_v1",
    "parse_finalization_observation_v1",
    "reservation_retry_disposition_v1",
    "terminal_device_id_reuse_semantics_v1",
    "transition_pending_reservation_terminal_v1_bytes",
    "validate_reservation_historical_identity_v1",
    "verification_statement_digest_v1",
]
