"""Dormant atomic owner for one exact Social ``enrollment-activate`` operation.

The caller supplies and owns one already-active PostgreSQL READ COMMITTED
transaction.  This owner composes the locked pre-effect authority, Ed25519
association effect, immutable receipt, and issued-to-consumed challenge
transition without starting or completing that transaction.  Returned evidence
is provisional until the caller commits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NoReturn, cast

from sqlalchemy.orm import Session

from app.services import social_enrollment_transition_authority as transition
from app.services import social_messaging_device_admission_contract as admission
from app.services.social_device_challenge_store import DeviceAdmissionChallengeV1, SqlAlchemyDeviceChallengeStore
from app.services.social_device_ed25519_association_storage import (
    CurrentEd25519AssociationV1,
    SqlAlchemyEd25519AssociationStore,
)
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1
from app.services.social_enrollment_receipt_storage import (
    SqlAlchemyEnrollmentAdmissionReceiptStore,
    StoredEnrollmentAdmissionReceiptV1,
    enrollment_receipt_id_v1,
)
from app.services.social_enrollment_transition_authority_storage import (
    SqlAlchemyTransactionBoundEnrollmentTransitionAuthority,
)
from app.services.social_messaging_device_proof_profile import MAX_SAFE_INTEGER

RUNTIME_ENABLED = False
ATOMIC_OWNER = "ubid_enrollment_activate_implemented_dormant"
ATOMIC_COMMIT = "caller_owned"
FINAL_ADMISSION = "denied"
UNAVAILABLE_MESSAGE = "social enrollment atomic owner unavailable"


class SocialEnrollmentAtomicOwnerUnavailable(ValueError):
    """One non-sensitive failure for authority, effect, or evidence denial."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


def _deny() -> NoReturn:
    raise SocialEnrollmentAtomicOwnerUnavailable()


@dataclass(frozen=True, slots=True, repr=False)
class ProvisionalEnrollmentActivationV1:
    """Typed evidence for mutations that only caller commit can publish."""

    authority: transition.EnrollmentTransitionAuthorityV1
    effect: admission.PreparedAdmissionEffectV1
    association: CurrentEd25519AssociationV1
    receipt: StoredEnrollmentAdmissionReceiptV1
    consumed_challenge: DeviceAdmissionChallengeV1
    publication_status: str = field(default="provisional_until_caller_commit", init=False)
    bearer_authority: str = field(default="none", init=False)
    reexecution_authority: str = field(default="none", init=False)
    final_admission: str = field(default=FINAL_ADMISSION, init=False)


def _time(value: object) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER:
        _deny()
    return cast(int, value)


def _exact_association(
    value: object,
    authority: transition.EnrollmentTransitionAuthorityV1,
) -> CurrentEd25519AssociationV1:
    if type(value) is not CurrentEd25519AssociationV1:
        _deny()
    association = cast(CurrentEd25519AssociationV1, value)
    if (
        association.subject != authority.subject
        or association.device_id != authority.device_id
        or association.ed25519_public_key != authority.proposed_ed25519_public_key
        or association.association_id != authority.proposed_association_id
        or association.association_version != authority.proposed_association_version
        or association.predecessor_association_id != authority.proposed_predecessor_association_id
        or association.authority_epoch != authority.proposed_authority_epoch
        or association.state != transition.PROPOSED_STATE
    ):
        _deny()
    return association


def _exact_receipt(
    value: object,
    authority: transition.EnrollmentTransitionAuthorityV1,
    effect: admission.PreparedAdmissionEffectV1,
    *,
    decided_at: int,
) -> StoredEnrollmentAdmissionReceiptV1:
    if type(value) is not StoredEnrollmentAdmissionReceiptV1:
        _deny()
    stored = cast(StoredEnrollmentAdmissionReceiptV1, value)
    receipt = stored.receipt
    if (
        type(receipt) is not admission.AdmissionReceiptV1
        or admission.parse_admission_receipt_v1(stored.receipt_wire) != receipt
        or receipt.receipt_id != enrollment_receipt_id_v1(authority)
        or receipt.challenge_id != authority.challenge_id
        or receipt.operation != transition.OPERATION
        or receipt.decided_at != decided_at
        or receipt.status != "committed"
        or stored.effect_id != effect.effect_id
        or stored.effect_digest != effect.effect_digest
        or stored.proposed_association_id != authority.proposed_association_id
        or stored.bearer_authority != "none"
        or stored.reexecution_authority != "none"
    ):
        _deny()
    return stored


def _exact_consumed_challenge(
    value: object,
    authority: transition.EnrollmentTransitionAuthorityV1,
    input_value: admission.VerificationInputV1,
) -> DeviceAdmissionChallengeV1:
    if type(value) is not DeviceAdmissionChallengeV1:
        _deny()
    challenge = cast(DeviceAdmissionChallengeV1, value)
    if (
        challenge.state != "consumed"
        or challenge.operation != transition.OPERATION
        or challenge.context != input_value.context
        or challenge.context.wire != input_value.context.wire
        or challenge.challenge_wire != input_value.challenge_wire
        or challenge.actual_request_wire is not None
        or challenge.routing_request_wire is not None
        or challenge.context.challenge_id != authority.challenge_id
        or challenge.context.subject != authority.subject
        or challenge.context.device_id != authority.device_id
        or challenge.context.ed25519_public_key != authority.proposed_ed25519_public_key
        or challenge.context.association_id != authority.proposed_association_id
        or challenge.context.association_version != authority.proposed_association_version
        or challenge.context.predecessor_association_id != authority.proposed_predecessor_association_id
        or challenge.context.authority_epoch != authority.proposed_authority_epoch
    ):
        _deny()
    return challenge


class SqlAlchemyTransactionBoundEnrollmentAtomicOwner:
    """Execute one enrollment activation inside the caller's exact transaction.

    Instances are one-shot.  A failed instance is poisoned, and a successful
    result cannot be used to replay the operation.  The caller must roll back
    every failure and is solely responsible for the eventual commit.
    """

    def __init__(
        self,
        session: Session,
        *,
        device_issuance_id: object,
        device_client_id: object,
        oauth_issuer: object,
        approver_oauth_session_id: object,
        approver_client_id: object,
    ) -> None:
        self._failed = False
        self._used = False
        try:
            self._authority = SqlAlchemyTransactionBoundEnrollmentTransitionAuthority(
                session,
                device_issuance_id=device_issuance_id,
                device_client_id=device_client_id,
                oauth_issuer=oauth_issuer,
                approver_oauth_session_id=approver_oauth_session_id,
                approver_client_id=approver_client_id,
            )
            self._associations = SqlAlchemyEd25519AssociationStore(session)
            self._receipts = SqlAlchemyEnrollmentAdmissionReceiptStore(session)
            self._challenges = SqlAlchemyDeviceChallengeStore(session)
            return
        except Exception:
            self._failed = True
        _deny()

    def execute_enrollment_activate(
        self,
        value: admission.VerificationInputV1,
        statement: AuthenticatedSocialDeviceVerificationStatementV1,
        *,
        observed_at: int,
        decided_at: int,
    ) -> ProvisionalEnrollmentActivationV1:
        """Provisionally execute effect, receipt, and consumption in that order."""

        try:
            if self._failed or self._used:
                _deny()
            self._used = True
            observed = _time(observed_at)
            decided = _time(decided_at)
            if type(value) is not admission.VerificationInputV1 or decided < observed:
                _deny()

            authority = self._authority.lock_transition_authority(
                value,
                statement,
                observed_at=observed,
            )
            if authority.observed_at != observed or decided >= authority.locked_deadline_ms:
                _deny()
            effect = transition.prepared_enrollment_effect_v1(authority)

            effect_arguments = {
                "input_wire": value.wire,
                "statement": statement,
                "now": decided,
            }
            if authority.transition_kind == "initial":
                association = self._associations.establish_initial(**effect_arguments)
            elif authority.transition_kind == "rotate":
                association = self._associations.rotate(
                    **effect_arguments,
                    expected_predecessor=authority.pre_effect_association_id,
                    expected_epoch=authority.pre_effect_authority_epoch,
                )
            elif authority.transition_kind == "reenroll":
                association = self._associations.reenroll(
                    **effect_arguments,
                    expected_predecessor=authority.pre_effect_association_id,
                    expected_epoch=authority.pre_effect_authority_epoch,
                )
            else:
                _deny()
            association = _exact_association(association, authority)

            receipt = self._receipts.store_committed(
                authority,
                proposed_association_id=association.association_id,
                decided_at=decided,
            )
            receipt = _exact_receipt(receipt, authority, effect, decided_at=decided)
            consumed = self._challenges.record_enrollment_consumed(
                authority,
                observed_at=decided,
            )
            consumed = _exact_consumed_challenge(consumed, authority, value)
            return ProvisionalEnrollmentActivationV1(
                authority=authority,
                effect=effect,
                association=association,
                receipt=receipt,
                consumed_challenge=consumed,
            )
        except Exception:
            self._failed = True
        _deny()


__all__ = [
    "ATOMIC_COMMIT",
    "ATOMIC_OWNER",
    "FINAL_ADMISSION",
    "ProvisionalEnrollmentActivationV1",
    "RUNTIME_ENABLED",
    "SocialEnrollmentAtomicOwnerUnavailable",
    "SqlAlchemyTransactionBoundEnrollmentAtomicOwner",
]
