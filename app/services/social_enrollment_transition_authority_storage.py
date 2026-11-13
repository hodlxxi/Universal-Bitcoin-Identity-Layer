"""PostgreSQL pre-effect authority for one Social enrollment transition.

The caller owns one already-active READ COMMITTED transaction.  This adapter
locks the exact issued challenge, then reuses the current-authority owner's
Full/session/X25519 lock sequence, and finally locks complete Ed25519 history.
It never changes any row or owns transaction lifecycle.

Global lock order:

1. Exact admission challenge row.
2. Current-Full subject advisory lock, User row, entitlement evidence.
3. OAuth clients, Social issuer, OAuth/browser/Session/Social issuance rows.
4. Exact current X25519 binding row.
5. Ed25519 pair advisory lock, chain row, then immutable event history.
"""

from __future__ import annotations

from typing import NoReturn, cast

from sqlalchemy.orm import Session

from app.services import social_enrollment_transition_authority as transition
from app.services import social_messaging_device_admission_contract as admission
from app.services.social_current_admission_authority import SqlAlchemyTransactionBoundAdmissionAuthority
from app.services.social_device_challenge_store import SqlAlchemyDeviceChallengeStore
from app.services.social_device_ed25519_association_storage import SqlAlchemyEd25519AssociationStore
from app.services.social_device_verification_statement import AuthenticatedSocialDeviceVerificationStatementV1

RUNTIME_ENABLED = False
CHALLENGE_CONSUMPTION = "not_implemented"
EFFECT_EXECUTION = "not_implemented"
RECEIPT_ISSUANCE = "not_implemented"
FINAL_ADMISSION = "denied"
UNAVAILABLE_MESSAGE = "social enrollment transition authority storage unavailable"


class SocialEnrollmentTransitionAuthorityStorageUnavailable(ValueError):
    """One non-sensitive failure for storage, authority, and mismatch denial."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE_MESSAGE)


def _deny() -> NoReturn:
    raise SocialEnrollmentTransitionAuthorityStorageUnavailable()


def _exact_input(value: object) -> admission.VerificationInputV1:
    try:
        if type(value) is not admission.VerificationInputV1:
            _deny()
        parsed = admission.parse_verification_input_v1(value.wire)
        if parsed != value or parsed.operation != transition.OPERATION:
            _deny()
        return cast(admission.VerificationInputV1, value)
    except Exception:
        pass
    _deny()


class SqlAlchemyTransactionBoundEnrollmentTransitionAuthority:
    """Construct typed transition authority from one locked pre-effect state."""

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
        self._session = session
        self._failed = False
        try:
            self._challenge_store = SqlAlchemyDeviceChallengeStore(session)
            self._current_authority = SqlAlchemyTransactionBoundAdmissionAuthority(
                session,
                device_issuance_id=device_issuance_id,
                device_client_id=device_client_id,
                oauth_issuer=oauth_issuer,
                approver_oauth_session_id=approver_oauth_session_id,
                approver_client_id=approver_client_id,
            )
            self._ed25519_store = SqlAlchemyEd25519AssociationStore(session)
            return
        except Exception:
            pass
        _deny()

    def lock_transition_authority(
        self,
        value: admission.VerificationInputV1,
        statement: AuthenticatedSocialDeviceVerificationStatementV1,
        *,
        observed_at: int,
    ) -> transition.EnrollmentTransitionAuthorityV1:
        """Authorize, but do not execute, the exact proposed enrollment effect."""

        try:
            if self._failed:
                _deny()
            value = _exact_input(value)
            if type(statement) is not AuthenticatedSocialDeviceVerificationStatementV1:
                _deny()
            context = value.context

            # A future consuming owner follows this same first lock.  The read
            # returns current columns after any wait and never mutates state.
            challenge = self._challenge_store.read_for_update(context.challenge_id)
            deadline = challenge.inspect_deadline(now=observed_at)
            if (
                challenge.state != "issued"
                or deadline.disposition != "current"
                or challenge.context != context
                or challenge.context.wire != context.wire
                or challenge.challenge_wire != value.challenge_wire
                or challenge.operation != transition.OPERATION
                or challenge.actual_request_wire is not None
                or challenge.routing_request_wire is not None
            ):
                _deny()

            # The exact verifier-produced type and every signed operation/input
            # binding are checked before durable authority can be returned.
            transition._authenticated_statement(
                value,
                statement,
                observed_at=observed_at,
            )

            locked_non_ed25519 = self._current_authority._lock_non_ed25519_authority(
                context,
                observed_at=observed_at,
            )
            lifecycle = self._ed25519_store.lock_lifecycle(
                context.subject,
                context.device_id,
            )
            non_ed25519 = self._current_authority._finalize_non_ed25519_authority(
                locked_non_ed25519,
            )
            locked_deadline_ms = min(
                non_ed25519.locked_deadline_ms,
                challenge.expires_at,
            )
            return transition.authorize_enrollment_transition_v1(
                value,
                statement,
                lifecycle,
                observed_at=observed_at,
                locked_deadline_ms=locked_deadline_ms,
                full_proof_id=non_ed25519.full_proof_id,
                approver_full_proof_id=non_ed25519.approver_full_proof_id,
            )
        except Exception:
            self._failed = True
        _deny()


__all__ = [
    "CHALLENGE_CONSUMPTION",
    "EFFECT_EXECUTION",
    "FINAL_ADMISSION",
    "RECEIPT_ISSUANCE",
    "RUNTIME_ENABLED",
    "SocialEnrollmentTransitionAuthorityStorageUnavailable",
    "SqlAlchemyTransactionBoundEnrollmentTransitionAuthority",
]
