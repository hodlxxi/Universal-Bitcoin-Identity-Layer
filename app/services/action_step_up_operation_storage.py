"""Atomic persistence of a verified step-up and its dormant operation reservation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.models import ActionOperation, ActionStepUpChallenge
from app.services.action_operation_storage import (
    ActionOperationStorageError,
    InvalidReservationError,
    Reservation,
    validate_reservation,
)
from app.services.action_step_up import (
    StepUpChallenge,
    StepUpProof,
    StepUpReason,
    VerifiedStepUp,
    _validate_persisted_challenge,
    _verify_step_up_candidate,
    step_up_verification_sha256,
)


class AtomicStepUpReserveStatus(str, Enum):
    NEW = "new"
    REPLAY = "replay"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    STEP_UP_REJECTED = "step_up_rejected"


@dataclass(frozen=True)
class AtomicStepUpReserveResult:
    status: AtomicStepUpReserveStatus
    operation: ActionOperation | None
    verification: VerifiedStepUp | None

    def __post_init__(self):
        valid = {
            AtomicStepUpReserveStatus.NEW: (
                self.operation is not None
                and self.verification is not None
                and self.verification.verified is True
                and self.verification.reason_code is StepUpReason.VERIFIED
            ),
            AtomicStepUpReserveStatus.REPLAY: self.operation is not None and self.verification is None,
            AtomicStepUpReserveStatus.IDEMPOTENCY_CONFLICT: (self.operation is not None and self.verification is None),
            AtomicStepUpReserveStatus.STEP_UP_REJECTED: (
                self.operation is None and self.verification is not None and self.verification.verified is False
            ),
        }
        if type(self.status) is not AtomicStepUpReserveStatus or not valid.get(self.status, False):
            raise ValueError("invalid atomic step-up reserve result")


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _challenge_from_row(row: ActionStepUpChallenge) -> StepUpChallenge:
    return StepUpChallenge(
        row.contract_version,
        row.challenge_id,
        row.actor_pubkey,
        row.oauth_client_id,
        row.token_jti,
        row.action,
        row.resource_id,
        row.request_sha256,
        row.nonce,
        _aware(row.issued_at),
        _aware(row.expires_at),
        row.signature_domain,
        _aware(row.consumed_at) if row.consumed_at else None,
    )


class SqlAlchemyAtomicStepUpOperationRepository:
    """Bind challenge consumption and operation insertion in one transaction."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def reserve_with_step_up(
        self,
        reservation: Reservation,
        proof: StepUpProof,
        consumed_at: datetime,
    ) -> AtomicStepUpReserveResult:
        validate_reservation(reservation)
        if reservation.step_up_challenge_id is None or reservation.step_up_verification_sha256 is not None:
            raise InvalidReservationError()
        if type(proof) is StepUpProof and reservation.step_up_challenge_id != proof.challenge_id:
            raise InvalidReservationError()
        try:
            if not isinstance(consumed_at, datetime) or consumed_at.tzinfo is None or consumed_at.utcoffset() is None:
                raise ValueError
            timestamp = consumed_at.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("timezone-aware datetime required") from None

        try:
            with self._session_factory() as session:
                existing = self._namespace_row(session, reservation)
                if existing is not None:
                    return self._existing_result(session, existing, reservation)

                row = session.get(ActionStepUpChallenge, reservation.step_up_challenge_id)
                if row is None:
                    return self._rejected(StepUpReason.CHALLENGE_NOT_FOUND)
                challenge = _challenge_from_row(row)
                verification = _verify_step_up_candidate(
                    challenge,
                    proof,
                    actor_pubkey=reservation.actor_pubkey,
                    oauth_client_id=reservation.oauth_client_id,
                    token_jti=reservation.token_jti,
                    action=reservation.action,
                    resource_id=reservation.resource_id,
                    request_sha256=reservation.request_sha256,
                    verified_at=timestamp,
                )
                if not verification.verified:
                    return AtomicStepUpReserveResult(AtomicStepUpReserveStatus.STEP_UP_REJECTED, None, verification)

                verification_hash = step_up_verification_sha256(verification)
                bound = replace(reservation, step_up_verification_sha256=verification_hash)
                consumed = session.execute(
                    update(ActionStepUpChallenge)
                    .where(
                        ActionStepUpChallenge.challenge_id == challenge.challenge_id,
                        ActionStepUpChallenge.contract_version == challenge.schema,
                        ActionStepUpChallenge.signature_domain == challenge.signature_domain,
                        ActionStepUpChallenge.actor_pubkey == challenge.actor_pubkey,
                        ActionStepUpChallenge.oauth_client_id == challenge.oauth_client_id,
                        ActionStepUpChallenge.token_jti == challenge.token_jti,
                        ActionStepUpChallenge.action == challenge.action,
                        (
                            ActionStepUpChallenge.resource_id.is_(None)
                            if challenge.resource_id is None
                            else ActionStepUpChallenge.resource_id == challenge.resource_id
                        ),
                        ActionStepUpChallenge.request_sha256 == challenge.request_sha256,
                        ActionStepUpChallenge.nonce == challenge.nonce,
                        ActionStepUpChallenge.issued_at == challenge.issued_at,
                        ActionStepUpChallenge.expires_at == challenge.expires_at,
                        ActionStepUpChallenge.issued_at <= timestamp,
                        ActionStepUpChallenge.expires_at > timestamp,
                        ActionStepUpChallenge.consumed_at.is_(None),
                    )
                    .values(consumed_at=timestamp)
                )
                if consumed.rowcount != 1:
                    session.rollback()
                    return self._resolve_after_race(reservation, timestamp)
                operation = ActionOperation(**vars(bound), state="reserved", updated_at=bound.reserved_at)
                session.add(operation)
                session.flush()
                session.commit()
                session.refresh(operation)
                session.expunge(operation)
                return AtomicStepUpReserveResult(AtomicStepUpReserveStatus.NEW, operation, verification)
        except IntegrityError:
            return self._resolve_after_race(reservation, timestamp)
        except ActionOperationStorageError:
            raise
        except SQLAlchemyError:
            raise ActionOperationStorageError() from None
        except Exception:
            raise ActionOperationStorageError() from None

    @staticmethod
    def _namespace_row(session, reservation: Reservation):
        return (
            session.query(ActionOperation)
            .filter_by(
                actor_pubkey=reservation.actor_pubkey,
                oauth_client_id=reservation.oauth_client_id,
                idempotency_key_sha256=reservation.idempotency_key_sha256,
            )
            .one_or_none()
        )

    @staticmethod
    def _existing_result(session, operation, reservation):
        session.expunge(operation)
        status = (
            AtomicStepUpReserveStatus.REPLAY
            if operation.request_fingerprint_sha256 == reservation.request_fingerprint_sha256
            else AtomicStepUpReserveStatus.IDEMPOTENCY_CONFLICT
        )
        return AtomicStepUpReserveResult(status, operation, None)

    @staticmethod
    def _rejected(reason: StepUpReason, challenge_id: str | None = None):
        return AtomicStepUpReserveResult(
            AtomicStepUpReserveStatus.STEP_UP_REJECTED,
            None,
            VerifiedStepUp(False, reason, challenge_id=challenge_id),
        )

    def _resolve_after_race(self, reservation: Reservation, timestamp: datetime):
        try:
            with self._session_factory() as session:
                existing = self._namespace_row(session, reservation)
                if existing is not None:
                    return self._existing_result(session, existing, reservation)
                row = session.get(ActionStepUpChallenge, reservation.step_up_challenge_id)
                if row is None:
                    return self._rejected(StepUpReason.CHALLENGE_NOT_FOUND)
                challenge = _challenge_from_row(row)
                state = _validate_persisted_challenge(challenge, timestamp)
                if state is StepUpReason.INVALID_REQUEST:
                    return self._rejected(state, challenge.challenge_id)
                if challenge.expires_at <= timestamp:
                    return self._rejected(StepUpReason.CHALLENGE_EXPIRED, challenge.challenge_id)
                if challenge.consumed_at is not None:
                    return self._rejected(StepUpReason.CHALLENGE_CONSUMED, challenge.challenge_id)
                if state is not None:
                    return self._rejected(state, challenge.challenge_id)
        except Exception:
            raise ActionOperationStorageError() from None
        raise ActionOperationStorageError()
