"""Atomic persistence primitives for dormant action operations; executes no actions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import and_, or_, update
from sqlalchemy.exc import IntegrityError

from app.models import ActionOperation
from app.services.action_idempotency import (
    OPERATION_CONTRACT_VERSION,
    IdempotencyError,
    request_fingerprint_sha256,
    token_reference_sha256,
)
from app.services.action_receipt import (
    canonical_json_bytes,
    parse_action_receipt,
    receipt_sha256,
    verify_action_receipt,
)

OPERATION_STATES = frozenset({"reserved", "executing", "completed", "failed", "indeterminate"})
ALLOWED_TRANSITIONS = frozenset(
    {
        ("reserved", "executing"),
        ("reserved", "failed"),
        ("executing", "completed"),
        ("executing", "failed"),
        ("executing", "indeterminate"),
    }
)


def is_allowed_transition(current_state: str, next_state: str) -> bool:
    return (current_state, next_state) in ALLOWED_TRANSITIONS


def _aware(value):
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


class ActionOperationStorageError(RuntimeError):
    def __init__(self):
        super().__init__("storage_unavailable")


class InvalidReservationError(ValueError):
    def __init__(self):
        super().__init__("invalid_reservation")


@dataclass(frozen=True)
class Reservation:
    contract_version: str
    actor_pubkey: str
    oauth_client_id: str
    token_jti: str
    token_reference_sha256: str
    action: str
    resource_id: str | None
    request_sha256: str
    idempotency_key_sha256: str
    request_fingerprint_sha256: str
    step_up_challenge_id: str | None
    step_up_verification_sha256: str | None
    policy_version: str
    authorization_decision_sha256: str
    reserved_at: datetime


@dataclass(frozen=True)
class ReserveResult:
    status: str
    operation: ActionOperation | None

    @property
    def is_new(self):
        return self.status == "new"


class SqlAlchemyActionOperationRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    def _safe(self, function):
        try:
            return function()
        except ActionOperationStorageError:
            raise
        except Exception:
            raise ActionOperationStorageError() from None

    def reserve(self, reservation: Reservation) -> ReserveResult:
        self._validate_reservation(reservation)

        def work():
            with self._session_factory() as session:
                row = ActionOperation(**vars(reservation), state="reserved", updated_at=reservation.reserved_at)
                session.add(row)
                try:
                    session.commit()
                    session.refresh(row)
                    session.expunge(row)
                    return ReserveResult("new", row)
                except IntegrityError:
                    session.rollback()
                    existing = (
                        session.query(ActionOperation)
                        .filter_by(
                            actor_pubkey=reservation.actor_pubkey,
                            oauth_client_id=reservation.oauth_client_id,
                            idempotency_key_sha256=reservation.idempotency_key_sha256,
                        )
                        .one_or_none()
                    )
                    if existing is None:
                        raise ActionOperationStorageError()
                    session.expunge(existing)
                    if existing.request_fingerprint_sha256 == reservation.request_fingerprint_sha256:
                        return ReserveResult("replay", existing)
                    return ReserveResult("idempotency_conflict", existing)

        return self._safe(work)

    @staticmethod
    def _validate_reservation(reservation: Reservation) -> None:
        try:
            if reservation.contract_version != OPERATION_CONTRACT_VERSION:
                raise InvalidReservationError()
            if not isinstance(reservation.idempotency_key_sha256, str) or not re.fullmatch(
                r"[0-9a-f]{64}", reservation.idempotency_key_sha256
            ):
                raise InvalidReservationError()
            expected_token_reference = token_reference_sha256(reservation.token_jti)
            expected_fingerprint = request_fingerprint_sha256(
                contract_version=reservation.contract_version,
                actor_pubkey=reservation.actor_pubkey,
                oauth_client_id=reservation.oauth_client_id,
                token_jti=reservation.token_jti,
                action=reservation.action,
                resource_id=reservation.resource_id,
                request_sha256=reservation.request_sha256,
                step_up_challenge_id=reservation.step_up_challenge_id,
            )
            if (
                reservation.token_reference_sha256 != expected_token_reference
                or reservation.request_fingerprint_sha256 != expected_fingerprint
            ):
                raise InvalidReservationError()
        except (IdempotencyError, TypeError):
            raise InvalidReservationError() from None

    def get_by_operation_id(self, operation_id: str):
        return self._safe(lambda: self._get(operation_id=operation_id))

    def get_by_idempotency_namespace(self, actor_pubkey: str, oauth_client_id: str, key_hash: str):
        return self._safe(
            lambda: self._get(
                actor_pubkey=actor_pubkey, oauth_client_id=oauth_client_id, idempotency_key_sha256=key_hash
            )
        )

    def _get(self, **filters):
        with self._session_factory() as session:
            row = session.query(ActionOperation).filter_by(**filters).one_or_none()
            if row is not None:
                session.expunge(row)
            return row

    def _transition(self, operation_id: str, expected_states: tuple[str, ...], values: dict, conditions=()) -> bool:
        def work():
            with self._session_factory() as session:
                result = session.execute(
                    update(ActionOperation)
                    .where(
                        ActionOperation.operation_id == operation_id,
                        ActionOperation.state.in_(expected_states),
                        *conditions,
                    )
                    .values(**values)
                )
                if result.rowcount != 1:
                    session.rollback()
                    return False
                session.commit()
                return True

        return self._safe(work)

    def mark_executing(self, operation_id: str, started_at: datetime) -> bool:
        return self._transition(
            operation_id, ("reserved",), {"state": "executing", "started_at": started_at, "updated_at": started_at}
        )

    def finalize_completed(self, operation_id: str, receipt: dict) -> bool:
        return self._finalize(operation_id, "completed", receipt, ("executing",))

    def finalize_failed(self, operation_id: str, receipt: dict) -> bool:
        return self._finalize(operation_id, "failed", receipt, ("reserved", "executing"))

    def _finalize(self, operation_id: str, state: str, receipt: dict, expected: tuple[str, ...]) -> bool:
        parsed = parse_action_receipt(receipt)
        if parsed["operation_id"] != operation_id or parsed["state"] != state or not verify_action_receipt(parsed):
            return False
        completed_at = datetime.fromisoformat(parsed["completed_at"].replace("Z", "+00:00"))
        started_at = datetime.fromisoformat(parsed["started_at"].replace("Z", "+00:00"))
        values = {
            "state": state,
            "started_at": started_at,
            "completed_at": completed_at,
            "failure_code": parsed["failure_code"],
            "result_sha256": parsed["result_sha256"],
            "receipt_json": parsed,
            "receipt_sha256": receipt_sha256(parsed),
            "receipt_signature": parsed["signature"],
            "signer_public_key": parsed["signer_public_key"],
            "updated_at": completed_at,
        }
        resource_condition = (
            ActionOperation.resource_id.is_(None)
            if parsed["resource_id"] is None
            else ActionOperation.resource_id == parsed["resource_id"]
        )
        step_up_id_condition = (
            ActionOperation.step_up_challenge_id.is_(None)
            if parsed["step_up_challenge_id"] is None
            else ActionOperation.step_up_challenge_id == parsed["step_up_challenge_id"]
        )
        step_up_hash_condition = (
            ActionOperation.step_up_verification_sha256.is_(None)
            if parsed["step_up_verification_sha256"] is None
            else ActionOperation.step_up_verification_sha256 == parsed["step_up_verification_sha256"]
        )
        conditions = (
            ActionOperation.actor_pubkey == parsed["actor_pubkey"],
            ActionOperation.oauth_client_id == parsed["oauth_client_id"],
            ActionOperation.token_reference_sha256 == parsed["token_reference_sha256"],
            ActionOperation.action == parsed["action"],
            resource_condition,
            ActionOperation.request_sha256 == parsed["request_sha256"],
            ActionOperation.idempotency_key_sha256 == parsed["idempotency_key_sha256"],
            ActionOperation.policy_version == parsed["policy_version"],
            ActionOperation.authorization_decision_sha256 == parsed["authorization_decision_sha256"],
            step_up_id_condition,
            step_up_hash_condition,
        )
        if state == "completed":
            conditions += (ActionOperation.started_at == started_at,)
        else:
            conditions += (
                or_(
                    and_(ActionOperation.state == "executing", ActionOperation.started_at == started_at),
                    and_(
                        ActionOperation.state == "reserved",
                        ActionOperation.started_at.is_(None),
                        ActionOperation.reserved_at == started_at,
                    ),
                ),
            )
        return self._transition(operation_id, expected, values, conditions)

    def mark_indeterminate(self, operation_id: str, updated_at: datetime) -> bool:
        return self._transition(operation_id, ("executing",), {"state": "indeterminate", "updated_at": updated_at})


def stored_receipt_bytes(operation: ActionOperation) -> bytes | None:
    """Return stored terminal JSON without reconstruction or re-signing."""
    return canonical_json_bytes(operation.receipt_json) if operation.receipt_json is not None else None
