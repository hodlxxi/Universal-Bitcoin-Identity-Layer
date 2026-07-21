"""SQLAlchemy persistence adapter for canonical action step-up challenges."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import update

from app.models import ActionStepUpChallenge
from app.services.action_step_up import StepUpChallenge


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class SqlAlchemyActionStepUpRepository:
    """Narrow repository using a caller-provided canonical session factory."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def create(self, challenge: StepUpChallenge) -> None:
        with self._session_factory() as session:
            session.add(
                ActionStepUpChallenge(
                    challenge_id=challenge.challenge_id,
                    contract_version=challenge.schema,
                    signature_domain=challenge.signature_domain,
                    actor_pubkey=challenge.actor_pubkey,
                    oauth_client_id=challenge.oauth_client_id,
                    token_jti=challenge.token_jti,
                    action=challenge.action,
                    resource_id=challenge.resource_id,
                    request_sha256=challenge.request_sha256,
                    nonce=challenge.nonce,
                    issued_at=challenge.issued_at,
                    expires_at=challenge.expires_at,
                )
            )
            session.commit()

    def get(self, challenge_id: str) -> StepUpChallenge | None:
        with self._session_factory() as session:
            row = session.get(ActionStepUpChallenge, challenge_id)
            if row is None:
                return None
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

    def consume(self, challenge: StepUpChallenge, consumed_at: datetime) -> bool:
        """Atomically consume only the exact still-live, still-unconsumed row."""
        with self._session_factory() as session:
            result = session.execute(
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
                    ActionStepUpChallenge.issued_at <= consumed_at,
                    ActionStepUpChallenge.expires_at > consumed_at,
                    ActionStepUpChallenge.consumed_at.is_(None),
                )
                .values(consumed_at=consumed_at)
            )
            session.commit()
            return result.rowcount == 1
