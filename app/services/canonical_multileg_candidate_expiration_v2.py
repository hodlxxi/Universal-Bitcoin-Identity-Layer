"""Dormant candidate-only lifecycle: seven-day expiry without deleting proof.

The immutable candidate and all signed outpoint rows are retained.
PostgreSQL arbitrates the live child/UTXO claim release and appends a
terminal event, in the caller's transaction, using DB time. Expired
candidates never grant/withdraw Full: there was no effective grant.
No route, scheduler, production migration or privilege assignment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

RUNTIME_ENABLED = False
EXPIRE_SQL = """
SELECT expired_proposal_id, released_outpoints, at_time
FROM public.expire_canonical_multileg_candidate_v2(:proposal_id)
"""


class MultiLegCandidateExpirationUnavailableV2(RuntimeError):
    """No valid, exclusive pending expiration transaction."""


@dataclass(frozen=True, slots=True)
class PendingExpiredMultiLegCandidateV2:
    proposal_id: str
    released_outpoints: int
    expired_at: datetime

    @property
    def durable(self) -> bool:
        """Caller-owned commit has not yet linearized the expiration."""
        return False

    @property
    def grants_full(self) -> bool:
        return False

    @property
    def is_effective(self) -> bool:
        return False


class SqlAlchemyMultiLegCandidateExpirationV2:
    """Privileged *internal-only* Postgres caller, no implicit commit."""

    def __init__(self, session: Session) -> None:
        if session is None or not callable(getattr(session, "execute", None)):
            raise MultiLegCandidateExpirationUnavailableV2("session_required")
        self._session = session

    def expire_in_transaction(self, proposal_id: str) -> PendingExpiredMultiLegCandidateV2:
        try:
            session = self._session
            if (
                not session.in_transaction()
                or session.get_transaction() is None
                or not session.get_transaction().is_active
                or session.get_bind().dialect.name != "postgresql"
                or session.new
                or session.dirty
                or session.deleted
                or session.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed"
            ):
                raise ValueError("bad transaction")
            if type(proposal_id) is not str or len(proposal_id) != 36:
                raise ValueError("bad id")
            result = session.execute(text(EXPIRE_SQL), {"proposal_id": proposal_id}).one()
            if (
                result.expired_proposal_id != proposal_id
                or type(result.released_outpoints) is not int
                or not 2 <= result.released_outpoints <= 256
                or type(result.at_time) is not datetime
                or result.at_time.tzinfo is None
            ):
                raise ValueError("invalid expiry receipt")
        except (SQLAlchemyError, ValueError, TypeError):
            raise MultiLegCandidateExpirationUnavailableV2("expiry_not_permitted") from None
        return PendingExpiredMultiLegCandidateV2(
            proposal_id, result.released_outpoints, result.at_time
        )
