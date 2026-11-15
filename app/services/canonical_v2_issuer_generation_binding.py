"""Issue #588: sponsor's exact OAuth generation bound to one-use consent.

All operations are inside caller-owned PostgreSQL READ COMMITTED transaction.
No issuer identity is accepted from HTTP JSON. The browser ingress supplies
the server-signed generation reference and configured OAuth client ID.

This provenance does not independently grant EFFECTIVE or Current Full.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.canonical_v2_tx_browser_authority import locked_browser_subject_in_transaction

RUNTIME_ENABLED = False
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

_INSERT = """
INSERT INTO public.canonical_multileg_consent_browser_bindings_v2 (
    challenge_sha256, sponsor_generation_id, sponsor_subject,
    client_id, issuer_user_id, bound_at
) VALUES (
    :challenge_sha256, :sponsor_generation_id, :sponsor_subject,
    :client_id, :issuer_user_id, :bound_at
) RETURNING challenge_sha256
"""

_LOCK = """
SELECT b.challenge_sha256, b.sponsor_generation_id, b.sponsor_subject,
       b.client_id, b.issuer_user_id, b.bound_at,
       c.issued_at, c.expires_at, c.consumed_at, c.proposal_sha256,
       c.sponsor_compressed_pubkey
  FROM public.canonical_multileg_consent_browser_bindings_v2 AS b
  JOIN public.canonical_multileg_consent_challenges_v2 AS c
    ON c.challenge_sha256 = b.challenge_sha256
 WHERE b.challenge_sha256 = :challenge_sha256
 FOR SHARE OF b, c
"""


class CanonicalV2IssuerGenerationUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("canonical v2 sponsor issuer generation unavailable")


def _deny() -> None:
    raise CanonicalV2IssuerGenerationUnavailable()


def _at(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _deny()
    at = value.astimezone(timezone.utc)
    if at.microsecond:
        _deny()
    return at


def _guard(db: Session) -> None:
    if (
        not isinstance(db, Session)
        or db.in_transaction() is not True
        or db.get_transaction() is None
        or db.get_transaction().is_active is not True
        or db.get_bind().dialect.name != "postgresql"
        or db.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed"
    ):
        _deny()


def bind_issuer_generation_in_transaction(
    db: Session,
    *,
    challenge_sha256: str,
    sponsor_generation_id: str,
    sponsor_subject: str,
    client_id: str,
    issued_at: datetime,
) -> None:
    """Bind exactly one DB-issued challenge to its locked signing browser."""
    try:
        _guard(db)
        if type(challenge_sha256) is not str or _HEX64.fullmatch(challenge_sha256) is None:
            _deny()
        at = _at(issued_at)
        locked = locked_browser_subject_in_transaction(
            db,
            generation_id=sponsor_generation_id,
            expected_subject=sponsor_subject,
            client_id=client_id,
            now=at,
        )
        row = db.execute(
            text(_INSERT),
            {
                "challenge_sha256": challenge_sha256,
                "sponsor_generation_id": locked.generation_id,
                "sponsor_subject": locked.subject,
                "client_id": locked.client_id,
                "issuer_user_id": locked.user_id,
                "bound_at": at,
            },
        ).scalar_one_or_none()
        if row != challenge_sha256:
            _deny()
    except CanonicalV2IssuerGenerationUnavailable:
        raise
    except Exception:
        raise CanonicalV2IssuerGenerationUnavailable() from None


def require_current_issuer_generation_in_transaction(
    db: Session,
    *,
    challenge_sha256: str,
    sponsor_subject: str,
    client_id: str,
    proposal_sha256: str,
    now: datetime,
) -> str:
    """Child finalization: require nonce's exact sponsor generation still active.

    This is a revocation fence: no cancellation, logout or replacement can
    commit between sponsor generation verification and candidate commit.
    """
    try:
        _guard(db)
        at = _at(now)
        if (
            type(challenge_sha256) is not str
            or _HEX64.fullmatch(challenge_sha256) is None
            or type(proposal_sha256) is not str
            or _HEX64.fullmatch(proposal_sha256) is None
        ):
            _deny()
        bound = db.execute(text(_LOCK), {"challenge_sha256": challenge_sha256}).mappings().one_or_none()
        if (
            bound is None
            or bound["sponsor_subject"] != sponsor_subject
            or bound["client_id"] != client_id
            or bound["proposal_sha256"] != proposal_sha256
            or bound["sponsor_compressed_pubkey"][2:] != sponsor_subject
            or bound["issued_at"] != bound["bound_at"]
            or bound["consumed_at"] is not None
            or not bound["issued_at"] <= at < bound["expires_at"]
        ):
            _deny()
        locked = locked_browser_subject_in_transaction(
            db,
            generation_id=bound["sponsor_generation_id"],
            expected_subject=sponsor_subject,
            client_id=client_id,
            now=at,
        )
        if locked.generation_id != bound["sponsor_generation_id"] or locked.user_id != bound["issuer_user_id"]:
            _deny()
        return locked.generation_id
    except CanonicalV2IssuerGenerationUnavailable:
        raise
    except Exception:
        raise CanonicalV2IssuerGenerationUnavailable() from None
