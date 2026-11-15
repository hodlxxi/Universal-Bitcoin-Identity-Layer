"""Issue #588: one-transaction browser generation proof for proposed admissions.

The existing OAuth lifecycle's browser_subject() uses its own transaction.
This guarded reader instead locks the User, OAuth client and exact browser
generation in the SAME PostgreSQL transaction owned by the caller, so
revocation, replacement and user/client deactivation cannot interleave
between the identity check and the candidate/nonce commit.

This grants NO EFFECTIVE or Current Full authority and registers no route.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth_api_core import canonical_xonly_pubkey
from app.models import OAuthBrowserGeneration, OAuthClient, User

RUNTIME_ENABLED = False
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class CanonicalV2TransactionBrowserUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("canonical v2 transaction browser identity unavailable")


@dataclass(frozen=True, slots=True)
class LockedCanonicalV2BrowserSubject:
    """Exact locked generation; only valid until caller transaction ends."""

    subject: str
    generation_id: str
    user_id: str
    client_id: str

    @property
    def grants_full(self) -> bool:
        return False


def _deny() -> None:
    raise CanonicalV2TransactionBrowserUnavailable()


def _timestamp(value: object) -> datetime:
    if type(value) is not datetime:
        _deny()
    if value.tzinfo is None:
        # OAuth generation SQL DateTime columns are UTC-naive.
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def locked_browser_subject_in_transaction(
    db: Session,
    *,
    generation_id: str,
    expected_subject: str,
    client_id: str,
    now: datetime,
) -> LockedCanonicalV2BrowserSubject:
    """Re-read exact, active signed-login generation with row locks.

    Lock order matches OAuth session lifecycle: User -> Client -> Browser.
    Never pass a caller-chosen client_id or generation_id from JSON; both
    must come from configured lifecycle and server-signed cookie storage.
    """
    try:
        if (
            not isinstance(db, Session)
            or db.in_transaction() is not True
            or db.get_transaction() is None
            or db.get_transaction().is_active is not True
            or db.get_bind().dialect.name != "postgresql"
            or type(generation_id) is not str
            or _HEX64.fullmatch(generation_id) is None
            or type(client_id) is not str
            or not 1 <= len(client_id) <= 255
            or client_id.strip() != client_id
            or type(expected_subject) is not str
            or canonical_xonly_pubkey(expected_subject) != expected_subject
            or type(now) is not datetime
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            _deny()
        at = now.astimezone(timezone.utc)
        if at.microsecond:
            _deny()
        if db.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed":
            _deny()

        # Find ID without trusting generation.subject; lock the exact User
        # first, then the configured OAuthClient, then that user's generation.
        user = db.execute(select(User).where(User.pubkey == expected_subject).with_for_update()).scalar_one_or_none()
        if user is None or user.is_active is not True or user.pubkey != expected_subject:
            _deny()
        client = db.execute(
            select(OAuthClient).where(OAuthClient.client_id == client_id).with_for_update()
        ).scalar_one_or_none()
        if client is None or client.is_active is not True:
            _deny()
        generation = db.execute(
            select(OAuthBrowserGeneration)
            .where(OAuthBrowserGeneration.generation_id == generation_id)
            .with_for_update()
        ).scalar_one_or_none()
        if (
            generation is None
            or generation.is_active is not True
            or generation.user_id != user.id
            or generation.client_id != client_id
            or generation.subject != expected_subject
            or not _timestamp(generation.created_at) <= at < _timestamp(generation.expires_at)
        ):
            _deny()
        return LockedCanonicalV2BrowserSubject(
            subject=expected_subject,
            generation_id=generation_id,
            user_id=user.id,
            client_id=client_id,
        )
    except CanonicalV2TransactionBrowserUnavailable:
        raise
    except Exception:
        raise CanonicalV2TransactionBrowserUnavailable() from None
