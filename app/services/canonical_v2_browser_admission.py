"""Opt-in browser-authenticated Canon V2 PROPOSED admission ingress (Issue #588).

Issue and finalize occur in separate requests from independently verified
OAuth browser generations. Existing PostgreSQL consent and candidate
registries remain the only nonce and UTXO writers. This module does not
grant Full, create an EFFECTIVE edge, or register an HTTP route.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from flask import current_app, has_request_context, request, session as browser_session
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_api_core import canonical_xonly_pubkey
from app.services.canonical_multi_outpoint_admission_proposal_v2 import CanonicalMultiOutpointAdmissionProposalV2
from app.services.canonical_multileg_candidate_registry_v2 import SqlAlchemyCanonicalMultiLegCandidateRegistryV2
from app.services.canonical_multileg_consent_storage_v2 import SqlAlchemyMultiLegConsentLedgerV2
from app.services.current_entitlement_evidence_storage import SqlAlchemyTransactionBoundCurrentFullVerifier
from app.services.oauth_browser_authentication import browser_reference
from app.services.oauth_session_lifecycle import configured_lifecycle
from app.services.canonical_v2_tx_browser_authority import locked_browser_subject_in_transaction

RUNTIME_ENABLED = False


class CanonicalV2BrowserAdmissionUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("canonical v2 authenticated browser admission unavailable")


def _deny() -> None:
    raise CanonicalV2BrowserAdmissionUnavailable()


def _verified_browser_subject(db: Session, *, expected_compressed: str, now: datetime) -> str:
    """Never trust request pubkey/access_level, even a signed Flask cookie alone."""
    try:
        if not has_request_context() or request.method != "POST" or request.query_string:
            _deny()
        lifecycle = configured_lifecycle(current_app)
        if lifecycle is None or request.headers.get("Origin") != lifecycle.browser_origin:
            _deny()
        if request.mimetype != "application/json":
            _deny()
        if type(browser_session.get("login_method")) is not str or browser_session.get("login_method") not in (
            "legacy",
            "nostr",
        ):
            _deny()
        stored = browser_session.get("logged_in_pubkey")
        if type(stored) is not str:
            _deny()
        cookie_subject = canonical_xonly_pubkey(stored)
        expected = canonical_xonly_pubkey(expected_compressed)
        if cookie_subject != expected or expected_compressed[:2] not in ("02", "03") or len(expected_compressed) != 66:
            _deny()
        # Read User, OAuthClient and this exact OAuthBrowserGeneration under
        # FOR UPDATE in the SAME caller-owned PostgreSQL admission transaction.
        # Logout/replacement must wait until the candidate/nonce commits.
        locked = locked_browser_subject_in_transaction(
            db,
            generation_id=browser_reference(),
            expected_subject=expected,
            client_id=lifecycle.client_id,
            now=now,
        )
        if locked.subject != expected:
            _deny()
        return locked.subject
    except CanonicalV2BrowserAdmissionUnavailable:
        raise
    except Exception:
        raise CanonicalV2BrowserAdmissionUnavailable() from None


def _time(clock: Callable[[], datetime]) -> datetime:
    try:
        at = clock()
        if type(at) is not datetime or at.tzinfo is None or at.utcoffset() is None:
            _deny()
        at = at.astimezone(timezone.utc)
        if at.microsecond:
            _deny()
        return at
    except CanonicalV2BrowserAdmissionUnavailable:
        raise
    except Exception:
        raise CanonicalV2BrowserAdmissionUnavailable() from None


def _effective_parent(session: Session, proposal: CanonicalMultiOutpointAdmissionProposalV2) -> None:
    policy = proposal.mirror.script_evidence
    if policy.sponsor_depth == 0:
        return
    # A candidate parent alone is NEVER sponsorship authority. Strict
    # two-output legacy parents need a separate canonical migration policy.
    try:
        row = session.execute(
            text(
                "SELECT proposal_id FROM public.canonical_multileg_effective_edges_v2 "
                "WHERE proposal_id=:parent AND child_xonly_pubkey=:sponsor "
                "AND child_depth=:depth FOR SHARE"
            ),
            {
                "parent": proposal.basis_record_id,
                "sponsor": policy.sponsor_xonly_pubkey,
                "depth": policy.sponsor_depth,
            },
        ).scalar_one_or_none()
        if row != proposal.basis_record_id:
            _deny()
    except CanonicalV2BrowserAdmissionUnavailable:
        raise
    except Exception:
        raise CanonicalV2BrowserAdmissionUnavailable() from None


def issue_from_verified_sponsor_browser_in_transaction(
    session: Session, proposal: CanonicalMultiOutpointAdmissionProposalV2, *, clock: Callable[[], datetime]
):
    """Sponsor browser: lock Current Full, then write DB-issued one-use nonce."""
    try:
        if type(proposal) is not CanonicalMultiOutpointAdmissionProposalV2 or not session.in_transaction():
            _deny()
        policy = proposal.mirror.script_evidence
        at = _time(clock)
        _verified_browser_subject(session, expected_compressed=policy.sponsor_compressed_pubkey, now=at)
        verified = SqlAlchemyTransactionBoundCurrentFullVerifier(session).verify_with_evidence_in_transaction(
            policy.sponsor_xonly_pubkey, now=at
        )
        if verified.verified_entitlement.subject != policy.sponsor_xonly_pubkey:
            _deny()
        _effective_parent(session, proposal)
        return SqlAlchemyMultiLegConsentLedgerV2(session, clock=clock).issue(
            proposal, authenticated_sponsor_pubkey=policy.sponsor_compressed_pubkey
        )
    except CanonicalV2BrowserAdmissionUnavailable:
        raise
    except Exception:
        raise CanonicalV2BrowserAdmissionUnavailable() from None


def reserve_from_verified_child_browser_in_transaction(
    session: Session,
    proposal: CanonicalMultiOutpointAdmissionProposalV2,
    *,
    sponsor_basis: object,
    challenge_sha256: str,
    sponsor_signature: str,
    child_signature: str,
    clock: Callable[[], datetime],
):
    """Child browser: verify its own generation, then Core + sponsor + nonce.

    Pending ONLY: the resulting candidate cannot grant Current Full.
    Caller MUST roll back the transaction on every exception.
    """
    try:
        if type(proposal) is not CanonicalMultiOutpointAdmissionProposalV2 or not session.in_transaction():
            _deny()
        policy = proposal.mirror.script_evidence
        at = _time(clock)
        _verified_browser_subject(session, expected_compressed=policy.child_compressed_pubkey, now=at)
        _effective_parent(session, proposal)
        return SqlAlchemyCanonicalMultiLegCandidateRegistryV2(
            session, clock=clock
        ).reserve_candidate_from_server_in_transaction(
            proposal,
            sponsor_basis=sponsor_basis,
            authenticated_sponsor_pubkey=policy.sponsor_compressed_pubkey,
            authenticated_child_pubkey=policy.child_compressed_pubkey,
            challenge_sha256=challenge_sha256,
            sponsor_signature=sponsor_signature,
            child_signature=child_signature,
        )
    except CanonicalV2BrowserAdmissionUnavailable:
        raise
    except Exception:
        raise CanonicalV2BrowserAdmissionUnavailable() from None
