"""Dormant atomic Canon V2 multi-UTXO candidate transaction (no Full grant).

This service composes:
  (1) exact source-bound multioutpoint proposal/observation,
  (2) transaction-bound *current sponsor Full* verifier,
  (3) the issued and one-use multioutpoint dual-signature challenge,
  (4) immutable candidate and ALL mirrored outpoint claims.

All operate on the caller's existing PostgreSQL transaction. The caller
MUST roll back on failure and MUST provide authenticated session identities,
an authoritative Bitcoin observation, and effective ancestor provenance.
This module does not source those independently: proposals and saved
candidate rows are NEVER current effective admission/Full authority.
No routes, deployment, cancellation or entitlement writes are enabled.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.services.canonical_admission_proposal_v2 import SponsorBasisV2
from app.services.canonical_multi_outpoint_admission_proposal_v2 import (
    CanonicalMultiOutpointAdmissionProposalV2,
    canonical_multi_outpoint_admission_proposal_v2_bytes,
    canonical_multi_outpoint_admission_proposal_v2_sha256,
    validate_canonical_multi_outpoint_admission_proposal_v2_sources,
)
from app.services.canonical_multileg_consent_storage_v2 import (
    SqlAlchemyMultiLegConsentLedgerV2,
)
from app.services.covenant_relation import CovenantDirection, CovenantRelationEvaluation
from app.services.current_entitlement_evidence_storage import (
    SqlAlchemyTransactionBoundCurrentFullVerifier,
)

RUNTIME_ENABLED = False

INSERT_CANDIDATE = """
INSERT INTO public.canonical_multileg_admission_candidates_v2 (
    proposal_id, proposal_sha256, mirror_sha256,
    sponsor_compressed_pubkey, sponsor_xonly_pubkey,
    child_compressed_pubkey, child_xonly_pubkey,
    sponsor_depth, child_depth, basis_kind, basis_record_id, basis_record_sha256,
    parent_proposal_id, parent_proposal_sha256, challenge_sha256, verification_sha256,
    sponsor_full_proof_id, sponsor_full_evidence_id, sponsor_full_evidence_sha256,
    sponsor_full_valid_until, observation_sha256, observation_block_height,
    snapshot_observed_at, earlier_sats, later_sats, trust_ceiling_sats,
    outpoint_count, candidate_created_at
)
SELECT
    :proposal_id, :proposal_sha256, :mirror_sha256,
    :sponsor_compressed_pubkey, :sponsor_xonly_pubkey,
    :child_compressed_pubkey, :child_xonly_pubkey,
    :sponsor_depth, :child_depth, :basis_kind, :basis_record_id, :basis_record_sha256,
    :parent_proposal_id, :parent_proposal_sha256, :challenge_sha256, :verification_sha256,
    :sponsor_full_proof_id, :sponsor_full_evidence_id, :sponsor_full_evidence_sha256,
    :sponsor_full_valid_until, :observation_sha256, :observation_block_height,
    :snapshot_observed_at, :earlier_sats, :later_sats, :trust_ceiling_sats,
    :outpoint_count, :candidate_created_at
FROM public.canonical_multileg_consent_challenges_v2 AS n
WHERE n.challenge_sha256 = :challenge_sha256
  AND n.proposal_schema = 'hodlxxi.canonical_multi_outpoint_admission_proposal.v2'
  AND n.proposal_sha256 = :proposal_sha256
  AND n.verification_sha256 = :verification_sha256
  AND n.consumed_at IS NOT NULL
  AND n.issuer_session_pubkey = :sponsor_compressed_pubkey
  AND n.child_compressed_pubkey = :child_compressed_pubkey
RETURNING proposal_id
"""

INSERT_OUTPOINT = """
INSERT INTO public.canonical_multileg_candidate_outpoints_v2 (
    proposal_id, leg_order, txid, vout, amount_sats, script_pubkey_sha256, descriptor_sha256
) VALUES (
    :proposal_id, :leg_order, :txid, :vout, :amount_sats, :script_pubkey_sha256, :descriptor_sha256
)
RETURNING txid, vout
"""

LOCK_PARENT = """
SELECT candidate.proposal_sha256, candidate.child_compressed_pubkey,
       candidate.child_depth
FROM public.canonical_multileg_admission_candidates_v2 AS candidate
JOIN public.canonical_multileg_live_child_claims_v2 AS reservation
  ON reservation.proposal_id = candidate.proposal_id
 AND reservation.child_xonly_pubkey = candidate.child_xonly_pubkey
WHERE candidate.proposal_id = :parent_id
  AND candidate.proposal_sha256 = :parent_sha
FOR SHARE OF candidate, reservation
"""


class CanonicalMultiLegCandidateUnavailableV2(RuntimeError):
    """No safe, complete pending multileg intake can be constructed."""


@dataclass(frozen=True, slots=True)
class PendingCanonicalMultiLegCandidateV2:
    proposal_id: str
    proposal_sha256: str
    challenge_sha256: str
    verification_sha256: str
    outpoint_count: int
    earlier_sats: int
    later_sats: int
    trust_ceiling_sats: int
    sponsor_full_proof_id: str

    @property
    def durable(self) -> bool:
        """Database commit and deferred completeness trigger have not run."""
        return False

    @property
    def grants_full(self) -> bool:
        return False

    @property
    def is_effective(self) -> bool:
        return False


class SqlAlchemyCanonicalMultiLegCandidateRegistryV2:
    """Compose exact 3+2 (or N+M) candidate intake in ONE Postgres transaction."""

    def __init__(self, session: Session, *, clock: Callable[[], datetime]) -> None:
        if session is None or not callable(getattr(session, "execute", None)) or not callable(clock):
            raise CanonicalMultiLegCandidateUnavailableV2("session_or_clock_required")
        self._session = session
        self._clock = clock

    def _guard(self) -> datetime:
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
                raise ValueError("transaction")
        except Exception:
            raise CanonicalMultiLegCandidateUnavailableV2("read_committed_pg_transaction_required") from None
        now = self._clock()
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            raise CanonicalMultiLegCandidateUnavailableV2("clock_required")
        now = now.astimezone(timezone.utc)
        if now.microsecond:
            raise CanonicalMultiLegCandidateUnavailableV2("second_precision_required")
        return now

    def reserve_candidate_in_transaction(
        self,
        proposal: CanonicalMultiOutpointAdmissionProposalV2,
        *,
        sponsor_basis: object,
        current_observation: CovenantRelationEvaluation,
        authenticated_sponsor_pubkey: str,
        authenticated_child_pubkey: str,
        challenge_sha256: str,
        sponsor_signature: str,
        child_signature: str,
        bitcoin_message_rpc: object,
    ) -> PendingCanonicalMultiLegCandidateV2:
        """Write a PROPOSED-only candidate; requires external trusted origins.

        The original registration/Bitcoin provenance and authenticated
        session are NOT established here. The parent must be a recorded
        multileg *candidate*, which still is NOT an effective admission.
        Strict 2-UTXO V2 parents are deliberately unsupported by this
        standalone schema, until a single authoritative cross-version
        effective registry exists.
        """
        now = self._guard()
        if type(proposal) is not CanonicalMultiOutpointAdmissionProposalV2:
            raise CanonicalMultiLegCandidateUnavailableV2("multileg_proposal_required")
        try:
            canonical_multi_outpoint_admission_proposal_v2_bytes(proposal)
            mirror = proposal.mirror
            policy = mirror.script_evidence
            if (
                type(authenticated_sponsor_pubkey) is not str
                or authenticated_sponsor_pubkey != policy.sponsor_compressed_pubkey
                or type(authenticated_child_pubkey) is not str
                or authenticated_child_pubkey != policy.child_compressed_pubkey
            ):
                raise CanonicalMultiLegCandidateUnavailableV2("session_identity_mismatch")
            validate_canonical_multi_outpoint_admission_proposal_v2_sources(
                proposal,
                mirror=mirror,
                observation=current_observation,
                sponsor_basis=sponsor_basis,
                now=now,
            )
        except CanonicalMultiLegCandidateUnavailableV2:
            raise
        except Exception:
            raise CanonicalMultiLegCandidateUnavailableV2("multileg_source_not_qualified") from None

        parent_id = None
        parent_sha = None
        if policy.sponsor_depth > 0:
            if type(sponsor_basis) is not CanonicalMultiOutpointAdmissionProposalV2:
                raise CanonicalMultiLegCandidateUnavailableV2("parent_must_be_registered_multileg_candidate")
            parent_id = proposal.basis_record_id
            parent_sha = proposal.basis_record_sha256
            try:
                row = (
                    self._session.execute(text(LOCK_PARENT), {"parent_id": parent_id, "parent_sha": parent_sha})
                    .mappings()
                    .one_or_none()
                )
            except SQLAlchemyError:
                raise CanonicalMultiLegCandidateUnavailableV2("parent_lock_unavailable") from None
            if (
                row is None
                or row["child_compressed_pubkey"] != policy.sponsor_compressed_pubkey
                or row["child_depth"] != policy.sponsor_depth
            ):
                raise CanonicalMultiLegCandidateUnavailableV2("parent_candidate_not_matched")

        # Independent Current-Full proof is obtained from locked Postgres
        # authority, not from any proposed parent or caller-supplied proof.
        try:
            current = SqlAlchemyTransactionBoundCurrentFullVerifier(self._session).verify_with_evidence_in_transaction(
                policy.sponsor_xonly_pubkey, now=now
            )
            proof = current.verified_entitlement
            if proof.subject != policy.sponsor_xonly_pubkey or not now < proof.expires_at:
                raise ValueError("current sponsor Full missing")
        except Exception:
            raise CanonicalMultiLegCandidateUnavailableV2("current_sponsor_full_required") from None

        # The DB-backed nonce is consumed on this exact caller-owned
        # transaction: on any later INSERT conflict the caller rolls back
        # both the nonce and every partial candidate/outpoint row.
        try:
            consumed = SqlAlchemyMultiLegConsentLedgerV2(self._session, clock=self._clock).consume(
                proposal,
                challenge_sha256=challenge_sha256,
                authenticated_child_pubkey=authenticated_child_pubkey,
                sponsor_signature=sponsor_signature,
                child_signature=child_signature,
                rpc=bitcoin_message_rpc,
            )
        except Exception:
            raise CanonicalMultiLegCandidateUnavailableV2("consent_not_consumable") from None

        proposal_hash = canonical_multi_outpoint_admission_proposal_v2_sha256(proposal)
        snapshot = proposal.snapshot
        params = {
            "proposal_id": proposal.proposal_id,
            "proposal_sha256": proposal_hash,
            "mirror_sha256": proposal.mirror_sha256,
            "sponsor_compressed_pubkey": policy.sponsor_compressed_pubkey,
            "sponsor_xonly_pubkey": policy.sponsor_xonly_pubkey,
            "child_compressed_pubkey": policy.child_compressed_pubkey,
            "child_xonly_pubkey": policy.child_xonly_pubkey,
            "sponsor_depth": policy.sponsor_depth,
            "child_depth": policy.child_depth,
            "basis_kind": proposal.basis_kind.value,
            "basis_record_id": proposal.basis_record_id,
            "basis_record_sha256": proposal.basis_record_sha256,
            "parent_proposal_id": parent_id,
            "parent_proposal_sha256": parent_sha,
            "challenge_sha256": consumed.challenge_sha256,
            "verification_sha256": consumed.verification_sha256,
            "sponsor_full_proof_id": proof.proof_id,
            "sponsor_full_evidence_id": current.evidence_id,
            "sponsor_full_evidence_sha256": current.source_evidence_sha256,
            "sponsor_full_valid_until": proof.expires_at,
            "observation_sha256": snapshot.observation_sha256,
            "observation_block_height": snapshot.observed_block_height,
            "snapshot_observed_at": snapshot.observed_at,
            "earlier_sats": snapshot.earlier_sats,
            "later_sats": snapshot.later_sats,
            "trust_ceiling_sats": snapshot.trust_ceiling_sats,
            "outpoint_count": snapshot.outpoint_count,
            "candidate_created_at": now,
        }
        try:
            inserted = self._session.execute(text(INSERT_CANDIDATE), params).scalar_one_or_none()
            if inserted != proposal.proposal_id:
                raise ValueError("nonce_verification_uncommitted")
            for utxo in mirror.outpoints:
                leg = "earlier" if utxo.direction is CovenantDirection.OUTGOING else "later"
                result = self._session.execute(
                    text(INSERT_OUTPOINT),
                    {
                        "proposal_id": proposal.proposal_id,
                        "leg_order": leg,
                        "txid": utxo.txid,
                        "vout": utxo.vout,
                        "amount_sats": utxo.amount_sats,
                        "script_pubkey_sha256": utxo.script_sha256,
                        "descriptor_sha256": utxo.descriptor_sha256,
                    },
                ).one_or_none()
                if result is None or result.txid != utxo.txid or result.vout != utxo.vout:
                    raise ValueError("outpoint_insert_incomplete")
        except (SQLAlchemyError, ValueError):
            raise CanonicalMultiLegCandidateUnavailableV2("candidate_conflict_or_incomplete") from None
        return PendingCanonicalMultiLegCandidateV2(
            proposal.proposal_id,
            proposal_hash,
            consumed.challenge_sha256,
            consumed.verification_sha256,
            snapshot.outpoint_count,
            snapshot.earlier_sats,
            snapshot.later_sats,
            snapshot.trust_ceiling_sats,
            proof.proof_id,
        )
