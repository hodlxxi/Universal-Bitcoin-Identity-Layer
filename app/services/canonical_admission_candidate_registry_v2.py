"""Dormant, transaction-bound Canon V2 CANDIDATE intake. Never Full.

One caller-owned PostgreSQL transaction must contain current sponsor Full
verification, nonce consumption, and both candidate outpoint inserts.
No method commits, publishes identity/Full, or activates an admission.
The caller is responsible for authenticating the session and rolling back
on any failure.

The caller-supplied Bitcoin observations and genesis evaluation are NOT
independent trusted state. No current-ancestor admission authority is
implemented. Therefore a candidate is NOT an effective edge.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.services.canonical_admission_consent_challenge_storage_v2 import (
    SqlAlchemyCanonicalAdmissionChallengeLedgerV2,
)
from app.services.canonical_admission_edge_v2 import (
    CanonicalAdmissionEdgeV2,
    CanonicalSponsorLineageNodeEvidenceV2,
    canonical_admission_edge_v2_sha256,
    evaluate_canonical_sponsor_lineage_v2,
)
from app.services.canonical_admission_proposal_v2 import (
    SponsorBasisV2,
    canonical_admission_proposal_v2_sha256,
)
from app.services.canonical_genesis_record import CanonicalGenesisEvaluation
from app.services.current_entitlement_evidence_storage import (
    SqlAlchemyTransactionBoundCurrentFullVerifier,
)

INSERT_CANDIDATE = """
INSERT INTO public.canonical_admission_candidates_v2 (
    edge_id, proposal_sha256, edge_sha256,
    sponsor_compressed_pubkey, sponsor_xonly_pubkey,
    child_compressed_pubkey, child_xonly_pubkey,
    sponsor_depth, child_depth, basis_kind,
    parent_edge_id, parent_proposal_sha256,
    registration_id, registration_sha256,
    funding_set_id, funding_set_sha256,
    challenge_sha256, verification_sha256,
    sponsor_full_proof_id, sponsor_full_evidence_id,
    sponsor_full_evidence_sha256, sponsor_full_valid_until,
    current_lineage_observed_at, candidate_created_at
)
SELECT
    :edge_id, :proposal_sha256, :edge_sha256,
    :sponsor_compressed_pubkey, :sponsor_xonly_pubkey,
    :child_compressed_pubkey, :child_xonly_pubkey,
    :sponsor_depth, :child_depth, :basis_kind,
    :parent_edge_id, :parent_proposal_sha256,
    :registration_id, :registration_sha256,
    :funding_set_id, :funding_set_sha256,
    :challenge_sha256, :verification_sha256,
    :sponsor_full_proof_id, :sponsor_full_evidence_id,
    :sponsor_full_evidence_sha256, :sponsor_full_valid_until,
    :current_lineage_observed_at, :candidate_created_at
FROM public.canonical_admission_consent_challenges_v2 AS consumed
WHERE consumed.challenge_sha256 = :challenge_sha256
  AND consumed.proposal_sha256 = :proposal_sha256
  AND consumed.verification_sha256 = :verification_sha256
  AND consumed.consumed_at IS NOT NULL
RETURNING edge_id
"""

INSERT_OUTPOINT = """
INSERT INTO public.canonical_admission_candidate_outpoints_v2
(edge_id, leg_order, txid, vout, amount_sats, witness_script_sha256)
VALUES (:edge_id, :leg_order, :txid, :vout, :amount_sats, :witness_script_sha256)
RETURNING leg_order
"""


class CanonicalAdmissionCandidateUnavailableV2(RuntimeError):
    """The exact, proposed-only transaction cannot be established."""


@dataclass(frozen=True, slots=True)
class PendingCanonicalAdmissionCandidateV2:
    edge_id: str
    edge_sha256: str
    proposal_sha256: str
    challenge_sha256: str
    verification_sha256: str
    sponsor_full_proof_id: str

    @property
    def grants_full(self) -> bool:
        return False

    @property
    def is_effective(self) -> bool:
        return False

    @property
    def durable(self) -> bool:
        """A method return is not a committed transaction."""
        return False


class SqlAlchemyCanonicalAdmissionCandidateRegistryV2:
    """Fail-closed transaction composition; no runtime wiring or grants."""

    def __init__(self, session: Session, *, clock: Callable[[], datetime]) -> None:
        if session is None or not callable(getattr(session, "execute", None)) or not callable(clock):
            raise CanonicalAdmissionCandidateUnavailableV2("session_or_clock_required")
        self._session = session
        self._clock = clock

    def _current_time(self) -> datetime:
        now = self._clock()
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            raise CanonicalAdmissionCandidateUnavailableV2("valid_clock_required")
        now = now.astimezone(timezone.utc)
        if now.microsecond:
            raise CanonicalAdmissionCandidateUnavailableV2("clock_must_have_second_precision")
        return now

    def _require_transaction(self) -> None:
        try:
            session = self._session
            if (
                not session.in_transaction()
                or session.get_bind().dialect.name != "postgresql"
                or session.get_transaction() is None
                or not session.get_transaction().is_active
                or session.new
                or session.dirty
                or session.deleted
                or session.execute(text("SHOW transaction_isolation")).scalar_one() != "read committed"
            ):
                raise ValueError
        except Exception:
            raise CanonicalAdmissionCandidateUnavailableV2("read_committed_postgres_transaction_required") from None

    def reserve_candidate_in_transaction(
        self,
        edge: CanonicalAdmissionEdgeV2,
        *,
        nodes: tuple[CanonicalSponsorLineageNodeEvidenceV2, ...],
        genesis_evaluation: CanonicalGenesisEvaluation,
        authenticated_sponsor_pubkey: str,
        authenticated_child_pubkey: str,
        challenge_sha256: str,
        sponsor_signature: str,
        child_signature: str,
        bitcoin_message_rpc: object,
    ) -> PendingCanonicalAdmissionCandidateV2:
        """Reserve one signed candidate and its exact UTXOs in a caller transaction.

        Strong at-this-transaction current-Full sponsor proof is evaluated
        from locked Postgres rows, never accepted as a caller-supplied digest.
        Lineage/Bitcoin observations are *typed caller inputs* and do not
        establish effective current ancestor registration. No Full results.
        """
        self._require_transaction()
        now = self._current_time()
        if type(edge) is not CanonicalAdmissionEdgeV2:
            raise CanonicalAdmissionCandidateUnavailableV2("edge_type")
        proposal = edge.proposal
        policy = proposal.script_evidence
        if (
            type(authenticated_sponsor_pubkey) is not str
            or authenticated_sponsor_pubkey != policy.sponsor_compressed_pubkey
            or type(authenticated_child_pubkey) is not str
            or authenticated_child_pubkey != policy.child_compressed_pubkey
        ):
            raise CanonicalAdmissionCandidateUnavailableV2("session_identity_mismatch")

        try:
            preflight = evaluate_canonical_sponsor_lineage_v2(
                edge.edge_id,
                nodes=nodes,
                genesis_evaluation=genesis_evaluation,
                evaluated_at=now,
            )
            if (
                preflight.target_edge_id != edge.edge_id
                or preflight.target_child_pubkey != policy.child_compressed_pubkey
                or preflight.edge_sha256_root_to_child[-1] != canonical_admission_edge_v2_sha256(edge)
            ):
                raise ValueError("lineage_target_mismatch")
        except Exception:
            raise CanonicalAdmissionCandidateUnavailableV2("source_lineage_not_qualified") from None

        # Do not accept a detached VerifiedCurrentFullEntitlement, a spoofed
        # proof_id, or a child with only a PARENT_PROPOSAL as authority.
        try:
            current = SqlAlchemyTransactionBoundCurrentFullVerifier(
                self._session
            ).verify_with_evidence_in_transaction(policy.sponsor_xonly_pubkey, now=now)
            full_proof = current.verified_entitlement
            if full_proof.subject != policy.sponsor_xonly_pubkey or not now < full_proof.expires_at:
                raise ValueError
        except Exception:
            raise CanonicalAdmissionCandidateUnavailableV2("sponsor_current_full_unavailable") from None

        # This reuses the exact issued challenge from the database, verifies
        # both role-specific BTC signatures and consumes the nonce in the
        # *same* caller-owned transaction as the candidate/outpoint inserts.
        try:
            consumed = SqlAlchemyCanonicalAdmissionChallengeLedgerV2(
                self._session, clock=self._clock
            ).consume(
                proposal,
                challenge_sha256=challenge_sha256,
                authenticated_child_pubkey=authenticated_child_pubkey,
                sponsor_signature=sponsor_signature,
                child_signature=child_signature,
                rpc=bitcoin_message_rpc,
            )
        except Exception:
            raise CanonicalAdmissionCandidateUnavailableV2("consent_not_consumable") from None

        basis_is_root = proposal.basis_kind is SponsorBasisV2.GENESIS
        parent_id = None if basis_is_root else proposal.basis_record_id
        parent_sha = None if basis_is_root else proposal.basis_record_sha256
        params = {
            "edge_id": edge.edge_id,
            "proposal_sha256": canonical_admission_proposal_v2_sha256(proposal),
            "edge_sha256": canonical_admission_edge_v2_sha256(edge),
            "sponsor_compressed_pubkey": policy.sponsor_compressed_pubkey,
            "sponsor_xonly_pubkey": policy.sponsor_xonly_pubkey,
            "child_compressed_pubkey": policy.child_compressed_pubkey,
            "child_xonly_pubkey": policy.child_xonly_pubkey,
            "sponsor_depth": policy.sponsor_depth,
            "child_depth": policy.child_depth,
            "basis_kind": proposal.basis_kind.value,
            "parent_edge_id": parent_id,
            "parent_proposal_sha256": parent_sha,
            "registration_id": proposal.registration_id,
            "registration_sha256": proposal.registration_sha256,
            "funding_set_id": proposal.funding_set_id,
            "funding_set_sha256": proposal.funding_set_sha256,
            "challenge_sha256": consumed.challenge_sha256,
            "verification_sha256": consumed.verification_sha256,
            "sponsor_full_proof_id": full_proof.proof_id,
            "sponsor_full_evidence_id": current.evidence_id,
            "sponsor_full_evidence_sha256": current.source_evidence_sha256,
            "sponsor_full_valid_until": full_proof.expires_at,
            "current_lineage_observed_at": min(x.current_observation.observed_at for x in nodes),
            "candidate_created_at": now,
        }
        try:
            added = self._session.execute(text(INSERT_CANDIDATE), params).scalar_one_or_none()
            if added != edge.edge_id:
                raise ValueError("consumed_challenge_not_matched")
            for outpoint in proposal.outpoints:
                leg = outpoint.leg_order
                inserted = self._session.execute(
                    text(INSERT_OUTPOINT),
                    {
                        "edge_id": edge.edge_id,
                        "leg_order": leg,
                        "txid": outpoint.txid,
                        "vout": outpoint.vout,
                        "amount_sats": outpoint.amount_sats,
                        "witness_script_sha256": outpoint.witness_script_sha256,
                    },
                ).scalar_one_or_none()
                if inserted != leg:
                    raise ValueError("outpoint_insert_unconfirmed")
        except (SQLAlchemyError, ValueError):
            # The caller MUST roll back this transaction (including consumed
            # nonce). A partial return is never treated as admission.
            raise CanonicalAdmissionCandidateUnavailableV2("candidate_conflict_or_write_failed") from None
        return PendingCanonicalAdmissionCandidateV2(
            edge.edge_id,
            params["edge_sha256"],
            params["proposal_sha256"],
            consumed.challenge_sha256,
            consumed.verification_sha256,
            full_proof.proof_id,
        )
