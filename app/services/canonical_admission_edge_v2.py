"""Canon V2 admission edge candidate and exact-chain evidence preflight.

This separate V2 schema does not reinterpret CanonicalAdmissionEdgeV1.
Every edge is explicitly PROPOSED. In particular, a complete parent
proposal chain or a plausible caller-supplied chain observation is NEVER
current Full membership or authorization for another admission.

No routes, persistence, migrations, Bitcoin RPC or entitlement writes.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone

from app.services.canonical_admission_proposal_v2 import (
    CanonicalAdmissionProposalV2,
    SponsorBasisV2,
    canonical_admission_proposal_v2_bytes,
    canonical_admission_proposal_v2_sha256,
    validate_canonical_admission_proposal_v2_sources,
)
from app.services.canonical_covenant_funding_set import CanonicalCovenantFundingSet
from app.services.canonical_genesis_record import (
    CanonicalGenesisEvaluation,
    CanonicalGenesisEvaluationState,
)
from app.services.covenant_relation import (
    CovenantRelationEvaluation,
    CovenantRelationObservation,
    covenant_relation_source_sha256,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    trusted_outpoints_from_registration,
)

EDGE_SCHEMA = "hodlxxi.canonical_admission_edge.v2"
EDGE_VERSION = "hodlxxi.canonical_admission_edge_service.v2"
LINEAGE_SCHEMA = "hodlxxi.canonical_sponsor_lineage_preflight.v2"
BOUNDARY = "proposed_only_no_admission_no_current_full"
MAX_DEPTH = 2288
MAX_OBSERVATION_AGE = timedelta(seconds=120)


class InvalidCanonicalAdmissionEdgeV2(ValueError):
    """A V2 candidate edge or complete evidence chain fails closed."""


def _fail(reason: str) -> None:
    raise InvalidCanonicalAdmissionEdgeV2(reason)


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail("invalid_utc_timestamp")
    result = value.astimezone(timezone.utc)
    if result.microsecond:
        _fail("timestamp_precision")
    return result


def _id(value: object) -> None:
    if type(value) is not str:
        _fail("invalid_edge_id")
    try:
        if str(uuid.UUID(value)) != value:
            _fail("invalid_edge_id")
    except (ValueError, TypeError, AttributeError):
        _fail("invalid_edge_id")


def _proposal(value: object) -> CanonicalAdmissionProposalV2:
    if type(value) is not CanonicalAdmissionProposalV2:
        _fail("proposal_type")
    try:
        canonical_admission_proposal_v2_bytes(value)
    except Exception:
        _fail("proposal_invalid")
    return value


@dataclass(frozen=True, slots=True)
class CanonicalAdmissionEdgeV2:
    """The first distinct versioned V2 edge: immutable and not effective."""

    schema: str
    version: str
    authorization_boundary: str
    edge_id: str
    proposal: CanonicalAdmissionProposalV2
    proposal_sha256: str
    created_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.schema) is not str
            or self.schema != EDGE_SCHEMA
            or type(self.version) is not str
            or self.version != EDGE_VERSION
            or type(self.authorization_boundary) is not str
            or self.authorization_boundary != BOUNDARY
        ):
            _fail("v2_edge_schema_or_boundary")
        _id(self.edge_id)
        proposal = _proposal(self.proposal)
        if (
            self.edge_id != proposal.proposal_id
            or self.proposal_sha256 != canonical_admission_proposal_v2_sha256(proposal)
            or _time(self.created_at) != proposal.proposed_at
        ):
            _fail("v2_edge_proposal_binding")

    @property
    def is_effective(self) -> bool:
        return False

    @property
    def grants_full(self) -> bool:
        return False


def create_canonical_admission_edge_v2(
    proposal: CanonicalAdmissionProposalV2,
) -> CanonicalAdmissionEdgeV2:
    proposal = _proposal(proposal)
    return CanonicalAdmissionEdgeV2(
        EDGE_SCHEMA,
        EDGE_VERSION,
        BOUNDARY,
        proposal.proposal_id,
        proposal,
        canonical_admission_proposal_v2_sha256(proposal),
        proposal.proposed_at,
    )


def canonical_admission_edge_v2_bytes(edge: CanonicalAdmissionEdgeV2) -> bytes:
    if type(edge) is not CanonicalAdmissionEdgeV2:
        _fail("edge_type")
    checked = CanonicalAdmissionEdgeV2(*(getattr(edge, f.name) for f in fields(CanonicalAdmissionEdgeV2)))
    data = {
        "schema": checked.schema,
        "version": checked.version,
        "authorization_boundary": checked.authorization_boundary,
        "edge_id": checked.edge_id,
        "proposal": json.loads(canonical_admission_proposal_v2_bytes(checked.proposal)),
        "proposal_sha256": checked.proposal_sha256,
        "created_at": checked.created_at.isoformat().replace("+00:00", "Z"),
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_admission_edge_v2_sha256(edge: CanonicalAdmissionEdgeV2) -> str:
    return hashlib.sha256(canonical_admission_edge_v2_bytes(edge)).hexdigest()


@dataclass(frozen=True, slots=True)
class CanonicalSponsorLineageNodeEvidenceV2:
    """All old and current sources for a single candidate edge.

    Both observations are caller inputs; independent Bitcoin Core origin
    and trusted committed registration must be checked by a later owner.
    """

    edge: CanonicalAdmissionEdgeV2
    registration: TrustedCovenantRegistration
    funding_set: CanonicalCovenantFundingSet
    original_observation: CovenantRelationEvaluation
    current_observation: CovenantRelationEvaluation

    def __post_init__(self) -> None:
        if (
            type(self.edge) is not CanonicalAdmissionEdgeV2
            or type(self.registration) is not TrustedCovenantRegistration
            or type(self.funding_set) is not CanonicalCovenantFundingSet
            or type(self.original_observation) is not CovenantRelationEvaluation
            or type(self.current_observation) is not CovenantRelationEvaluation
        ):
            _fail("lineage_evidence_type")
        canonical_admission_edge_v2_bytes(self.edge)


@dataclass(frozen=True, slots=True)
class CanonicalSponsorLineagePreflightV2:
    schema: str
    authorization_boundary: str
    target_edge_id: str
    target_child_pubkey: str
    target_child_depth: int
    evaluated_at: datetime
    edge_ids_root_to_child: tuple[str, ...]
    edge_sha256_root_to_child: tuple[str, ...]
    current_observation_sha256_root_to_child: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema != LINEAGE_SCHEMA or self.authorization_boundary != BOUNDARY:
            _fail("lineage_schema")
        _id(self.target_edge_id)
        if (
            type(self.target_child_pubkey) is not str
            or len(self.target_child_pubkey) != 66
            or self.target_child_pubkey[:2] not in ("02", "03")
            or any(c not in "0123456789abcdef" for c in self.target_child_pubkey)
        ):
            _fail("lineage_target_key")
        _time(self.evaluated_at)
        if (
            type(self.target_child_depth) is not int
            or not 1 <= self.target_child_depth <= MAX_DEPTH
            or type(self.edge_ids_root_to_child) is not tuple
            or type(self.edge_sha256_root_to_child) is not tuple
            or type(self.current_observation_sha256_root_to_child) is not tuple
            or len(self.edge_ids_root_to_child) != self.target_child_depth
            or len(self.edge_sha256_root_to_child) != self.target_child_depth
            or len(self.current_observation_sha256_root_to_child) != self.target_child_depth
            or self.edge_ids_root_to_child[-1] != self.target_edge_id
        ):
            _fail("lineage_path_binding")
        for edge_id in self.edge_ids_root_to_child:
            _id(edge_id)
        for digest in (
            *self.edge_sha256_root_to_child,
            *self.current_observation_sha256_root_to_child,
        ):
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                _fail("lineage_digest")

    @property
    def grants_full(self) -> bool:
        return False

    @property
    def sponsor_authorized(self) -> bool:
        return False

    @property
    def is_effective(self) -> bool:
        return False


def _checked_current_observation(
    registration: TrustedCovenantRegistration,
    current: CovenantRelationEvaluation,
    *,
    evaluated_at: datetime,
) -> CovenantRelationEvaluation:
    try:
        observation = CovenantRelationEvaluation(*(getattr(current, f.name) for f in fields(CovenantRelationEvaluation)))
        expected = trusted_outpoints_from_registration(registration)
        if (
            observation.subject_pubkey != registration.subject_xonly_pubkey
            or observation.counterparty_pubkey != registration.counterparty_xonly_pubkey
            or not observation.observed_at <= evaluated_at <= observation.observed_at + MAX_OBSERVATION_AGE
            or len(observation.observations) != 2
        ):
            _fail("current_observation_missing_or_stale")
        expected_set = {
            (x.direction, x.txid, x.vout, x.amount_sats, x.script_sha256, x.descriptor_sha256)
            for x in expected
        }
        observed_set = {
            (x.direction, x.txid, x.vout, x.amount_sats, x.script_sha256, x.descriptor_sha256)
            for x in observation.observations
        }
        if (
            observed_set != expected_set
            or any(type(x) is not CovenantRelationObservation or not x.unspent or x.confirmations < 1
                   for x in observation.observations)
        ):
            _fail("current_outpoints_missing_spent_or_mismatched")
        return observation
    except InvalidCanonicalAdmissionEdgeV2:
        raise
    except Exception:
        _fail("current_observation_invalid")


def evaluate_canonical_sponsor_lineage_v2(
    target_edge_id: str,
    *,
    nodes: tuple[CanonicalSponsorLineageNodeEvidenceV2, ...],
    genesis_evaluation: CanonicalGenesisEvaluation,
    evaluated_at: datetime,
) -> CanonicalSponsorLineagePreflightV2:
    """Verify complete exact V2 proposal chain and fresh per-leg observations.

    A historical proposed edge is never equivalent to an effective edge.
    This returns a *structural* preflight, not a Full/sponsor authorization.
    """
    at = _time(evaluated_at)
    _id(target_edge_id)
    if type(nodes) is not tuple or not 1 <= len(nodes) <= MAX_DEPTH:
        _fail("invalid_lineage_population")
    if type(genesis_evaluation) is not CanonicalGenesisEvaluation:
        _fail("genesis_source_type")
    try:
        genesis = CanonicalGenesisEvaluation(
            *(getattr(genesis_evaluation, f.name) for f in fields(CanonicalGenesisEvaluation))
        )
    except Exception:
        _fail("genesis_invalid")
    if genesis.state is not CanonicalGenesisEvaluationState.GENESIS_ACTIVE:
        _fail("genesis_not_active")
    verified = []
    for value in nodes:
        if type(value) is not CanonicalSponsorLineageNodeEvidenceV2:
            _fail("lineage_evidence_type")
        verified.append(
            CanonicalSponsorLineageNodeEvidenceV2(
                value.edge,
                value.registration,
                value.funding_set,
                value.original_observation,
                value.current_observation,
            )
        )
    index = {item.edge.edge_id: item for item in verified}
    if len(index) != len(verified):
        _fail("duplicate_edge_id")
    if target_edge_id not in index:
        _fail("missing_target_edge")
    target = index[target_edge_id].edge.proposal
    if len(verified) != target.script_evidence.child_depth:
        _fail("missing_or_extraneous_ancestry")
    seen_ids = set()
    reversed_path = []
    current = index[target_edge_id]
    while True:
        proposal = current.edge.proposal
        if proposal.proposal_id in seen_ids:
            _fail("lineage_cycle")
        seen_ids.add(proposal.proposal_id)
        reversed_path.append(current)
        if proposal.basis_kind is SponsorBasisV2.GENESIS:
            if proposal.script_evidence.child_depth != 1:
                _fail("root_depth")
            break
        parent = index.get(proposal.basis_record_id)
        if parent is None:
            _fail("missing_parent")
        if (
            proposal.basis_record_sha256 != canonical_admission_proposal_v2_sha256(parent.edge.proposal)
            or proposal.script_evidence.sponsor_depth != parent.edge.proposal.script_evidence.child_depth
            or proposal.script_evidence.sponsor_compressed_pubkey
            != parent.edge.proposal.script_evidence.child_compressed_pubkey
        ):
            _fail("parent_identity_or_digest_mismatch")
        current = parent
    path = tuple(reversed(reversed_path))
    if len(path) != len(nodes):
        _fail("extraneous_or_duplicate_lineage")
    children = set()
    outpoints = set()
    edge_hashes = []
    observation_hashes = []
    for position, item in enumerate(path):
        edge = item.edge
        proposal = edge.proposal
        script = proposal.script_evidence
        basis = genesis if position == 0 else path[position - 1].edge.proposal
        if script.child_depth != position + 1:
            _fail("depth_gap")
        if script.child_xonly_pubkey in children:
            _fail("duplicate_child_in_path")
        children.add(script.child_xonly_pubkey)
        try:
            validate_canonical_admission_proposal_v2_sources(
                proposal,
                registration=item.registration,
                funding_set=item.funding_set,
                sponsor_basis=basis,
                observation=item.original_observation,
                now=proposal.proposed_at,
            )
        except Exception:
            _fail("historical_proposal_sources_invalid")
        current_observation = _checked_current_observation(
            item.registration, item.current_observation, evaluated_at=at
        )
        for leg in proposal.outpoints:
            key = (leg.txid, leg.vout)
            if key in outpoints:
                _fail("outpoint_reused_in_lineage")
            outpoints.add(key)
        if proposal.proposed_at > at:
            _fail("proposal_from_future")
        edge_hashes.append(canonical_admission_edge_v2_sha256(edge))
        observation_hashes.append(covenant_relation_source_sha256(current_observation))
    result = CanonicalSponsorLineagePreflightV2(
        LINEAGE_SCHEMA,
        BOUNDARY,
        target_edge_id,
        target.script_evidence.child_compressed_pubkey,
        target.script_evidence.child_depth,
        at,
        tuple(item.edge.edge_id for item in path),
        tuple(edge_hashes),
        tuple(observation_hashes),
    )
    return result
