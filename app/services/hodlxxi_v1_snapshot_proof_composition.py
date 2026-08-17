"""Pure local HODLXXI Network Profile V1 snapshot-proof composition.

The caller supplies every source, observation, and timestamp.  This module does
no lookup, I/O, signing, publication, entitlement mutation, or authorization of
a runtime action.  Its output is an unsigned local evaluation only.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import json

from app.services.canonical_admission_edge import (
    GRAPH_ID,
    HUMAN_PROFILE,
    NETWORK,
    CanonicalAdmissionEdge,
    canonical_admission_edge_bytes,
    canonical_admission_edge_sha256,
    parse_canonical_admission_edge,
)
from app.services.canonical_genesis_record import (
    PARTICIPANT_ID,
    CanonicalGenesisRecord,
    canonical_genesis_record_bytes,
    canonical_genesis_record_sha256,
    parse_canonical_genesis_record,
)
from app.services.canonical_sponsor_lineage import CanonicalSponsorLineageEdgeEvidence
from app.services.canonical_crt_authorization_proof import (
    CanonicalCrtAuthorizationProof,
    canonical_crt_authorization_proof_bytes,
    canonical_crt_authorization_proof_sha256,
    parse_canonical_crt_authorization_proof,
)
from app.services.canonical_crt_authorization_proof_resolver import (
    resolve_canonical_crt_authorization_proof_from_snapshot,
)
from app.services.covenant_relation import (
    CovenantRelationEvaluation,
    covenant_relation_source_sha256,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    canonical_trusted_registration_bytes,
    trusted_outpoints_from_registration,
    trusted_registration_sha256,
)
from app.services.trusted_crt_authorization_source_plan import (
    TrustedCrtAuthorizationSourcePlan,
    TrustedCrtLineageSource,
    TrustedCrtSubjectKind,
    trusted_crt_authorization_source_plan_manifest_sha256,
)
from app.services.trusted_crt_bitcoin_observation_snapshot import (
    TrustedCrtBitcoinObservationResolution,
    TrustedCrtBitcoinObservationSnapshot,
    TrustedCrtBitcoinObservationState,
    TrustedCrtObservedLineageRelation,
    trusted_crt_bitcoin_observation_snapshot_sha256,
    trusted_crt_outpoint_manifest_sha256,
)

SCHEMA = "hodlxxi.v1.local_snapshot_proof_composition.v1"
COMPOSER_VERSION = "hodlxxi.v1.local_snapshot_proof_composer.v1"
AUTHORITY_STATE = "unsigned_local_evaluation"
STATUS = (
    "IMPLEMENTED_DORMANT",
    "HODLXXI_V1_PROFILE_SPECIFIC",
    "LOCAL_UNSIGNED_SNAPSHOT_COMPOSITION",
    "SOURCE_PLAN_BOUND",
    "BITCOIN_SNAPSHOT_BOUND",
    "PR6_11_EVIDENCE_COMPOSITION",
    "PR6_16_PROOF_RESOLUTION",
    "NOT_PORTABLE_AUTHORITY",
    "NOT_SIGNED",
    "NOT_ATTESTED",
    "NOT_REPLICA_PROTOCOL",
    "NOT_FORK_DETECTION",
    "NOT_LIVE_SOURCE_LOOKUP",
    "NOT_RUNTIME_ENTITLEMENT",
    "NOT_RUNTIME_AUTHORIZATION",
    "NOT_DEPLOYED",
)
EXPLICIT_NON_CLAIMS = (
    "no repository lookup",
    "no database read or write",
    "no Bitcoin RPC call",
    "no LND call",
    "no network request",
    "no participant or target discovery",
    "no fabricated Bitcoin observation",
    "no descriptor import or custody proof",
    "no transaction broadcast",
    "no signing",
    "no issuer attestation",
    "no authority-legitimacy proof",
    "no proof of private-key possession",
    "no portable trust bundle",
    "no replica synchronization",
    "no graph checkpoint",
    "no cross-node fork detection",
    "no universal freshness claim",
    "no claim after freshness_deadline",
    "no JWT or session issuance",
    "no FULL/LIMITED session mutation",
    "no entitlement evidence write",
    "no action authorization",
    "no administrator or sponsor permission grant",
    "no HTTP route",
    "no MCP tool",
    "no paid job",
    "no CLI",
    "no scheduler",
    "no migration",
    "no deployment",
    "no replacement of the active legacy runtime path",
)


class InvalidHodlxxiV1SnapshotProofComposition(ValueError):
    """The supplied local V1 snapshot is malformed or inconsistently bound."""


def _fail() -> None:
    raise InvalidHodlxxiV1SnapshotProofComposition("invalid HODLXXI V1 local snapshot composition")


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
        _fail()
    return value


def _registration(value: object) -> TrustedCovenantRegistration:
    if type(value) is not TrustedCovenantRegistration:
        _fail()
    try:
        detached = TrustedCovenantRegistration(
            *(deepcopy(getattr(value, field)) for field in TrustedCovenantRegistration.__dataclass_fields__)
        )
        canonical_trusted_registration_bytes(detached)
        return detached
    except Exception:
        _fail()


def _evaluation(value: object) -> CovenantRelationEvaluation:
    if type(value) is not CovenantRelationEvaluation:
        _fail()
    try:
        return CovenantRelationEvaluation(
            *(deepcopy(getattr(value, field)) for field in CovenantRelationEvaluation.__dataclass_fields__)
        )
    except Exception:
        _fail()


def _plan(value: object) -> TrustedCrtAuthorizationSourcePlan:
    if type(value) is not TrustedCrtAuthorizationSourcePlan:
        _fail()
    try:
        genesis = tuple(
            parse_canonical_genesis_record(canonical_genesis_record_bytes(x)) for x in value.genesis_records
        )
        sources = []
        for source in value.lineage_sources:
            if type(source) is not TrustedCrtLineageSource:
                _fail()
            sources.append(
                TrustedCrtLineageSource(
                    source.depth,
                    source.edge_id,
                    source.edge_sha256,
                    source.registration_id,
                    source.registration_sha256,
                    source.observation_required,
                    parse_canonical_admission_edge(canonical_admission_edge_bytes(source.edge)),
                    _registration(source.registration),
                )
            )
        detached = TrustedCrtAuthorizationSourcePlan(
            value.schema,
            value.adapter_version,
            value.graph_or_protocol_id,
            value.subject_kind,
            value.participant_id,
            value.compressed_public_key,
            value.x_only_public_key,
            value.depth,
            value.target_edge_id,
            value.target_edge_sha256,
            genesis,
            tuple(sources),
            deepcopy(value.relevant_records),
            value.manifest_sha256,
            deepcopy(value.explicit_non_claims),
            value.human_interpretation_required,
        )
        if trusted_crt_authorization_source_plan_manifest_sha256(detached) != detached.manifest_sha256:
            _fail()
        return detached
    except InvalidHodlxxiV1SnapshotProofComposition:
        raise
    except Exception:
        _fail()


def _resolution(value: object, plan: TrustedCrtAuthorizationSourcePlan):
    if type(value) is not TrustedCrtBitcoinObservationResolution:
        _fail()
    manifest = trusted_crt_authorization_source_plan_manifest_sha256(plan)
    if value.source_plan_manifest_sha256 != manifest:
        _fail()
    required = tuple(x for x in plan.lineage_sources if x.observation_required)
    if value.state is TrustedCrtBitcoinObservationState.NOT_REQUIRED:
        if value.snapshot is not None or required:
            _fail()
        return TrustedCrtBitcoinObservationResolution(value.state, manifest, None)
    if value.state is not TrustedCrtBitcoinObservationState.OBSERVED:
        _fail()
    snapshot = value.snapshot
    if type(snapshot) is not TrustedCrtBitcoinObservationSnapshot:
        _fail()
    if type(snapshot.source_plan) is not TrustedCrtAuthorizationSourcePlan:
        _fail()
    if trusted_crt_authorization_source_plan_manifest_sha256(snapshot.source_plan) != manifest:
        _fail()
    if canonical_crt_plan_identity(snapshot.source_plan) != canonical_crt_plan_identity(plan):
        _fail()
    relations = []
    for relation in snapshot.observed_relations:
        if type(relation) is not TrustedCrtObservedLineageRelation:
            _fail()
        relations.append(
            TrustedCrtObservedLineageRelation(
                relation.depth,
                relation.edge_id,
                relation.edge_sha256,
                relation.registration_id,
                relation.registration_sha256,
                deepcopy(relation.trusted_outpoints),
                relation.trusted_outpoints_sha256,
                _evaluation(relation.relation_evaluation),
                relation.relation_evaluation_sha256,
            )
        )
    detached = TrustedCrtBitcoinObservationSnapshot(
        snapshot.schema,
        snapshot.adapter_version,
        manifest,
        plan,
        snapshot.graph_or_protocol_id,
        snapshot.participant_id,
        snapshot.target_edge_id,
        snapshot.source_plan_depth,
        snapshot.observed_block_height,
        snapshot.observed_best_block_hash,
        snapshot.observation_started_at,
        snapshot.observation_completed_at,
        tuple(relations),
        snapshot.snapshot_sha256,
        deepcopy(snapshot.explicit_non_claims),
        snapshot.human_interpretation_required,
    )
    if trusted_crt_bitcoin_observation_snapshot_sha256(detached) != snapshot.snapshot_sha256:
        _fail()
    return TrustedCrtBitcoinObservationResolution(value.state, manifest, detached)


def canonical_crt_plan_identity(plan: TrustedCrtAuthorizationSourcePlan) -> tuple:
    return (
        plan.manifest_sha256,
        plan.graph_or_protocol_id,
        plan.participant_id,
        plan.target_edge_id,
        plan.depth,
        tuple(
            (x.depth, x.edge_id, x.edge_sha256, x.registration_id, x.registration_sha256, x.observation_required)
            for x in plan.lineage_sources
        ),
    )


@dataclass(frozen=True, slots=True)
class HodlxxiV1SnapshotProofCompositionRequest:
    source_plan: TrustedCrtAuthorizationSourcePlan
    bitcoin_observation_resolution: TrustedCrtBitcoinObservationResolution
    evaluated_at: datetime
    freshness_deadline: datetime

    def __post_init__(self):
        if type(self) is not HodlxxiV1SnapshotProofCompositionRequest:
            _fail()
        evaluated_at, deadline = _utc(self.evaluated_at), _utc(self.freshness_deadline)
        if deadline < evaluated_at:
            _fail()
        plan = _plan(self.source_plan)
        resolution = _resolution(self.bitcoin_observation_resolution, plan)
        if resolution.state is TrustedCrtBitcoinObservationState.OBSERVED:
            completed = resolution.snapshot.observation_completed_at
            if evaluated_at < completed or deadline < completed:
                _fail()
        object.__setattr__(self, "source_plan", plan)
        object.__setattr__(self, "bitcoin_observation_resolution", resolution)


def _evidence_payload(evidence, plan_digest, snapshot_digest):
    return {
        "graph_or_protocol_id": GRAPH_ID,
        "human_profile": HUMAN_PROFILE,
        "source_plan_manifest_sha256": plan_digest.manifest_sha256,
        "bitcoin_snapshot_sha256": snapshot_digest,
        "edge_evidence": [
            {
                "depth": source.depth,
                "edge_id": item.record.edge_id,
                "edge_sha256": canonical_admission_edge_sha256(item.record),
                "registration_id": item.trusted_registration.registration_id,
                "registration_sha256": trusted_registration_sha256(item.trusted_registration),
                "observation_required": source.observation_required,
                "relation_evaluation_sha256": (
                    None
                    if item.observation_evaluation is None
                    else covenant_relation_source_sha256(item.observation_evaluation)
                ),
            }
            for source, item in zip(plan_digest.lineage_sources, evidence)
        ],
    }


def hodlxxi_v1_edge_evidence_manifest_bytes(
    edge_evidence: tuple[CanonicalSponsorLineageEdgeEvidence, ...],
    *,
    source_plan: TrustedCrtAuthorizationSourcePlan,
    bitcoin_snapshot_sha256: str | None,
) -> bytes:
    if type(edge_evidence) is not tuple or any(
        type(x) is not CanonicalSponsorLineageEdgeEvidence for x in edge_evidence
    ):
        _fail()
    plan = _plan(source_plan)
    if len(edge_evidence) != len(plan.lineage_sources):
        _fail()
    return json.dumps(
        _evidence_payload(edge_evidence, plan, bitcoin_snapshot_sha256),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def hodlxxi_v1_edge_evidence_manifest_sha256(*args, **kwargs) -> str:
    return sha256(hodlxxi_v1_edge_evidence_manifest_bytes(*args, **kwargs)).hexdigest()


def _detach_evidence(value: object) -> tuple[CanonicalSponsorLineageEdgeEvidence, ...]:
    if type(value) is not tuple:
        _fail()
    detached = []
    for item in value:
        if type(item) is not CanonicalSponsorLineageEdgeEvidence:
            _fail()
        edge = parse_canonical_admission_edge(canonical_admission_edge_bytes(item.record))
        registration = _registration(item.trusted_registration)
        evaluation = None if item.observation_evaluation is None else _evaluation(item.observation_evaluation)
        detached.append(CanonicalSponsorLineageEdgeEvidence(edge, registration, evaluation))
    return tuple(detached)


def _authoritative_evidence(
    plan: TrustedCrtAuthorizationSourcePlan,
    resolution: TrustedCrtBitcoinObservationResolution,
) -> tuple[CanonicalSponsorLineageEdgeEvidence, ...]:
    relations = (
        {}
        if resolution.snapshot is None
        else {
            (item.depth, item.edge_id, item.edge_sha256, item.registration_id, item.registration_sha256): item
            for item in resolution.snapshot.observed_relations
        }
    )
    if resolution.snapshot is not None and len(relations) != len(resolution.snapshot.observed_relations):
        _fail()
    evidence = []
    for source in plan.lineage_sources:
        key = (source.depth, source.edge_id, source.edge_sha256, source.registration_id, source.registration_sha256)
        relation = relations.pop(key, None)
        if source.observation_required is not (relation is not None):
            _fail()
        evidence.append(
            CanonicalSponsorLineageEdgeEvidence(
                source.edge,
                source.registration,
                None if relation is None else relation.relation_evaluation,
            )
        )
    if relations:
        _fail()
    return _detach_evidence(tuple(evidence))


def _resolve_proof(plan, evidence, evaluated_at):
    proof = resolve_canonical_crt_authorization_proof_from_snapshot(
        participant_id=plan.participant_id,
        compressed_public_key=plan.compressed_public_key,
        x_only_public_key=plan.x_only_public_key,
        depth=plan.depth,
        evaluated_at=evaluated_at,
        genesis_records=plan.genesis_records,
        target_edge_id=plan.target_edge_id,
        edge_evidence=evidence,
    )
    if type(proof) is not CanonicalCrtAuthorizationProof:
        _fail()
    encoded = canonical_crt_authorization_proof_bytes(proof)
    parsed = parse_canonical_crt_authorization_proof(encoded)
    if canonical_crt_authorization_proof_bytes(parsed) != encoded:
        _fail()
    return parsed


@dataclass(frozen=True, slots=True)
class HodlxxiV1SnapshotProofCompositionResult:
    schema: str
    composer_version: str
    graph_or_protocol_id: str
    network: str
    human_profile: str
    genesis_participant_id: str
    source_plan: TrustedCrtAuthorizationSourcePlan
    bitcoin_observation_resolution: TrustedCrtBitcoinObservationResolution
    source_plan_manifest_sha256: str
    bitcoin_observation_state: TrustedCrtBitcoinObservationState
    bitcoin_snapshot_sha256: str | None
    observed_block_height: int | None
    observed_best_block_hash: str | None
    observation_started_at: datetime | None
    observation_completed_at: datetime | None
    participant_id: str
    target_edge_id: str | None
    depth: int
    evaluated_at: datetime
    freshness_deadline: datetime
    edge_evidence: tuple[CanonicalSponsorLineageEdgeEvidence, ...]
    edge_evidence_manifest_sha256: str
    authorization_proof: CanonicalCrtAuthorizationProof
    authorization_proof_sha256: str
    authority_state: str
    explicit_non_claims: tuple[str, ...]
    human_interpretation_required: bool
    result_sha256: str

    def __post_init__(self):
        if type(self) is not HodlxxiV1SnapshotProofCompositionResult:
            _fail()
        if (
            self.schema != SCHEMA
            or self.composer_version != COMPOSER_VERSION
            or self.graph_or_protocol_id != GRAPH_ID
            or self.network != NETWORK
            or self.human_profile != HUMAN_PROFILE
            or self.genesis_participant_id != PARTICIPANT_ID
            or type(self.bitcoin_observation_state) is not TrustedCrtBitcoinObservationState
            or self.authority_state != AUTHORITY_STATE
            or self.explicit_non_claims != EXPLICIT_NON_CLAIMS
            or self.human_interpretation_required is not True
            or type(self.edge_evidence) is not tuple
            or any(type(x) is not CanonicalSponsorLineageEdgeEvidence for x in self.edge_evidence)
            or type(self.authorization_proof) is not CanonicalCrtAuthorizationProof
        ):
            _fail()
        evaluated_at, deadline = _utc(self.evaluated_at), _utc(self.freshness_deadline)
        if deadline < evaluated_at:
            _fail()
        plan = _plan(self.source_plan)
        resolution = _resolution(self.bitcoin_observation_resolution, plan)
        snapshot = resolution.snapshot
        if resolution.state is TrustedCrtBitcoinObservationState.NOT_REQUIRED:
            if any(
                value is not None
                for value in (
                    self.bitcoin_snapshot_sha256,
                    self.observed_block_height,
                    self.observed_best_block_hash,
                    self.observation_started_at,
                    self.observation_completed_at,
                )
            ):
                _fail()
        else:
            if snapshot is None or any(
                value is None
                for value in (
                    self.bitcoin_snapshot_sha256,
                    self.observed_block_height,
                    self.observed_best_block_hash,
                    self.observation_started_at,
                    self.observation_completed_at,
                )
            ):
                _fail()
            completed = snapshot.observation_completed_at
            if evaluated_at < completed or deadline < completed:
                _fail()
        expected_evidence = _authoritative_evidence(plan, resolution)
        detached_evidence = _detach_evidence(self.edge_evidence)
        expected_snapshot_digest = (
            None if snapshot is None else trusted_crt_bitcoin_observation_snapshot_sha256(snapshot)
        )
        expected_scalars = (
            trusted_crt_authorization_source_plan_manifest_sha256(plan),
            resolution.state,
            expected_snapshot_digest,
            None if snapshot is None else snapshot.observed_block_height,
            None if snapshot is None else snapshot.observed_best_block_hash,
            None if snapshot is None else snapshot.observation_started_at,
            None if snapshot is None else snapshot.observation_completed_at,
            plan.participant_id,
            plan.target_edge_id,
            plan.depth,
        )
        if (
            expected_scalars
            != (
                self.source_plan_manifest_sha256,
                self.bitcoin_observation_state,
                self.bitcoin_snapshot_sha256,
                self.observed_block_height,
                self.observed_best_block_hash,
                self.observation_started_at,
                self.observation_completed_at,
                self.participant_id,
                self.target_edge_id,
                self.depth,
            )
            or detached_evidence != expected_evidence
        ):
            _fail()
        if plan.subject_kind is TrustedCrtSubjectKind.GENESIS:
            if (
                resolution.state is not TrustedCrtBitcoinObservationState.NOT_REQUIRED
                or plan.target_edge_id is not None
                or plan.depth != 0
                or detached_evidence
            ):
                _fail()
        expected_proof = _resolve_proof(plan, expected_evidence, evaluated_at)
        proof_bytes = canonical_crt_authorization_proof_bytes(self.authorization_proof)
        proof = parse_canonical_crt_authorization_proof(proof_bytes)
        if (
            canonical_crt_authorization_proof_bytes(proof) != proof_bytes
            or canonical_crt_authorization_proof_sha256(proof) != self.authorization_proof_sha256
            or proof_bytes != canonical_crt_authorization_proof_bytes(expected_proof)
        ):
            _fail()
        expected_manifest = hodlxxi_v1_edge_evidence_manifest_sha256(
            self.edge_evidence,
            source_plan=plan,
            bitcoin_snapshot_sha256=self.bitcoin_snapshot_sha256,
        )
        if expected_manifest != self.edge_evidence_manifest_sha256:
            _fail()
        object.__setattr__(self, "source_plan", plan)
        object.__setattr__(self, "bitcoin_observation_resolution", resolution)
        object.__setattr__(self, "edge_evidence", detached_evidence)
        object.__setattr__(self, "authorization_proof", proof)
        if self.result_sha256 != _result_sha256_unchecked(self):
            _fail()


def _timestamp(value):
    return None if value is None else value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _result_payload(value):
    return {
        "schema": value.schema,
        "composer_version": value.composer_version,
        "graph_or_protocol_id": value.graph_or_protocol_id,
        "network": value.network,
        "human_profile": value.human_profile,
        "genesis_participant_id": value.genesis_participant_id,
        "source_plan_manifest_sha256": value.source_plan_manifest_sha256,
        "bitcoin_observation_state": value.bitcoin_observation_state.value,
        "bitcoin_snapshot_sha256": value.bitcoin_snapshot_sha256,
        "observed_block_height": value.observed_block_height,
        "observed_best_block_hash": value.observed_best_block_hash,
        "observation_started_at": _timestamp(value.observation_started_at),
        "observation_completed_at": _timestamp(value.observation_completed_at),
        "participant_id": value.participant_id,
        "target_edge_id": value.target_edge_id,
        "depth": value.depth,
        "evaluated_at": _timestamp(value.evaluated_at),
        "freshness_deadline": _timestamp(value.freshness_deadline),
        "edge_evidence_manifest_sha256": value.edge_evidence_manifest_sha256,
        "authorization_proof_sha256": value.authorization_proof_sha256,
        "authority_state": value.authority_state,
        "explicit_non_claims": list(value.explicit_non_claims),
        "human_interpretation_required": value.human_interpretation_required,
    }


def _result_bytes_unchecked(value):
    return json.dumps(
        _result_payload(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _result_sha256_unchecked(value):
    return sha256(_result_bytes_unchecked(value)).hexdigest()


def hodlxxi_v1_snapshot_proof_composition_bytes(value) -> bytes:
    if type(value) is not HodlxxiV1SnapshotProofCompositionResult:
        _fail()
    validated = HodlxxiV1SnapshotProofCompositionResult(*(getattr(value, f) for f in value.__dataclass_fields__))
    return _result_bytes_unchecked(validated)


def hodlxxi_v1_snapshot_proof_composition_sha256(value) -> str:
    return sha256(hodlxxi_v1_snapshot_proof_composition_bytes(value)).hexdigest()


def compose_hodlxxi_v1_snapshot_authorization_proof(
    request: HodlxxiV1SnapshotProofCompositionRequest,
) -> HodlxxiV1SnapshotProofCompositionResult:
    if type(request) is not HodlxxiV1SnapshotProofCompositionRequest:
        _fail()
    request = HodlxxiV1SnapshotProofCompositionRequest(*(getattr(request, f) for f in request.__dataclass_fields__))
    plan, resolution = request.source_plan, request.bitcoin_observation_resolution
    snapshot = resolution.snapshot
    evidence = _authoritative_evidence(plan, resolution)
    proof = _resolve_proof(plan, evidence, request.evaluated_at)
    snapshot_digest = None if snapshot is None else trusted_crt_bitcoin_observation_snapshot_sha256(snapshot)
    manifest_digest = trusted_crt_authorization_source_plan_manifest_sha256(plan)
    evidence_digest = hodlxxi_v1_edge_evidence_manifest_sha256(
        evidence, source_plan=plan, bitcoin_snapshot_sha256=snapshot_digest
    )
    values = dict(
        schema=SCHEMA,
        composer_version=COMPOSER_VERSION,
        graph_or_protocol_id=GRAPH_ID,
        network=NETWORK,
        human_profile=HUMAN_PROFILE,
        genesis_participant_id=PARTICIPANT_ID,
        source_plan=plan,
        bitcoin_observation_resolution=resolution,
        source_plan_manifest_sha256=manifest_digest,
        bitcoin_observation_state=resolution.state,
        bitcoin_snapshot_sha256=snapshot_digest,
        observed_block_height=None if snapshot is None else snapshot.observed_block_height,
        observed_best_block_hash=None if snapshot is None else snapshot.observed_best_block_hash,
        observation_started_at=None if snapshot is None else snapshot.observation_started_at,
        observation_completed_at=None if snapshot is None else snapshot.observation_completed_at,
        participant_id=plan.participant_id,
        target_edge_id=plan.target_edge_id,
        depth=plan.depth,
        evaluated_at=request.evaluated_at,
        freshness_deadline=request.freshness_deadline,
        edge_evidence=evidence,
        edge_evidence_manifest_sha256=evidence_digest,
        authorization_proof=proof,
        authorization_proof_sha256=canonical_crt_authorization_proof_sha256(proof),
        authority_state=AUTHORITY_STATE,
        explicit_non_claims=EXPLICIT_NON_CLAIMS,
        human_interpretation_required=True,
    )
    digest = _result_sha256_unchecked(type("Payload", (), values)())
    return HodlxxiV1SnapshotProofCompositionResult(**values, result_sha256=digest)
