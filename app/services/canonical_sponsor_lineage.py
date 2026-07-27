"""Pure, dormant canonical sponsor-lineage evidence-snapshot evaluator V1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from hashlib import sha256
import json
import re
import uuid

from app.services.canonical_admission_edge import (
    AdmissionEdgeCurrentReason,
    AdmissionEdgeEvaluationState,
    CanonicalAdmissionEdge,
    CanonicalAdmissionEdgeCurrentEvaluation,
    GENESIS_COMPRESSED_KEY,
    GENESIS_PARTICIPANT_ID,
    GENESIS_XONLY_KEY,
    canonical_admission_edge_current_evaluation_sha256,
    canonical_admission_edge_sha256,
    evaluate_canonical_admission_edge_current,
)
from app.services.canonical_genesis_record import (
    CanonicalGenesisEvaluation,
    CanonicalGenesisEvaluationState,
)
from app.services.covenant_relation import CovenantRelationEvaluation, covenant_relation_source_sha256
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    trusted_registration_sha256,
)

SCHEMA = "hodlxxi.canonical_sponsor_lineage_evaluation.v1"
EVALUATOR_VERSION = "hodlxxi.canonical_sponsor_lineage_evaluator.v1"
VERIFICATION_RULE = "hodlxxi.canonical_sponsor_lineage_verification.v1"
GRAPH_ID = "hodlxxi.crt_membership_graph.v1"
NETWORK = "bitcoin"
HUMAN_PROFILE = "legacy_777"
MAXIMUM_CANONICAL_CHILD_DEPTH = 2288
MANDATORY_NON_CLAIMS = tuple(sorted((
    "no FULL/LIMITED authorization grant",
    "no automatic Bitcoin RPC observation claim",
    "no decentralization or universal-legitimacy proof",
    "no fairness or informed-consent proof",
    "no future-cooperation guarantee",
    "no legal identity, KYC or complete personhood proof",
    "no ownership, custody or guardianship proof",
    "no production enforcement or deployment claim",
    "no proof of current private-key possession",
    "no reputation or rank grant",
    "no runtime administration or server-privilege grant",
    "no sincerity, loyalty, affection or trustworthiness proof",
    "no sponsor ownership or control over a child",
    "no validity for current_144 or cooperative admission templates",
    "no validity outside the exact supplied evidence snapshot and evaluated_at",
)))
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX66 = re.compile(r"(?:02|03)[0-9a-f]{64}\Z")


class InvalidCanonicalSponsorLineage(ValueError):
    """The lineage snapshot or canonical evaluation violates the V1 contract."""


class CanonicalSponsorLineageState(Enum):
    ACTIVE = "active"
    PROVISIONAL = "provisional"
    DISPUTED = "disputed"
    LINEAGE_INACTIVE = "lineage_inactive"
    UNKNOWN = "unknown"


class CanonicalSponsorLineageReason(Enum):
    EXACT_LINEAGE_ACTIVE = "exact_lineage_active"
    GENESIS_PROVISIONAL = "genesis_provisional"
    GENESIS_DISPUTED = "genesis_disputed"
    GENESIS_LINEAGE_INACTIVE = "genesis_lineage_inactive"
    GENESIS_UNKNOWN = "genesis_unknown"
    ANCESTOR_PROVISIONAL = "ancestor_provisional"
    TARGET_PROVISIONAL = "target_provisional"
    ANCESTOR_DISPUTED = "ancestor_disputed"
    TARGET_DISPUTED = "target_disputed"
    ANCESTOR_EDGE_INACTIVE = "ancestor_edge_inactive"
    TARGET_EDGE_INACTIVE = "target_edge_inactive"
    ANCESTOR_LOCAL_EVALUATION_UNKNOWN = "ancestor_local_evaluation_unknown"
    TARGET_LOCAL_EVALUATION_UNKNOWN = "target_local_evaluation_unknown"
    MISSING_TARGET_EVIDENCE = "missing_target_evidence"
    MISSING_PARENT_EVIDENCE = "missing_parent_evidence"
    PARENT_DIGEST_MISMATCH = "parent_digest_mismatch"
    PARENT_IDENTITY_MISMATCH = "parent_identity_mismatch"
    PARENT_DEPTH_MISMATCH = "parent_depth_mismatch"
    PARENT_GRAPH_OR_PROFILE_MISMATCH = "parent_graph_or_profile_mismatch"
    DUPLICATE_EDGE_ID = "duplicate_edge_id"
    DUPLICATE_EDGE_DIGEST = "duplicate_edge_digest"
    DUPLICATE_CHILD_IDENTITY = "duplicate_child_identity"
    CYCLE_DETECTED = "cycle_detected"
    EXTRANEOUS_EDGE_EVIDENCE = "extraneous_edge_evidence"
    MAXIMUM_DEPTH_EXCEEDED = "maximum_depth_exceeded"
    MALFORMED_OR_UNTRUSTED_INPUT = "malformed_or_untrusted_input"


def _utc(value: object) -> datetime:
    if (type(value) is not datetime or value.tzinfo is None
            or value.utcoffset() != timedelta(0) or value.microsecond):
        raise InvalidCanonicalSponsorLineage("evaluated_at")
    return value


def _uuid(value: object) -> str:
    if type(value) is not str:
        raise InvalidCanonicalSponsorLineage("uuid")
    try:
        canonical = str(uuid.UUID(value))
    except ValueError:
        raise InvalidCanonicalSponsorLineage("uuid") from None
    if value != canonical:
        raise InvalidCanonicalSponsorLineage("uuid")
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise InvalidCanonicalSponsorLineage("digest")
    return value


@dataclass(frozen=True, slots=True)
class CanonicalSponsorLineageEdgeEvidence:
    record: CanonicalAdmissionEdge
    trusted_registration: TrustedCovenantRegistration
    observation_evaluation: CovenantRelationEvaluation

    def __post_init__(self):
        if (type(self.record) is not CanonicalAdmissionEdge
                or type(self.trusted_registration) is not TrustedCovenantRegistration
                or type(self.observation_evaluation) is not CovenantRelationEvaluation):
            raise InvalidCanonicalSponsorLineage("evidence type")
        CanonicalAdmissionEdge(*(getattr(self.record, f) for f in CanonicalAdmissionEdge.__dataclass_fields__))
        TrustedCovenantRegistration(*(
            getattr(self.trusted_registration, f)
            for f in TrustedCovenantRegistration.__dataclass_fields__
        ))
        CovenantRelationEvaluation(*(
            getattr(self.observation_evaluation, f)
            for f in CovenantRelationEvaluation.__dataclass_fields__
        ))


@dataclass(frozen=True, slots=True)
class CanonicalSponsorLineageNode:
    depth: int
    edge_id: str
    edge_sha256: str
    sponsor_participant_id: str
    sponsor_compressed_public_key: str
    sponsor_x_only_public_key: str
    child_participant_id: str
    child_compressed_public_key: str
    child_x_only_public_key: str
    local_evaluation_state: AdmissionEdgeEvaluationState
    local_evaluation_reason: AdmissionEdgeCurrentReason
    trusted_registration_id: str
    trusted_registration_sha256: str
    sponsor_basis_record_id: str
    sponsor_basis_record_sha256: str
    observation_evaluation_sha256: str
    local_current_evaluation_sha256: str

    def __post_init__(self):
        if type(self.depth) is not int or not 1 <= self.depth <= MAXIMUM_CANONICAL_CHILD_DEPTH:
            raise InvalidCanonicalSponsorLineage("node depth")
        _uuid(self.edge_id); _uuid(self.trusted_registration_id); _uuid(self.sponsor_basis_record_id)
        for value in (self.edge_sha256, self.trusted_registration_sha256,
                      self.sponsor_basis_record_sha256, self.observation_evaluation_sha256,
                      self.local_current_evaluation_sha256):
            _digest(value)
        if (
            type(self.local_evaluation_state) is not AdmissionEdgeEvaluationState
            or type(self.local_evaluation_reason) is not AdmissionEdgeCurrentReason
        ):
            raise InvalidCanonicalSponsorLineage("node local enum")
        for value in (
            self.sponsor_compressed_public_key,
            self.child_compressed_public_key,
        ):
            if type(value) is not str or _HEX66.fullmatch(value) is None:
                raise InvalidCanonicalSponsorLineage("node compressed key")
        for value in (
            self.sponsor_x_only_public_key,
            self.child_x_only_public_key,
        ):
            _digest(value)
        if (
            self.sponsor_compressed_public_key[2:] != self.sponsor_x_only_public_key
            or self.child_compressed_public_key[2:] != self.child_x_only_public_key
            or self.sponsor_participant_id == self.child_participant_id
            or self.child_participant_id != self.child_x_only_public_key
            or (
                self.depth == 1
                and (
                    self.sponsor_participant_id != GENESIS_PARTICIPANT_ID
                    or self.sponsor_compressed_public_key != GENESIS_COMPRESSED_KEY
                    or self.sponsor_x_only_public_key != GENESIS_XONLY_KEY
                )
            )
            or (
                self.depth > 1
                and self.sponsor_participant_id != self.sponsor_x_only_public_key
            )
        ):
            raise InvalidCanonicalSponsorLineage("node participant identity")
        expected = {
            AdmissionEdgeEvaluationState.ACTIVE: {
                AdmissionEdgeCurrentReason.EXACT_CURRENT_EDGE_ACTIVE
            },
            AdmissionEdgeEvaluationState.PROVISIONAL: {
                AdmissionEdgeCurrentReason.RECORD_PROPOSED
            },
            AdmissionEdgeEvaluationState.DISPUTED: {
                AdmissionEdgeCurrentReason.RECORD_DISPUTED,
                AdmissionEdgeCurrentReason.REGISTRATION_DISPUTED,
            },
            AdmissionEdgeEvaluationState.EDGE_INACTIVE: {
                AdmissionEdgeCurrentReason.RECORD_REVOKED,
                AdmissionEdgeCurrentReason.RECORD_SUPERSEDED,
                AdmissionEdgeCurrentReason.REGISTRATION_REVOKED,
                AdmissionEdgeCurrentReason.REGISTRATION_SUPERSEDED,
                AdmissionEdgeCurrentReason.MISSING_REQUIRED_LEG,
                AdmissionEdgeCurrentReason.SPENT_REQUIRED_LEG,
                AdmissionEdgeCurrentReason.INSUFFICIENT_CONFIRMATIONS,
                AdmissionEdgeCurrentReason.UNEQUAL_LEG_AMOUNTS,
            },
            AdmissionEdgeEvaluationState.UNKNOWN: {
                AdmissionEdgeCurrentReason.REGISTRATION_BINDING_MISMATCH,
                AdmissionEdgeCurrentReason.OBSERVATION_BINDING_MISMATCH,
                AdmissionEdgeCurrentReason.MALFORMED_OR_UNTRUSTED_INPUT,
            },
        }
        if (
            self.local_evaluation_state not in expected
            or self.local_evaluation_reason
            not in expected[self.local_evaluation_state]
        ):
            raise InvalidCanonicalSponsorLineage("node state reason")


@dataclass(frozen=True, slots=True)
class CanonicalSponsorLineageEvaluation:
    schema: str
    evaluator_version: str
    verification_rule: str
    graph_or_protocol_id: str
    network: str
    human_profile: str
    target_edge_id: str
    target_edge_sha256: str | None
    target_participant_id: str | None
    target_compressed_public_key: str | None
    target_x_only_public_key: str | None
    target_depth: int | None
    evaluated_at: datetime
    state: CanonicalSponsorLineageState
    reason_code: CanonicalSponsorLineageReason
    controlling_depth: int | None
    controlling_edge_id: str | None
    selected_genesis_record_id: str | None
    selected_genesis_record_sha256: str | None
    lineage_nodes: tuple[CanonicalSponsorLineageNode, ...]
    relevant_records: tuple[tuple[str, str], ...]
    explicit_non_claims: tuple[str, ...]
    human_interpretation_required: bool

    def __post_init__(self):
        if (self.schema, self.evaluator_version, self.verification_rule,
            self.graph_or_protocol_id, self.network, self.human_profile) != (
            SCHEMA, EVALUATOR_VERSION, VERIFICATION_RULE, GRAPH_ID, NETWORK, HUMAN_PROFILE
        ) or type(self.state) is not CanonicalSponsorLineageState or type(
            self.reason_code) is not CanonicalSponsorLineageReason:
            raise InvalidCanonicalSponsorLineage("fixed evaluation contract")
        _uuid(self.target_edge_id); _utc(self.evaluated_at)
        if self.explicit_non_claims != MANDATORY_NON_CLAIMS or self.human_interpretation_required is not True:
            raise InvalidCanonicalSponsorLineage("non-claims")
        target_metadata = (
            self.target_edge_sha256,
            self.target_participant_id,
            self.target_compressed_public_key,
            self.target_x_only_public_key,
            self.target_depth,
        )
        if any(item is None for item in target_metadata) != all(
            item is None for item in target_metadata
        ):
            raise InvalidCanonicalSponsorLineage("partial target metadata")
        if self.target_edge_sha256 is not None:
            _digest(self.target_edge_sha256)
            if (
                type(self.target_depth) is not int
                or not 1 <= self.target_depth <= MAXIMUM_CANONICAL_CHILD_DEPTH
                or type(self.target_compressed_public_key) is not str
                or _HEX66.fullmatch(self.target_compressed_public_key) is None
                or self.target_compressed_public_key[2:] != self.target_x_only_public_key
                or self.target_participant_id != self.target_x_only_public_key
            ):
                raise InvalidCanonicalSponsorLineage("target metadata")
            _digest(self.target_x_only_public_key)
        if (self.selected_genesis_record_id is None) != (
            self.selected_genesis_record_sha256 is None
        ):
            raise InvalidCanonicalSponsorLineage("partial genesis reference")
        if self.selected_genesis_record_id is not None:
            _uuid(self.selected_genesis_record_id); _digest(self.selected_genesis_record_sha256)
        if type(self.lineage_nodes) is not tuple or any(
            type(x) is not CanonicalSponsorLineageNode for x in self.lineage_nodes
        ):
            raise InvalidCanonicalSponsorLineage("nodes")
        if self.lineage_nodes:
            if (
                tuple(x.depth for x in self.lineage_nodes)
                != tuple(range(1, len(self.lineage_nodes) + 1))
                or self.target_depth != self.lineage_nodes[-1].depth
                or len(self.lineage_nodes) != self.target_depth
                or (
                    self.lineage_nodes[-1].edge_id,
                    self.lineage_nodes[-1].edge_sha256,
                    self.lineage_nodes[-1].child_participant_id,
                    self.lineage_nodes[-1].child_compressed_public_key,
                    self.lineage_nodes[-1].child_x_only_public_key,
                )
                != (
                    self.target_edge_id,
                    self.target_edge_sha256,
                    self.target_participant_id,
                    self.target_compressed_public_key,
                    self.target_x_only_public_key,
                )
                or any(
                    (
                        parent.child_participant_id,
                        parent.child_compressed_public_key,
                        parent.child_x_only_public_key,
                        parent.depth,
                        parent.edge_id,
                        parent.edge_sha256,
                    )
                    != (
                        child.sponsor_participant_id,
                        child.sponsor_compressed_public_key,
                        child.sponsor_x_only_public_key,
                        child.depth - 1,
                        child.sponsor_basis_record_id,
                        child.sponsor_basis_record_sha256,
                    )
                    for parent, child in zip(
                        self.lineage_nodes, self.lineage_nodes[1:]
                    )
                )
            ):
                raise InvalidCanonicalSponsorLineage("lineage continuity")
            if (
                self.selected_genesis_record_id is None
                or (
                    self.lineage_nodes[0].sponsor_basis_record_id,
                    self.lineage_nodes[0].sponsor_basis_record_sha256,
                )
                != (
                    self.selected_genesis_record_id,
                    self.selected_genesis_record_sha256,
                )
            ):
                raise InvalidCanonicalSponsorLineage("lineage genesis")
            if (
                len({node.edge_id for node in self.lineage_nodes})
                != len(self.lineage_nodes)
                or len({node.edge_sha256 for node in self.lineage_nodes})
                != len(self.lineage_nodes)
                or len({node.child_participant_id for node in self.lineage_nodes})
                != len(self.lineage_nodes)
                or len({node.child_x_only_public_key for node in self.lineage_nodes})
                != len(self.lineage_nodes)
                or len(
                    {
                        (node.sponsor_participant_id, node.child_participant_id)
                        for node in self.lineage_nodes
                    }
                )
                != len(self.lineage_nodes)
            ):
                raise InvalidCanonicalSponsorLineage("duplicate lineage identity")
        if type(self.relevant_records) is not tuple or self.relevant_records != tuple(
            sorted(self.relevant_records)
        ) or len({x[0] for x in self.relevant_records}) != len(self.relevant_records):
            raise InvalidCanonicalSponsorLineage("relevant records")
        for record_id, digest in self.relevant_records:
            _uuid(record_id); _digest(digest)
        expected_relevant = set()
        if self.lineage_nodes:
            expected_relevant.add(
                (
                    self.selected_genesis_record_id,
                    self.selected_genesis_record_sha256,
                )
            )
            for node in self.lineage_nodes:
                expected_relevant.update(
                    (
                        (node.edge_id, node.edge_sha256),
                        (
                            node.trusted_registration_id,
                            node.trusted_registration_sha256,
                        ),
                    )
                )
        if set(self.relevant_records) != expected_relevant:
            raise InvalidCanonicalSponsorLineage("relevant record policy")
        state_reasons = {
            CanonicalSponsorLineageState.ACTIVE: {
                CanonicalSponsorLineageReason.EXACT_LINEAGE_ACTIVE
            },
            CanonicalSponsorLineageState.PROVISIONAL: {
                CanonicalSponsorLineageReason.GENESIS_PROVISIONAL,
                CanonicalSponsorLineageReason.ANCESTOR_PROVISIONAL,
                CanonicalSponsorLineageReason.TARGET_PROVISIONAL,
            },
            CanonicalSponsorLineageState.DISPUTED: {
                CanonicalSponsorLineageReason.GENESIS_DISPUTED,
                CanonicalSponsorLineageReason.ANCESTOR_DISPUTED,
                CanonicalSponsorLineageReason.TARGET_DISPUTED,
            },
            CanonicalSponsorLineageState.LINEAGE_INACTIVE: {
                CanonicalSponsorLineageReason.GENESIS_LINEAGE_INACTIVE,
                CanonicalSponsorLineageReason.ANCESTOR_EDGE_INACTIVE,
                CanonicalSponsorLineageReason.TARGET_EDGE_INACTIVE,
            },
            CanonicalSponsorLineageState.UNKNOWN: {
                CanonicalSponsorLineageReason.GENESIS_UNKNOWN,
                CanonicalSponsorLineageReason.ANCESTOR_LOCAL_EVALUATION_UNKNOWN,
                CanonicalSponsorLineageReason.TARGET_LOCAL_EVALUATION_UNKNOWN,
                CanonicalSponsorLineageReason.MISSING_TARGET_EVIDENCE,
                CanonicalSponsorLineageReason.MISSING_PARENT_EVIDENCE,
                CanonicalSponsorLineageReason.PARENT_DIGEST_MISMATCH,
                CanonicalSponsorLineageReason.PARENT_IDENTITY_MISMATCH,
                CanonicalSponsorLineageReason.PARENT_DEPTH_MISMATCH,
                CanonicalSponsorLineageReason.PARENT_GRAPH_OR_PROFILE_MISMATCH,
                CanonicalSponsorLineageReason.DUPLICATE_EDGE_ID,
                CanonicalSponsorLineageReason.DUPLICATE_EDGE_DIGEST,
                CanonicalSponsorLineageReason.DUPLICATE_CHILD_IDENTITY,
                CanonicalSponsorLineageReason.CYCLE_DETECTED,
                CanonicalSponsorLineageReason.EXTRANEOUS_EDGE_EVIDENCE,
                CanonicalSponsorLineageReason.MAXIMUM_DEPTH_EXCEEDED,
                CanonicalSponsorLineageReason.MALFORMED_OR_UNTRUSTED_INPUT,
            },
        }
        if self.reason_code not in state_reasons[self.state]:
            raise InvalidCanonicalSponsorLineage("lineage state reason")
        genesis_reasons = {
            CanonicalSponsorLineageReason.GENESIS_PROVISIONAL,
            CanonicalSponsorLineageReason.GENESIS_DISPUTED,
            CanonicalSponsorLineageReason.GENESIS_LINEAGE_INACTIVE,
            CanonicalSponsorLineageReason.GENESIS_UNKNOWN,
        }
        ancestor_reasons = {
            CanonicalSponsorLineageReason.ANCESTOR_PROVISIONAL,
            CanonicalSponsorLineageReason.ANCESTOR_DISPUTED,
            CanonicalSponsorLineageReason.ANCESTOR_EDGE_INACTIVE,
            CanonicalSponsorLineageReason.ANCESTOR_LOCAL_EVALUATION_UNKNOWN,
        }
        target_reasons = {
            CanonicalSponsorLineageReason.TARGET_PROVISIONAL,
            CanonicalSponsorLineageReason.TARGET_DISPUTED,
            CanonicalSponsorLineageReason.TARGET_EDGE_INACTIVE,
            CanonicalSponsorLineageReason.TARGET_LOCAL_EVALUATION_UNKNOWN,
        }
        if self.state is CanonicalSponsorLineageState.ACTIVE:
            if (
                self.controlling_depth is not None
                or self.controlling_edge_id is not None
                or not self.lineage_nodes
                or any(
                    node.local_evaluation_state
                    is not AdmissionEdgeEvaluationState.ACTIVE
                    for node in self.lineage_nodes
                )
                or len(self.relevant_records) != 1 + 2 * self.target_depth
            ):
                raise InvalidCanonicalSponsorLineage("active lineage")
        elif self.reason_code in genesis_reasons:
            if self.controlling_depth != 0 or self.controlling_edge_id is not None:
                raise InvalidCanonicalSponsorLineage("genesis control")
        elif self.reason_code in ancestor_reasons | target_reasons:
            if (
                type(self.controlling_depth) is not int
                or not 1 <= self.controlling_depth <= len(self.lineage_nodes)
                or self.controlling_edge_id
                != self.lineage_nodes[self.controlling_depth - 1].edge_id
                or (
                    self.reason_code in ancestor_reasons
                    and self.controlling_depth == self.target_depth
                )
                or (
                    self.reason_code in target_reasons
                    and self.controlling_depth != self.target_depth
                )
            ):
                raise InvalidCanonicalSponsorLineage("edge control")
        elif self.controlling_depth is not None or self.controlling_edge_id is not None:
            raise InvalidCanonicalSponsorLineage("structural control")


def _canonical_genesis_reference(
    value: CanonicalGenesisEvaluation,
) -> tuple[str, str]:
    """Resolve the one immutable genesis record controlling this snapshot."""
    value = CanonicalGenesisEvaluation(
        *(getattr(value, field) for field in value.__dataclass_fields__)
    )
    if value.state is CanonicalGenesisEvaluationState.GENESIS_ACTIVE:
        selected = (
            value.selected_effective_record_id,
            value.selected_effective_record_sha256,
        )
        if selected not in value.relevant_records:
            raise InvalidCanonicalSponsorLineage("selected genesis relevance")
        return selected
    if len(value.relevant_records) != 1:
        raise InvalidCanonicalSponsorLineage("ambiguous genesis reference")
    (controlling,) = value.relevant_records
    return controlling


def _result(reason, evaluated_at, target_edge_id, *, target=None, nodes=(), genesis=None,
            state=CanonicalSponsorLineageState.UNKNOWN, control_depth=None, control_edge=None,
            relevant=()):
    return CanonicalSponsorLineageEvaluation(
        SCHEMA, EVALUATOR_VERSION, VERIFICATION_RULE, GRAPH_ID, NETWORK, HUMAN_PROFILE,
        target_edge_id,
        canonical_admission_edge_sha256(target) if target else None,
        target.child_participant_id if target else None,
        target.child_compressed_public_key if target else None,
        target.child_x_only_public_key if target else None,
        target.child_depth if target else None,
        evaluated_at, state, reason, control_depth, control_edge,
        genesis[0] if genesis else None, genesis[1] if genesis else None,
        tuple(nodes), tuple(sorted(relevant)), MANDATORY_NON_CLAIMS, True,
    )


def evaluate_canonical_sponsor_lineage(
    target_edge_id: str, *, edge_evidence: tuple[CanonicalSponsorLineageEdgeEvidence, ...],
    genesis_evaluation: CanonicalGenesisEvaluation, evaluated_at: datetime,
) -> CanonicalSponsorLineageEvaluation:
    """Resolve and evaluate one exact finite lineage snapshot, fail closed."""
    evaluated_at = _utc(evaluated_at)
    _uuid(target_edge_id)
    try:
        if type(edge_evidence) is not tuple:
            raise InvalidCanonicalSponsorLineage("evidence tuple")
        genesis_evaluation = CanonicalGenesisEvaluation(*(
            getattr(genesis_evaluation, f) for f in CanonicalGenesisEvaluation.__dataclass_fields__
        ))
        rebuilt = tuple(CanonicalSponsorLineageEdgeEvidence(
            x.record, x.trusted_registration, x.observation_evaluation
        ) for x in edge_evidence if type(x) is CanonicalSponsorLineageEdgeEvidence)
        if len(rebuilt) != len(edge_evidence):
            raise InvalidCanonicalSponsorLineage("evidence type")
    except Exception:
        return _result(CanonicalSponsorLineageReason.MALFORMED_OR_UNTRUSTED_INPUT,
                       evaluated_at, target_edge_id)
    ids = [x.record.edge_id for x in rebuilt]
    if len(ids) != len(set(ids)):
        return _result(CanonicalSponsorLineageReason.DUPLICATE_EDGE_ID, evaluated_at, target_edge_id)
    digests = [canonical_admission_edge_sha256(x.record) for x in rebuilt]
    if len(digests) != len(set(digests)):
        return _result(CanonicalSponsorLineageReason.DUPLICATE_EDGE_DIGEST, evaluated_at, target_edge_id)
    index = {x.record.edge_id: x for x in rebuilt}
    if target_edge_id not in index:
        return _result(CanonicalSponsorLineageReason.MISSING_TARGET_EVIDENCE, evaluated_at, target_edge_id)
    target = index[target_edge_id].record
    if target.child_depth > MAXIMUM_CANONICAL_CHILD_DEPTH:
        return _result(CanonicalSponsorLineageReason.MAXIMUM_DEPTH_EXCEEDED,
                       evaluated_at, target_edge_id, target=target)
    path, visited_ids, visited_digests, child_ids, child_keys = [], set(), set(), set(), set()
    current = index[target_edge_id]
    while True:
        record = current.record
        digest = canonical_admission_edge_sha256(record)
        if record.edge_id in visited_ids or digest in visited_digests:
            return _result(CanonicalSponsorLineageReason.CYCLE_DETECTED,
                           evaluated_at, target_edge_id, target=target)
        if record.child_participant_id in child_ids or record.child_x_only_public_key in child_keys:
            return _result(CanonicalSponsorLineageReason.DUPLICATE_CHILD_IDENTITY,
                           evaluated_at, target_edge_id, target=target)
        visited_ids.add(record.edge_id); visited_digests.add(digest)
        child_ids.add(record.child_participant_id); child_keys.add(record.child_x_only_public_key)
        path.append(current)
        if record.child_depth == 1:
            break
        parent = index.get(record.sponsor_basis_record_id)
        if parent is None:
            return _result(CanonicalSponsorLineageReason.MISSING_PARENT_EVIDENCE,
                           evaluated_at, target_edge_id, target=target)
        p = parent.record
        if canonical_admission_edge_sha256(p) != record.sponsor_basis_record_sha256:
            reason = CanonicalSponsorLineageReason.PARENT_DIGEST_MISMATCH
        elif p.graph_or_protocol_id != record.graph_or_protocol_id or p.human_profile != record.human_profile:
            reason = CanonicalSponsorLineageReason.PARENT_GRAPH_OR_PROFILE_MISMATCH
        elif p.child_depth != record.sponsor_depth or record.child_depth != record.sponsor_depth + 1:
            reason = CanonicalSponsorLineageReason.PARENT_DEPTH_MISMATCH
        elif (p.child_participant_id, p.child_compressed_public_key, p.child_x_only_public_key) != (
            record.sponsor_participant_id, record.sponsor_compressed_public_key,
            record.sponsor_x_only_public_key):
            reason = CanonicalSponsorLineageReason.PARENT_IDENTITY_MISMATCH
        else:
            current = parent
            continue
        return _result(reason, evaluated_at, target_edge_id, target=target)
    path.reverse()
    if len(path) != target.child_depth or len(rebuilt) != target.child_depth:
        return _result(CanonicalSponsorLineageReason.EXTRANEOUS_EDGE_EVIDENCE,
                       evaluated_at, target_edge_id, target=target)
    try:
        genesis = _canonical_genesis_reference(genesis_evaluation)
    except InvalidCanonicalSponsorLineage:
        return _result(
            CanonicalSponsorLineageReason.MALFORMED_OR_UNTRUSTED_INPUT,
            evaluated_at,
            target_edge_id,
            target=target,
        )
    root = path[0].record
    if root.sponsor_basis_record_id != genesis[0] or (
        root.sponsor_basis_record_sha256 != genesis[1]
    ):
        return _result(CanonicalSponsorLineageReason.PARENT_DIGEST_MISMATCH,
                       evaluated_at, target_edge_id, target=target)
    nodes, locals_, relevant = [], [], [genesis]
    for position, evidence in enumerate(path):
        parent = None if position == 0 else path[position - 1].record
        local = evaluate_canonical_admission_edge_current(
            evidence.record, trusted_registration=evidence.trusted_registration,
            observation_evaluation=evidence.observation_evaluation,
            genesis_evaluation=genesis_evaluation if position == 0 else None,
            parent_edge=parent, evaluated_at=evaluated_at,
        )
        locals_.append(local)
        record, registration = evidence.record, evidence.trusted_registration
        nodes.append(CanonicalSponsorLineageNode(
            record.child_depth, record.edge_id, canonical_admission_edge_sha256(record),
            record.sponsor_participant_id, record.sponsor_compressed_public_key,
            record.sponsor_x_only_public_key, record.child_participant_id,
            record.child_compressed_public_key, record.child_x_only_public_key,
            local.state, local.reason_code, registration.registration_id,
            trusted_registration_sha256(registration), record.sponsor_basis_record_id,
            record.sponsor_basis_record_sha256,
            covenant_relation_source_sha256(evidence.observation_evaluation),
            canonical_admission_edge_current_evaluation_sha256(local),
        ))
        relevant.extend(((record.edge_id, canonical_admission_edge_sha256(record)),
                         (registration.registration_id, trusted_registration_sha256(registration))))
    genesis_map = {
        CanonicalGenesisEvaluationState.PROVISIONAL: (CanonicalSponsorLineageState.PROVISIONAL,
            CanonicalSponsorLineageReason.GENESIS_PROVISIONAL),
        CanonicalGenesisEvaluationState.DISPUTED: (CanonicalSponsorLineageState.DISPUTED,
            CanonicalSponsorLineageReason.GENESIS_DISPUTED),
        CanonicalGenesisEvaluationState.LINEAGE_INACTIVE: (CanonicalSponsorLineageState.LINEAGE_INACTIVE,
            CanonicalSponsorLineageReason.GENESIS_LINEAGE_INACTIVE),
        CanonicalGenesisEvaluationState.UNKNOWN: (CanonicalSponsorLineageState.UNKNOWN,
            CanonicalSponsorLineageReason.GENESIS_UNKNOWN),
    }
    if genesis_evaluation.state in genesis_map:
        state, reason = genesis_map[genesis_evaluation.state]
        return _result(reason, evaluated_at, target_edge_id, target=target, nodes=nodes,
                       genesis=genesis, state=state, control_depth=0, relevant=relevant)
    for position, local in enumerate(locals_, 1):
        if local.state is AdmissionEdgeEvaluationState.ACTIVE:
            continue
        target_control = position == target.child_depth
        mapping = {
            AdmissionEdgeEvaluationState.PROVISIONAL: (
                CanonicalSponsorLineageState.PROVISIONAL,
                CanonicalSponsorLineageReason.TARGET_PROVISIONAL if target_control
                else CanonicalSponsorLineageReason.ANCESTOR_PROVISIONAL),
            AdmissionEdgeEvaluationState.DISPUTED: (
                CanonicalSponsorLineageState.DISPUTED,
                CanonicalSponsorLineageReason.TARGET_DISPUTED if target_control
                else CanonicalSponsorLineageReason.ANCESTOR_DISPUTED),
            AdmissionEdgeEvaluationState.EDGE_INACTIVE: (
                CanonicalSponsorLineageState.LINEAGE_INACTIVE,
                CanonicalSponsorLineageReason.TARGET_EDGE_INACTIVE if target_control
                else CanonicalSponsorLineageReason.ANCESTOR_EDGE_INACTIVE),
            AdmissionEdgeEvaluationState.UNKNOWN: (
                CanonicalSponsorLineageState.UNKNOWN,
                CanonicalSponsorLineageReason.TARGET_LOCAL_EVALUATION_UNKNOWN if target_control
                else CanonicalSponsorLineageReason.ANCESTOR_LOCAL_EVALUATION_UNKNOWN),
        }
        state, reason = mapping[local.state]
        return _result(reason, evaluated_at, target_edge_id, target=target, nodes=nodes,
                       genesis=genesis, state=state, control_depth=position,
                       control_edge=local.edge_id, relevant=relevant)
    return _result(CanonicalSponsorLineageReason.EXACT_LINEAGE_ACTIVE, evaluated_at,
                   target_edge_id, target=target, nodes=nodes, genesis=genesis,
                   state=CanonicalSponsorLineageState.ACTIVE, relevant=relevant)


def _dict(value: CanonicalSponsorLineageEvaluation) -> dict:
    payload = {f: getattr(value, f) for f in value.__dataclass_fields__}
    payload["evaluated_at"] = value.evaluated_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    payload["state"] = value.state.value
    payload["reason_code"] = value.reason_code.value
    payload["lineage_nodes"] = [
        {
            f: (
                getattr(node, f).value
                if f in ("local_evaluation_state", "local_evaluation_reason")
                else getattr(node, f)
            )
            for f in node.__dataclass_fields__
        }
        for node in value.lineage_nodes
    ]
    payload["relevant_records"] = [list(x) for x in value.relevant_records]
    payload["explicit_non_claims"] = list(value.explicit_non_claims)
    return payload


def canonical_sponsor_lineage_evaluation_bytes(value: CanonicalSponsorLineageEvaluation) -> bytes:
    if type(value) is not CanonicalSponsorLineageEvaluation:
        raise InvalidCanonicalSponsorLineage("evaluation type")
    try:
        value = CanonicalSponsorLineageEvaluation(*(
            getattr(value, f) for f in CanonicalSponsorLineageEvaluation.__dataclass_fields__
        ))
    except InvalidCanonicalSponsorLineage:
        raise
    except Exception:
        raise InvalidCanonicalSponsorLineage("evaluation value") from None
    return json.dumps(_dict(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def canonical_sponsor_lineage_evaluation_sha256(value: CanonicalSponsorLineageEvaluation) -> str:
    return sha256(canonical_sponsor_lineage_evaluation_bytes(value)).hexdigest()


def parse_canonical_sponsor_lineage_evaluation(value: bytes | str) -> CanonicalSponsorLineageEvaluation:
    if type(value) is bytes:
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            raise InvalidCanonicalSponsorLineage("ASCII") from None
    if type(value) is not str:
        raise InvalidCanonicalSponsorLineage("JSON")
    try:
        def pairs(items):
            result = {}
            for key, item in items:
                if key in result:
                    raise ValueError()
                result[key] = item
            return result

        data = json.loads(
            value,
            parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            object_pairs_hook=pairs,
        )
        if type(data) is not dict or set(data) != set(CanonicalSponsorLineageEvaluation.__dataclass_fields__):
            raise ValueError()
        nodes = data["lineage_nodes"]
        if type(nodes) is not list or any(
            type(x) is not dict or set(x) != set(CanonicalSponsorLineageNode.__dataclass_fields__)
            for x in nodes
        ):
            raise ValueError()
        timestamp = data["evaluated_at"]
        if type(timestamp) is not str or not timestamp.endswith("Z"):
            raise ValueError()
        result = CanonicalSponsorLineageEvaluation(**{
            **data,
            "evaluated_at": datetime.fromisoformat(timestamp[:-1] + "+00:00"),
            "state": CanonicalSponsorLineageState(data["state"]),
            "reason_code": CanonicalSponsorLineageReason(data["reason_code"]),
            "lineage_nodes": tuple(
                CanonicalSponsorLineageNode(
                    **{
                        **x,
                        "local_evaluation_state": AdmissionEdgeEvaluationState(
                            x["local_evaluation_state"]
                        ),
                        "local_evaluation_reason": AdmissionEdgeCurrentReason(
                            x["local_evaluation_reason"]
                        ),
                    }
                )
                for x in nodes
            ),
            "relevant_records": tuple(tuple(x) for x in data["relevant_records"]),
            "explicit_non_claims": tuple(data["explicit_non_claims"]),
        })
    except Exception:
        raise InvalidCanonicalSponsorLineage("JSON") from None
    if canonical_sponsor_lineage_evaluation_bytes(result).decode("ascii") != value:
        raise InvalidCanonicalSponsorLineage("noncanonical JSON")
    return result
