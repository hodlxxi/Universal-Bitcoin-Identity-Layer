"""Pure, dormant canonical CRT Membership Evaluator V1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from hashlib import sha256
import json
import re
import uuid

from app.services.canonical_genesis_record import (
    COMPRESSED_KEY as GENESIS_COMPRESSED_KEY,
    GRAPH_ID,
    PARTICIPANT_ID as GENESIS_PARTICIPANT_ID,
    XONLY_KEY as GENESIS_XONLY_KEY,
    CanonicalGenesisEvaluation,
    CanonicalGenesisEvaluationState,
    canonical_genesis_evaluation_bytes,
    canonical_genesis_evaluation_sha256,
    parse_canonical_genesis_evaluation,
)
from app.services.canonical_sponsor_lineage import (
    HUMAN_PROFILE,
    NETWORK,
    CanonicalSponsorLineageEvaluation,
    CanonicalSponsorLineageReason,
    CanonicalSponsorLineageState,
    canonical_sponsor_lineage_evaluation_bytes,
    canonical_sponsor_lineage_evaluation_sha256,
    parse_canonical_sponsor_lineage_evaluation,
)

SCHEMA = "hodlxxi.canonical_crt_membership_evaluation.v1"
EVALUATOR_VERSION = "hodlxxi.canonical_crt_membership_evaluator.v1"
VERIFICATION_RULE = "hodlxxi.canonical_crt_membership_verification.v1"

MANDATORY_NON_CLAIMS = tuple(sorted((
    "no FULL/LIMITED authorization grant",
    "no automatic Bitcoin RPC observation claim",
    "no automatic storage lookup claim",
    "no decentralization or universal-legitimacy proof",
    "no entitlement or user-role write",
    "no fairness or informed-consent proof",
    "no invite or sponsor permission grant",
    "no legal identity, KYC or complete personhood proof",
    "no ownership, custody or guardianship proof",
    "no production enforcement or deployment claim",
    "no proof of current private-key possession",
    "no reputation, rank or trustworthiness grant",
    "no runtime administration or server-privilege grant",
    "no sincerity, loyalty or future-cooperation guarantee",
    "no sponsor ownership or control over a participant",
    "no validity for current_144 or cooperative admission templates",
    "no validity outside the exact source evaluation and evaluated_at",
)))

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX66 = re.compile(r"(?:02|03)[0-9a-f]{64}\Z")


class InvalidCanonicalCrtMembership(ValueError):
    """The request or canonical membership result violates the V1 contract."""


class CanonicalCrtMembershipSubjectKind(Enum):
    GENESIS = "genesis"
    ORDINARY = "ordinary"


class CanonicalCrtMembershipSourceKind(Enum):
    CANONICAL_GENESIS_EVALUATION = "canonical_genesis_evaluation"
    CANONICAL_SPONSOR_LINEAGE_EVALUATION = "canonical_sponsor_lineage_evaluation"


class CanonicalCrtMembershipState(Enum):
    GENESIS_ACTIVE = "genesis_active"
    ACTIVE = "active"
    PROVISIONAL = "provisional"
    EDGE_INACTIVE = "edge_inactive"
    LINEAGE_INACTIVE = "lineage_inactive"
    DISPUTED = "disputed"
    UNKNOWN = "unknown"


class CanonicalCrtMembershipReason(Enum):
    EXACT_GENESIS_MEMBERSHIP_ACTIVE = "exact_genesis_membership_active"
    EXACT_PARTICIPANT_MEMBERSHIP_ACTIVE = "exact_participant_membership_active"
    GENESIS_PROVISIONAL = "genesis_provisional"
    ANCESTOR_PROVISIONAL = "ancestor_provisional"
    TARGET_PROVISIONAL = "target_provisional"
    GENESIS_DISPUTED = "genesis_disputed"
    ANCESTOR_DISPUTED = "ancestor_disputed"
    TARGET_DISPUTED = "target_disputed"
    TARGET_EDGE_INACTIVE = "target_edge_inactive"
    ANCESTOR_EDGE_INACTIVE = "ancestor_edge_inactive"
    GENESIS_LINEAGE_INACTIVE = "genesis_lineage_inactive"
    GENESIS_UNKNOWN = "genesis_unknown"
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
    SOURCE_KIND_MISMATCH = "source_kind_mismatch"
    SOURCE_SUBJECT_MISMATCH = "source_subject_mismatch"
    SOURCE_TIME_MISMATCH = "source_time_mismatch"
    SOURCE_GRAPH_OR_PROFILE_MISMATCH = "source_graph_or_profile_mismatch"


_GENESIS_SOURCE_STATE_REASONS = {
    CanonicalGenesisEvaluationState.GENESIS_ACTIVE: {"exact_effective_record"},
    CanonicalGenesisEvaluationState.PROVISIONAL: {"proposed_only"},
    CanonicalGenesisEvaluationState.DISPUTED: {
        "controlling_dispute",
        "multiple_effective_records",
    },
    CanonicalGenesisEvaluationState.LINEAGE_INACTIVE: {
        "all_records_revoked",
        "succession_policy_unavailable",
    },
    CanonicalGenesisEvaluationState.UNKNOWN: {
        "effective_timestamp_in_future",
        "malformed_or_untrusted_input",
        "multiple_records_without_transition_policy",
        "no_records",
        "succession_policy_unavailable",
    },
}

_LINEAGE_SOURCE_STATE_REASONS = {
    CanonicalSponsorLineageState.ACTIVE: {
        CanonicalSponsorLineageReason.EXACT_LINEAGE_ACTIVE,
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


def _validate_genesis_source_state_reason(
    source_state: str, source_reason_code: str
) -> CanonicalGenesisEvaluationState:
    try:
        state = CanonicalGenesisEvaluationState(source_state)
    except (TypeError, ValueError):
        raise InvalidCanonicalCrtMembership("genesis source state") from None
    if (
        type(source_reason_code) is not str
        or source_reason_code not in _GENESIS_SOURCE_STATE_REASONS[state]
    ):
        raise InvalidCanonicalCrtMembership("genesis source reason")
    return state


def _validate_lineage_source_state_reason(
    source_state: str, source_reason_code: str
) -> tuple[CanonicalSponsorLineageState, CanonicalSponsorLineageReason]:
    try:
        state = CanonicalSponsorLineageState(source_state)
        reason = CanonicalSponsorLineageReason(source_reason_code)
    except (TypeError, ValueError):
        raise InvalidCanonicalCrtMembership("lineage source enum") from None
    if reason not in _LINEAGE_SOURCE_STATE_REASONS[state]:
        raise InvalidCanonicalCrtMembership("lineage source state reason")
    return state, reason


_STATE_REASONS = {
    CanonicalCrtMembershipState.GENESIS_ACTIVE: {
        CanonicalCrtMembershipReason.EXACT_GENESIS_MEMBERSHIP_ACTIVE,
    },
    CanonicalCrtMembershipState.ACTIVE: {
        CanonicalCrtMembershipReason.EXACT_PARTICIPANT_MEMBERSHIP_ACTIVE,
    },
    CanonicalCrtMembershipState.PROVISIONAL: {
        CanonicalCrtMembershipReason.GENESIS_PROVISIONAL,
        CanonicalCrtMembershipReason.ANCESTOR_PROVISIONAL,
        CanonicalCrtMembershipReason.TARGET_PROVISIONAL,
    },
    CanonicalCrtMembershipState.EDGE_INACTIVE: {
        CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE,
    },
    CanonicalCrtMembershipState.LINEAGE_INACTIVE: {
        CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE,
        CanonicalCrtMembershipReason.GENESIS_LINEAGE_INACTIVE,
    },
    CanonicalCrtMembershipState.DISPUTED: {
        CanonicalCrtMembershipReason.GENESIS_DISPUTED,
        CanonicalCrtMembershipReason.ANCESTOR_DISPUTED,
        CanonicalCrtMembershipReason.TARGET_DISPUTED,
    },
    CanonicalCrtMembershipState.UNKNOWN: {
        reason for reason in CanonicalCrtMembershipReason
        if reason.value.endswith("unknown")
        or reason in {
            CanonicalCrtMembershipReason.MISSING_TARGET_EVIDENCE,
            CanonicalCrtMembershipReason.MISSING_PARENT_EVIDENCE,
            CanonicalCrtMembershipReason.PARENT_DIGEST_MISMATCH,
            CanonicalCrtMembershipReason.PARENT_IDENTITY_MISMATCH,
            CanonicalCrtMembershipReason.PARENT_DEPTH_MISMATCH,
            CanonicalCrtMembershipReason.PARENT_GRAPH_OR_PROFILE_MISMATCH,
            CanonicalCrtMembershipReason.DUPLICATE_EDGE_ID,
            CanonicalCrtMembershipReason.DUPLICATE_EDGE_DIGEST,
            CanonicalCrtMembershipReason.DUPLICATE_CHILD_IDENTITY,
            CanonicalCrtMembershipReason.CYCLE_DETECTED,
            CanonicalCrtMembershipReason.EXTRANEOUS_EDGE_EVIDENCE,
            CanonicalCrtMembershipReason.MAXIMUM_DEPTH_EXCEEDED,
            CanonicalCrtMembershipReason.MALFORMED_OR_UNTRUSTED_INPUT,
            CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH,
            CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH,
            CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH,
            CanonicalCrtMembershipReason.SOURCE_GRAPH_OR_PROFILE_MISMATCH,
        }
    },
}


def _utc(value: object) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond
    ):
        raise InvalidCanonicalCrtMembership("evaluated_at")
    return value


def _uuid(value: object) -> str:
    if type(value) is not str:
        raise InvalidCanonicalCrtMembership("uuid")
    try:
        canonical = str(uuid.UUID(value))
    except ValueError:
        raise InvalidCanonicalCrtMembership("uuid") from None
    if value != canonical:
        raise InvalidCanonicalCrtMembership("uuid")
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise InvalidCanonicalCrtMembership("digest")
    return value


@dataclass(frozen=True, slots=True)
class CanonicalCrtMembershipEvaluation:
    schema: str
    evaluator_version: str
    verification_rule: str
    graph_or_protocol_id: str
    network: str
    human_profile: str
    subject_kind: CanonicalCrtMembershipSubjectKind
    participant_id: str
    compressed_public_key: str
    x_only_public_key: str
    depth: int
    target_edge_id: str | None
    target_edge_sha256: str | None
    evaluated_at: datetime
    state: CanonicalCrtMembershipState
    reason_code: CanonicalCrtMembershipReason
    source_evaluation_kind: CanonicalCrtMembershipSourceKind
    source_evaluation_sha256: str
    source_state: str
    source_reason_code: str
    controlling_depth: int | None
    controlling_edge_id: str | None
    selected_genesis_record_id: str | None
    selected_genesis_record_sha256: str | None
    relevant_records: tuple[tuple[str, str], ...]
    explicit_non_claims: tuple[str, ...]
    human_interpretation_required: bool

    def __post_init__(self):
        if (
            (
                self.schema,
                self.evaluator_version,
                self.verification_rule,
                self.graph_or_protocol_id,
                self.network,
                self.human_profile,
            )
            != (SCHEMA, EVALUATOR_VERSION, VERIFICATION_RULE, GRAPH_ID, NETWORK, HUMAN_PROFILE)
            or type(self.subject_kind) is not CanonicalCrtMembershipSubjectKind
            or type(self.state) is not CanonicalCrtMembershipState
            or type(self.reason_code) is not CanonicalCrtMembershipReason
            or type(self.source_evaluation_kind) is not CanonicalCrtMembershipSourceKind
            or self.reason_code not in _STATE_REASONS[self.state]
            or self.explicit_non_claims != MANDATORY_NON_CLAIMS
            or self.human_interpretation_required is not True
        ):
            raise InvalidCanonicalCrtMembership("fixed result contract")
        _utc(self.evaluated_at)
        if type(self.depth) is not int or self.depth < 0:
            raise InvalidCanonicalCrtMembership("depth")
        if type(self.compressed_public_key) is not str or _HEX66.fullmatch(
            self.compressed_public_key
        ) is None or self.compressed_public_key[2:] != self.x_only_public_key:
            raise InvalidCanonicalCrtMembership("participant key")
        _digest(self.x_only_public_key)
        _digest(self.source_evaluation_sha256)
        if type(self.source_state) is not str or not self.source_state:
            raise InvalidCanonicalCrtMembership("source state")
        if type(self.source_reason_code) is not str or not self.source_reason_code:
            raise InvalidCanonicalCrtMembership("source reason")
        if self.source_evaluation_kind is CanonicalCrtMembershipSourceKind.CANONICAL_GENESIS_EVALUATION:
            source_state = _validate_genesis_source_state_reason(
                self.source_state, self.source_reason_code
            )
            source_reason = None
        else:
            source_state, source_reason = _validate_lineage_source_state_reason(
                self.source_state, self.source_reason_code
            )
        expected_source_kind = (
            CanonicalCrtMembershipSourceKind.CANONICAL_GENESIS_EVALUATION
            if self.subject_kind is CanonicalCrtMembershipSubjectKind.GENESIS
            else CanonicalCrtMembershipSourceKind.CANONICAL_SPONSOR_LINEAGE_EVALUATION
        )
        kind_mismatch = self.source_evaluation_kind is not expected_source_kind
        if kind_mismatch != (
            self.state is CanonicalCrtMembershipState.UNKNOWN
            and self.reason_code is CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH
        ):
            raise InvalidCanonicalCrtMembership("source kind subject")
        if self.subject_kind is CanonicalCrtMembershipSubjectKind.GENESIS:
            if (
                (self.participant_id, self.compressed_public_key, self.x_only_public_key, self.depth)
                != (GENESIS_PARTICIPANT_ID, GENESIS_COMPRESSED_KEY, GENESIS_XONLY_KEY, 0)
                or self.target_edge_id is not None
                or self.target_edge_sha256 is not None
            ):
                raise InvalidCanonicalCrtMembership("genesis subject")
        elif (
            self.depth < 1
            or self.participant_id != self.x_only_public_key
            or self.participant_id == GENESIS_PARTICIPANT_ID
            or self.target_edge_id is None
        ):
            raise InvalidCanonicalCrtMembership("ordinary subject")
        if self.target_edge_id is not None:
            _uuid(self.target_edge_id)
        if self.target_edge_sha256 is not None:
            _digest(self.target_edge_sha256)
        if self.subject_kind is CanonicalCrtMembershipSubjectKind.ORDINARY and (
            self.target_edge_sha256 is None
            and self.source_reason_code
            not in {
                CanonicalSponsorLineageReason.MISSING_TARGET_EVIDENCE.value,
                CanonicalSponsorLineageReason.MALFORMED_OR_UNTRUSTED_INPUT.value,
            }
            and self.source_state != CanonicalSponsorLineageState.UNKNOWN.value
            and not self.reason_code.value.startswith("source_")
        ):
            raise InvalidCanonicalCrtMembership("missing target digest")
        if (self.selected_genesis_record_id is None) != (
            self.selected_genesis_record_sha256 is None
        ):
            raise InvalidCanonicalCrtMembership("partial genesis reference")
        if self.selected_genesis_record_id is not None:
            _uuid(self.selected_genesis_record_id)
            _digest(self.selected_genesis_record_sha256)
        if (
            type(self.relevant_records) is not tuple
            or self.relevant_records != tuple(sorted(self.relevant_records))
            or len({item[0] for item in self.relevant_records}) != len(self.relevant_records)
        ):
            raise InvalidCanonicalCrtMembership("relevant records")
        for record_id, digest in self.relevant_records:
            _uuid(record_id)
            _digest(digest)
        if (
            self.target_edge_sha256 is not None
            and (self.target_edge_id, self.target_edge_sha256) not in self.relevant_records
        ):
            raise InvalidCanonicalCrtMembership("target relevance")
        if (
            self.selected_genesis_record_id is not None
            and (
                self.selected_genesis_record_id,
                self.selected_genesis_record_sha256,
            )
            not in self.relevant_records
        ):
            raise InvalidCanonicalCrtMembership("genesis relevance")
        if self.state is CanonicalCrtMembershipState.GENESIS_ACTIVE:
            if (
                self.controlling_depth is not None
                or self.controlling_edge_id is not None
                or self.selected_genesis_record_id is None
                or (
                    self.selected_genesis_record_id,
                    self.selected_genesis_record_sha256,
                )
                not in self.relevant_records
            ):
                raise InvalidCanonicalCrtMembership("active genesis")
        elif self.subject_kind is CanonicalCrtMembershipSubjectKind.GENESIS:
            expected_depth = None if self.reason_code.value.startswith("source_") else 0
            if self.controlling_depth != expected_depth or self.controlling_edge_id is not None:
                raise InvalidCanonicalCrtMembership("genesis control")
        elif self.state is CanonicalCrtMembershipState.ACTIVE:
            if (
                self.controlling_depth is not None
                or self.controlling_edge_id is not None
                or self.target_edge_sha256 is None
                or self.selected_genesis_record_id is None
                or len(self.relevant_records) != 1 + 2 * self.depth
            ):
                raise InvalidCanonicalCrtMembership("active ordinary")
        elif self.reason_code.value.startswith("source_"):
            if self.controlling_depth is not None or self.controlling_edge_id is not None:
                raise InvalidCanonicalCrtMembership("binding control")
        elif self.reason_code in {
            CanonicalCrtMembershipReason.GENESIS_PROVISIONAL,
            CanonicalCrtMembershipReason.GENESIS_DISPUTED,
            CanonicalCrtMembershipReason.GENESIS_LINEAGE_INACTIVE,
            CanonicalCrtMembershipReason.GENESIS_UNKNOWN,
        }:
            if self.controlling_depth != 0 or self.controlling_edge_id is not None:
                raise InvalidCanonicalCrtMembership("genesis lineage control")
        elif self.reason_code in {
            CanonicalCrtMembershipReason.MISSING_TARGET_EVIDENCE,
            CanonicalCrtMembershipReason.MISSING_PARENT_EVIDENCE,
            CanonicalCrtMembershipReason.PARENT_DIGEST_MISMATCH,
            CanonicalCrtMembershipReason.PARENT_IDENTITY_MISMATCH,
            CanonicalCrtMembershipReason.PARENT_DEPTH_MISMATCH,
            CanonicalCrtMembershipReason.PARENT_GRAPH_OR_PROFILE_MISMATCH,
            CanonicalCrtMembershipReason.DUPLICATE_EDGE_ID,
            CanonicalCrtMembershipReason.DUPLICATE_EDGE_DIGEST,
            CanonicalCrtMembershipReason.DUPLICATE_CHILD_IDENTITY,
            CanonicalCrtMembershipReason.CYCLE_DETECTED,
            CanonicalCrtMembershipReason.EXTRANEOUS_EDGE_EVIDENCE,
            CanonicalCrtMembershipReason.MAXIMUM_DEPTH_EXCEEDED,
            CanonicalCrtMembershipReason.MALFORMED_OR_UNTRUSTED_INPUT,
        }:
            if self.controlling_depth is not None or self.controlling_edge_id is not None:
                raise InvalidCanonicalCrtMembership("structural control")
        else:
            if (
                type(self.controlling_depth) is not int
                or not 1 <= self.controlling_depth <= self.depth
                or self.controlling_edge_id is None
            ):
                raise InvalidCanonicalCrtMembership("edge control")
            _uuid(self.controlling_edge_id)
            target_reason = self.reason_code in {
                CanonicalCrtMembershipReason.TARGET_PROVISIONAL,
                CanonicalCrtMembershipReason.TARGET_DISPUTED,
                CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE,
                CanonicalCrtMembershipReason.TARGET_LOCAL_EVALUATION_UNKNOWN,
            }
            if target_reason != (
                self.controlling_depth == self.depth
                and self.controlling_edge_id == self.target_edge_id
            ):
                raise InvalidCanonicalCrtMembership("target control")
        if not self.reason_code.value.startswith("source_"):
            if self.source_evaluation_kind is CanonicalCrtMembershipSourceKind.CANONICAL_GENESIS_EVALUATION:
                expected_state, expected_reason = _GENESIS_MAPPING[source_state]
                if self.state is not expected_state or self.reason_code is not expected_reason:
                    raise InvalidCanonicalCrtMembership("genesis source mapping")
            else:
                expected_state, expected_reason = _LINEAGE_MAPPING[source_reason]
                expected_source_state = {
                    CanonicalCrtMembershipState.ACTIVE: CanonicalSponsorLineageState.ACTIVE,
                    CanonicalCrtMembershipState.PROVISIONAL: CanonicalSponsorLineageState.PROVISIONAL,
                    CanonicalCrtMembershipState.DISPUTED: CanonicalSponsorLineageState.DISPUTED,
                    CanonicalCrtMembershipState.EDGE_INACTIVE:
                        CanonicalSponsorLineageState.LINEAGE_INACTIVE,
                    CanonicalCrtMembershipState.LINEAGE_INACTIVE:
                        CanonicalSponsorLineageState.LINEAGE_INACTIVE,
                    CanonicalCrtMembershipState.UNKNOWN: CanonicalSponsorLineageState.UNKNOWN,
                }[expected_state]
                if (
                    source_state is not expected_source_state
                    or self.state is not expected_state
                    or self.reason_code is not expected_reason
                ):
                    raise InvalidCanonicalCrtMembership("lineage source mapping")


_GENESIS_MAPPING = {
    CanonicalGenesisEvaluationState.GENESIS_ACTIVE: (
        CanonicalCrtMembershipState.GENESIS_ACTIVE,
        CanonicalCrtMembershipReason.EXACT_GENESIS_MEMBERSHIP_ACTIVE,
    ),
    CanonicalGenesisEvaluationState.PROVISIONAL: (
        CanonicalCrtMembershipState.PROVISIONAL,
        CanonicalCrtMembershipReason.GENESIS_PROVISIONAL,
    ),
    CanonicalGenesisEvaluationState.DISPUTED: (
        CanonicalCrtMembershipState.DISPUTED,
        CanonicalCrtMembershipReason.GENESIS_DISPUTED,
    ),
    CanonicalGenesisEvaluationState.LINEAGE_INACTIVE: (
        CanonicalCrtMembershipState.LINEAGE_INACTIVE,
        CanonicalCrtMembershipReason.GENESIS_LINEAGE_INACTIVE,
    ),
    CanonicalGenesisEvaluationState.UNKNOWN: (
        CanonicalCrtMembershipState.UNKNOWN,
        CanonicalCrtMembershipReason.GENESIS_UNKNOWN,
    ),
}

_LINEAGE_MAPPING = {
    CanonicalSponsorLineageReason.EXACT_LINEAGE_ACTIVE: (
        CanonicalCrtMembershipState.ACTIVE,
        CanonicalCrtMembershipReason.EXACT_PARTICIPANT_MEMBERSHIP_ACTIVE,
    ),
    **{
        reason: (
            CanonicalCrtMembershipState.EDGE_INACTIVE
            if reason is CanonicalSponsorLineageReason.TARGET_EDGE_INACTIVE
            else CanonicalCrtMembershipState.LINEAGE_INACTIVE
            if reason in {
                CanonicalSponsorLineageReason.ANCESTOR_EDGE_INACTIVE,
                CanonicalSponsorLineageReason.GENESIS_LINEAGE_INACTIVE,
            }
            else CanonicalCrtMembershipState.PROVISIONAL
            if "provisional" in reason.value
            else CanonicalCrtMembershipState.DISPUTED
            if "disputed" in reason.value
            else CanonicalCrtMembershipState.UNKNOWN,
            CanonicalCrtMembershipReason(reason.value),
        )
        for reason in CanonicalSponsorLineageReason
        if reason is not CanonicalSponsorLineageReason.EXACT_LINEAGE_ACTIVE
    },
}


def _make_result(
    *, subject_kind, participant_id, compressed_public_key, x_only_public_key,
    depth, target_edge_id, target_edge_sha256, evaluated_at, state, reason,
    source_kind, source_digest, source_state, source_reason, control_depth,
    control_edge, selected_id, selected_digest, relevant,
) -> CanonicalCrtMembershipEvaluation:
    return CanonicalCrtMembershipEvaluation(
        SCHEMA, EVALUATOR_VERSION, VERIFICATION_RULE, GRAPH_ID, NETWORK, HUMAN_PROFILE,
        subject_kind, participant_id, compressed_public_key, x_only_public_key, depth,
        target_edge_id, target_edge_sha256, evaluated_at, state, reason, source_kind,
        source_digest, source_state, source_reason, control_depth, control_edge,
        selected_id, selected_digest, tuple(relevant), MANDATORY_NON_CLAIMS, True,
    )


def evaluate_canonical_crt_membership(
    *,
    participant_id: str,
    compressed_public_key: str,
    x_only_public_key: str,
    depth: int,
    evaluated_at: datetime,
    target_edge_id: str | None = None,
    genesis_evaluation: CanonicalGenesisEvaluation | None = None,
    lineage_evaluation: CanonicalSponsorLineageEvaluation | None = None,
) -> CanonicalCrtMembershipEvaluation:
    """Compose exactly one authoritative lower-level evaluation, fail closed."""
    try:
        _utc(evaluated_at)
        if type(depth) is not int or depth < 0:
            raise InvalidCanonicalCrtMembership("depth")
        if type(compressed_public_key) is not str or _HEX66.fullmatch(compressed_public_key) is None:
            raise InvalidCanonicalCrtMembership("compressed key")
        _digest(x_only_public_key)
        if compressed_public_key[2:] != x_only_public_key:
            raise InvalidCanonicalCrtMembership("key correspondence")
        if (genesis_evaluation is None) == (lineage_evaluation is None):
            raise InvalidCanonicalCrtMembership("exactly one source")
        genesis_mode = depth == 0 or participant_id == GENESIS_PARTICIPANT_ID
        if genesis_mode:
            if (
                (participant_id, compressed_public_key, x_only_public_key, depth)
                != (GENESIS_PARTICIPANT_ID, GENESIS_COMPRESSED_KEY, GENESIS_XONLY_KEY, 0)
                or target_edge_id is not None
            ):
                raise InvalidCanonicalCrtMembership("genesis request")
            subject_kind = CanonicalCrtMembershipSubjectKind.GENESIS
        else:
            if depth < 1 or participant_id != x_only_public_key or target_edge_id is None:
                raise InvalidCanonicalCrtMembership("ordinary request")
            _uuid(target_edge_id)
            subject_kind = CanonicalCrtMembershipSubjectKind.ORDINARY
    except InvalidCanonicalCrtMembership:
        raise
    except Exception:
        raise InvalidCanonicalCrtMembership("request") from None

    if subject_kind is CanonicalCrtMembershipSubjectKind.GENESIS:
        if genesis_evaluation is None:
            if type(lineage_evaluation) is not CanonicalSponsorLineageEvaluation:
                raise InvalidCanonicalCrtMembership("source type")
            try:
                source = parse_canonical_sponsor_lineage_evaluation(
                    canonical_sponsor_lineage_evaluation_bytes(lineage_evaluation)
                )
            except Exception:
                raise InvalidCanonicalCrtMembership("source value") from None
            return _make_result(
                subject_kind=subject_kind,
                participant_id=participant_id,
                compressed_public_key=compressed_public_key,
                x_only_public_key=x_only_public_key,
                depth=depth,
                target_edge_id=None,
                target_edge_sha256=None,
                evaluated_at=evaluated_at,
                state=CanonicalCrtMembershipState.UNKNOWN,
                reason=CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH,
                source_kind=CanonicalCrtMembershipSourceKind.CANONICAL_SPONSOR_LINEAGE_EVALUATION,
                source_digest=canonical_sponsor_lineage_evaluation_sha256(source),
                source_state=source.state.value,
                source_reason=source.reason_code.value,
                control_depth=None,
                control_edge=None,
                selected_id=source.selected_genesis_record_id,
                selected_digest=source.selected_genesis_record_sha256,
                relevant=source.relevant_records,
            )
        if type(genesis_evaluation) is not CanonicalGenesisEvaluation:
            raise InvalidCanonicalCrtMembership("source type")
        try:
            source = parse_canonical_genesis_evaluation(
                canonical_genesis_evaluation_bytes(genesis_evaluation)
            )
        except Exception:
            raise InvalidCanonicalCrtMembership("source value") from None
        state, reason = _GENESIS_MAPPING[source.state]
        if source.graph_or_protocol_id != GRAPH_ID:
            state, reason = (
                CanonicalCrtMembershipState.UNKNOWN,
                CanonicalCrtMembershipReason.SOURCE_GRAPH_OR_PROFILE_MISMATCH,
            )
        elif source.evaluated_at != evaluated_at:
            state, reason = (
                CanonicalCrtMembershipState.UNKNOWN,
                CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH,
            )
        elif (
            source.genesis_participant_id,
            source.compressed_public_key,
            source.x_only_public_key,
        ) != (participant_id, compressed_public_key, x_only_public_key):
            state, reason = (
                CanonicalCrtMembershipState.UNKNOWN,
                CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH,
            )
        binding = reason.value.startswith("source_")
        return _make_result(
            subject_kind=subject_kind, participant_id=participant_id,
            compressed_public_key=compressed_public_key, x_only_public_key=x_only_public_key,
            depth=depth, target_edge_id=None, target_edge_sha256=None,
            evaluated_at=evaluated_at, state=state, reason=reason,
            source_kind=CanonicalCrtMembershipSourceKind.CANONICAL_GENESIS_EVALUATION,
            source_digest=canonical_genesis_evaluation_sha256(source),
            source_state=source.state.value, source_reason=source.reason_code,
            control_depth=None if state is CanonicalCrtMembershipState.GENESIS_ACTIVE or binding else 0,
            control_edge=None, selected_id=source.selected_effective_record_id,
            selected_digest=source.selected_effective_record_sha256,
            relevant=source.relevant_records,
        )

    if lineage_evaluation is None:
        if type(genesis_evaluation) is not CanonicalGenesisEvaluation:
            raise InvalidCanonicalCrtMembership("source type")
        try:
            source = parse_canonical_genesis_evaluation(
                canonical_genesis_evaluation_bytes(genesis_evaluation)
            )
        except Exception:
            raise InvalidCanonicalCrtMembership("source value") from None
        return _make_result(
            subject_kind=subject_kind,
            participant_id=participant_id,
            compressed_public_key=compressed_public_key,
            x_only_public_key=x_only_public_key,
            depth=depth,
            target_edge_id=target_edge_id,
            target_edge_sha256=None,
            evaluated_at=evaluated_at,
            state=CanonicalCrtMembershipState.UNKNOWN,
            reason=CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH,
            source_kind=CanonicalCrtMembershipSourceKind.CANONICAL_GENESIS_EVALUATION,
            source_digest=canonical_genesis_evaluation_sha256(source),
            source_state=source.state.value,
            source_reason=source.reason_code,
            control_depth=None,
            control_edge=None,
            selected_id=source.selected_effective_record_id,
            selected_digest=source.selected_effective_record_sha256,
            relevant=source.relevant_records,
        )
    if type(lineage_evaluation) is not CanonicalSponsorLineageEvaluation:
        raise InvalidCanonicalCrtMembership("source type")
    try:
        source = parse_canonical_sponsor_lineage_evaluation(
            canonical_sponsor_lineage_evaluation_bytes(lineage_evaluation)
        )
    except Exception:
        raise InvalidCanonicalCrtMembership("source value") from None
    state, reason = _LINEAGE_MAPPING[source.reason_code]
    binding_reason = None
    if (
        source.graph_or_protocol_id != GRAPH_ID
        or source.network != NETWORK
        or source.human_profile != HUMAN_PROFILE
    ):
        binding_reason = CanonicalCrtMembershipReason.SOURCE_GRAPH_OR_PROFILE_MISMATCH
    elif source.evaluated_at != evaluated_at:
        binding_reason = CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH
    elif source.target_edge_id != target_edge_id:
        binding_reason = CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH
    elif source.target_participant_id is not None and (
        source.target_participant_id,
        source.target_compressed_public_key,
        source.target_x_only_public_key,
        source.target_depth,
    ) != (participant_id, compressed_public_key, x_only_public_key, depth):
        binding_reason = CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH
    if binding_reason is not None:
        state, reason = CanonicalCrtMembershipState.UNKNOWN, binding_reason
    return _make_result(
        subject_kind=subject_kind, participant_id=participant_id,
        compressed_public_key=compressed_public_key, x_only_public_key=x_only_public_key,
        depth=depth, target_edge_id=target_edge_id,
        target_edge_sha256=(
            source.target_edge_sha256
            if source.target_edge_id == target_edge_id
            and (source.target_edge_id, source.target_edge_sha256)
            in source.relevant_records
            else None
        ), evaluated_at=evaluated_at,
        state=state, reason=reason,
        source_kind=CanonicalCrtMembershipSourceKind.CANONICAL_SPONSOR_LINEAGE_EVALUATION,
        source_digest=canonical_sponsor_lineage_evaluation_sha256(source),
        source_state=source.state.value, source_reason=source.reason_code.value,
        control_depth=None if binding_reason else source.controlling_depth,
        control_edge=None if binding_reason else source.controlling_edge_id,
        selected_id=source.selected_genesis_record_id,
        selected_digest=source.selected_genesis_record_sha256,
        relevant=source.relevant_records,
    )


def _dict(value: CanonicalCrtMembershipEvaluation) -> dict:
    payload = {field: getattr(value, field) for field in value.__dataclass_fields__}
    payload["subject_kind"] = value.subject_kind.value
    payload["state"] = value.state.value
    payload["reason_code"] = value.reason_code.value
    payload["source_evaluation_kind"] = value.source_evaluation_kind.value
    payload["evaluated_at"] = value.evaluated_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    payload["relevant_records"] = [list(item) for item in value.relevant_records]
    payload["explicit_non_claims"] = list(value.explicit_non_claims)
    return payload


def canonical_crt_membership_evaluation_bytes(value: CanonicalCrtMembershipEvaluation) -> bytes:
    if type(value) is not CanonicalCrtMembershipEvaluation:
        raise InvalidCanonicalCrtMembership("evaluation type")
    try:
        value = CanonicalCrtMembershipEvaluation(
            *(getattr(value, field) for field in value.__dataclass_fields__)
        )
    except InvalidCanonicalCrtMembership:
        raise
    except Exception:
        raise InvalidCanonicalCrtMembership("evaluation value") from None
    return json.dumps(
        _dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def canonical_crt_membership_evaluation_sha256(value: CanonicalCrtMembershipEvaluation) -> str:
    return sha256(canonical_crt_membership_evaluation_bytes(value)).hexdigest()


def parse_canonical_crt_membership_evaluation(
    value: bytes | str,
) -> CanonicalCrtMembershipEvaluation:
    if type(value) is bytes:
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            raise InvalidCanonicalCrtMembership("ASCII") from None
    if type(value) is not str:
        raise InvalidCanonicalCrtMembership("JSON")
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
        if (
            type(data) is not dict
            or set(data) != set(CanonicalCrtMembershipEvaluation.__dataclass_fields__)
            or type(data["relevant_records"]) is not list
            or type(data["explicit_non_claims"]) is not list
            or any(type(item) is not list or len(item) != 2 for item in data["relevant_records"])
        ):
            raise ValueError()
        timestamp = data["evaluated_at"]
        if type(timestamp) is not str or not timestamp.endswith("Z"):
            raise ValueError()
        result = CanonicalCrtMembershipEvaluation(
            **{
                **data,
                "subject_kind": CanonicalCrtMembershipSubjectKind(data["subject_kind"]),
                "state": CanonicalCrtMembershipState(data["state"]),
                "reason_code": CanonicalCrtMembershipReason(data["reason_code"]),
                "source_evaluation_kind": CanonicalCrtMembershipSourceKind(
                    data["source_evaluation_kind"]
                ),
                "evaluated_at": datetime.fromisoformat(timestamp[:-1] + "+00:00"),
                "relevant_records": tuple(tuple(item) for item in data["relevant_records"]),
                "explicit_non_claims": tuple(data["explicit_non_claims"]),
            }
        )
    except Exception:
        raise InvalidCanonicalCrtMembership("JSON") from None
    if canonical_crt_membership_evaluation_bytes(result).decode("ascii") != value:
        raise InvalidCanonicalCrtMembership("noncanonical JSON")
    return result
