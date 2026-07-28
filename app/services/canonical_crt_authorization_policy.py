"""Pure, dormant Canonical CRT Authorization Policy V1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
import json
from types import MappingProxyType

from app.services.canonical_crt_membership import (
    GRAPH_ID,
    HUMAN_PROFILE,
    NETWORK,
    CanonicalCrtMembershipEvaluation,
    CanonicalCrtMembershipReason,
    CanonicalCrtMembershipState,
    CanonicalCrtMembershipSubjectKind,
    canonical_crt_membership_evaluation_bytes,
    canonical_crt_membership_evaluation_sha256,
    parse_canonical_crt_membership_evaluation,
)

SCHEMA = "hodlxxi.canonical_crt_authorization_evaluation.v1"
POLICY_VERSION = "hodlxxi.canonical_crt_authorization_policy.v1"
VERIFICATION_RULE = "hodlxxi.canonical_crt_authorization_verification.v1"

MANDATORY_NON_CLAIMS = tuple(sorted((
    "no action authorization grant by this evaluation alone",
    "no administrator or operator status grant",
    "no automatic Bitcoin RPC observation claim",
    "no automatic action_authorization integration",
    "no automatic current_full_relation_satisfied claim",
    "no automatic mapping to runtime IdentityClass",
    "no automatic scope grant",
    "no automatic storage lookup claim",
    "no entitlement record write",
    "no fairness or informed-consent proof",
    "no invite or sponsor permission grant",
    "no legal identity, KYC or complete personhood proof",
    "no ownership, custody or guardianship proof",
    "no production enforcement or deployment claim",
    "no proof of current private-key possession",
    "no reputation, rank or trustworthiness grant",
    "no replacement of active legacy wallet-ratio authorization paths",
    "no runtime administration or server-privilege grant",
    "no user-role or session mutation",
    "no validity for current_144 or cooperative admission templates",
    "no validity outside the exact source membership evaluation and evaluated_at",
)))


class InvalidCanonicalCrtAuthorization(ValueError):
    """The request or canonical authorization result violates the V1 contract."""


class CanonicalCrtAuthorizationClass(Enum):
    FULL = "full"
    LIMITED = "limited"


class CanonicalCrtAuthorizationReason(Enum):
    EXACT_GENESIS_MEMBERSHIP_FULL = "exact_genesis_membership_full"
    EXACT_PARTICIPANT_MEMBERSHIP_FULL = "exact_participant_membership_full"
    PROVISIONAL_MEMBERSHIP_LIMITED = "provisional_membership_limited"
    EDGE_INACTIVE_MEMBERSHIP_LIMITED = "edge_inactive_membership_limited"
    LINEAGE_INACTIVE_MEMBERSHIP_LIMITED = "lineage_inactive_membership_limited"
    DISPUTED_MEMBERSHIP_LIMITED = "disputed_membership_limited"
    UNKNOWN_MEMBERSHIP_LIMITED = "unknown_membership_limited"


_POLICY_MAPPING = MappingProxyType({
    CanonicalCrtMembershipState.GENESIS_ACTIVE: (
        CanonicalCrtAuthorizationClass.FULL,
        CanonicalCrtAuthorizationReason.EXACT_GENESIS_MEMBERSHIP_FULL,
    ),
    CanonicalCrtMembershipState.ACTIVE: (
        CanonicalCrtAuthorizationClass.FULL,
        CanonicalCrtAuthorizationReason.EXACT_PARTICIPANT_MEMBERSHIP_FULL,
    ),
    CanonicalCrtMembershipState.PROVISIONAL: (
        CanonicalCrtAuthorizationClass.LIMITED,
        CanonicalCrtAuthorizationReason.PROVISIONAL_MEMBERSHIP_LIMITED,
    ),
    CanonicalCrtMembershipState.EDGE_INACTIVE: (
        CanonicalCrtAuthorizationClass.LIMITED,
        CanonicalCrtAuthorizationReason.EDGE_INACTIVE_MEMBERSHIP_LIMITED,
    ),
    CanonicalCrtMembershipState.LINEAGE_INACTIVE: (
        CanonicalCrtAuthorizationClass.LIMITED,
        CanonicalCrtAuthorizationReason.LINEAGE_INACTIVE_MEMBERSHIP_LIMITED,
    ),
    CanonicalCrtMembershipState.DISPUTED: (
        CanonicalCrtAuthorizationClass.LIMITED,
        CanonicalCrtAuthorizationReason.DISPUTED_MEMBERSHIP_LIMITED,
    ),
    CanonicalCrtMembershipState.UNKNOWN: (
        CanonicalCrtAuthorizationClass.LIMITED,
        CanonicalCrtAuthorizationReason.UNKNOWN_MEMBERSHIP_LIMITED,
    ),
})


def _canonical_source(value: object) -> CanonicalCrtMembershipEvaluation:
    if type(value) is not CanonicalCrtMembershipEvaluation:
        raise InvalidCanonicalCrtAuthorization("source membership type")
    try:
        return parse_canonical_crt_membership_evaluation(
            canonical_crt_membership_evaluation_bytes(value)
        )
    except Exception:
        raise InvalidCanonicalCrtAuthorization("source membership value") from None


@dataclass(frozen=True, slots=True)
class CanonicalCrtAuthorizationEvaluation:
    schema: str
    policy_version: str
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
    authorization_class: CanonicalCrtAuthorizationClass
    reason_code: CanonicalCrtAuthorizationReason
    current_full_membership_satisfied: bool
    source_membership_state: CanonicalCrtMembershipState
    source_membership_reason_code: CanonicalCrtMembershipReason
    source_membership_evaluation_sha256: str
    source_membership_evaluation: CanonicalCrtMembershipEvaluation
    explicit_non_claims: tuple[str, ...]
    human_interpretation_required: bool

    def __post_init__(self) -> None:
        try:
            source = _canonical_source(self.source_membership_evaluation)
            if (
                type(self.graph_or_protocol_id) is not str
                or type(self.network) is not str
                or type(self.human_profile) is not str
                or type(self.participant_id) is not str
                or type(self.compressed_public_key) is not str
                or type(self.x_only_public_key) is not str
                or type(self.depth) is not int
                or (
                    self.target_edge_id is not None
                    and type(self.target_edge_id) is not str
                )
                or (
                    self.target_edge_sha256 is not None
                    and type(self.target_edge_sha256) is not str
                )
                or type(self.evaluated_at) is not datetime
                or type(self.source_membership_evaluation_sha256) is not str
            ):
                raise InvalidCanonicalCrtAuthorization("primitive result types")
            if (
                (self.schema, self.policy_version, self.verification_rule)
                != (SCHEMA, POLICY_VERSION, VERIFICATION_RULE)
                or (self.graph_or_protocol_id, self.network, self.human_profile)
                != (GRAPH_ID, NETWORK, HUMAN_PROFILE)
                or type(self.subject_kind) is not CanonicalCrtMembershipSubjectKind
                or type(self.source_membership_state) is not CanonicalCrtMembershipState
                or type(self.source_membership_reason_code) is not CanonicalCrtMembershipReason
                or type(self.authorization_class) is not CanonicalCrtAuthorizationClass
                or type(self.reason_code) is not CanonicalCrtAuthorizationReason
                or type(self.current_full_membership_satisfied) is not bool
                or self.explicit_non_claims != MANDATORY_NON_CLAIMS
                or self.human_interpretation_required is not True
            ):
                raise InvalidCanonicalCrtAuthorization("fixed result contract")
            if (
                self.graph_or_protocol_id,
                self.network,
                self.human_profile,
                self.subject_kind,
                self.participant_id,
                self.compressed_public_key,
                self.x_only_public_key,
                self.depth,
                self.target_edge_id,
                self.target_edge_sha256,
                self.evaluated_at,
                self.source_membership_state,
                self.source_membership_reason_code,
            ) != (
                source.graph_or_protocol_id,
                source.network,
                source.human_profile,
                source.subject_kind,
                source.participant_id,
                source.compressed_public_key,
                source.x_only_public_key,
                source.depth,
                source.target_edge_id,
                source.target_edge_sha256,
                source.evaluated_at,
                source.state,
                source.reason_code,
            ):
                raise InvalidCanonicalCrtAuthorization("source binding")
            if self.source_membership_evaluation_sha256 != (
                canonical_crt_membership_evaluation_sha256(source)
            ):
                raise InvalidCanonicalCrtAuthorization("source digest")
            expected_class, expected_reason = _POLICY_MAPPING[source.state]
            if (
                (self.authorization_class, self.reason_code)
                != (expected_class, expected_reason)
                or self.current_full_membership_satisfied
                is not (expected_class is CanonicalCrtAuthorizationClass.FULL)
                or (
                    source.state is CanonicalCrtMembershipState.GENESIS_ACTIVE
                    and source.subject_kind is not CanonicalCrtMembershipSubjectKind.GENESIS
                )
                or (
                    source.state is CanonicalCrtMembershipState.ACTIVE
                    and source.subject_kind is not CanonicalCrtMembershipSubjectKind.ORDINARY
                )
            ):
                raise InvalidCanonicalCrtAuthorization("policy outcome")
        except InvalidCanonicalCrtAuthorization:
            raise
        except Exception:
            raise InvalidCanonicalCrtAuthorization("evaluation value") from None


def evaluate_canonical_crt_authorization(
    membership_evaluation: CanonicalCrtMembershipEvaluation,
) -> CanonicalCrtAuthorizationEvaluation:
    """Map exactly one canonical membership evaluation to a Canon class."""
    source = _canonical_source(membership_evaluation)
    authorization_class, reason = _POLICY_MAPPING[source.state]
    return CanonicalCrtAuthorizationEvaluation(
        SCHEMA,
        POLICY_VERSION,
        VERIFICATION_RULE,
        source.graph_or_protocol_id,
        source.network,
        source.human_profile,
        source.subject_kind,
        source.participant_id,
        source.compressed_public_key,
        source.x_only_public_key,
        source.depth,
        source.target_edge_id,
        source.target_edge_sha256,
        source.evaluated_at,
        authorization_class,
        reason,
        authorization_class is CanonicalCrtAuthorizationClass.FULL,
        source.state,
        source.reason_code,
        canonical_crt_membership_evaluation_sha256(source),
        source,
        MANDATORY_NON_CLAIMS,
        True,
    )


def _dict(value: CanonicalCrtAuthorizationEvaluation) -> dict[str, object]:
    source = json.loads(
        canonical_crt_membership_evaluation_bytes(
            value.source_membership_evaluation
        ).decode("ascii")
    )
    return {
        "schema": value.schema,
        "policy_version": value.policy_version,
        "verification_rule": value.verification_rule,
        "graph_or_protocol_id": value.graph_or_protocol_id,
        "network": value.network,
        "human_profile": value.human_profile,
        "subject_kind": value.subject_kind.value,
        "participant_id": value.participant_id,
        "compressed_public_key": value.compressed_public_key,
        "x_only_public_key": value.x_only_public_key,
        "depth": value.depth,
        "target_edge_id": value.target_edge_id,
        "target_edge_sha256": value.target_edge_sha256,
        "evaluated_at": value.evaluated_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "authorization_class": value.authorization_class.value,
        "reason_code": value.reason_code.value,
        "current_full_membership_satisfied": value.current_full_membership_satisfied,
        "source_membership_state": value.source_membership_state.value,
        "source_membership_reason_code": value.source_membership_reason_code.value,
        "source_membership_evaluation_sha256": value.source_membership_evaluation_sha256,
        "source_membership_evaluation": source,
        "explicit_non_claims": list(value.explicit_non_claims),
        "human_interpretation_required": value.human_interpretation_required,
    }


def canonical_crt_authorization_evaluation_bytes(
    value: CanonicalCrtAuthorizationEvaluation,
) -> bytes:
    if type(value) is not CanonicalCrtAuthorizationEvaluation:
        raise InvalidCanonicalCrtAuthorization("evaluation type")
    try:
        value = CanonicalCrtAuthorizationEvaluation(
            *(getattr(value, field) for field in value.__dataclass_fields__)
        )
        return json.dumps(
            _dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except InvalidCanonicalCrtAuthorization:
        raise
    except Exception:
        raise InvalidCanonicalCrtAuthorization("evaluation value") from None


def canonical_crt_authorization_evaluation_sha256(
    value: CanonicalCrtAuthorizationEvaluation,
) -> str:
    return sha256(canonical_crt_authorization_evaluation_bytes(value)).hexdigest()


def parse_canonical_crt_authorization_evaluation(
    value: bytes | str,
) -> CanonicalCrtAuthorizationEvaluation:
    if type(value) is bytes:
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            raise InvalidCanonicalCrtAuthorization("ASCII") from None
    if type(value) is not str:
        raise InvalidCanonicalCrtAuthorization("JSON")
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
            or set(data) != set(CanonicalCrtAuthorizationEvaluation.__dataclass_fields__)
            or type(data["source_membership_evaluation"]) is not dict
            or type(data["explicit_non_claims"]) is not list
        ):
            raise ValueError()
        timestamp = data["evaluated_at"]
        if type(timestamp) is not str or not timestamp.endswith("Z"):
            raise ValueError()
        nested_bytes = json.dumps(
            data["source_membership_evaluation"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        source = parse_canonical_crt_membership_evaluation(nested_bytes)
        result = CanonicalCrtAuthorizationEvaluation(
            **{
                **data,
                "subject_kind": CanonicalCrtMembershipSubjectKind(data["subject_kind"]),
                "evaluated_at": datetime.fromisoformat(timestamp[:-1] + "+00:00"),
                "authorization_class": CanonicalCrtAuthorizationClass(
                    data["authorization_class"]
                ),
                "reason_code": CanonicalCrtAuthorizationReason(data["reason_code"]),
                "source_membership_state": CanonicalCrtMembershipState(
                    data["source_membership_state"]
                ),
                "source_membership_reason_code": CanonicalCrtMembershipReason(
                    data["source_membership_reason_code"]
                ),
                "source_membership_evaluation": source,
                "explicit_non_claims": tuple(data["explicit_non_claims"]),
            }
        )
    except Exception:
        raise InvalidCanonicalCrtAuthorization("JSON") from None
    if canonical_crt_authorization_evaluation_bytes(result).decode("ascii") != value:
        raise InvalidCanonicalCrtAuthorization("noncanonical JSON")
    return result
