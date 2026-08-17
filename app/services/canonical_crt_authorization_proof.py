"""Pure, dormant Canonical CRT Authorization Proof V1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
import json
from types import MappingProxyType

from app.services.canonical_crt_authorization_policy import (
    CanonicalCrtAuthorizationClass,
    CanonicalCrtAuthorizationEvaluation,
    CanonicalCrtAuthorizationReason,
    canonical_crt_authorization_evaluation_bytes,
    canonical_crt_authorization_evaluation_sha256,
    parse_canonical_crt_authorization_evaluation,
)
from app.services.canonical_crt_membership import (
    CanonicalCrtMembershipReason,
    CanonicalCrtMembershipSourceKind,
    CanonicalCrtMembershipState,
    CanonicalCrtMembershipSubjectKind,
    canonical_crt_membership_evaluation_sha256,
)

SCHEMA = "hodlxxi.canonical_crt_authorization_proof.v1"
BUILDER_VERSION = "hodlxxi.canonical_crt_authorization_proof_builder.v1"
VERIFICATION_RULE = "hodlxxi.canonical_crt_authorization_proof_verification.v1"

MANDATORY_NON_CLAIMS = tuple(
    sorted(
        (
            "no action authorization grant by this proof alone",
            "no administrator or operator status grant",
            "no authenticity claim from SHA-256 alone",
            "no automatic Bitcoin RPC observation claim",
            "no automatic action_authorization integration",
            "no automatic current_full_relation_satisfied claim",
            "no automatic mapping to runtime IdentityClass",
            "no automatic scope grant",
            "no automatic storage lookup claim",
            "no claim that the source remains current after evaluated_at",
            "no cryptographic signature or issuer-attestation claim",
            "no entitlement record write",
            "no fairness or informed-consent proof",
            "no independent recomputation of membership or authorization",
            "no independent validation of lower-level Bitcoin evidence",
            "no invite or sponsor permission grant",
            "no legal identity, KYC or complete personhood proof",
            "no ownership, custody or guardianship proof",
            "no production enforcement or deployment claim",
            "no proof of current private-key possession",
            "no public endpoint, route, API or MCP publication claim",
            "no replacement of active legacy wallet-ratio authorization paths",
            "no reputation, rank or trustworthiness grant",
            "no runtime administration or server-privilege grant",
            "no user-role or session mutation",
            "no validity for current_144 or cooperative admission templates",
            "no validity outside the exact nested authorization evaluation",
        )
    )
)


class InvalidCanonicalCrtAuthorizationProof(ValueError):
    """The request or canonical proof violates the V1 contract."""


class CanonicalCrtAuthorizationProofConclusion(Enum):
    FULL_BY_EXACT_GENESIS_MEMBERSHIP = "full_by_exact_genesis_membership"
    FULL_BY_EXACT_PARTICIPANT_MEMBERSHIP = "full_by_exact_participant_membership"
    LIMITED_BY_PROVISIONAL_MEMBERSHIP = "limited_by_provisional_membership"
    LIMITED_BY_TARGET_EDGE_INACTIVITY = "limited_by_target_edge_inactivity"
    LIMITED_BY_LINEAGE_INACTIVITY = "limited_by_lineage_inactivity"
    LIMITED_BY_DISPUTED_MEMBERSHIP = "limited_by_disputed_membership"
    LIMITED_BY_UNKNOWN_MEMBERSHIP = "limited_by_unknown_membership"


class CanonicalCrtAuthorizationProofBasis(Enum):
    GENESIS_RECORD = "genesis_record"
    COMPLETE_SPONSOR_LINEAGE = "complete_sponsor_lineage"
    GENESIS_CONTROL = "genesis_control"
    TARGET_EDGE = "target_edge"
    ANCESTOR_EDGE = "ancestor_edge"
    TARGET_EVIDENCE = "target_evidence"
    LINEAGE_STRUCTURE = "lineage_structure"
    SOURCE_BINDING = "source_binding"


_CONCLUSION_BY_REASON = MappingProxyType(
    {
        CanonicalCrtAuthorizationReason.EXACT_GENESIS_MEMBERSHIP_FULL: CanonicalCrtAuthorizationProofConclusion.FULL_BY_EXACT_GENESIS_MEMBERSHIP,
        CanonicalCrtAuthorizationReason.EXACT_PARTICIPANT_MEMBERSHIP_FULL: CanonicalCrtAuthorizationProofConclusion.FULL_BY_EXACT_PARTICIPANT_MEMBERSHIP,
        CanonicalCrtAuthorizationReason.PROVISIONAL_MEMBERSHIP_LIMITED: CanonicalCrtAuthorizationProofConclusion.LIMITED_BY_PROVISIONAL_MEMBERSHIP,
        CanonicalCrtAuthorizationReason.EDGE_INACTIVE_MEMBERSHIP_LIMITED: CanonicalCrtAuthorizationProofConclusion.LIMITED_BY_TARGET_EDGE_INACTIVITY,
        CanonicalCrtAuthorizationReason.LINEAGE_INACTIVE_MEMBERSHIP_LIMITED: CanonicalCrtAuthorizationProofConclusion.LIMITED_BY_LINEAGE_INACTIVITY,
        CanonicalCrtAuthorizationReason.DISPUTED_MEMBERSHIP_LIMITED: CanonicalCrtAuthorizationProofConclusion.LIMITED_BY_DISPUTED_MEMBERSHIP,
        CanonicalCrtAuthorizationReason.UNKNOWN_MEMBERSHIP_LIMITED: CanonicalCrtAuthorizationProofConclusion.LIMITED_BY_UNKNOWN_MEMBERSHIP,
    }
)

_BASIS_BY_REASON = MappingProxyType(
    {
        CanonicalCrtMembershipReason.EXACT_GENESIS_MEMBERSHIP_ACTIVE: CanonicalCrtAuthorizationProofBasis.GENESIS_RECORD,
        CanonicalCrtMembershipReason.EXACT_PARTICIPANT_MEMBERSHIP_ACTIVE: CanonicalCrtAuthorizationProofBasis.COMPLETE_SPONSOR_LINEAGE,
        CanonicalCrtMembershipReason.GENESIS_PROVISIONAL: CanonicalCrtAuthorizationProofBasis.GENESIS_CONTROL,
        CanonicalCrtMembershipReason.GENESIS_DISPUTED: CanonicalCrtAuthorizationProofBasis.GENESIS_CONTROL,
        CanonicalCrtMembershipReason.GENESIS_LINEAGE_INACTIVE: CanonicalCrtAuthorizationProofBasis.GENESIS_CONTROL,
        CanonicalCrtMembershipReason.GENESIS_UNKNOWN: CanonicalCrtAuthorizationProofBasis.GENESIS_CONTROL,
        CanonicalCrtMembershipReason.TARGET_PROVISIONAL: CanonicalCrtAuthorizationProofBasis.TARGET_EDGE,
        CanonicalCrtMembershipReason.TARGET_DISPUTED: CanonicalCrtAuthorizationProofBasis.TARGET_EDGE,
        CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE: CanonicalCrtAuthorizationProofBasis.TARGET_EDGE,
        CanonicalCrtMembershipReason.TARGET_LOCAL_EVALUATION_UNKNOWN: CanonicalCrtAuthorizationProofBasis.TARGET_EDGE,
        CanonicalCrtMembershipReason.ANCESTOR_PROVISIONAL: CanonicalCrtAuthorizationProofBasis.ANCESTOR_EDGE,
        CanonicalCrtMembershipReason.ANCESTOR_DISPUTED: CanonicalCrtAuthorizationProofBasis.ANCESTOR_EDGE,
        CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE: CanonicalCrtAuthorizationProofBasis.ANCESTOR_EDGE,
        CanonicalCrtMembershipReason.ANCESTOR_LOCAL_EVALUATION_UNKNOWN: CanonicalCrtAuthorizationProofBasis.ANCESTOR_EDGE,
        CanonicalCrtMembershipReason.MISSING_TARGET_EVIDENCE: CanonicalCrtAuthorizationProofBasis.TARGET_EVIDENCE,
        CanonicalCrtMembershipReason.MISSING_PARENT_EVIDENCE: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.PARENT_DIGEST_MISMATCH: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.PARENT_IDENTITY_MISMATCH: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.PARENT_DEPTH_MISMATCH: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.PARENT_GRAPH_OR_PROFILE_MISMATCH: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.DUPLICATE_EDGE_ID: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.DUPLICATE_EDGE_DIGEST: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.DUPLICATE_CHILD_IDENTITY: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.CYCLE_DETECTED: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.EXTRANEOUS_EDGE_EVIDENCE: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.MAXIMUM_DEPTH_EXCEEDED: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.MALFORMED_OR_UNTRUSTED_INPUT: CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE,
        CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH: CanonicalCrtAuthorizationProofBasis.SOURCE_BINDING,
        CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH: CanonicalCrtAuthorizationProofBasis.SOURCE_BINDING,
        CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH: CanonicalCrtAuthorizationProofBasis.SOURCE_BINDING,
        CanonicalCrtMembershipReason.SOURCE_GRAPH_OR_PROFILE_MISMATCH: CanonicalCrtAuthorizationProofBasis.SOURCE_BINDING,
    }
)

_SOURCE_BINDING_REASONS = frozenset(
    {
        CanonicalCrtMembershipReason.SOURCE_KIND_MISMATCH,
        CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH,
        CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH,
        CanonicalCrtMembershipReason.SOURCE_GRAPH_OR_PROFILE_MISMATCH,
    }
)

assert set(_CONCLUSION_BY_REASON) == set(CanonicalCrtAuthorizationReason)
assert set(_BASIS_BY_REASON) == set(CanonicalCrtMembershipReason)


def _canonical_source(value: object) -> CanonicalCrtAuthorizationEvaluation:
    if type(value) is not CanonicalCrtAuthorizationEvaluation:
        raise InvalidCanonicalCrtAuthorizationProof("source authorization type")
    try:
        return parse_canonical_crt_authorization_evaluation(canonical_crt_authorization_evaluation_bytes(value))
    except Exception:
        raise InvalidCanonicalCrtAuthorizationProof("source authorization value") from None


def _basis(source: CanonicalCrtAuthorizationEvaluation):
    membership = source.source_membership_evaluation
    if membership.reason_code in _SOURCE_BINDING_REASONS:
        return CanonicalCrtAuthorizationProofBasis.SOURCE_BINDING
    if membership.subject_kind is CanonicalCrtMembershipSubjectKind.GENESIS:
        return CanonicalCrtAuthorizationProofBasis.GENESIS_RECORD
    return _BASIS_BY_REASON[membership.reason_code]


def _explanation(
    authorization_class,
    authorization_reason,
    membership_state,
    membership_reason,
    proof_basis,
) -> str:
    return (
        f"authorization_class={authorization_class.value}; "
        f"authorization_reason={authorization_reason.value}; "
        f"membership_state={membership_state.value}; "
        f"membership_reason={membership_reason.value}; "
        f"proof_basis={proof_basis.value}"
    )


@dataclass(frozen=True, slots=True)
class CanonicalCrtAuthorizationProof:
    schema: str
    builder_version: str
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
    authorization_reason_code: CanonicalCrtAuthorizationReason
    current_full_membership_satisfied: bool
    membership_state: CanonicalCrtMembershipState
    membership_reason_code: CanonicalCrtMembershipReason
    source_evaluation_kind: CanonicalCrtMembershipSourceKind
    source_evaluation_sha256: str
    source_state: str
    source_reason_code: str
    controlling_depth: int | None
    controlling_edge_id: str | None
    selected_genesis_record_id: str | None
    selected_genesis_record_sha256: str | None
    relevant_records: tuple[tuple[str, str], ...]
    proof_conclusion: CanonicalCrtAuthorizationProofConclusion
    proof_basis: CanonicalCrtAuthorizationProofBasis
    canonical_explanation: str
    source_authorization_evaluation_sha256: str
    source_membership_evaluation_sha256: str
    source_authorization_evaluation: CanonicalCrtAuthorizationEvaluation
    explicit_non_claims: tuple[str, ...]
    human_interpretation_required: bool

    def __post_init__(self) -> None:
        try:
            source = _canonical_source(self.source_authorization_evaluation)
            membership = source.source_membership_evaluation
            required_strings = (
                self.schema,
                self.builder_version,
                self.verification_rule,
                self.graph_or_protocol_id,
                self.network,
                self.human_profile,
                self.participant_id,
                self.compressed_public_key,
                self.x_only_public_key,
                self.source_evaluation_sha256,
                self.source_state,
                self.source_reason_code,
                self.canonical_explanation,
                self.source_authorization_evaluation_sha256,
                self.source_membership_evaluation_sha256,
            )
            optional_strings = (
                self.target_edge_id,
                self.target_edge_sha256,
                self.controlling_edge_id,
                self.selected_genesis_record_id,
                self.selected_genesis_record_sha256,
            )
            if (
                any(type(value) is not str for value in required_strings)
                or any(value is not None and type(value) is not str for value in optional_strings)
                or type(self.depth) is not int
                or type(self.evaluated_at) is not datetime
                or (self.controlling_depth is not None and type(self.controlling_depth) is not int)
                or type(self.relevant_records) is not tuple
                or any(type(item) is not tuple or len(item) != 2 for item in self.relevant_records)
                or any(
                    type(record_id) is not str or type(digest) is not str for record_id, digest in self.relevant_records
                )
                or type(self.explicit_non_claims) is not tuple
                or any(type(item) is not str for item in self.explicit_non_claims)
            ):
                raise InvalidCanonicalCrtAuthorizationProof("primitive types")
            if (
                (self.schema, self.builder_version, self.verification_rule)
                != (SCHEMA, BUILDER_VERSION, VERIFICATION_RULE)
                or type(self.subject_kind) is not CanonicalCrtMembershipSubjectKind
                or type(self.authorization_class) is not CanonicalCrtAuthorizationClass
                or type(self.authorization_reason_code) is not CanonicalCrtAuthorizationReason
                or type(self.current_full_membership_satisfied) is not bool
                or type(self.membership_state) is not CanonicalCrtMembershipState
                or type(self.membership_reason_code) is not CanonicalCrtMembershipReason
                or type(self.source_evaluation_kind) is not CanonicalCrtMembershipSourceKind
                or type(self.proof_conclusion) is not CanonicalCrtAuthorizationProofConclusion
                or type(self.proof_basis) is not CanonicalCrtAuthorizationProofBasis
                or self.explicit_non_claims != MANDATORY_NON_CLAIMS
                or self.human_interpretation_required is not True
            ):
                raise InvalidCanonicalCrtAuthorizationProof("fixed contract")
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
                self.authorization_class,
                self.authorization_reason_code,
                self.current_full_membership_satisfied,
                self.membership_state,
                self.membership_reason_code,
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
                source.authorization_class,
                source.reason_code,
                source.current_full_membership_satisfied,
                source.source_membership_state,
                source.source_membership_reason_code,
            ):
                raise InvalidCanonicalCrtAuthorizationProof("authorization source binding")
            if (
                self.source_evaluation_kind,
                self.source_evaluation_sha256,
                self.source_state,
                self.source_reason_code,
                self.controlling_depth,
                self.controlling_edge_id,
                self.selected_genesis_record_id,
                self.selected_genesis_record_sha256,
                self.relevant_records,
            ) != (
                membership.source_evaluation_kind,
                membership.source_evaluation_sha256,
                membership.source_state,
                membership.source_reason_code,
                membership.controlling_depth,
                membership.controlling_edge_id,
                membership.selected_genesis_record_id,
                membership.selected_genesis_record_sha256,
                membership.relevant_records,
            ):
                raise InvalidCanonicalCrtAuthorizationProof("membership source binding")
            authorization_digest = canonical_crt_authorization_evaluation_sha256(source)
            membership_digest = canonical_crt_membership_evaluation_sha256(membership)
            if (
                self.source_authorization_evaluation_sha256 != authorization_digest
                or self.source_membership_evaluation_sha256 != membership_digest
                or self.source_membership_evaluation_sha256 != source.source_membership_evaluation_sha256
            ):
                raise InvalidCanonicalCrtAuthorizationProof("source digest")
            expected_conclusion = _CONCLUSION_BY_REASON[source.reason_code]
            expected_basis = _basis(source)
            if (
                self.proof_conclusion is not expected_conclusion
                or self.proof_basis is not expected_basis
                or self.canonical_explanation
                != _explanation(
                    source.authorization_class,
                    source.reason_code,
                    membership.state,
                    membership.reason_code,
                    expected_basis,
                )
            ):
                raise InvalidCanonicalCrtAuthorizationProof("explanation")
            is_full = source.authorization_class is CanonicalCrtAuthorizationClass.FULL
            if source.current_full_membership_satisfied is not is_full:
                raise InvalidCanonicalCrtAuthorizationProof("class boolean")
            if expected_conclusion is (CanonicalCrtAuthorizationProofConclusion.FULL_BY_EXACT_GENESIS_MEMBERSHIP):
                if (
                    source.subject_kind is not CanonicalCrtMembershipSubjectKind.GENESIS
                    or membership.state is not CanonicalCrtMembershipState.GENESIS_ACTIVE
                ):
                    raise InvalidCanonicalCrtAuthorizationProof("genesis full")
            elif expected_conclusion is (CanonicalCrtAuthorizationProofConclusion.FULL_BY_EXACT_PARTICIPANT_MEMBERSHIP):
                if (
                    source.subject_kind is not CanonicalCrtMembershipSubjectKind.ORDINARY
                    or membership.state is not CanonicalCrtMembershipState.ACTIVE
                ):
                    raise InvalidCanonicalCrtAuthorizationProof("participant full")
            elif is_full:
                raise InvalidCanonicalCrtAuthorizationProof("limited conclusion")
            self._validate_basis(membership)
        except InvalidCanonicalCrtAuthorizationProof:
            raise
        except Exception:
            raise InvalidCanonicalCrtAuthorizationProof("proof value") from None

    def _validate_basis(self, membership) -> None:
        basis = self.proof_basis
        ordinary = self.subject_kind is CanonicalCrtMembershipSubjectKind.ORDINARY
        if basis is CanonicalCrtAuthorizationProofBasis.GENESIS_RECORD:
            valid = (
                not ordinary
                and self.depth == 0
                and self.target_edge_id is None
                and self.target_edge_sha256 is None
                and self.controlling_edge_id is None
                and (
                    (
                        self.membership_state is CanonicalCrtMembershipState.GENESIS_ACTIVE
                        and self.controlling_depth is None
                        and self.selected_genesis_record_id is not None
                        and self.selected_genesis_record_sha256 is not None
                    )
                    or (
                        self.membership_state
                        in {
                            CanonicalCrtMembershipState.PROVISIONAL,
                            CanonicalCrtMembershipState.DISPUTED,
                            CanonicalCrtMembershipState.LINEAGE_INACTIVE,
                            CanonicalCrtMembershipState.UNKNOWN,
                        }
                        and self.membership_reason_code not in _SOURCE_BINDING_REASONS
                        and self.controlling_depth == 0
                    )
                )
            )
        elif basis is CanonicalCrtAuthorizationProofBasis.COMPLETE_SPONSOR_LINEAGE:
            valid = (
                ordinary
                and self.membership_state is CanonicalCrtMembershipState.ACTIVE
                and self.controlling_depth is None
                and self.controlling_edge_id is None
                and self.target_edge_id is not None
                and self.selected_genesis_record_id is not None
            )
        elif basis is CanonicalCrtAuthorizationProofBasis.GENESIS_CONTROL:
            valid = (
                ordinary
                and self.controlling_depth == 0
                and self.controlling_edge_id is None
                and self.selected_genesis_record_id is not None
            )
        elif basis is CanonicalCrtAuthorizationProofBasis.TARGET_EDGE:
            valid = (
                ordinary and self.controlling_depth == self.depth and self.controlling_edge_id == self.target_edge_id
            )
        elif basis is CanonicalCrtAuthorizationProofBasis.ANCESTOR_EDGE:
            valid = (
                ordinary
                and type(self.controlling_depth) is int
                and 1 <= self.controlling_depth < self.depth
                and self.controlling_edge_id is not None
            )
        elif basis is CanonicalCrtAuthorizationProofBasis.TARGET_EVIDENCE:
            valid = ordinary and self.membership_reason_code is CanonicalCrtMembershipReason.MISSING_TARGET_EVIDENCE
        elif basis is CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE:
            valid = ordinary and self.controlling_depth is None and self.controlling_edge_id is None
        else:
            valid = (
                self.controlling_depth is None
                and self.controlling_edge_id is None
                and self.membership_reason_code in _SOURCE_BINDING_REASONS
            )
        if not valid:
            raise InvalidCanonicalCrtAuthorizationProof("basis structure")


def build_canonical_crt_authorization_proof(
    authorization_evaluation: CanonicalCrtAuthorizationEvaluation,
) -> CanonicalCrtAuthorizationProof:
    """Explain exactly one complete canonical PR6.13 evaluation."""
    try:
        source = _canonical_source(authorization_evaluation)
        membership = source.source_membership_evaluation
        basis = _basis(source)
        return CanonicalCrtAuthorizationProof(
            SCHEMA,
            BUILDER_VERSION,
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
            source.authorization_class,
            source.reason_code,
            source.current_full_membership_satisfied,
            membership.state,
            membership.reason_code,
            membership.source_evaluation_kind,
            membership.source_evaluation_sha256,
            membership.source_state,
            membership.source_reason_code,
            membership.controlling_depth,
            membership.controlling_edge_id,
            membership.selected_genesis_record_id,
            membership.selected_genesis_record_sha256,
            membership.relevant_records,
            _CONCLUSION_BY_REASON[source.reason_code],
            basis,
            _explanation(
                source.authorization_class,
                source.reason_code,
                membership.state,
                membership.reason_code,
                basis,
            ),
            canonical_crt_authorization_evaluation_sha256(source),
            canonical_crt_membership_evaluation_sha256(membership),
            source,
            MANDATORY_NON_CLAIMS,
            True,
        )
    except InvalidCanonicalCrtAuthorizationProof:
        raise
    except Exception:
        raise InvalidCanonicalCrtAuthorizationProof("build input") from None


def _dict(value: CanonicalCrtAuthorizationProof) -> dict[str, object]:
    source = json.loads(
        canonical_crt_authorization_evaluation_bytes(value.source_authorization_evaluation).decode("ascii")
    )
    payload = {field: getattr(value, field) for field in value.__dataclass_fields__}
    for field in (
        "subject_kind",
        "authorization_class",
        "authorization_reason_code",
        "membership_state",
        "membership_reason_code",
        "source_evaluation_kind",
        "proof_conclusion",
        "proof_basis",
    ):
        payload[field] = getattr(value, field).value
    payload["evaluated_at"] = value.evaluated_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    payload["relevant_records"] = [list(item) for item in value.relevant_records]
    payload["source_authorization_evaluation"] = source
    payload["explicit_non_claims"] = list(value.explicit_non_claims)
    return payload


def canonical_crt_authorization_proof_bytes(
    value: CanonicalCrtAuthorizationProof,
) -> bytes:
    if type(value) is not CanonicalCrtAuthorizationProof:
        raise InvalidCanonicalCrtAuthorizationProof("proof type")
    try:
        value = CanonicalCrtAuthorizationProof(*(getattr(value, field) for field in value.__dataclass_fields__))
        return json.dumps(
            _dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except InvalidCanonicalCrtAuthorizationProof:
        raise
    except Exception:
        raise InvalidCanonicalCrtAuthorizationProof("proof value") from None


def canonical_crt_authorization_proof_sha256(
    value: CanonicalCrtAuthorizationProof,
) -> str:
    return sha256(canonical_crt_authorization_proof_bytes(value)).hexdigest()


def parse_canonical_crt_authorization_proof(
    value: bytes | str,
) -> CanonicalCrtAuthorizationProof:
    if type(value) is bytes:
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            raise InvalidCanonicalCrtAuthorizationProof("ASCII") from None
    if type(value) is not str:
        raise InvalidCanonicalCrtAuthorizationProof("JSON")
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
            or set(data) != set(CanonicalCrtAuthorizationProof.__dataclass_fields__)
            or type(data["source_authorization_evaluation"]) is not dict
            or type(data["relevant_records"]) is not list
            or type(data["explicit_non_claims"]) is not list
            or any(type(item) is not list or len(item) != 2 for item in data["relevant_records"])
        ):
            raise ValueError()
        timestamp = data["evaluated_at"]
        if type(timestamp) is not str or not timestamp.endswith("Z"):
            raise ValueError()
        nested = json.dumps(
            data["source_authorization_evaluation"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        source = parse_canonical_crt_authorization_evaluation(nested)
        result = CanonicalCrtAuthorizationProof(
            **{
                **data,
                "subject_kind": CanonicalCrtMembershipSubjectKind(data["subject_kind"]),
                "evaluated_at": datetime.fromisoformat(timestamp[:-1] + "+00:00"),
                "authorization_class": CanonicalCrtAuthorizationClass(data["authorization_class"]),
                "authorization_reason_code": CanonicalCrtAuthorizationReason(data["authorization_reason_code"]),
                "membership_state": CanonicalCrtMembershipState(data["membership_state"]),
                "membership_reason_code": CanonicalCrtMembershipReason(data["membership_reason_code"]),
                "source_evaluation_kind": CanonicalCrtMembershipSourceKind(data["source_evaluation_kind"]),
                "relevant_records": tuple(tuple(item) for item in data["relevant_records"]),
                "proof_conclusion": CanonicalCrtAuthorizationProofConclusion(data["proof_conclusion"]),
                "proof_basis": CanonicalCrtAuthorizationProofBasis(data["proof_basis"]),
                "source_authorization_evaluation": source,
                "explicit_non_claims": tuple(data["explicit_non_claims"]),
            }
        )
    except Exception:
        raise InvalidCanonicalCrtAuthorizationProof("JSON") from None
    if canonical_crt_authorization_proof_bytes(result).decode("ascii") != value:
        raise InvalidCanonicalCrtAuthorizationProof("noncanonical JSON")
    return result
