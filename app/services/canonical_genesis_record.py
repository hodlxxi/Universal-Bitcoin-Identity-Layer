"""Pure, dormant canonical E923 genesis-record domain contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
import re
import uuid

SCHEMA = "hodlxxi.canonical_genesis_record.v1"
RECORD_VERSION = "hodlxxi.canonical_genesis_record_service.v1"
EVALUATOR_VERSION = "hodlxxi.canonical_genesis_evaluator.v1"
GRAPH_ID = "hodlxxi.crt_membership_graph.v1"
PARTICIPANT_ID = "E923"
COMPRESSED_KEY = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
XONLY_KEY = "3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
VERIFICATION_RULE = "hodlxxi.canonical_genesis_record_verification.v1"
CLAIM = (
    "The named HODLXXI CRT graph declares E923, bound to the stated "
    "cryptographic anchor, as its depth-0 genesis participant under the exact "
    "Bitcoin legacy_777 parameters and the stated record-verification rule."
)
AMENDMENT_POLICY = "evidence_preserving_future_policy_required"
RETENTION_POLICY = "append_preserved_no_silent_erasure"
MANDATORY_NON_CLAIMS = tuple(
    sorted(
        (
            "no reciprocal admission proof",
            "no independent reciprocal trust proof",
            "no decentralization proof",
            "no universal legitimacy proof",
            "no ownership, custody or guardianship proof",
            "no moral authority or permanent authority proof",
            "no runtime administration or server-privilege grant",
            "no permission to bypass later admission or lineage rules",
            "no legal identity, KYC or complete personhood proof",
            "no proof that source-controlled record validity establishes current private-key possession",
            "no FULL/LIMITED authorization grant",
        )
    )
)
REQUIRED_EVIDENCE_IDS = frozenset(("canon_genesis_bootstrap_v1", "e923_operator_continuity", "source_publication"))
INTEGRITY_BASES = frozenset(("content_sha256", "self_canonical_digest_externally_pinned"))
EVALUATION_REASON_CODES = frozenset(
    (
        "all_records_revoked",
        "controlling_dispute",
        "effective_timestamp_in_future",
        "exact_effective_record",
        "malformed_or_untrusted_input",
        "multiple_effective_records",
        "multiple_records_without_transition_policy",
        "no_records",
        "proposed_only",
        "succession_policy_unavailable",
    )
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX66 = re.compile(r"^[0-9a-f]{66}$")


class InvalidCanonicalGenesisRecord(ValueError):
    """The supplied record is not the exact bounded canonical contract."""


class CanonicalGenesisLifecycle(Enum):
    PROPOSED = "proposed"
    EFFECTIVE = "effective"
    DISPUTED = "disputed"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


class CanonicalGenesisEvaluationState(Enum):
    GENESIS_ACTIVE = "genesis_active"
    PROVISIONAL = "provisional"
    DISPUTED = "disputed"
    LINEAGE_INACTIVE = "lineage_inactive"
    UNKNOWN = "unknown"


def _text(value: object, name: str, maximum: int = 512) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise InvalidCanonicalGenesisRecord(name)
    if len(value.encode("utf-8")) > maximum:
        raise InvalidCanonicalGenesisRecord(name)
    return value


def _uuid(value: object, name: str) -> str:
    value = _text(value, name, 36)
    try:
        canonical = str(uuid.UUID(value))
    except ValueError:
        raise InvalidCanonicalGenesisRecord(name) from None
    if value != canonical:
        raise InvalidCanonicalGenesisRecord(name)
    return value


def _time(value: object, name: str, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise InvalidCanonicalGenesisRecord(name)
    if value.utcoffset().total_seconds() != 0:
        raise InvalidCanonicalGenesisRecord(name)
    return value


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_time(value: object, name: str, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if type(value) is not str or not value.endswith("Z"):
        raise InvalidCanonicalGenesisRecord(name)
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise InvalidCanonicalGenesisRecord(name) from None
    if _timestamp(result) != value:
        raise InvalidCanonicalGenesisRecord(name)
    return result


@dataclass(frozen=True, slots=True)
class CanonicalGenesisEvidenceReference:
    reference_id: str
    reference_kind: str
    location: str
    integrity_basis: str
    content_sha256: str | None
    context: str

    def __post_init__(self):
        _text(self.reference_id, "reference_id", 64)
        _text(self.reference_kind, "reference_kind", 64)
        _text(self.location, "location", 512)
        _text(self.context, "context", 512)
        if self.integrity_basis not in INTEGRITY_BASES:
            raise InvalidCanonicalGenesisRecord("integrity_basis")
        if self.integrity_basis == "content_sha256":
            if type(self.content_sha256) is not str or not _HEX64.fullmatch(self.content_sha256):
                raise InvalidCanonicalGenesisRecord("content_sha256")
        elif self.content_sha256 is not None:
            raise InvalidCanonicalGenesisRecord("self digest")


@dataclass(frozen=True, slots=True)
class CanonicalGenesisIdentityAnchor:
    anchor_type: str
    key_purpose: str
    encoding: str
    compressed_public_key: str
    x_only_public_key: str
    evidence_reference_ids: tuple[str, ...]

    def __post_init__(self):
        if (
            self.anchor_type != "secp256k1_public_key"
            or self.key_purpose != "genesis_participant_identity"
            or self.encoding != "SEC1_compressed"
            or self.compressed_public_key != COMPRESSED_KEY
            or self.x_only_public_key != XONLY_KEY
            or self.compressed_public_key[2:] != self.x_only_public_key
        ):
            raise InvalidCanonicalGenesisRecord("identity_anchor")
        if (
            type(self.evidence_reference_ids) is not tuple
            or not self.evidence_reference_ids
            or len(self.evidence_reference_ids) > 16
            or len(set(self.evidence_reference_ids)) != len(self.evidence_reference_ids)
        ):
            raise InvalidCanonicalGenesisRecord("identity evidence")
        for value in self.evidence_reference_ids:
            _text(value, "identity evidence", 64)


@dataclass(frozen=True, slots=True)
class CanonicalGenesisContradictionContext:
    reason: str | None
    evidence_reference_ids: tuple[str, ...]
    unresolved_controlling_dispute: bool

    def __post_init__(self):
        if self.reason is not None:
            _text(self.reason, "contradiction reason", 512)
        if type(self.evidence_reference_ids) is not tuple or len(self.evidence_reference_ids) > 16:
            raise InvalidCanonicalGenesisRecord("contradiction evidence")
        if len(set(self.evidence_reference_ids)) != len(self.evidence_reference_ids):
            raise InvalidCanonicalGenesisRecord("contradiction evidence")
        for value in self.evidence_reference_ids:
            _text(value, "contradiction evidence", 64)
        if type(self.unresolved_controlling_dispute) is not bool:
            raise InvalidCanonicalGenesisRecord("controlling dispute")


@dataclass(frozen=True, slots=True)
class CanonicalGenesisRecord:
    schema: str
    record_version: str
    record_id: str
    graph_or_protocol_id: str
    genesis_participant_id: str
    genesis_depth: int
    identity_anchor: CanonicalGenesisIdentityAnchor
    network: str
    human_profile: str
    anchor_middle_height: int
    delta_blocks: int
    lifecycle_state: CanonicalGenesisLifecycle
    created_at: datetime
    lifecycle_changed_at: datetime
    effective_at: datetime | None
    superseded_by_record_id: str | None
    issuer_context: str
    verification_rule: str
    claim: str
    evidence_references: tuple[CanonicalGenesisEvidenceReference, ...]
    explicit_non_claims: tuple[str, ...]
    amendment_succession_policy: str
    contradiction_context: CanonicalGenesisContradictionContext
    privacy_scope: str
    retention_policy: str
    human_interpretation_required: bool

    def __post_init__(self):
        if (
            self.schema != SCHEMA
            or self.record_version != RECORD_VERSION
            or self.graph_or_protocol_id != GRAPH_ID
            or self.genesis_participant_id != PARTICIPANT_ID
            or type(self.genesis_depth) is not int
            or self.genesis_depth != 0
            or self.network != "bitcoin"
            or self.human_profile != "legacy_777"
            or type(self.anchor_middle_height) is not int
            or self.anchor_middle_height != 1777777
            or type(self.delta_blocks) is not int
            or self.delta_blocks != 777
            or type(self.lifecycle_state) is not CanonicalGenesisLifecycle
            or self.verification_rule != VERIFICATION_RULE
            or self.claim != CLAIM
            or self.amendment_succession_policy != AMENDMENT_POLICY
            or self.privacy_scope != "public"
            or self.retention_policy != RETENTION_POLICY
            or self.human_interpretation_required is not True
        ):
            raise InvalidCanonicalGenesisRecord("fixed record contract")
        _uuid(self.record_id, "record_id")
        _text(self.issuer_context, "issuer_context", 256)
        if type(self.identity_anchor) is not CanonicalGenesisIdentityAnchor:
            raise InvalidCanonicalGenesisRecord("identity_anchor type")
        try:
            CanonicalGenesisIdentityAnchor(
                *(getattr(self.identity_anchor, field) for field in CanonicalGenesisIdentityAnchor.__dataclass_fields__)
            )
        except (AttributeError, TypeError, ValueError):
            raise InvalidCanonicalGenesisRecord("identity_anchor reconstruction") from None
        created = _time(self.created_at, "created_at")
        changed = _time(self.lifecycle_changed_at, "lifecycle_changed_at")
        effective = _time(self.effective_at, "effective_at", True)
        if changed < created:
            raise InvalidCanonicalGenesisRecord("lifecycle time")
        if self.superseded_by_record_id is not None:
            _uuid(self.superseded_by_record_id, "successor")
            if self.superseded_by_record_id == self.record_id:
                raise InvalidCanonicalGenesisRecord("successor")
        if type(self.evidence_references) is not tuple or not (3 <= len(self.evidence_references) <= 16):
            raise InvalidCanonicalGenesisRecord("evidence")
        refs = []
        for item in self.evidence_references:
            if type(item) is not CanonicalGenesisEvidenceReference:
                raise InvalidCanonicalGenesisRecord("evidence type")
            refs.append(
                CanonicalGenesisEvidenceReference(
                    *(getattr(item, field) for field in CanonicalGenesisEvidenceReference.__dataclass_fields__)
                )
            )
        ids = [item.reference_id for item in refs]
        if len(ids) != len(set(ids)) or not REQUIRED_EVIDENCE_IDS.issubset(ids):
            raise InvalidCanonicalGenesisRecord("required evidence")
        if not set(self.identity_anchor.evidence_reference_ids).issubset(ids):
            raise InvalidCanonicalGenesisRecord("identity evidence")
        if type(self.explicit_non_claims) is not tuple or self.explicit_non_claims != MANDATORY_NON_CLAIMS:
            raise InvalidCanonicalGenesisRecord("non-claims")
        if type(self.contradiction_context) is not CanonicalGenesisContradictionContext:
            raise InvalidCanonicalGenesisRecord("contradiction type")
        try:
            context = CanonicalGenesisContradictionContext(
                *(
                    getattr(self.contradiction_context, field)
                    for field in CanonicalGenesisContradictionContext.__dataclass_fields__
                )
            )
        except (AttributeError, TypeError, ValueError):
            raise InvalidCanonicalGenesisRecord("contradiction reconstruction") from None
        if not set(context.evidence_reference_ids).issubset(ids):
            raise InvalidCanonicalGenesisRecord("contradiction evidence")
        state = self.lifecycle_state
        if state is CanonicalGenesisLifecycle.PROPOSED:
            valid = effective is None and self.superseded_by_record_id is None
        elif state is CanonicalGenesisLifecycle.EFFECTIVE:
            valid = (
                effective is not None
                and effective >= created
                and changed >= effective
                and self.superseded_by_record_id is None
                and not context.unresolved_controlling_dispute
            )
        elif state is CanonicalGenesisLifecycle.DISPUTED:
            valid = (
                context.reason is not None
                and bool(context.evidence_reference_ids)
                and context.unresolved_controlling_dispute
                and self.superseded_by_record_id is None
            )
        elif state is CanonicalGenesisLifecycle.SUPERSEDED:
            valid = self.superseded_by_record_id is not None
        else:
            valid = (
                context.reason is not None
                and bool(context.evidence_reference_ids)
                and self.superseded_by_record_id is None
            )
        if not valid:
            raise InvalidCanonicalGenesisRecord("lifecycle consistency")


def _evidence_dict(value: CanonicalGenesisEvidenceReference) -> dict:
    return {
        "content_sha256": value.content_sha256,
        "context": value.context,
        "integrity_basis": value.integrity_basis,
        "location": value.location,
        "reference_id": value.reference_id,
        "reference_kind": value.reference_kind,
    }


def canonical_genesis_record_dict(record: CanonicalGenesisRecord) -> dict:
    """Reconstruct, validate and return the exact serializable field set."""
    if type(record) is not CanonicalGenesisRecord:
        raise InvalidCanonicalGenesisRecord("record type")
    record = CanonicalGenesisRecord(*(getattr(record, field) for field in CanonicalGenesisRecord.__dataclass_fields__))
    anchor = record.identity_anchor
    context = record.contradiction_context
    return {
        "amendment_succession_policy": record.amendment_succession_policy,
        "anchor_middle_height": record.anchor_middle_height,
        "claim": record.claim,
        "contradiction_context": {
            "evidence_reference_ids": sorted(context.evidence_reference_ids),
            "reason": context.reason,
            "unresolved_controlling_dispute": context.unresolved_controlling_dispute,
        },
        "created_at": _timestamp(record.created_at),
        "delta_blocks": record.delta_blocks,
        "effective_at": _timestamp(record.effective_at),
        "evidence_references": [
            _evidence_dict(item) for item in sorted(record.evidence_references, key=lambda item: item.reference_id)
        ],
        "explicit_non_claims": list(record.explicit_non_claims),
        "genesis_depth": record.genesis_depth,
        "genesis_participant_id": record.genesis_participant_id,
        "graph_or_protocol_id": record.graph_or_protocol_id,
        "human_interpretation_required": record.human_interpretation_required,
        "human_profile": record.human_profile,
        "identity_anchor": {
            "anchor_type": anchor.anchor_type,
            "compressed_public_key": anchor.compressed_public_key,
            "encoding": anchor.encoding,
            "evidence_reference_ids": sorted(anchor.evidence_reference_ids),
            "key_purpose": anchor.key_purpose,
            "x_only_public_key": anchor.x_only_public_key,
        },
        "issuer_context": record.issuer_context,
        "lifecycle_changed_at": _timestamp(record.lifecycle_changed_at),
        "lifecycle_state": record.lifecycle_state.value,
        "network": record.network,
        "privacy_scope": record.privacy_scope,
        "record_id": record.record_id,
        "record_version": record.record_version,
        "retention_policy": record.retention_policy,
        "schema": record.schema,
        "superseded_by_record_id": record.superseded_by_record_id,
        "verification_rule": record.verification_rule,
    }


def canonical_genesis_record_bytes(record: CanonicalGenesisRecord) -> bytes:
    return json.dumps(
        canonical_genesis_record_dict(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_genesis_record_sha256(record: CanonicalGenesisRecord) -> str:
    return sha256(canonical_genesis_record_bytes(record)).hexdigest()


def _exact_dict(value: object, keys: set[str], name: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise InvalidCanonicalGenesisRecord(name)
    return value


def parse_canonical_genesis_record(value: bytes | str | dict) -> CanonicalGenesisRecord:
    """Strictly parse without normalizing malformed primitives or field sets."""
    if type(value) is bytes:
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            raise InvalidCanonicalGenesisRecord("UTF-8") from None
    if type(value) is str:
        try:

            def reject_number(_):
                raise ValueError()

            def reject_duplicate_keys(pairs):
                result = {}
                for key, item in pairs:
                    if key in result:
                        raise ValueError("duplicate key")
                    result[key] = item
                return result

            value = json.loads(
                value,
                parse_float=reject_number,
                parse_constant=reject_number,
                object_pairs_hook=reject_duplicate_keys,
            )
        except (ValueError, json.JSONDecodeError):
            raise InvalidCanonicalGenesisRecord("JSON") from None
    keys = set(CanonicalGenesisRecord.__dataclass_fields__)
    data = _exact_dict(value, keys, "record fields")
    anchor_data = _exact_dict(
        data["identity_anchor"],
        set(CanonicalGenesisIdentityAnchor.__dataclass_fields__),
        "anchor fields",
    )
    context_data = _exact_dict(
        data["contradiction_context"],
        set(CanonicalGenesisContradictionContext.__dataclass_fields__),
        "context fields",
    )
    if type(data["evidence_references"]) is not list:
        raise InvalidCanonicalGenesisRecord("evidence primitive")
    evidence = []
    for item in data["evidence_references"]:
        item = _exact_dict(
            item,
            set(CanonicalGenesisEvidenceReference.__dataclass_fields__),
            "evidence fields",
        )
        evidence.append(CanonicalGenesisEvidenceReference(**item))
    if type(data["explicit_non_claims"]) is not list:
        raise InvalidCanonicalGenesisRecord("non-claims primitive")
    for field in ("evidence_reference_ids",):
        if type(anchor_data[field]) is not list or type(context_data[field]) is not list:
            raise InvalidCanonicalGenesisRecord("reference primitive")
    try:
        return CanonicalGenesisRecord(
            **{
                **data,
                "identity_anchor": CanonicalGenesisIdentityAnchor(
                    **{
                        **anchor_data,
                        "evidence_reference_ids": tuple(anchor_data["evidence_reference_ids"]),
                    }
                ),
                "contradiction_context": CanonicalGenesisContradictionContext(
                    **{
                        **context_data,
                        "evidence_reference_ids": tuple(context_data["evidence_reference_ids"]),
                    }
                ),
                "evidence_references": tuple(evidence),
                "explicit_non_claims": tuple(data["explicit_non_claims"]),
                "lifecycle_state": CanonicalGenesisLifecycle(data["lifecycle_state"]),
                "created_at": _parse_time(data["created_at"], "created_at"),
                "lifecycle_changed_at": _parse_time(data["lifecycle_changed_at"], "lifecycle_changed_at"),
                "effective_at": _parse_time(data["effective_at"], "effective_at", True),
            }
        )
    except (TypeError, ValueError):
        raise InvalidCanonicalGenesisRecord("record value") from None


@dataclass(frozen=True, slots=True)
class CanonicalGenesisEvaluation:
    evaluator_version: str
    graph_or_protocol_id: str
    state: CanonicalGenesisEvaluationState
    genesis_participant_id: str
    compressed_public_key: str
    x_only_public_key: str
    evaluated_at: datetime
    selected_effective_record_id: str | None
    selected_effective_record_sha256: str | None
    relevant_records: tuple[tuple[str, str], ...]
    reason_code: str
    human_interpretation_required: bool
    claim: str
    explicit_non_claims: tuple[str, ...]

    def __post_init__(self):
        if (
            self.evaluator_version != EVALUATOR_VERSION
            or self.graph_or_protocol_id != GRAPH_ID
            or type(self.state) is not CanonicalGenesisEvaluationState
            or self.genesis_participant_id != PARTICIPANT_ID
            or self.compressed_public_key != COMPRESSED_KEY
            or self.x_only_public_key != XONLY_KEY
            or self.reason_code not in EVALUATION_REASON_CODES
            or self.human_interpretation_required is not True
            or self.claim != CLAIM
            or self.explicit_non_claims != MANDATORY_NON_CLAIMS
        ):
            raise InvalidCanonicalGenesisRecord("evaluation fixed contract")
        evaluated = _time(self.evaluated_at, "evaluated_at")
        if _parse_time(_timestamp(evaluated), "evaluated_at") != evaluated:
            raise InvalidCanonicalGenesisRecord("evaluated_at precision")
        if (self.selected_effective_record_id is None) != (self.selected_effective_record_sha256 is None):
            raise InvalidCanonicalGenesisRecord("selected record")
        if self.selected_effective_record_id is not None:
            _uuid(self.selected_effective_record_id, "selected record")
            if not _HEX64.fullmatch(self.selected_effective_record_sha256):
                raise InvalidCanonicalGenesisRecord("selected digest")
        if (self.state is CanonicalGenesisEvaluationState.GENESIS_ACTIVE) != (
            self.selected_effective_record_id is not None
        ):
            raise InvalidCanonicalGenesisRecord("selected state")
        allowed_reasons = {
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
        if self.reason_code not in allowed_reasons[self.state]:
            raise InvalidCanonicalGenesisRecord("evaluation reason state")
        if type(self.relevant_records) is not tuple:
            raise InvalidCanonicalGenesisRecord("relevant records")
        for item in self.relevant_records:
            if type(item) is not tuple or len(item) != 2:
                raise InvalidCanonicalGenesisRecord("relevant record")
            _uuid(item[0], "relevant record")
            if type(item[1]) is not str or not _HEX64.fullmatch(item[1]):
                raise InvalidCanonicalGenesisRecord("relevant digest")
        if (
            self.relevant_records != tuple(sorted(self.relevant_records))
            or len(set(self.relevant_records)) != len(self.relevant_records)
            or len({item[0] for item in self.relevant_records}) != len(self.relevant_records)
        ):
            raise InvalidCanonicalGenesisRecord("relevant records")
        if (
            self.selected_effective_record_id is not None
            and (
                self.selected_effective_record_id,
                self.selected_effective_record_sha256,
            )
            not in self.relevant_records
        ):
            raise InvalidCanonicalGenesisRecord("selected relevance")


def _genesis_evaluation_dict(value: CanonicalGenesisEvaluation) -> dict:
    return {
        "claim": value.claim,
        "compressed_public_key": value.compressed_public_key,
        "evaluated_at": _timestamp(value.evaluated_at),
        "evaluator_version": value.evaluator_version,
        "explicit_non_claims": list(value.explicit_non_claims),
        "genesis_participant_id": value.genesis_participant_id,
        "graph_or_protocol_id": value.graph_or_protocol_id,
        "human_interpretation_required": value.human_interpretation_required,
        "reason_code": value.reason_code,
        "relevant_records": [list(item) for item in value.relevant_records],
        "selected_effective_record_id": value.selected_effective_record_id,
        "selected_effective_record_sha256": value.selected_effective_record_sha256,
        "state": value.state.value,
        "x_only_public_key": value.x_only_public_key,
    }


def canonical_genesis_evaluation_bytes(value: CanonicalGenesisEvaluation) -> bytes:
    """Return the exact canonical identity of one genesis evaluation."""
    if type(value) is not CanonicalGenesisEvaluation:
        raise InvalidCanonicalGenesisRecord("evaluation type")
    try:
        value = CanonicalGenesisEvaluation(
            *(getattr(value, field) for field in CanonicalGenesisEvaluation.__dataclass_fields__)
        )
    except InvalidCanonicalGenesisRecord:
        raise
    except Exception:
        raise InvalidCanonicalGenesisRecord("evaluation value") from None
    return json.dumps(
        _genesis_evaluation_dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_genesis_evaluation_sha256(value: CanonicalGenesisEvaluation) -> str:
    return sha256(canonical_genesis_evaluation_bytes(value)).hexdigest()


def parse_canonical_genesis_evaluation(value: bytes | str) -> CanonicalGenesisEvaluation:
    """Strictly parse an exact canonical genesis-evaluation identity."""
    if type(value) is bytes:
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            raise InvalidCanonicalGenesisRecord("ASCII") from None
    if type(value) is not str:
        raise InvalidCanonicalGenesisRecord("evaluation JSON")
    try:

        def reject_duplicate_keys(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = item
            return result

        def reject_number(_):
            raise ValueError()

        data = json.loads(
            value,
            parse_float=reject_number,
            parse_constant=reject_number,
            object_pairs_hook=reject_duplicate_keys,
        )
        if (
            type(data) is not dict
            or set(data) != set(CanonicalGenesisEvaluation.__dataclass_fields__)
            or type(data["relevant_records"]) is not list
            or type(data["explicit_non_claims"]) is not list
            or any(type(item) is not list or len(item) != 2 for item in data["relevant_records"])
        ):
            raise ValueError()
        result = CanonicalGenesisEvaluation(
            **{
                **data,
                "state": CanonicalGenesisEvaluationState(data["state"]),
                "evaluated_at": _parse_time(data["evaluated_at"], "evaluated_at"),
                "relevant_records": tuple(tuple(item) for item in data["relevant_records"]),
                "explicit_non_claims": tuple(data["explicit_non_claims"]),
            }
        )
    except Exception:
        raise InvalidCanonicalGenesisRecord("evaluation JSON") from None
    if canonical_genesis_evaluation_bytes(result).decode("ascii") != value:
        raise InvalidCanonicalGenesisRecord("noncanonical evaluation JSON")
    return result


def evaluate_canonical_genesis(
    records, *, graph_or_protocol_id: str, evaluated_at: datetime
) -> CanonicalGenesisEvaluation:
    """Evaluate trusted immutable records; every malformed condition fails closed."""
    if graph_or_protocol_id != GRAPH_ID:
        raise InvalidCanonicalGenesisRecord("wrong graph")
    _time(evaluated_at, "evaluated_at")
    if _parse_time(_timestamp(evaluated_at), "evaluated_at") != evaluated_at:
        raise InvalidCanonicalGenesisRecord("evaluated_at precision")
    state = CanonicalGenesisEvaluationState.UNKNOWN
    reason = "no_records"
    selected = None
    relevant = []
    try:
        if type(records) not in (tuple, list):
            raise InvalidCanonicalGenesisRecord("records type")
        valid = []
        for record in records:
            rebuilt = parse_canonical_genesis_record(canonical_genesis_record_dict(record))
            valid.append(rebuilt)
            relevant.append((rebuilt.record_id, canonical_genesis_record_sha256(rebuilt)))
        relevant.sort()
        if len({item[0] for item in relevant}) != len(relevant):
            raise InvalidCanonicalGenesisRecord("duplicate record")
        disputed = [
            item
            for item in valid
            if item.lifecycle_state is CanonicalGenesisLifecycle.DISPUTED
            or item.contradiction_context.unresolved_controlling_dispute
        ]
        effective = [
            item
            for item in valid
            if item.lifecycle_state is CanonicalGenesisLifecycle.EFFECTIVE and item.effective_at <= evaluated_at
        ]
        if disputed:
            state, reason = (
                CanonicalGenesisEvaluationState.DISPUTED,
                "controlling_dispute",
            )
        elif len(effective) > 1:
            state, reason = (
                CanonicalGenesisEvaluationState.DISPUTED,
                "multiple_effective_records",
            )
        elif len(valid) == 1 and len(effective) == 1:
            selected = effective[0]
            state, reason = (
                CanonicalGenesisEvaluationState.GENESIS_ACTIVE,
                "exact_effective_record",
            )
        elif len(valid) > 1 and effective:
            reason = (
                "succession_policy_unavailable"
                if any(item.lifecycle_state is CanonicalGenesisLifecycle.SUPERSEDED for item in valid)
                else "multiple_records_without_transition_policy"
            )
        elif any(
            item.lifecycle_state is CanonicalGenesisLifecycle.EFFECTIVE and item.effective_at > evaluated_at
            for item in valid
        ):
            reason = "effective_timestamp_in_future"
        elif valid and all(
            item.lifecycle_state in (CanonicalGenesisLifecycle.REVOKED, CanonicalGenesisLifecycle.SUPERSEDED)
            for item in valid
        ):
            state, reason = CanonicalGenesisEvaluationState.LINEAGE_INACTIVE, (
                "succession_policy_unavailable"
                if any(item.lifecycle_state is CanonicalGenesisLifecycle.SUPERSEDED for item in valid)
                else "all_records_revoked"
            )
        elif valid and all(item.lifecycle_state is CanonicalGenesisLifecycle.PROPOSED for item in valid):
            state, reason = CanonicalGenesisEvaluationState.PROVISIONAL, "proposed_only"
    except Exception:
        state, reason, selected, relevant = (
            CanonicalGenesisEvaluationState.UNKNOWN,
            "malformed_or_untrusted_input",
            None,
            [],
        )
    return CanonicalGenesisEvaluation(
        EVALUATOR_VERSION,
        GRAPH_ID,
        state,
        PARTICIPANT_ID,
        COMPRESSED_KEY,
        XONLY_KEY,
        evaluated_at,
        selected.record_id if selected else None,
        canonical_genesis_record_sha256(selected) if selected else None,
        tuple(relevant),
        reason,
        True,
        CLAIM,
        MANDATORY_NON_CLAIMS,
    )
