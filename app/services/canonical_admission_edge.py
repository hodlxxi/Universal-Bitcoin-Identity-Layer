"""Dormant canonical human admission-edge registry and current-edge evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from hashlib import sha256
import json
import re
import uuid

from app.services.canonical_genesis_record import (
    CanonicalGenesisEvaluation,
    CanonicalGenesisEvaluationState,
)
from app.services.covenant_relation import (
    CovenantDirection,
    CovenantRelationEvaluation,
    EVALUATION_SCHEMA,
    MAX_BITCOIN_SATS,
    MAX_VOUT,
    covenant_relation_source_sha256,
)
from app.services.mirrored_covenant_pair import (
    CovenantDeltaProfile,
    CovenantTemplateFamily,
    ValidatedMirroredCovenantPair,
    parse_covenant_leg,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    trusted_registration_sha256,
)

EDGE_SCHEMA = "hodlxxi.canonical_admission_edge.v1"
EDGE_VERSION = "hodlxxi.canonical_admission_edge_service.v1"
EVALUATOR_VERSION = "hodlxxi.canonical_admission_edge_evaluator.v1"
CURRENT_EVALUATOR_VERSION = "hodlxxi.canonical_admission_edge_current_evaluator.v1"
VERIFICATION_RULE = "hodlxxi.canonical_admission_edge_verification.v1"
GRAPH_ID = "hodlxxi.crt_membership_graph.v1"
NETWORK = "bitcoin"
HUMAN_PROFILE = "legacy_777"
GENESIS_PARTICIPANT_ID = "E923"
GENESIS_COMPRESSED_KEY = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
GENESIS_XONLY_KEY = "3d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
BASE_MIDDLE_HEIGHT = 1777777
DELTA_BLOCKS = 777
MIN_CONFIRMATIONS = 1
RETENTION_POLICY = "append_preserved_no_silent_erasure"
MANDATORY_NON_CLAIMS = tuple(
    sorted(
        (
            "no FULL/LIMITED authorization grant",
            "no complete ancestry proof for depths greater than one",
            "no decentralization or universal-legitimacy proof",
            "no fairness or informed-consent proof",
            "no future-cooperation guarantee",
            "no legal identity, KYC or complete personhood proof",
            "no operator-agent current_144 admission",
            "no ownership, custody or guardianship proof",
            "no permission to bypass lineage evaluation",
            "no production enforcement or deployment claim",
            "no proof of current private-key possession",
            "no reputation or rank grant",
            "no runtime administration or server-privilege grant",
            "no sincerity, affection, loyalty or trustworthiness proof",
            "no sponsor ownership or control over the child",
        )
    )
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX66 = re.compile(r"(?:02|03)[0-9a-f]{64}\Z")
_HEX_EVEN = re.compile(r"(?:[0-9a-f]{2})+\Z")


class InvalidCanonicalAdmissionEdge(ValueError):
    """An admission edge or its evaluation violates the exact V1 contract."""


class AdmissionEdgeDirection(Enum):
    SPONSOR_TO_CHILD = "sponsor_to_child"
    CHILD_TO_SPONSOR = "child_to_sponsor"


class SponsorBasisKind(Enum):
    CANONICAL_GENESIS_RECORD = "canonical_genesis_record"
    CANONICAL_ADMISSION_EDGE = "canonical_admission_edge"


class AdmissionEdgeLifecycle(Enum):
    PROPOSED = "proposed"
    EFFECTIVE = "effective"
    DISPUTED = "disputed"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


class AdmissionEdgeEvaluationState(Enum):
    ACTIVE = "active"
    PROVISIONAL = "provisional"
    EDGE_INACTIVE = "edge_inactive"
    LINEAGE_INACTIVE = "lineage_inactive"
    DISPUTED = "disputed"
    UNKNOWN = "unknown"


class AdmissionEdgeReason(Enum):
    EXACT_DEPTH1_ADMISSION_ACTIVE = "exact_depth1_admission_active"
    RECORD_PROPOSED = "record_proposed"
    RECORD_DISPUTED = "record_disputed"
    RECORD_REVOKED = "record_revoked"
    RECORD_SUPERSEDED = "record_superseded"
    GENESIS_PROVISIONAL = "genesis_provisional"
    GENESIS_DISPUTED = "genesis_disputed"
    GENESIS_LINEAGE_INACTIVE = "genesis_lineage_inactive"
    GENESIS_UNKNOWN = "genesis_unknown"
    REGISTRATION_REVOKED = "registration_revoked"
    REGISTRATION_SUPERSEDED = "registration_superseded"
    REGISTRATION_DISPUTED = "registration_disputed"
    REGISTRATION_BINDING_MISMATCH = "registration_binding_mismatch"
    MISSING_REQUIRED_LEG = "missing_required_leg"
    SPENT_REQUIRED_LEG = "spent_required_leg"
    INSUFFICIENT_CONFIRMATIONS = "insufficient_confirmations"
    OBSERVATION_BINDING_MISMATCH = "observation_binding_mismatch"
    UNEQUAL_LEG_AMOUNTS = "unequal_leg_amounts"
    SPONSOR_LINEAGE_EVALUATOR_UNAVAILABLE = "sponsor_lineage_evaluator_unavailable"
    MALFORMED_OR_UNTRUSTED_INPUT = "malformed_or_untrusted_input"


class AdmissionEdgeCurrentReason(Enum):
    EXACT_CURRENT_EDGE_ACTIVE = "exact_current_edge_active"
    RECORD_PROPOSED = "record_proposed"
    RECORD_DISPUTED = "record_disputed"
    RECORD_REVOKED = "record_revoked"
    RECORD_SUPERSEDED = "record_superseded"
    REGISTRATION_REVOKED = "registration_revoked"
    REGISTRATION_SUPERSEDED = "registration_superseded"
    REGISTRATION_DISPUTED = "registration_disputed"
    REGISTRATION_BINDING_MISMATCH = "registration_binding_mismatch"
    MISSING_REQUIRED_LEG = "missing_required_leg"
    SPENT_REQUIRED_LEG = "spent_required_leg"
    INSUFFICIENT_CONFIRMATIONS = "insufficient_confirmations"
    OBSERVATION_BINDING_MISMATCH = "observation_binding_mismatch"
    UNEQUAL_LEG_AMOUNTS = "unequal_leg_amounts"
    MALFORMED_OR_UNTRUSTED_INPUT = "malformed_or_untrusted_input"


def _fail(name: str) -> None:
    raise InvalidCanonicalAdmissionEdge(name)


def _digest(value: object, name: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _fail(name)
    return value


def _uuid(value: object, name: str) -> str:
    if type(value) is not str:
        _fail(name)
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        _fail(name)
    if value != canonical:
        _fail(name)
    return value


def _time(value: object, name: str, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
    ):
        _fail(name)
    return value


def _timestamp(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_time(value: object, name: str, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if type(value) is not str or not value.endswith("Z"):
        _fail(name)
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(name)
    if _timestamp(result) != value:
        _fail(name)
    return result


def cascade_heights(child_depth: int) -> tuple[int, int, int]:
    if type(child_depth) is not int or child_depth < 1:
        _fail("child_depth")
    middle = BASE_MIDDLE_HEIGHT - DELTA_BLOCKS * (child_depth - 1)
    early, late = middle - DELTA_BLOCKS, middle + DELTA_BLOCKS
    if early <= 0:
        _fail("depth outside positive block-height range")
    return early, middle, late


@dataclass(frozen=True, slots=True)
class AdmissionContradictionContext:
    reason: str | None
    evidence: tuple[str, ...]
    unresolved_controlling_dispute: bool

    def __post_init__(self):
        if self.reason is not None and (type(self.reason) is not str or not self.reason.strip()):
            _fail("contradiction reason")
        if type(self.evidence) is not tuple or self.evidence != tuple(sorted(self.evidence)):
            _fail("contradiction evidence")
        if len(set(self.evidence)) != len(self.evidence):
            _fail("contradiction evidence")
        for item in self.evidence:
            _digest(item, "contradiction evidence")
        if type(self.unresolved_controlling_dispute) is not bool:
            _fail("contradiction dispute")


@dataclass(frozen=True, slots=True)
class CanonicalAdmissionLeg:
    direction: AdmissionEdgeDirection
    sender_participant_id: str
    sender_compressed_public_key: str
    sender_x_only_public_key: str
    receiver_participant_id: str
    receiver_compressed_public_key: str
    receiver_x_only_public_key: str
    receiver_cltv_height: int
    sender_cltv_height: int
    raw_script_hex: str
    txid: str
    vout: int
    amount_sats: int
    witness_script_sha256: str
    descriptor_sha256: str | None

    def __post_init__(self):
        if type(self.direction) is not AdmissionEdgeDirection:
            _fail("leg direction")
        for value in (self.sender_participant_id, self.receiver_participant_id):
            if type(value) is not str or not value:
                _fail("participant id")
        for value in (
            self.sender_compressed_public_key,
            self.receiver_compressed_public_key,
        ):
            if type(value) is not str or _HEX66.fullmatch(value) is None:
                _fail("compressed key")
        for value in (self.sender_x_only_public_key, self.receiver_x_only_public_key):
            _digest(value, "x-only key")
        if (
            self.sender_compressed_public_key[2:] != self.sender_x_only_public_key
            or self.receiver_compressed_public_key[2:] != self.receiver_x_only_public_key
        ):
            _fail("key binding")
        for value in (self.receiver_cltv_height, self.sender_cltv_height):
            if type(value) is not int or value <= 0 or value > 499_999_999:
                _fail("height")
        if type(self.raw_script_hex) is not str or _HEX_EVEN.fullmatch(self.raw_script_hex) is None:
            _fail("raw script")
        try:
            parsed = parse_covenant_leg(self.raw_script_hex)
        except Exception:
            _fail("raw script")
        if (
            parsed.template_family is not CovenantTemplateFamily.CLTV_ONLY
            or parsed.cooperative_pubkeys != ()
            or parsed.delta_blocks != DELTA_BLOCKS
            or parsed.receiver_pubkey != self.receiver_compressed_public_key
            or parsed.receiver_xonly_pubkey != self.receiver_x_only_public_key
            or parsed.sender_pubkey != self.sender_compressed_public_key
            or parsed.sender_xonly_pubkey != self.sender_x_only_public_key
            or parsed.receiver_height != self.receiver_cltv_height
            or parsed.sender_height != self.sender_cltv_height
            or parsed.script_sha256 != self.witness_script_sha256
        ):
            _fail("raw script binding")
        _digest(self.txid, "txid")
        if type(self.vout) is not int or not 0 <= self.vout <= MAX_VOUT:
            _fail("vout")
        if type(self.amount_sats) is not int or not 1 <= self.amount_sats <= MAX_BITCOIN_SATS:
            _fail("amount_sats")
        _digest(self.witness_script_sha256, "witness script")
        if self.descriptor_sha256 is not None:
            _digest(self.descriptor_sha256, "descriptor")


@dataclass(frozen=True, slots=True)
class CanonicalAdmissionEdge:
    schema: str
    edge_version: str
    edge_id: str
    graph_or_protocol_id: str
    network: str
    human_profile: str
    verification_rule: str
    sponsor_participant_id: str
    sponsor_compressed_public_key: str
    sponsor_x_only_public_key: str
    sponsor_depth: int
    child_participant_id: str
    child_compressed_public_key: str
    child_x_only_public_key: str
    child_depth: int
    early_height: int
    middle_height: int
    late_height: int
    trusted_registration_id: str
    trusted_registration_sha256: str
    pair_sha256: str
    validator_version: str
    sponsor_basis_kind: SponsorBasisKind
    sponsor_basis_record_id: str
    sponsor_basis_record_sha256: str
    lifecycle_state: AdmissionEdgeLifecycle
    created_at: datetime
    lifecycle_changed_at: datetime
    effective_at: datetime | None
    superseded_by_edge_id: str | None
    legs: tuple[CanonicalAdmissionLeg, ...]
    contradiction_context: AdmissionContradictionContext
    explicit_non_claims: tuple[str, ...]
    retention_policy: str
    human_interpretation_required: bool

    def __post_init__(self):
        if (
            self.schema != EDGE_SCHEMA
            or self.edge_version != EDGE_VERSION
            or self.graph_or_protocol_id != GRAPH_ID
            or self.network != NETWORK
            or self.human_profile != HUMAN_PROFILE
            or self.verification_rule != VERIFICATION_RULE
            or self.retention_policy != RETENTION_POLICY
            or self.explicit_non_claims != MANDATORY_NON_CLAIMS
            or self.human_interpretation_required is not True
        ):
            _fail("fixed edge contract")
        _uuid(self.edge_id, "edge id")
        _uuid(self.trusted_registration_id, "registration id")
        _uuid(self.sponsor_basis_record_id, "basis id")
        for value in (
            self.trusted_registration_sha256,
            self.pair_sha256,
            self.sponsor_basis_record_sha256,
        ):
            _digest(value, "digest")
        if type(self.validator_version) is not str or not self.validator_version:
            _fail("validator version")
        if type(self.sponsor_depth) is not int or self.sponsor_depth < 0:
            _fail("sponsor depth")
        if type(self.child_depth) is not int or self.child_depth != self.sponsor_depth + 1:
            _fail("child depth")
        if (self.early_height, self.middle_height, self.late_height) != cascade_heights(self.child_depth):
            _fail("cascade heights")
        for participant in (self.sponsor_participant_id, self.child_participant_id):
            if type(participant) is not str or not participant:
                _fail("participant id")
        for key in (
            self.sponsor_compressed_public_key,
            self.child_compressed_public_key,
        ):
            if type(key) is not str or _HEX66.fullmatch(key) is None:
                _fail("compressed key")
        for key in (self.sponsor_x_only_public_key, self.child_x_only_public_key):
            _digest(key, "x-only key")
        if (
            self.sponsor_compressed_public_key[2:] != self.sponsor_x_only_public_key
            or self.child_compressed_public_key[2:] != self.child_x_only_public_key
            or self.sponsor_participant_id == self.child_participant_id
            or self.sponsor_compressed_public_key == self.child_compressed_public_key
            or self.sponsor_x_only_public_key == self.child_x_only_public_key
        ):
            _fail("distinct role-bound identities")
        if self.child_participant_id != self.child_x_only_public_key:
            _fail("child participant convention")
        if self.sponsor_depth == 0:
            if (
                self.sponsor_basis_kind is not SponsorBasisKind.CANONICAL_GENESIS_RECORD
                or self.sponsor_participant_id != GENESIS_PARTICIPANT_ID
                or self.sponsor_compressed_public_key != GENESIS_COMPRESSED_KEY
                or self.sponsor_x_only_public_key != GENESIS_XONLY_KEY
            ):
                _fail("genesis basis")
        elif (
            self.sponsor_basis_kind is not SponsorBasisKind.CANONICAL_ADMISSION_EDGE
            or self.sponsor_participant_id != self.sponsor_x_only_public_key
        ):
            _fail("parent basis or sponsor participant convention")
        if type(self.lifecycle_state) is not AdmissionEdgeLifecycle:
            _fail("lifecycle")
        created = _time(self.created_at, "created")
        changed = _time(self.lifecycle_changed_at, "changed")
        effective = _time(self.effective_at, "effective", True)
        if changed < created:
            _fail("lifecycle time")
        if self.superseded_by_edge_id is not None:
            _uuid(self.superseded_by_edge_id, "successor")
            if self.superseded_by_edge_id == self.edge_id:
                _fail("successor")
        context = AdmissionContradictionContext(
            *(getattr(self.contradiction_context, f) for f in AdmissionContradictionContext.__dataclass_fields__)
        )
        state = self.lifecycle_state
        valid = {
            AdmissionEdgeLifecycle.PROPOSED: effective is None and self.superseded_by_edge_id is None,
            AdmissionEdgeLifecycle.EFFECTIVE: effective is not None
            and effective >= created
            and changed >= effective
            and self.superseded_by_edge_id is None
            and not context.unresolved_controlling_dispute,
            AdmissionEdgeLifecycle.DISPUTED: context.reason is not None
            and bool(context.evidence)
            and context.unresolved_controlling_dispute
            and self.superseded_by_edge_id is None,
            AdmissionEdgeLifecycle.SUPERSEDED: self.superseded_by_edge_id is not None,
            AdmissionEdgeLifecycle.REVOKED: context.reason is not None
            and bool(context.evidence)
            and self.superseded_by_edge_id is None,
        }[state]
        if not valid:
            _fail("lifecycle consistency")
        if type(self.legs) is not tuple or len(self.legs) != 2:
            _fail("exactly two legs")
        legs = tuple(
            CanonicalAdmissionLeg(*(getattr(x, f) for f in CanonicalAdmissionLeg.__dataclass_fields__))
            for x in self.legs
        )
        by_direction = {x.direction: x for x in legs}
        if len(by_direction) != 2 or set(by_direction) != set(AdmissionEdgeDirection):
            _fail("leg directions")
        sponsor_to_child = by_direction[AdmissionEdgeDirection.SPONSOR_TO_CHILD]
        child_to_sponsor = by_direction[AdmissionEdgeDirection.CHILD_TO_SPONSOR]
        expected = (
            (
                sponsor_to_child,
                self.sponsor_participant_id,
                self.sponsor_compressed_public_key,
                self.sponsor_x_only_public_key,
                self.child_participant_id,
                self.child_compressed_public_key,
                self.child_x_only_public_key,
                self.early_height,
                self.middle_height,
            ),
            (
                child_to_sponsor,
                self.child_participant_id,
                self.child_compressed_public_key,
                self.child_x_only_public_key,
                self.sponsor_participant_id,
                self.sponsor_compressed_public_key,
                self.sponsor_x_only_public_key,
                self.middle_height,
                self.late_height,
            ),
        )
        for (
            leg,
            sender_id,
            sender_key,
            sender_x,
            receiver_id,
            receiver_key,
            receiver_x,
            receiver_h,
            sender_h,
        ) in expected:
            if (
                leg.sender_participant_id,
                leg.sender_compressed_public_key,
                leg.sender_x_only_public_key,
                leg.receiver_participant_id,
                leg.receiver_compressed_public_key,
                leg.receiver_x_only_public_key,
                leg.receiver_cltv_height,
                leg.sender_cltv_height,
            ) != (
                sender_id,
                sender_key,
                sender_x,
                receiver_id,
                receiver_key,
                receiver_x,
                receiver_h,
                sender_h,
            ):
                _fail("leg role binding")
            if leg.receiver_participant_id != (
                GENESIS_PARTICIPANT_ID
                if leg.receiver_x_only_public_key == GENESIS_XONLY_KEY
                else leg.receiver_x_only_public_key
            ) or leg.sender_participant_id != (
                GENESIS_PARTICIPANT_ID
                if leg.sender_x_only_public_key == GENESIS_XONLY_KEY
                else leg.sender_x_only_public_key
            ):
                _fail("leg participant convention")
        if (
            sponsor_to_child.amount_sats != child_to_sponsor.amount_sats
            or sponsor_to_child.raw_script_hex == child_to_sponsor.raw_script_hex
            or sponsor_to_child.witness_script_sha256 == child_to_sponsor.witness_script_sha256
            or (sponsor_to_child.txid, sponsor_to_child.vout) == (child_to_sponsor.txid, child_to_sponsor.vout)
        ):
            _fail("leg equality or distinctness")
        object.__setattr__(self, "legs", (sponsor_to_child, child_to_sponsor))


def _leg_dict(leg: CanonicalAdmissionLeg) -> dict:
    result = {field: getattr(leg, field) for field in CanonicalAdmissionLeg.__dataclass_fields__}
    result["direction"] = leg.direction.value
    return result


def canonical_admission_edge_dict(record: CanonicalAdmissionEdge) -> dict:
    record = _validated_record(record)
    result = {field: getattr(record, field) for field in CanonicalAdmissionEdge.__dataclass_fields__}
    result.update(
        lifecycle_state=record.lifecycle_state.value,
        sponsor_basis_kind=record.sponsor_basis_kind.value,
        created_at=_timestamp(record.created_at),
        lifecycle_changed_at=_timestamp(record.lifecycle_changed_at),
        effective_at=_timestamp(record.effective_at),
        legs=[_leg_dict(x) for x in record.legs],
        contradiction_context={
            "reason": record.contradiction_context.reason,
            "evidence": list(record.contradiction_context.evidence),
            "unresolved_controlling_dispute": record.contradiction_context.unresolved_controlling_dispute,
        },
        explicit_non_claims=list(record.explicit_non_claims),
    )
    return result


def canonical_admission_edge_bytes(record: CanonicalAdmissionEdge) -> bytes:
    return json.dumps(
        canonical_admission_edge_dict(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_admission_edge_sha256(record: CanonicalAdmissionEdge) -> str:
    return sha256(canonical_admission_edge_bytes(record)).hexdigest()


def _validated_record(value: object) -> CanonicalAdmissionEdge:
    if type(value) is not CanonicalAdmissionEdge:
        _fail("record type")
    return CanonicalAdmissionEdge(*(getattr(value, f) for f in CanonicalAdmissionEdge.__dataclass_fields__))


def parse_canonical_admission_edge(value: bytes | str | dict) -> CanonicalAdmissionEdge:
    if type(value) is bytes:
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            _fail("UTF-8")
    if type(value) is str:

        def reject(_: str):
            raise ValueError()

        def pairs(items):
            result = {}
            for key, item in items:
                if key in result:
                    raise ValueError()
                result[key] = item
            return result

        try:
            value = json.loads(
                value,
                parse_float=reject,
                parse_constant=reject,
                object_pairs_hook=pairs,
            )
        except (ValueError, json.JSONDecodeError):
            _fail("JSON")
    if type(value) is not dict or set(value) != set(CanonicalAdmissionEdge.__dataclass_fields__):
        _fail("record fields")
    data = dict(value)
    if type(data["legs"]) is not list:
        _fail("legs")
    legs = []
    for item in data["legs"]:
        if type(item) is not dict or set(item) != set(CanonicalAdmissionLeg.__dataclass_fields__):
            _fail("leg fields")
        legs.append(CanonicalAdmissionLeg(**{**item, "direction": AdmissionEdgeDirection(item["direction"])}))
    context = data["contradiction_context"]
    if (
        type(context) is not dict
        or set(context) != set(AdmissionContradictionContext.__dataclass_fields__)
        or type(context["evidence"]) is not list
    ):
        _fail("contradiction fields")
    if type(data["explicit_non_claims"]) is not list:
        _fail("non-claims")
    try:
        return CanonicalAdmissionEdge(
            **{
                **data,
                "sponsor_basis_kind": SponsorBasisKind(data["sponsor_basis_kind"]),
                "lifecycle_state": AdmissionEdgeLifecycle(data["lifecycle_state"]),
                "created_at": _parse_time(data["created_at"], "created"),
                "lifecycle_changed_at": _parse_time(data["lifecycle_changed_at"], "changed"),
                "effective_at": _parse_time(data["effective_at"], "effective", True),
                "legs": tuple(legs),
                "contradiction_context": AdmissionContradictionContext(
                    **{**context, "evidence": tuple(context["evidence"])}
                ),
                "explicit_non_claims": tuple(data["explicit_non_claims"]),
            }
        )
    except (TypeError, ValueError):
        _fail("record value")


def validate_admission_sources(
    record: CanonicalAdmissionEdge,
    registration: TrustedCovenantRegistration,
    *,
    genesis_evaluation: CanonicalGenesisEvaluation | None = None,
    parent_edge: CanonicalAdmissionEdge | None = None,
    require_active: bool = True,
) -> CanonicalAdmissionEdge:
    record = _validated_record(record)
    registration = TrustedCovenantRegistration(
        *(getattr(registration, f) for f in TrustedCovenantRegistration.__dataclass_fields__)
    )
    pair: ValidatedMirroredCovenantPair = registration.mirrored_pair
    incoming, outgoing = registration.outpoints
    legs = record.legs
    static = (
        record.trusted_registration_id == registration.registration_id
        and record.trusted_registration_sha256 == trusted_registration_sha256(registration)
        and record.pair_sha256 == registration.pair_sha256
        and record.validator_version == registration.validator_version
        and registration.network == NETWORK
        and registration.subject_pubkey == record.child_compressed_public_key
        and registration.subject_xonly_pubkey == record.child_x_only_public_key
        and registration.counterparty_pubkey == record.sponsor_compressed_public_key
        and registration.counterparty_xonly_pubkey == record.sponsor_x_only_public_key
        and registration.template_family is CovenantTemplateFamily.CLTV_ONLY
        and registration.delta_profile is CovenantDeltaProfile.LEGACY_777
        and registration.delta_blocks == DELTA_BLOCKS
        and incoming.amount_sats == outgoing.amount_sats == legs[0].amount_sats == legs[1].amount_sats
        and incoming.amount_sats > 0
    )
    for binding, leg, direction in (
        (incoming, legs[0], CovenantDirection.INCOMING),
        (outgoing, legs[1], CovenantDirection.OUTGOING),
    ):
        static = (
            static
            and binding.direction is direction
            and (
                binding.txid,
                binding.vout,
                binding.amount_sats,
                binding.witness_script_sha256,
                binding.descriptor_sha256,
            )
            == (
                leg.txid,
                leg.vout,
                leg.amount_sats,
                leg.witness_script_sha256,
                leg.descriptor_sha256,
            )
        )
    static = (
        static
        and pair.earlier_leg.raw_script_hex == legs[0].raw_script_hex
        and pair.earlier_leg.script_sha256 == legs[0].witness_script_sha256
        and pair.earlier_leg.receiver_pubkey == record.child_compressed_public_key
        and pair.earlier_leg.receiver_xonly_pubkey == record.child_x_only_public_key
        and pair.earlier_leg.sender_pubkey == record.sponsor_compressed_public_key
        and pair.earlier_leg.sender_xonly_pubkey == record.sponsor_x_only_public_key
        and pair.earlier_leg.receiver_height == record.early_height
        and pair.earlier_leg.sender_height == record.middle_height
        and pair.later_leg.raw_script_hex == legs[1].raw_script_hex
        and pair.later_leg.script_sha256 == legs[1].witness_script_sha256
        and pair.later_leg.receiver_pubkey == record.sponsor_compressed_public_key
        and pair.later_leg.receiver_xonly_pubkey == record.sponsor_x_only_public_key
        and pair.later_leg.sender_pubkey == record.child_compressed_public_key
        and pair.later_leg.sender_xonly_pubkey == record.child_x_only_public_key
        and pair.later_leg.receiver_height == record.middle_height
        and pair.later_leg.sender_height == record.late_height
    )
    if not static or (
        require_active and registration.lifecycle_state is not TrustedCovenantRegistrationLifecycle.ACTIVE
    ):
        _fail("trusted registration binding")
    if record.sponsor_depth == 0:
        if type(genesis_evaluation) is not CanonicalGenesisEvaluation or parent_edge is not None:
            _fail("genesis source")
        genesis_evaluation = CanonicalGenesisEvaluation(
            *(getattr(genesis_evaluation, f) for f in CanonicalGenesisEvaluation.__dataclass_fields__)
        )
        if genesis_evaluation.state is CanonicalGenesisEvaluationState.GENESIS_ACTIVE and (
            genesis_evaluation.selected_effective_record_id != record.sponsor_basis_record_id
            or genesis_evaluation.selected_effective_record_sha256 != record.sponsor_basis_record_sha256
        ):
            _fail("genesis source")
        if require_active and genesis_evaluation.state is not CanonicalGenesisEvaluationState.GENESIS_ACTIVE:
            _fail("genesis source")
    else:
        if genesis_evaluation is not None or type(parent_edge) is not CanonicalAdmissionEdge:
            _fail("parent source")
        parent_edge = _validated_record(parent_edge)
        if (
            parent_edge.lifecycle_state is not AdmissionEdgeLifecycle.EFFECTIVE
            or parent_edge.edge_id != record.sponsor_basis_record_id
            or canonical_admission_edge_sha256(parent_edge) != record.sponsor_basis_record_sha256
            or parent_edge.graph_or_protocol_id != record.graph_or_protocol_id
            or parent_edge.human_profile != record.human_profile
            or parent_edge.child_participant_id != record.sponsor_participant_id
            or parent_edge.child_compressed_public_key != record.sponsor_compressed_public_key
            or parent_edge.child_x_only_public_key != record.sponsor_x_only_public_key
            or parent_edge.child_depth != record.sponsor_depth
        ):
            _fail("parent source")
    return record


@dataclass(frozen=True, slots=True)
class CanonicalAdmissionEdgeEvaluation:
    evaluator_version: str
    graph_or_protocol_id: str
    edge_id: str
    edge_sha256: str
    sponsor_participant_id: str
    sponsor_compressed_public_key: str
    sponsor_x_only_public_key: str
    sponsor_depth: int
    child_participant_id: str
    child_compressed_public_key: str
    child_x_only_public_key: str
    child_depth: int
    early_height: int
    middle_height: int
    late_height: int
    evaluated_at: datetime
    state: AdmissionEdgeEvaluationState
    reason_code: AdmissionEdgeReason
    selected_registration_id: str | None
    selected_registration_sha256: str | None
    selected_sponsor_basis_record_id: str | None
    selected_sponsor_basis_record_sha256: str | None
    observation_source_sha256: str | None
    relevant_records: tuple[tuple[str, str], ...]
    explicit_non_claims: tuple[str, ...]
    human_interpretation_required: bool

    def __post_init__(self):
        if (
            self.evaluator_version != EVALUATOR_VERSION
            or self.graph_or_protocol_id != GRAPH_ID
            or type(self.state) is not AdmissionEdgeEvaluationState
            or type(self.reason_code) is not AdmissionEdgeReason
            or self.explicit_non_claims != MANDATORY_NON_CLAIMS
            or self.human_interpretation_required is not True
        ):
            _fail("evaluation contract")
        _uuid(self.edge_id, "edge id")
        _digest(self.edge_sha256, "edge digest")
        _time(self.evaluated_at, "evaluated")
        for participant in (self.sponsor_participant_id, self.child_participant_id):
            if type(participant) is not str or not participant:
                _fail("evaluation participant")
        for key in (self.sponsor_compressed_public_key, self.child_compressed_public_key):
            if type(key) is not str or _HEX66.fullmatch(key) is None:
                _fail("evaluation compressed key")
        for key in (self.sponsor_x_only_public_key, self.child_x_only_public_key):
            _digest(key, "evaluation x-only key")
        if (
            self.sponsor_compressed_public_key[2:] != self.sponsor_x_only_public_key
            or self.child_compressed_public_key[2:] != self.child_x_only_public_key
            or self.sponsor_participant_id == self.child_participant_id
            or type(self.sponsor_depth) is not int
            or type(self.child_depth) is not int
            or self.child_depth != self.sponsor_depth + 1
            or (self.early_height, self.middle_height, self.late_height) != cascade_heights(self.child_depth)
        ):
            _fail("evaluation identity or arithmetic")
        if (
            self.child_participant_id != self.child_x_only_public_key
            or (
                self.sponsor_depth == 0
                and (
                    self.sponsor_participant_id != GENESIS_PARTICIPANT_ID
                    or self.sponsor_compressed_public_key != GENESIS_COMPRESSED_KEY
                    or self.sponsor_x_only_public_key != GENESIS_XONLY_KEY
                )
            )
            or (self.sponsor_depth > 0 and self.sponsor_participant_id != self.sponsor_x_only_public_key)
        ):
            _fail("evaluation participant convention")
        expected = {
            AdmissionEdgeEvaluationState.ACTIVE: {AdmissionEdgeReason.EXACT_DEPTH1_ADMISSION_ACTIVE},
            AdmissionEdgeEvaluationState.PROVISIONAL: {
                AdmissionEdgeReason.RECORD_PROPOSED,
                AdmissionEdgeReason.GENESIS_PROVISIONAL,
            },
            AdmissionEdgeEvaluationState.DISPUTED: {
                AdmissionEdgeReason.RECORD_DISPUTED,
                AdmissionEdgeReason.REGISTRATION_DISPUTED,
                AdmissionEdgeReason.GENESIS_DISPUTED,
            },
            AdmissionEdgeEvaluationState.EDGE_INACTIVE: {
                AdmissionEdgeReason.RECORD_REVOKED,
                AdmissionEdgeReason.RECORD_SUPERSEDED,
                AdmissionEdgeReason.REGISTRATION_REVOKED,
                AdmissionEdgeReason.REGISTRATION_SUPERSEDED,
                AdmissionEdgeReason.MISSING_REQUIRED_LEG,
                AdmissionEdgeReason.SPENT_REQUIRED_LEG,
                AdmissionEdgeReason.INSUFFICIENT_CONFIRMATIONS,
                AdmissionEdgeReason.UNEQUAL_LEG_AMOUNTS,
            },
            AdmissionEdgeEvaluationState.LINEAGE_INACTIVE: {AdmissionEdgeReason.GENESIS_LINEAGE_INACTIVE},
            AdmissionEdgeEvaluationState.UNKNOWN: {
                AdmissionEdgeReason.GENESIS_UNKNOWN,
                AdmissionEdgeReason.REGISTRATION_BINDING_MISMATCH,
                AdmissionEdgeReason.OBSERVATION_BINDING_MISMATCH,
                AdmissionEdgeReason.SPONSOR_LINEAGE_EVALUATOR_UNAVAILABLE,
                AdmissionEdgeReason.MALFORMED_OR_UNTRUSTED_INPUT,
            },
        }
        if self.reason_code not in expected[self.state]:
            _fail("evaluation state reason")
        active = self.state is AdmissionEdgeEvaluationState.ACTIVE
        refs = (
            self.selected_registration_id,
            self.selected_registration_sha256,
            self.selected_sponsor_basis_record_id,
            self.selected_sponsor_basis_record_sha256,
            self.observation_source_sha256,
        )
        paired_refs = (
            (self.selected_registration_id, self.selected_registration_sha256),
            (self.selected_sponsor_basis_record_id, self.selected_sponsor_basis_record_sha256),
        )
        for record_id, record_digest in paired_refs:
            if (record_id is None) != (record_digest is None):
                _fail("evaluation selected reference")
            if record_id is not None:
                _uuid(record_id, "evaluation selected id")
                _digest(record_digest, "evaluation selected digest")
        if self.observation_source_sha256 is not None:
            _digest(self.observation_source_sha256, "observation digest")
        if active:
            if any(x is None for x in refs) or self.child_depth != 1:
                _fail("active references")
        elif any(x is not None for x in refs[:4]):
            _fail("non-active selected references")
        if (
            type(self.relevant_records) is not tuple
            or self.relevant_records != tuple(sorted(self.relevant_records))
            or len(set(self.relevant_records)) != len(self.relevant_records)
            or len({item[0] for item in self.relevant_records}) != len(self.relevant_records)
        ):
            _fail("relevant records")
        for item in self.relevant_records:
            if type(item) is not tuple or len(item) != 2:
                _fail("relevant record")
            _uuid(item[0], "relevant record id")
            _digest(item[1], "relevant record digest")
        if active:
            required = {
                (self.edge_id, self.edge_sha256),
                (self.selected_registration_id, self.selected_registration_sha256),
                (
                    self.selected_sponsor_basis_record_id,
                    self.selected_sponsor_basis_record_sha256,
                ),
            }
            if set(self.relevant_records) != required:
                _fail("active relevant records")


@dataclass(frozen=True, slots=True)
class CanonicalAdmissionEdgeCurrentEvaluation:
    evaluator_version: str
    graph_or_protocol_id: str
    edge_id: str
    edge_sha256: str
    sponsor_participant_id: str
    sponsor_compressed_public_key: str
    sponsor_x_only_public_key: str
    sponsor_depth: int
    child_participant_id: str
    child_compressed_public_key: str
    child_x_only_public_key: str
    child_depth: int
    early_height: int
    middle_height: int
    late_height: int
    evaluated_at: datetime
    state: AdmissionEdgeEvaluationState
    reason_code: AdmissionEdgeCurrentReason
    selected_registration_id: str | None
    selected_registration_sha256: str | None
    selected_sponsor_basis_record_id: str | None
    selected_sponsor_basis_record_sha256: str | None
    observation_source_sha256: str | None
    relevant_records: tuple[tuple[str, str], ...]
    explicit_non_claims: tuple[str, ...]
    human_interpretation_required: bool

    def __post_init__(self):
        if (
            self.evaluator_version != CURRENT_EVALUATOR_VERSION
            or self.graph_or_protocol_id != GRAPH_ID
            or type(self.state) is not AdmissionEdgeEvaluationState
            or type(self.reason_code) is not AdmissionEdgeCurrentReason
            or self.explicit_non_claims != MANDATORY_NON_CLAIMS
            or self.human_interpretation_required is not True
        ):
            _fail("current evaluation contract")
        _uuid(self.edge_id, "edge id")
        _digest(self.edge_sha256, "edge digest")
        _time(self.evaluated_at, "evaluated")
        for participant in (self.sponsor_participant_id, self.child_participant_id):
            if type(participant) is not str or not participant:
                _fail("current evaluation participant")
        for key in (self.sponsor_compressed_public_key, self.child_compressed_public_key):
            if type(key) is not str or _HEX66.fullmatch(key) is None:
                _fail("current evaluation compressed key")
        for key in (self.sponsor_x_only_public_key, self.child_x_only_public_key):
            _digest(key, "current evaluation x-only key")
        if (
            self.sponsor_compressed_public_key[2:] != self.sponsor_x_only_public_key
            or self.child_compressed_public_key[2:] != self.child_x_only_public_key
            or self.sponsor_participant_id == self.child_participant_id
            or type(self.sponsor_depth) is not int
            or type(self.child_depth) is not int
            or self.child_depth != self.sponsor_depth + 1
            or (self.early_height, self.middle_height, self.late_height) != cascade_heights(self.child_depth)
            or self.child_participant_id != self.child_x_only_public_key
            or (
                self.sponsor_depth == 0
                and (
                    self.sponsor_participant_id != GENESIS_PARTICIPANT_ID
                    or self.sponsor_compressed_public_key != GENESIS_COMPRESSED_KEY
                    or self.sponsor_x_only_public_key != GENESIS_XONLY_KEY
                )
            )
            or (self.sponsor_depth > 0 and self.sponsor_participant_id != self.sponsor_x_only_public_key)
        ):
            _fail("current evaluation identity or arithmetic")
        expected = {
            AdmissionEdgeEvaluationState.ACTIVE: {AdmissionEdgeCurrentReason.EXACT_CURRENT_EDGE_ACTIVE},
            AdmissionEdgeEvaluationState.PROVISIONAL: {AdmissionEdgeCurrentReason.RECORD_PROPOSED},
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
        if self.state not in expected or self.reason_code not in expected[self.state]:
            _fail("current evaluation state reason")
        refs = (
            self.selected_registration_id,
            self.selected_registration_sha256,
            self.selected_sponsor_basis_record_id,
            self.selected_sponsor_basis_record_sha256,
            self.observation_source_sha256,
        )
        for record_id, digest in (
            (self.selected_registration_id, self.selected_registration_sha256),
            (
                self.selected_sponsor_basis_record_id,
                self.selected_sponsor_basis_record_sha256,
            ),
        ):
            if (record_id is None) != (digest is None):
                _fail("current evaluation selected reference")
            if record_id is not None:
                _uuid(record_id, "current evaluation selected id")
                _digest(digest, "current evaluation selected digest")
        if self.observation_source_sha256 is not None:
            _digest(self.observation_source_sha256, "current observation digest")
        active = self.state is AdmissionEdgeEvaluationState.ACTIVE
        if active and any(x is None for x in refs):
            _fail("current active references")
        if not active and any(x is not None for x in refs[:4]):
            _fail("current non-active selected references")
        if (
            type(self.relevant_records) is not tuple
            or self.relevant_records != tuple(sorted(self.relevant_records))
            or len(set(self.relevant_records)) != len(self.relevant_records)
            or len({item[0] for item in self.relevant_records}) != len(self.relevant_records)
        ):
            _fail("current relevant records")
        for item in self.relevant_records:
            if type(item) is not tuple or len(item) != 2:
                _fail("current relevant record")
            _uuid(item[0], "current relevant record id")
            _digest(item[1], "current relevant record digest")
        required = {
            (self.edge_id, self.edge_sha256),
            (self.selected_registration_id, self.selected_registration_sha256),
            (
                self.selected_sponsor_basis_record_id,
                self.selected_sponsor_basis_record_sha256,
            ),
        }
        if active and set(self.relevant_records) != required:
            _fail("current active relevant records")


def validate_immediate_sponsor_basis(
    record: CanonicalAdmissionEdge,
    *,
    genesis_evaluation: CanonicalGenesisEvaluation | None = None,
    parent_edge: CanonicalAdmissionEdge | None = None,
) -> CanonicalAdmissionEdge:
    """Validate immutable immediate-basis identity without parent lifecycle policy."""
    record = _validated_record(record)
    if record.child_depth == 1:
        if type(genesis_evaluation) is not CanonicalGenesisEvaluation or parent_edge is not None:
            _fail("genesis source")
        genesis_evaluation = CanonicalGenesisEvaluation(
            *(getattr(genesis_evaluation, f) for f in CanonicalGenesisEvaluation.__dataclass_fields__)
        )
        if genesis_evaluation.state is CanonicalGenesisEvaluationState.GENESIS_ACTIVE:
            controlling = (
                genesis_evaluation.selected_effective_record_id,
                genesis_evaluation.selected_effective_record_sha256,
            )
        elif len(genesis_evaluation.relevant_records) == 1:
            (controlling,) = genesis_evaluation.relevant_records
        else:
            _fail("genesis source")
        if controlling != (
            record.sponsor_basis_record_id,
            record.sponsor_basis_record_sha256,
        ):
            _fail("genesis source")
    else:
        if genesis_evaluation is not None or type(parent_edge) is not CanonicalAdmissionEdge:
            _fail("parent source")
        parent_edge = _validated_record(parent_edge)
        if (
            parent_edge.edge_id != record.sponsor_basis_record_id
            or canonical_admission_edge_sha256(parent_edge) != record.sponsor_basis_record_sha256
            or parent_edge.graph_or_protocol_id != record.graph_or_protocol_id
            or parent_edge.human_profile != record.human_profile
            or parent_edge.child_participant_id != record.sponsor_participant_id
            or parent_edge.child_compressed_public_key != record.sponsor_compressed_public_key
            or parent_edge.child_x_only_public_key != record.sponsor_x_only_public_key
            or parent_edge.child_depth != record.sponsor_depth
        ):
            _fail("parent source")
    return record


def _evaluate_canonical_admission_edge(
    record: CanonicalAdmissionEdge,
    *,
    trusted_registration: TrustedCovenantRegistration,
    observation_evaluation: CovenantRelationEvaluation | None,
    genesis_evaluation: CanonicalGenesisEvaluation | None,
    parent_edge: CanonicalAdmissionEdge | None,
    evaluated_at: datetime,
    current_only: bool,
) -> CanonicalAdmissionEdgeEvaluation:
    """Pure fail-closed current evaluation; deeper lineage is deliberately unavailable."""
    evaluated_at = _time(evaluated_at, "evaluated")
    try:
        record = _validated_record(record)
        registration = TrustedCovenantRegistration(
            *(getattr(trusted_registration, f) for f in TrustedCovenantRegistration.__dataclass_fields__)
        )
        digest = canonical_admission_edge_sha256(record)
    except Exception:
        raise InvalidCanonicalAdmissionEdge("malformed_or_untrusted_input") from None
    state, reason = (
        AdmissionEdgeEvaluationState.UNKNOWN,
        AdmissionEdgeReason.MALFORMED_OR_UNTRUSTED_INPUT,
    )
    observation_digest = None
    try:
        if current_only:
            validate_immediate_sponsor_basis(record, genesis_evaluation=genesis_evaluation, parent_edge=parent_edge)
        elif record.child_depth == 1:
            validate_admission_sources(
                record,
                registration,
                genesis_evaluation=genesis_evaluation,
                require_active=False,
            )
        if record.sponsor_depth > 0:
            # The record itself proves only its exact immutable immediate-parent
            # binding; current ancestry is deliberately outside this evaluator.
            _validated_record(record)
            if (
                record.trusted_registration_id != registration.registration_id
                or record.trusted_registration_sha256 != trusted_registration_sha256(registration)
                or record.pair_sha256 != registration.pair_sha256
                or record.validator_version != registration.validator_version
                or registration.network != NETWORK
                or registration.subject_pubkey != record.child_compressed_public_key
                or registration.subject_xonly_pubkey != record.child_x_only_public_key
                or registration.counterparty_pubkey != record.sponsor_compressed_public_key
                or registration.counterparty_xonly_pubkey != record.sponsor_x_only_public_key
                or registration.template_family is not CovenantTemplateFamily.CLTV_ONLY
                or registration.delta_profile is not CovenantDeltaProfile.LEGACY_777
                or registration.delta_blocks != DELTA_BLOCKS
                or registration.mirrored_pair.earlier_leg.raw_script_hex != record.legs[0].raw_script_hex
                or registration.mirrored_pair.earlier_leg.script_sha256 != record.legs[0].witness_script_sha256
                or registration.mirrored_pair.later_leg.raw_script_hex != record.legs[1].raw_script_hex
                or registration.mirrored_pair.later_leg.script_sha256 != record.legs[1].witness_script_sha256
                or tuple(
                    (
                        binding.txid,
                        binding.vout,
                        binding.amount_sats,
                        binding.witness_script_sha256,
                        binding.descriptor_sha256,
                    )
                    for binding in registration.outpoints
                )
                != tuple(
                    (leg.txid, leg.vout, leg.amount_sats, leg.witness_script_sha256, leg.descriptor_sha256)
                    for leg in record.legs
                )
            ):
                _fail("trusted registration binding")
        if (
            record.contradiction_context.unresolved_controlling_dispute
            or record.lifecycle_state is AdmissionEdgeLifecycle.DISPUTED
        ):
            state, reason = (
                AdmissionEdgeEvaluationState.DISPUTED,
                AdmissionEdgeReason.RECORD_DISPUTED,
            )
        elif record.lifecycle_state is AdmissionEdgeLifecycle.PROPOSED:
            state, reason = (
                AdmissionEdgeEvaluationState.PROVISIONAL,
                AdmissionEdgeReason.RECORD_PROPOSED,
            )
        elif record.lifecycle_state is AdmissionEdgeLifecycle.REVOKED:
            state, reason = (
                AdmissionEdgeEvaluationState.EDGE_INACTIVE,
                AdmissionEdgeReason.RECORD_REVOKED,
            )
        elif record.lifecycle_state is AdmissionEdgeLifecycle.SUPERSEDED:
            state, reason = (
                AdmissionEdgeEvaluationState.EDGE_INACTIVE,
                AdmissionEdgeReason.RECORD_SUPERSEDED,
            )
        elif registration.lifecycle_state is TrustedCovenantRegistrationLifecycle.DISPUTED:
            state, reason = (
                AdmissionEdgeEvaluationState.DISPUTED,
                AdmissionEdgeReason.REGISTRATION_DISPUTED,
            )
        elif registration.lifecycle_state is TrustedCovenantRegistrationLifecycle.REVOKED:
            state, reason = (
                AdmissionEdgeEvaluationState.EDGE_INACTIVE,
                AdmissionEdgeReason.REGISTRATION_REVOKED,
            )
        elif registration.lifecycle_state is TrustedCovenantRegistrationLifecycle.SUPERSEDED:
            state, reason = (
                AdmissionEdgeEvaluationState.EDGE_INACTIVE,
                AdmissionEdgeReason.REGISTRATION_SUPERSEDED,
            )
        elif record.child_depth > 1 and not current_only:
            state, reason = (
                AdmissionEdgeEvaluationState.UNKNOWN,
                AdmissionEdgeReason.SPONSOR_LINEAGE_EVALUATOR_UNAVAILABLE,
            )
        elif not current_only and genesis_evaluation.state is CanonicalGenesisEvaluationState.PROVISIONAL:
            state, reason = (
                AdmissionEdgeEvaluationState.PROVISIONAL,
                AdmissionEdgeReason.GENESIS_PROVISIONAL,
            )
        elif not current_only and genesis_evaluation.state is CanonicalGenesisEvaluationState.DISPUTED:
            state, reason = (
                AdmissionEdgeEvaluationState.DISPUTED,
                AdmissionEdgeReason.GENESIS_DISPUTED,
            )
        elif not current_only and genesis_evaluation.state is CanonicalGenesisEvaluationState.LINEAGE_INACTIVE:
            state, reason = (
                AdmissionEdgeEvaluationState.LINEAGE_INACTIVE,
                AdmissionEdgeReason.GENESIS_LINEAGE_INACTIVE,
            )
        elif not current_only and genesis_evaluation.state is CanonicalGenesisEvaluationState.UNKNOWN:
            state, reason = (
                AdmissionEdgeEvaluationState.UNKNOWN,
                AdmissionEdgeReason.GENESIS_UNKNOWN,
            )
        else:
            try:
                evaluation = CovenantRelationEvaluation(
                    *(getattr(observation_evaluation, f) for f in CovenantRelationEvaluation.__dataclass_fields__)
                )
            except Exception:
                _fail("observation binding")
            observation_digest = covenant_relation_source_sha256(evaluation)
            if (
                evaluation.schema != EVALUATION_SCHEMA
                or evaluation.network != NETWORK
                or evaluation.subject_pubkey != record.child_x_only_public_key
                or evaluation.counterparty_pubkey != record.sponsor_x_only_public_key
                or evaluation.observed_at > evaluated_at
            ):
                state, reason = (
                    AdmissionEdgeEvaluationState.UNKNOWN,
                    AdmissionEdgeReason.OBSERVATION_BINDING_MISMATCH,
                )
            elif len(evaluation.observations) < 2:
                state, reason = (
                    AdmissionEdgeEvaluationState.EDGE_INACTIVE,
                    AdmissionEdgeReason.MISSING_REQUIRED_LEG,
                )
            elif len(evaluation.observations) > 2:
                state, reason = (
                    AdmissionEdgeEvaluationState.UNKNOWN,
                    AdmissionEdgeReason.OBSERVATION_BINDING_MISMATCH,
                )
            else:
                by_direction = {x.direction: x for x in evaluation.observations}
                mismatch = len(by_direction) != 2
                for direction, leg in (
                    (CovenantDirection.INCOMING, record.legs[0]),
                    (CovenantDirection.OUTGOING, record.legs[1]),
                ):
                    item = by_direction.get(direction)
                    mismatch = (
                        mismatch
                        or item is None
                        or (
                            item.subject_pubkey,
                            item.counterparty_pubkey,
                            item.direction,
                            item.txid,
                            item.vout,
                            item.amount_sats,
                            item.script_sha256,
                            item.descriptor_sha256,
                        )
                        != (
                            record.child_x_only_public_key,
                            record.sponsor_x_only_public_key,
                            direction,
                            leg.txid,
                            leg.vout,
                            leg.amount_sats,
                            sha256(bytes.fromhex("0020" + leg.witness_script_sha256)).hexdigest(),
                            leg.descriptor_sha256,
                        )
                    )
                if mismatch:
                    state, reason = (
                        AdmissionEdgeEvaluationState.UNKNOWN,
                        AdmissionEdgeReason.OBSERVATION_BINDING_MISMATCH,
                    )
                elif any(not x.unspent for x in evaluation.observations):
                    state, reason = (
                        AdmissionEdgeEvaluationState.EDGE_INACTIVE,
                        AdmissionEdgeReason.SPENT_REQUIRED_LEG,
                    )
                elif any(x.confirmations < MIN_CONFIRMATIONS for x in evaluation.observations):
                    state, reason = (
                        AdmissionEdgeEvaluationState.EDGE_INACTIVE,
                        AdmissionEdgeReason.INSUFFICIENT_CONFIRMATIONS,
                    )
                elif len({x.amount_sats for x in evaluation.observations}) != 1:
                    state, reason = (
                        AdmissionEdgeEvaluationState.EDGE_INACTIVE,
                        AdmissionEdgeReason.UNEQUAL_LEG_AMOUNTS,
                    )
                else:
                    state, reason = (
                        AdmissionEdgeEvaluationState.ACTIVE,
                        AdmissionEdgeReason.EXACT_DEPTH1_ADMISSION_ACTIVE,
                    )
    except Exception as exc:
        if isinstance(exc, InvalidCanonicalAdmissionEdge) and str(exc) == "trusted registration binding":
            state, reason = (
                AdmissionEdgeEvaluationState.UNKNOWN,
                AdmissionEdgeReason.REGISTRATION_BINDING_MISMATCH,
            )
        elif isinstance(exc, InvalidCanonicalAdmissionEdge) and str(exc) == "observation binding":
            state, reason = (
                AdmissionEdgeEvaluationState.UNKNOWN,
                AdmissionEdgeReason.OBSERVATION_BINDING_MISMATCH,
            )
        else:
            state, reason = (
                AdmissionEdgeEvaluationState.UNKNOWN,
                AdmissionEdgeReason.MALFORMED_OR_UNTRUSTED_INPUT,
            )
    active = state is AdmissionEdgeEvaluationState.ACTIVE
    relevant = [(record.edge_id, digest)]
    if active:
        relevant.extend(
            (
                (registration.registration_id, trusted_registration_sha256(registration)),
                (record.sponsor_basis_record_id, record.sponsor_basis_record_sha256),
            )
        )
    result_type = CanonicalAdmissionEdgeCurrentEvaluation if current_only else CanonicalAdmissionEdgeEvaluation
    result_reason = (
        AdmissionEdgeCurrentReason(
            "exact_current_edge_active" if state is AdmissionEdgeEvaluationState.ACTIVE else reason.value
        )
        if current_only
        else reason
    )
    return result_type(
        CURRENT_EVALUATOR_VERSION if current_only else EVALUATOR_VERSION,
        GRAPH_ID,
        record.edge_id,
        digest,
        record.sponsor_participant_id,
        record.sponsor_compressed_public_key,
        record.sponsor_x_only_public_key,
        record.sponsor_depth,
        record.child_participant_id,
        record.child_compressed_public_key,
        record.child_x_only_public_key,
        record.child_depth,
        record.early_height,
        record.middle_height,
        record.late_height,
        evaluated_at,
        state,
        result_reason,
        registration.registration_id if active else None,
        trusted_registration_sha256(registration) if active else None,
        record.sponsor_basis_record_id if active else None,
        record.sponsor_basis_record_sha256 if active else None,
        observation_digest,
        tuple(sorted(relevant)),
        MANDATORY_NON_CLAIMS,
        True,
    )


def evaluate_canonical_admission_edge_current(
    record: CanonicalAdmissionEdge,
    *,
    trusted_registration: TrustedCovenantRegistration,
    observation_evaluation: CovenantRelationEvaluation | None,
    evaluated_at: datetime,
    genesis_evaluation: CanonicalGenesisEvaluation | None = None,
    parent_edge: CanonicalAdmissionEdge | None = None,
) -> CanonicalAdmissionEdgeCurrentEvaluation:
    """Evaluate one exact edge's current local evidence, without ancestry claims."""
    return _evaluate_canonical_admission_edge(
        record,
        trusted_registration=trusted_registration,
        observation_evaluation=observation_evaluation,
        genesis_evaluation=genesis_evaluation,
        parent_edge=parent_edge,
        evaluated_at=evaluated_at,
        current_only=True,
    )


def evaluate_canonical_admission_edge(
    record: CanonicalAdmissionEdge,
    *,
    trusted_registration: TrustedCovenantRegistration,
    observation_evaluation: CovenantRelationEvaluation | None,
    genesis_evaluation: CanonicalGenesisEvaluation,
    evaluated_at: datetime,
) -> CanonicalAdmissionEdgeEvaluation:
    """Preserved PR6.10 wrapper; complete lineage remains deliberately unavailable."""
    return _evaluate_canonical_admission_edge(
        record,
        trusted_registration=trusted_registration,
        observation_evaluation=observation_evaluation,
        genesis_evaluation=genesis_evaluation,
        parent_edge=None,
        evaluated_at=evaluated_at,
        current_only=False,
    )


def _current_evaluation_dict(
    value: CanonicalAdmissionEdgeCurrentEvaluation,
) -> dict:
    payload = {field: getattr(value, field) for field in value.__dataclass_fields__}
    payload["evaluated_at"] = _timestamp(value.evaluated_at)
    payload["state"] = value.state.value
    payload["reason_code"] = value.reason_code.value
    payload["relevant_records"] = [list(item) for item in value.relevant_records]
    payload["explicit_non_claims"] = list(value.explicit_non_claims)
    return payload


def canonical_admission_edge_current_evaluation_bytes(
    value: CanonicalAdmissionEdgeCurrentEvaluation,
) -> bytes:
    if type(value) is not CanonicalAdmissionEdgeCurrentEvaluation:
        _fail("current evaluation type")
    value = CanonicalAdmissionEdgeCurrentEvaluation(*(getattr(value, field) for field in value.__dataclass_fields__))
    return json.dumps(
        _current_evaluation_dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_admission_edge_current_evaluation_sha256(
    value: CanonicalAdmissionEdgeCurrentEvaluation,
) -> str:
    return sha256(canonical_admission_edge_current_evaluation_bytes(value)).hexdigest()


def parse_canonical_admission_edge_current_evaluation(
    value: bytes | str,
) -> CanonicalAdmissionEdgeCurrentEvaluation:
    if type(value) is bytes:
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            _fail("current evaluation ASCII")
    if type(value) is not str:
        _fail("current evaluation JSON")

    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError
            result[key] = item
        return result

    try:
        data = json.loads(
            value,
            object_pairs_hook=pairs,
            parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if (
            type(data) is not dict
            or set(data) != set(CanonicalAdmissionEdgeCurrentEvaluation.__dataclass_fields__)
            or type(data["evaluated_at"]) is not str
            or not data["evaluated_at"].endswith("Z")
            or type(data["relevant_records"]) is not list
            or any(type(item) is not list or len(item) != 2 for item in data["relevant_records"])
            or type(data["explicit_non_claims"]) is not list
        ):
            raise ValueError
        result = CanonicalAdmissionEdgeCurrentEvaluation(
            **{
                **data,
                "evaluated_at": datetime.fromisoformat(data["evaluated_at"][:-1] + "+00:00"),
                "state": AdmissionEdgeEvaluationState(data["state"]),
                "reason_code": AdmissionEdgeCurrentReason(data["reason_code"]),
                "relevant_records": tuple(tuple(item) for item in data["relevant_records"]),
                "explicit_non_claims": tuple(data["explicit_non_claims"]),
            }
        )
    except Exception:
        _fail("current evaluation JSON")
    if canonical_admission_edge_current_evaluation_bytes(result).decode("ascii") != value:
        _fail("current evaluation noncanonical JSON")
    return result
