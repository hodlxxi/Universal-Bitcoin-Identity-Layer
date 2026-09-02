"""Read-only legacy covenant inventory and canonical bootstrap planning.

The planner consumes injected observations and an injected snapshot of Canon.  It
has no persistence or Bitcoin RPC dependency and deliberately exposes no apply
operation.  Exact keys, scripts and outpoints remain in memory; public plan
serialization contains only domain-separated opaque hashes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
import json
import re
from typing import Iterable

from app.services.canonical_admission_edge import (
    GRAPH_ID,
    DELTA_BLOCKS,
    GENESIS_XONLY_KEY,
    MIN_CONFIRMATIONS,
    AdmissionEdgeLifecycle,
    CanonicalAdmissionEdge,
    cascade_heights,
    canonical_admission_edge_bytes,
    validate_admission_sources,
)
from app.services.canonical_genesis_record import (
    CanonicalGenesisEvaluationState,
    CanonicalGenesisRecord,
    evaluate_canonical_genesis,
)
from app.services.mirrored_covenant_pair import (
    CovenantDeltaProfile,
    CovenantTemplateFamily,
    ParsedCovenantLeg,
    parse_covenant_leg,
    validate_mirrored_covenant_pair,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    canonical_trusted_registration_bytes,
)

SCHEMA = "hodlxxi.legacy_covenant_canonical_migration_plan.v1"
MODE = "read_only_dry_run"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_EVEN = re.compile(r"(?:[0-9a-f]{2})+\Z")
_RAW_DESCRIPTOR = re.compile(r"(?:^|\()raw\(([0-9A-Fa-f]+)\)(?:\)|#[0-9a-z]+|$)")
_MAX_SATS = 2_100_000_000_000_000


class InvalidMigrationPlannerInput(ValueError):
    """An injected observation or canonical snapshot is malformed."""


class MigrationDecision(Enum):
    ALREADY_CANONICAL = "already_canonical"
    ELIGIBLE_FOR_BOOTSTRAP = "eligible_for_bootstrap"
    INCOMPLETE_RELATION = "incomplete_relation"
    INCOMPLETE_FUNDING = "incomplete_funding"
    UNCONFIRMED_FUNDING = "unconfirmed_funding"
    UNSUPPORTED_PROFILE = "unsupported_profile"
    AMBIGUOUS = "ambiguous"
    UNREACHABLE_FROM_GENESIS = "unreachable_from_genesis"
    CANONICAL_CONFLICT = "canonical_conflict"
    INVALID = "invalid"
    NOT_APPLICABLE = "not_applicable"


class LegacyRelationshipClass(Enum):
    ROLE_SWAPPED_CONTIGUOUS_TRIPLE = "role_swapped_contiguous_triple"
    ROLE_SWAPPED_SAME_WINDOW = "role_swapped_same_window"
    SINGLE_SCRIPT_ONLY = "single_script_only"
    MULTIPLE_SCRIPTS_OTHER = "multiple_scripts_other"
    NESTED_OR_COOPERATIVE = "nested_or_cooperative"
    UNSUPPORTED_DELTA = "unsupported_delta"
    AMBIGUOUS_MULTIPLE_PROFILES = "ambiguous_multiple_profiles"


def _fail() -> None:
    raise InvalidMigrationPlannerInput("legacy covenant migration planner input unavailable")


def _opaque(kind: str, payload: bytes) -> str:
    digest = sha256(b"hodlxxi:legacy-migration:v1:" + kind.encode("ascii") + b":" + payload).hexdigest()
    return f"{kind}_{digest[:24]}"


def _script_ref(script_hex: str) -> str:
    return _opaque("script", bytes.fromhex(script_hex))


def _participant_ref(xonly: str) -> str:
    return _opaque("participant", bytes.fromhex(xonly))


def _relationship_ref(participants: tuple[str, str]) -> str:
    return _opaque("relationship", b"".join(bytes.fromhex(value) for value in participants))


def _outpoint_ref(txid: str, vout: int) -> str:
    return _opaque("outpoint", bytes.fromhex(txid) + vout.to_bytes(4, "big"))


def _wallet_ref(value: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        _fail()
    return _opaque("wallet", value.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class LegacyWalletOutpoint:
    txid: str
    vout: int
    amount_sats: int
    confirmations: int
    script_pubkey_hex: str

    def __post_init__(self):
        if (
            type(self.txid) is not str
            or _HEX64.fullmatch(self.txid) is None
            or type(self.vout) is not int
            or not 0 <= self.vout <= 0xFFFFFFFF
            or type(self.amount_sats) is not int
            or not 0 <= self.amount_sats <= _MAX_SATS
            or type(self.confirmations) is not int
            or self.confirmations < 0
            or type(self.script_pubkey_hex) is not str
            or _HEX_EVEN.fullmatch(self.script_pubkey_hex) is None
        ):
            _fail()


@dataclass(frozen=True, slots=True)
class LegacyWalletObservation:
    wallet_id: str
    descriptors: tuple[str, ...]
    outpoints: tuple[LegacyWalletOutpoint, ...]

    def __post_init__(self):
        _wallet_ref(self.wallet_id)
        if type(self.descriptors) is not tuple or type(self.outpoints) is not tuple:
            _fail()
        if any(type(value) is not str for value in self.descriptors):
            _fail()
        if any(type(value) is not LegacyWalletOutpoint for value in self.outpoints):
            _fail()


@dataclass(frozen=True, slots=True)
class CanonicalKnownRelationship:
    participants: tuple[str, str]
    script_sha256s: tuple[str, ...]
    active: bool
    source_ref: str

    def __post_init__(self):
        if (
            type(self.participants) is not tuple
            or len(self.participants) != 2
            or tuple(sorted(self.participants)) != self.participants
            or self.participants[0] == self.participants[1]
            or any(_HEX64.fullmatch(value) is None for value in self.participants)
            or type(self.script_sha256s) is not tuple
            or tuple(sorted(set(self.script_sha256s))) != self.script_sha256s
            or any(_HEX64.fullmatch(value) is None for value in self.script_sha256s)
            or type(self.active) is not bool
            or type(self.source_ref) is not str
            or not self.source_ref
        ):
            _fail()

    @classmethod
    def from_registration(cls, registration: TrustedCovenantRegistration):
        canonical_trusted_registration_bytes(registration)
        pair = registration.mirrored_pair
        return cls(
            tuple(sorted((registration.subject_xonly_pubkey, registration.counterparty_xonly_pubkey))),
            tuple(sorted((pair.earlier_leg.script_sha256, pair.later_leg.script_sha256))),
            registration.lifecycle_state is TrustedCovenantRegistrationLifecycle.ACTIVE,
            _opaque("canonical", registration.registration_id.encode("ascii")),
        )


@dataclass(frozen=True, slots=True)
class CanonicalHistoricalRelationship:
    relationship: CanonicalKnownRelationship
    reasons: tuple[str, ...]

    def __post_init__(self):
        if (
            type(self.relationship) is not CanonicalKnownRelationship
            or type(self.reasons) is not tuple
            or not self.reasons
            or tuple(sorted(set(self.reasons))) != self.reasons
            or any(type(value) is not str or not value for value in self.reasons)
        ):
            _fail()


@dataclass(frozen=True, slots=True)
class CanonicalReadSnapshot:
    genesis_active: bool
    reachable_depths: tuple[tuple[str, int], ...]
    known_relationships: tuple[CanonicalKnownRelationship, ...] = ()
    browser_user_xonly_keys: frozenset[str] = frozenset()
    historical_relationships: tuple[CanonicalHistoricalRelationship, ...] = ()

    def __post_init__(self):
        if type(self.genesis_active) is not bool or type(self.reachable_depths) is not tuple:
            _fail()
        depths = dict(self.reachable_depths)
        if len(depths) != len(self.reachable_depths):
            _fail()
        for key, depth in self.reachable_depths:
            if _HEX64.fullmatch(key) is None or type(depth) is not int or depth < 0:
                _fail()
        if self.genesis_active and depths.get(GENESIS_XONLY_KEY) != 0:
            _fail()
        if type(self.known_relationships) is not tuple or any(
            type(value) is not CanonicalKnownRelationship for value in self.known_relationships
        ):
            _fail()
        if type(self.browser_user_xonly_keys) is not frozenset or any(
            _HEX64.fullmatch(value) is None for value in self.browser_user_xonly_keys
        ):
            _fail()
        if type(self.historical_relationships) is not tuple or any(
            type(value) is not CanonicalHistoricalRelationship for value in self.historical_relationships
        ):
            _fail()

    @classmethod
    def from_canonical_records(
        cls,
        *,
        genesis_records: Iterable[CanonicalGenesisRecord],
        evaluated_at: datetime,
        admission_edges: Iterable[CanonicalAdmissionEdge],
        registrations: Iterable[TrustedCovenantRegistration],
        current_root_registration_id: str | None = None,
        browser_user_xonly_keys: Iterable[str] = (),
    ) -> "CanonicalReadSnapshot":
        """Build a read snapshot after validating exact existing Canon records."""
        evaluation = evaluate_canonical_genesis(
            tuple(genesis_records), graph_or_protocol_id=GRAPH_ID, evaluated_at=evaluated_at
        )
        genesis_active = evaluation.state is CanonicalGenesisEvaluationState.GENESIS_ACTIVE
        depths = {GENESIS_XONLY_KEY: 0} if genesis_active else {}
        registrations = tuple(registrations)
        for registration in registrations:
            canonical_trusted_registration_bytes(registration)
        registrations_by_id = {value.registration_id: value for value in registrations}
        if len(registrations_by_id) != len(registrations):
            _fail()
        if current_root_registration_id is not None:
            root_registration = registrations_by_id.get(current_root_registration_id)
            if (
                not genesis_active
                or root_registration is None
                or root_registration.lifecycle_state is not TrustedCovenantRegistrationLifecycle.ACTIVE
            ):
                _fail()
        edges = []
        for edge in admission_edges:
            canonical_admission_edge_bytes(edge)
            edges.append(edge)
        edges_by_id = {value.edge_id: value for value in edges}
        if len(edges_by_id) != len(edges):
            _fail()
        effective_edges_by_child: dict[str, CanonicalAdmissionEdge] = {}
        effective_edges_by_pair: dict[tuple[str, str], CanonicalAdmissionEdge] = {}
        for edge in edges:
            if edge.lifecycle_state is not AdmissionEdgeLifecycle.EFFECTIVE:
                continue
            pair = tuple(sorted((edge.sponsor_x_only_public_key, edge.child_x_only_public_key)))
            if edge.child_x_only_public_key in effective_edges_by_child or pair in effective_edges_by_pair:
                _fail()
            effective_edges_by_child[edge.child_x_only_public_key] = edge
            effective_edges_by_pair[pair] = edge
            registration = registrations_by_id.get(edge.trusted_registration_id)
            if registration is None:
                _fail()
            try:
                validate_admission_sources(
                    edge,
                    registration,
                    genesis_evaluation=evaluation if edge.sponsor_depth == 0 else None,
                    parent_edge=(edges_by_id.get(edge.sponsor_basis_record_id) if edge.sponsor_depth > 0 else None),
                    require_active=True,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                _fail()
        changed = True
        while changed:
            changed = False
            for edge in edges:
                if edge.lifecycle_state is not AdmissionEdgeLifecycle.EFFECTIVE:
                    continue
                if depths.get(edge.sponsor_x_only_public_key) != edge.sponsor_depth:
                    continue
                if edge.child_x_only_public_key in depths and depths[edge.child_x_only_public_key] != edge.child_depth:
                    _fail()
                if edge.child_x_only_public_key not in depths:
                    depths[edge.child_x_only_public_key] = edge.child_depth
                    changed = True
        current_registration_ids = {edge.trusted_registration_id for edge in effective_edges_by_child.values()}
        if current_root_registration_id is not None:
            current_registration_ids.add(current_root_registration_id)
        known = tuple(
            sorted(
                (
                    CanonicalKnownRelationship.from_registration(registrations_by_id[registration_id])
                    for registration_id in current_registration_ids
                ),
                key=lambda value: (value.participants, value.script_sha256s, value.source_ref),
            )
        )
        historical_edge_registration_ids = {
            edge.trusted_registration_id
            for edge in edges
            if edge.lifecycle_state is not AdmissionEdgeLifecycle.EFFECTIVE
        }
        historical = []
        for registration_id, registration in registrations_by_id.items():
            if registration_id in current_registration_ids:
                continue
            reasons = []
            if registration_id in historical_edge_registration_ids:
                reasons.append("historical_admission_edge_not_current_authority")
            if registration.lifecycle_state is TrustedCovenantRegistrationLifecycle.ACTIVE:
                reasons.append("active_registration_without_effective_admission")
            if not reasons:
                reasons.append("registration_without_current_admission_authority")
            historical.append(
                CanonicalHistoricalRelationship(
                    CanonicalKnownRelationship.from_registration(registration),
                    tuple(sorted(reasons)),
                )
            )
        return cls(
            genesis_active,
            tuple(sorted(depths.items())),
            known,
            frozenset(browser_user_xonly_keys),
            tuple(
                sorted(
                    historical,
                    key=lambda value: (
                        value.relationship.participants,
                        value.relationship.script_sha256s,
                        value.relationship.source_ref,
                    ),
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class _ObservedScript:
    script_hex: str
    script_sha256: str
    parsed: ParsedCovenantLeg | None
    wallet_refs: tuple[str, ...]
    diagnostic_reason: str | None


@dataclass(frozen=True, slots=True)
class _ObservedOutpoint:
    value: LegacyWalletOutpoint
    wallet_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LegacyRelationshipCandidate:
    relationship_ref: str
    participant_refs: tuple[str, str]
    role_orientation: tuple[tuple[str, str], ...]
    script_refs: tuple[str, ...]
    relationship_class: LegacyRelationshipClass
    script_classes: tuple[str, ...]
    timelock_windows: tuple[tuple[int, int], ...]
    deltas: tuple[int, ...]
    unique_outpoint_count: int
    current_sats: int
    minimum_confirmations: int | None
    observed_in_wallet_count: int
    already_represented_in_canon: bool
    reachable_from_genesis: bool
    has_browser_user: tuple[bool, bool]
    decision: MigrationDecision
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "already_represented_in_canon": self.already_represented_in_canon,
            "candidate_decision": self.decision.value,
            "current_sats": self.current_sats,
            "deltas": list(self.deltas),
            "has_browser_user": list(self.has_browser_user),
            "minimum_confirmations": self.minimum_confirmations,
            "observed_in_wallet_count": self.observed_in_wallet_count,
            "opaque_participant_refs": list(self.participant_refs),
            "role_orientation": [list(value) for value in self.role_orientation],
            "opaque_script_refs": list(self.script_refs),
            "unique_script_count": len(self.script_refs),
            "reachable_from_canonical_genesis": self.reachable_from_genesis,
            "reasons": list(self.reasons),
            "relationship_class": self.relationship_class.value,
            "relationship_ref": self.relationship_ref,
            "script_classes": list(self.script_classes),
            "timelock_windows": [list(value) for value in self.timelock_windows],
            "unique_outpoint_count": self.unique_outpoint_count,
        }


@dataclass(frozen=True, slots=True)
class MigrationPlanSummary:
    observation_wallet_count: int
    descriptor_occurrence_count: int
    raw_descriptor_occurrence_count: int
    non_raw_descriptor_occurrence_count: int
    descriptor_class_counts: tuple[tuple[str, int], ...]
    unique_witness_script_count: int
    malformed_script_count: int
    unique_outpoint_count: int
    duplicate_outpoint_occurrence_count: int
    relationship_count: int
    participant_count: int
    already_canonical_count: int
    eligible_candidate_count: int
    blocked_count: int

    def to_dict(self) -> dict:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["descriptor_class_counts"] = {key: value for key, value in self.descriptor_class_counts}
        return result


@dataclass(frozen=True, slots=True)
class MigrationPlan:
    summary: MigrationPlanSummary
    relationships: tuple[LegacyRelationshipCandidate, ...]
    diagnostic_scripts: tuple[dict, ...]

    def content_dict(self) -> dict:
        rows = [value.to_dict() for value in self.relationships]
        return {
            "already_canonical": [
                value["relationship_ref"]
                for value in rows
                if value["candidate_decision"] == MigrationDecision.ALREADY_CANONICAL.value
            ],
            "blocked": [
                value["relationship_ref"]
                for value in rows
                if value["candidate_decision"]
                not in (
                    MigrationDecision.ALREADY_CANONICAL.value,
                    MigrationDecision.ELIGIBLE_FOR_BOOTSTRAP.value,
                )
            ],
            "diagnostic_scripts": list(self.diagnostic_scripts),
            "eligible_candidates": [
                value["relationship_ref"]
                for value in rows
                if value["candidate_decision"] == MigrationDecision.ELIGIBLE_FOR_BOOTSTRAP.value
            ],
            "mode": MODE,
            "relationships": rows,
            "schema": SCHEMA,
            "summary": self.summary.to_dict(),
        }

    def to_dict(self) -> dict:
        content = self.content_dict()
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return {**content, "plan_sha256": sha256(encoded).hexdigest()}

    def to_json(self, *, pretty: bool = False) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
            ensure_ascii=True,
        )

    def human_summary(self) -> str:
        value = self.summary
        return (
            "READ-ONLY DRY RUN\n"
            f"wallets={value.observation_wallet_count} scripts={value.unique_witness_script_count} "
            f"outpoints={value.unique_outpoint_count} relationships={value.relationship_count}\n"
            f"already_canonical={value.already_canonical_count} "
            f"eligible={value.eligible_candidate_count} blocked={value.blocked_count}"
        )


def native_p2wsh_script_pubkey(witness_script_hex: str) -> str:
    if type(witness_script_hex) is not str or _HEX_EVEN.fullmatch(witness_script_hex) is None:
        _fail()
    return "0020" + sha256(bytes.fromhex(witness_script_hex)).hexdigest()


def _extract_raw(descriptor: str) -> str | None:
    cleaned = descriptor.strip()
    if "#" in cleaned:
        cleaned = cleaned.rsplit("#", 1)[0]
    match = _RAW_DESCRIPTOR.search(cleaned)
    if match is None:
        return None
    return match.group(1).lower()


def _descriptor_class(descriptor: str) -> str:
    cleaned = descriptor.strip().lower()
    if "raw(" in cleaned:
        return "raw"
    for kind in ("addr", "wpkh"):
        if cleaned.startswith(kind + "("):
            return kind
    return "other"


def _classify(scripts: tuple[_ObservedScript, ...]) -> LegacyRelationshipClass:
    if any(
        value.parsed is not None and value.parsed.template_family is not CovenantTemplateFamily.CLTV_ONLY
        for value in scripts
    ):
        return LegacyRelationshipClass.NESTED_OR_COOPERATIVE
    if len(scripts) == 1:
        return LegacyRelationshipClass.SINGLE_SCRIPT_ONLY
    if len(scripts) != 2:
        profiles = {value.parsed.delta_blocks for value in scripts if value.parsed is not None}
        if len(profiles) > 1:
            return LegacyRelationshipClass.AMBIGUOUS_MULTIPLE_PROFILES
        return LegacyRelationshipClass.MULTIPLE_SCRIPTS_OTHER
    first, second = (value.parsed for value in scripts)
    assert first is not None and second is not None
    if first.delta_blocks not in (144, DELTA_BLOCKS) or second.delta_blocks not in (144, DELTA_BLOCKS):
        return LegacyRelationshipClass.UNSUPPORTED_DELTA
    for subject in (first.receiver_pubkey, first.sender_pubkey):
        try:
            validate_mirrored_covenant_pair(
                scripts[0].script_hex,
                scripts[1].script_hex,
                subject_pubkey=subject,
                allowed_delta_profiles=(CovenantDeltaProfile.CURRENT_144, CovenantDeltaProfile.LEGACY_777),
            )
            return LegacyRelationshipClass.ROLE_SWAPPED_CONTIGUOUS_TRIPLE
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            pass
    if (
        first.receiver_xonly_pubkey == second.sender_xonly_pubkey
        and first.sender_xonly_pubkey == second.receiver_xonly_pubkey
        and first.receiver_height == second.receiver_height
        and first.sender_height == second.sender_height
    ):
        return LegacyRelationshipClass.ROLE_SWAPPED_SAME_WINDOW
    return LegacyRelationshipClass.MULTIPLE_SCRIPTS_OTHER


def _initial_decision(
    kind: LegacyRelationshipClass, deltas: tuple[int, ...]
) -> tuple[MigrationDecision, tuple[str, ...]]:
    if kind is LegacyRelationshipClass.SINGLE_SCRIPT_ONLY:
        return MigrationDecision.INCOMPLETE_RELATION, ("only_one_script",)
    if kind is LegacyRelationshipClass.ROLE_SWAPPED_SAME_WINDOW:
        return MigrationDecision.UNSUPPORTED_PROFILE, ("same_window_not_current_canon",)
    if kind is LegacyRelationshipClass.NESTED_OR_COOPERATIVE:
        return MigrationDecision.UNSUPPORTED_PROFILE, ("nested_or_cooperative_not_current_human_canon",)
    if kind is LegacyRelationshipClass.UNSUPPORTED_DELTA:
        return MigrationDecision.UNSUPPORTED_PROFILE, (
            "delta_164_unsupported" if 164 in deltas else "unsupported_delta",
        )
    if kind in (
        LegacyRelationshipClass.MULTIPLE_SCRIPTS_OTHER,
        LegacyRelationshipClass.AMBIGUOUS_MULTIPLE_PROFILES,
    ):
        return MigrationDecision.AMBIGUOUS, ("conflicting_scripts_for_same_pair",)
    if deltas != (144,) and deltas != (DELTA_BLOCKS,):
        return MigrationDecision.AMBIGUOUS, ("ambiguous_multiple_profiles",)
    if deltas == (144,):
        return MigrationDecision.UNSUPPORTED_PROFILE, ("delta_144_not_current_human_canon",)
    return MigrationDecision.UNREACHABLE_FROM_GENESIS, ("sponsor_not_canonical",)


class LegacyCovenantCanonicalMigrationPlanner:
    """Pure, deterministic planner.  There are intentionally no write methods."""

    def plan(
        self,
        observations: Iterable[LegacyWalletObservation],
        canonical: CanonicalReadSnapshot,
    ) -> MigrationPlan:
        wallets = tuple(observations)
        if type(canonical) is not CanonicalReadSnapshot or any(
            type(value) is not LegacyWalletObservation for value in wallets
        ):
            _fail()
        wallet_ids = [_wallet_ref(value.wallet_id) for value in wallets]
        if len(wallet_ids) != len(set(wallet_ids)):
            _fail()

        descriptor_count = sum(len(value.descriptors) for value in wallets)
        descriptor_classes: dict[str, int] = {}
        raw_count = 0
        scripts_by_hex: dict[str, set[str]] = {}
        diagnostic: list[dict] = []
        for wallet, wallet_ref in zip(wallets, wallet_ids):
            for descriptor in wallet.descriptors:
                kind = _descriptor_class(descriptor)
                descriptor_classes[kind] = descriptor_classes.get(kind, 0) + 1
                raw = _extract_raw(descriptor)
                if raw is None:
                    if "raw(" in descriptor.lower():
                        diagnostic.append(
                            {
                                "reason": "malformed_descriptor_or_script",
                                "script_ref": _opaque("malformed", descriptor.encode("utf-8")),
                            }
                        )
                    continue
                raw_count += 1
                if _HEX_EVEN.fullmatch(raw) is None:
                    diagnostic.append(
                        {"reason": "malformed_descriptor_or_script", "script_ref": _opaque("malformed", raw.encode())}
                    )
                    continue
                scripts_by_hex.setdefault(raw, set()).add(wallet_ref)

        scripts: list[_ObservedScript] = []
        for raw, provenance in scripts_by_hex.items():
            try:
                parsed = parse_covenant_leg(raw)
                reason = None
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                parsed = None
                reason = "malformed_or_unsupported_script"
            digest = sha256(bytes.fromhex(raw)).hexdigest()
            scripts.append(_ObservedScript(raw, digest, parsed, tuple(sorted(provenance)), reason))
            if parsed is None:
                diagnostic.append({"reason": reason, "script_ref": _script_ref(raw)})

        outpoints: dict[tuple[str, int], tuple[LegacyWalletOutpoint, set[str]]] = {}
        outpoint_occurrences = 0
        for wallet, wallet_ref in zip(wallets, wallet_ids):
            for value in wallet.outpoints:
                outpoint_occurrences += 1
                key = (value.txid, value.vout)
                if key in outpoints and outpoints[key][0] != value:
                    _fail()
                outpoints.setdefault(key, (value, set()))[1].add(wallet_ref)
        unique_outpoints = tuple(
            _ObservedOutpoint(value, tuple(sorted(provenance))) for value, provenance in outpoints.values()
        )

        grouped: dict[tuple[str, str], list[_ObservedScript]] = {}
        for value in scripts:
            if value.parsed is None:
                continue
            participants = tuple(sorted((value.parsed.receiver_xonly_pubkey, value.parsed.sender_xonly_pubkey)))
            if participants[0] == participants[1]:
                diagnostic.append({"reason": "identical_participants", "script_ref": _script_ref(value.script_hex)})
                continue
            grouped.setdefault(participants, []).append(value)

        known_by_pair: dict[tuple[str, str], list[CanonicalKnownRelationship]] = {}
        for value in canonical.known_relationships:
            known_by_pair.setdefault(value.participants, []).append(value)
        historical_by_pair: dict[tuple[str, str], list[CanonicalHistoricalRelationship]] = {}
        for value in canonical.historical_relationships:
            historical_by_pair.setdefault(value.relationship.participants, []).append(value)
        reachable = dict(canonical.reachable_depths) if canonical.genesis_active else {}
        pending = set(grouped)
        result: dict[tuple[str, str], LegacyRelationshipCandidate] = {}

        while pending:
            newly_reachable = None
            for participants in sorted(pending):
                candidate = self._relationship(
                    participants,
                    tuple(sorted(grouped[participants], key=lambda value: value.script_sha256)),
                    unique_outpoints,
                    known_by_pair.get(participants, []),
                    historical_by_pair.get(participants, []),
                    reachable,
                    canonical.browser_user_xonly_keys,
                )
                if candidate.decision is MigrationDecision.ELIGIBLE_FOR_BOOTSTRAP:
                    child = next(key for key in participants if key not in reachable)
                    sponsor = next(key for key in participants if key in reachable)
                    reachable[child] = reachable[sponsor] + 1
                    result[participants] = candidate
                    pending.remove(participants)
                    newly_reachable = child
                    break
                if candidate.decision is not MigrationDecision.UNREACHABLE_FROM_GENESIS:
                    result[participants] = candidate
                    pending.remove(participants)
                    break
            if newly_reachable is None and all(
                self._relationship(
                    participants,
                    tuple(sorted(grouped[participants], key=lambda value: value.script_sha256)),
                    unique_outpoints,
                    known_by_pair.get(participants, []),
                    historical_by_pair.get(participants, []),
                    reachable,
                    canonical.browser_user_xonly_keys,
                ).decision
                is MigrationDecision.UNREACHABLE_FROM_GENESIS
                for participants in pending
            ):
                for participants in sorted(pending):
                    result[participants] = self._relationship(
                        participants,
                        tuple(sorted(grouped[participants], key=lambda value: value.script_sha256)),
                        unique_outpoints,
                        known_by_pair.get(participants, []),
                        historical_by_pair.get(participants, []),
                        reachable,
                        canonical.browser_user_xonly_keys,
                    )
                pending.clear()

        relationships = tuple(sorted(result.values(), key=lambda value: value.relationship_ref))
        participant_keys = {key for pair in grouped for key in pair}
        already = sum(value.decision is MigrationDecision.ALREADY_CANONICAL for value in relationships)
        eligible = sum(value.decision is MigrationDecision.ELIGIBLE_FOR_BOOTSTRAP for value in relationships)
        summary = MigrationPlanSummary(
            len(wallets),
            descriptor_count,
            raw_count,
            descriptor_count - raw_count,
            tuple(sorted(descriptor_classes.items())),
            len(scripts_by_hex),
            sum(value.parsed is None for value in scripts),
            len(unique_outpoints),
            outpoint_occurrences - len(unique_outpoints),
            len(relationships),
            len(participant_keys),
            already,
            eligible,
            len(relationships) - already - eligible,
        )
        return MigrationPlan(summary, relationships, tuple(sorted(diagnostic, key=lambda value: tuple(value.items()))))

    def _relationship(
        self,
        participants: tuple[str, str],
        scripts: tuple[_ObservedScript, ...],
        outpoints: tuple[_ObservedOutpoint, ...],
        known: list[CanonicalKnownRelationship],
        historical: list[CanonicalHistoricalRelationship],
        reachable: dict[str, int],
        browser_users: frozenset[str],
    ) -> LegacyRelationshipCandidate:
        kind = _classify(scripts)
        deltas = tuple(sorted({value.parsed.delta_blocks for value in scripts if value.parsed is not None}))
        decision, reasons = _initial_decision(kind, deltas)
        script_hashes = tuple(sorted(value.script_sha256 for value in scripts))
        exact_canon = [value for value in known if value.script_sha256s == script_hashes and value.active]
        if len(exact_canon) == 1 and len(known) == 1:
            decision, reasons = MigrationDecision.ALREADY_CANONICAL, ("canonical_record_already_exists",)
        elif known:
            decision, reasons = MigrationDecision.CANONICAL_CONFLICT, ("conflicting_current_canonical_record",)
        elif historical:
            decision = MigrationDecision.CANONICAL_CONFLICT
            reasons = tuple(sorted({reason for value in historical for reason in value.reasons}))

        matched = [
            value
            for value in outpoints
            if any(value.value.script_pubkey_hex == native_p2wsh_script_pubkey(script.script_hex) for script in scripts)
        ]
        by_script = {
            script.script_sha256: [
                value
                for value in matched
                if value.value.script_pubkey_hex == native_p2wsh_script_pubkey(script.script_hex)
            ]
            for script in scripts
        }
        is_current_pair = kind is LegacyRelationshipClass.ROLE_SWAPPED_CONTIGUOUS_TRIPLE and deltas == (DELTA_BLOCKS,)
        proven_orientations: list[tuple[str, str]] = []
        if decision is MigrationDecision.UNREACHABLE_FROM_GENESIS and is_current_pair:
            orientations = []
            for sponsor in participants:
                if sponsor not in reachable:
                    continue
                child = participants[1] if sponsor == participants[0] else participants[0]
                expected = cascade_heights(reachable[sponsor] + 1)
                first, second = (value.parsed for value in scripts)
                assert first is not None and second is not None
                legs = (first, second)
                oriented = any(
                    leg.receiver_xonly_pubkey == child
                    and leg.sender_xonly_pubkey == sponsor
                    and (leg.receiver_height, leg.sender_height) == expected[:2]
                    for leg in legs
                ) and any(
                    leg.receiver_xonly_pubkey == sponsor
                    and leg.sender_xonly_pubkey == child
                    and (leg.receiver_height, leg.sender_height) == expected[1:]
                    for leg in legs
                )
                if oriented:
                    orientations.append((sponsor, child))
            proven_orientations = orientations
            if len(orientations) > 1:
                decision, reasons = MigrationDecision.AMBIGUOUS, ("ambiguous_sponsor_orientation",)
            elif len(orientations) == 1:
                if any(len(values) == 0 for values in by_script.values()):
                    decision, reasons = MigrationDecision.INCOMPLETE_FUNDING, ("only_one_funded_leg",)
                elif any(len(values) != 1 for values in by_script.values()):
                    decision, reasons = MigrationDecision.AMBIGUOUS, ("multiple_outpoints_for_required_leg",)
                elif any(values[0].value.confirmations < MIN_CONFIRMATIONS for values in by_script.values()):
                    decision, reasons = MigrationDecision.UNCONFIRMED_FUNDING, ("minimum_confirmations_not_met",)
                else:
                    amounts = {values[0].value.amount_sats for values in by_script.values()}
                    if len(amounts) != 1 or 0 in amounts:
                        decision, reasons = MigrationDecision.INCOMPLETE_FUNDING, ("required_leg_amounts_do_not_match",)
                    else:
                        decision, reasons = MigrationDecision.ELIGIBLE_FOR_BOOTSTRAP, (
                            "current_legacy_777_structure_proven",
                            "exact_p2wsh_funding_proven",
                            "canonical_sponsor_lineage_proven",
                        )
            elif any(value in reachable for value in participants):
                decision, reasons = MigrationDecision.INVALID, ("candidate_heights_do_not_match_depth",)

        wallet_refs = {ref for value in scripts for ref in value.wallet_refs}
        wallet_refs.update(ref for value in matched for ref in value.wallet_refs)
        return LegacyRelationshipCandidate(
            _relationship_ref(participants),
            tuple(_participant_ref(value) for value in participants),
            tuple(
                (f"sponsor:{_participant_ref(sponsor)}", f"child:{_participant_ref(child)}")
                for sponsor, child in proven_orientations
            ),
            tuple(_script_ref(value.script_hex) for value in scripts),
            kind,
            tuple(sorted({value.parsed.template_family.value for value in scripts if value.parsed is not None})),
            tuple(
                sorted(
                    {
                        (value.parsed.receiver_height, value.parsed.sender_height)
                        for value in scripts
                        if value.parsed is not None
                    }
                )
            ),
            deltas,
            len(matched),
            sum(value.value.amount_sats for value in matched),
            min((value.value.confirmations for value in matched), default=None),
            len(wallet_refs),
            bool(exact_canon),
            any(value in reachable for value in participants),
            tuple(value in browser_users for value in participants),
            decision,
            tuple(sorted(reasons)),
        )
