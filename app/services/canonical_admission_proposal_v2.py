"""Pure, proposed-only Canon V2 admission binding over existing trusted sources.

An immutable V2 proposal is not an effective admission edge, is not durable
registration, and cannot grant Full. The caller-supplied digest references
are NEVER treated as verified signatures or consent.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from enum import Enum

from app.services.canonical_covenant_funding_set import (
    CanonicalCovenantFundingSet,
    CovenantFundingSetLifecycle,
    canonical_covenant_funding_set_sha256,
    validate_funding_set_registration,
)
from app.services.canonical_genesis_record import (
    CanonicalGenesisEvaluation,
    CanonicalGenesisEvaluationState,
)
from app.services.canonical_sponsored_script_policy_v2 import (
    CanonicalSponsoredScriptEvidenceV2,
    canonical_sponsored_script_evidence_v2_sha256,
)
from app.services.covenant_relation import (
    CovenantDirection,
    CovenantRelationEvaluation,
    CovenantRelationObservation,
    covenant_relation_source_sha256,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    trusted_registration_sha256,
    trusted_outpoints_from_registration,
)

SCHEMA = "hodlxxi.canonical_sponsored_admission_proposal.v2"
VERSION = "hodlxxi.canonical_sponsored_admission_proposal_service.v2"
BOUNDARY = "proposed_only_no_current_full_or_consent_verification"
MAX_OBSERVATION_AGE = timedelta(seconds=120)
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f-]{36}\Z")


class InvalidCanonicalAdmissionProposalV2(ValueError):
    """The proposed V2 admission or an asserted supporting source is invalid."""


class SponsorBasisV2(Enum):
    GENESIS = "genesis_record"
    PARENT_PROPOSAL = "parent_v2_proposal"


def _fail(reason: str) -> None:
    raise InvalidCanonicalAdmissionProposalV2(reason)


def _digest(value: object, field: str) -> None:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        _fail(field)


def _uuid(value: object, field: str) -> None:
    if type(value) is not str or _UUID.fullmatch(value) is None:
        _fail(field)
    try:
        if str(uuid.UUID(value)) != value:
            _fail(field)
    except (TypeError, ValueError, AttributeError):
        _fail(field)


def _time(value: object, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail(field)
    value = value.astimezone(timezone.utc)
    if value.microsecond != 0:
        _fail(field)
    return value


def _revalidate_script(value: object) -> CanonicalSponsoredScriptEvidenceV2:
    if type(value) is not CanonicalSponsoredScriptEvidenceV2:
        _fail("script_evidence_type")
    try:
        return CanonicalSponsoredScriptEvidenceV2(
            *(getattr(value, f.name) for f in fields(CanonicalSponsoredScriptEvidenceV2))
        )
    except Exception:
        _fail("script_evidence_invalid")


@dataclass(frozen=True, slots=True)
class V2AdmissionOutpoint:
    leg_order: str
    direction: CovenantDirection
    txid: str
    vout: int
    amount_sats: int
    witness_script_sha256: str
    descriptor_sha256: str | None

    def __post_init__(self) -> None:
        if type(self.leg_order) is not str or self.leg_order not in ("earlier", "later"):
            _fail("leg_order")
        if type(self.direction) is not CovenantDirection:
            _fail("direction")
        _digest(self.txid, "txid")
        if type(self.vout) is not int or not 0 <= self.vout <= 0xFFFFFFFF:
            _fail("vout")
        if type(self.amount_sats) is not int or not 1 <= self.amount_sats <= 2_100_000_000_000_000:
            _fail("amount_sats")
        _digest(self.witness_script_sha256, "witness_script_sha256")
        if self.descriptor_sha256 is not None:
            _digest(self.descriptor_sha256, "descriptor_sha256")


@dataclass(frozen=True, slots=True)
class CanonicalAdmissionProposalV2:
    schema: str
    version: str
    authorization_boundary: str
    proposal_id: str
    proposed_at: datetime
    basis_kind: SponsorBasisV2
    basis_record_id: str
    basis_record_sha256: str
    script_evidence: CanonicalSponsoredScriptEvidenceV2
    script_evidence_sha256: str
    registration_id: str
    registration_sha256: str
    funding_set_id: str
    funding_set_sha256: str
    observation_sha256: str
    observed_at: datetime
    observed_block_height: int
    mirror_sats_per_leg: int
    outpoints: tuple[V2AdmissionOutpoint, V2AdmissionOutpoint]
    sponsor_import_event_sha256: str
    sponsor_key_proof_reference_sha256: str
    child_acceptance_reference_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.schema) is not str
            or self.schema != SCHEMA
            or type(self.version) is not str
            or self.version != VERSION
            or type(self.authorization_boundary) is not str
            or self.authorization_boundary != BOUNDARY
        ):
            _fail("fixed_v2_proposal_contract")
        for name in ("proposal_id", "basis_record_id", "registration_id", "funding_set_id"):
            _uuid(getattr(self, name), name)
        for name in (
            "basis_record_sha256",
            "script_evidence_sha256",
            "registration_sha256",
            "funding_set_sha256",
            "observation_sha256",
            "sponsor_import_event_sha256",
            "sponsor_key_proof_reference_sha256",
            "child_acceptance_reference_sha256",
        ):
            _digest(getattr(self, name), name)
        if (
            len({
                self.sponsor_import_event_sha256,
                self.sponsor_key_proof_reference_sha256,
                self.child_acceptance_reference_sha256,
            }) != 3
        ):
            _fail("distinct_evidence_references")
        if type(self.basis_kind) is not SponsorBasisV2:
            _fail("basis_kind")
        evidence = _revalidate_script(self.script_evidence)
        if self.script_evidence_sha256 != canonical_sponsored_script_evidence_v2_sha256(evidence):
            _fail("script_evidence_digest")
        if (evidence.sponsor_depth == 0) != (self.basis_kind is SponsorBasisV2.GENESIS):
            _fail("basis_depth")
        if type(self.observed_block_height) is not int or self.observed_block_height < 0:
            _fail("observed_block_height")
        if type(self.mirror_sats_per_leg) is not int or not 1 <= self.mirror_sats_per_leg <= 2_100_000_000_000_000:
            _fail("mirror_sats_per_leg")
        created = _time(self.proposed_at, "proposed_at")
        observed = _time(self.observed_at, "observed_at")
        if not observed <= created <= observed + MAX_OBSERVATION_AGE:
            _fail("observation_age")
        if type(self.outpoints) is not tuple or len(self.outpoints) != 2:
            _fail("two_outpoints")
        if any(type(item) is not V2AdmissionOutpoint for item in self.outpoints):
            _fail("outpoint_type")
        a, b = (V2AdmissionOutpoint(*(getattr(x, f.name) for f in fields(V2AdmissionOutpoint)))
                for x in self.outpoints)
        if (
            (a.leg_order, b.leg_order) != ("earlier", "later")
            or (a.direction, b.direction) != (CovenantDirection.OUTGOING, CovenantDirection.INCOMING)
            or (a.witness_script_sha256, b.witness_script_sha256) != (
                evidence.earlier_script_sha256, evidence.later_script_sha256
            )
            or (a.amount_sats, b.amount_sats) != (self.mirror_sats_per_leg,) * 2
            or (a.txid, a.vout) == (b.txid, b.vout)
        ):
            _fail("outpoint_script_or_amount_binding")
        object.__setattr__(self, "proposed_at", created)
        object.__setattr__(self, "observed_at", observed)
        object.__setattr__(self, "script_evidence", evidence)
        object.__setattr__(self, "outpoints", (a, b))

    @property
    def grants_full(self) -> bool:
        return False

    @property
    def is_effective(self) -> bool:
        return False


def canonical_admission_proposal_v2_bytes(proposal: CanonicalAdmissionProposalV2) -> bytes:
    if type(proposal) is not CanonicalAdmissionProposalV2:
        _fail("proposal_type")
    value = CanonicalAdmissionProposalV2(
        *(getattr(proposal, f.name) for f in fields(CanonicalAdmissionProposalV2))
    )
    payload = {}
    for field in fields(value):
        key = field.name
        content = getattr(value, key)
        if key == "script_evidence":
            content = {f.name: getattr(content, f.name) for f in fields(content)}
        elif key == "outpoints":
            content = [
                {f.name: (getattr(item, f.name).value if f.name == "direction" else getattr(item, f.name))
                 for f in fields(item)}
                for item in content
            ]
        elif key == "basis_kind":
            content = content.value
        elif key in ("proposed_at", "observed_at"):
            content = content.isoformat().replace("+00:00", "Z")
        payload[key] = content
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_admission_proposal_v2_sha256(proposal: CanonicalAdmissionProposalV2) -> str:
    return hashlib.sha256(canonical_admission_proposal_v2_bytes(proposal)).hexdigest()


def _checked_registration(value: object) -> TrustedCovenantRegistration:
    if type(value) is not TrustedCovenantRegistration:
        _fail("registration_type")
    try:
        copy = TrustedCovenantRegistration(
            *(getattr(value, f.name) for f in fields(TrustedCovenantRegistration))
        )
    except Exception:
        _fail("registration_invalid")
    if copy.lifecycle_state is not TrustedCovenantRegistrationLifecycle.ACTIVE:
        _fail("registration_not_active")
    return copy


def _checked_funding(
    value: object, registration: TrustedCovenantRegistration
) -> CanonicalCovenantFundingSet:
    if type(value) is not CanonicalCovenantFundingSet:
        _fail("funding_set_type")
    try:
        copy = CanonicalCovenantFundingSet(
            *(getattr(value, f.name) for f in fields(CanonicalCovenantFundingSet))
        )
        validate_funding_set_registration(copy, registration)
    except Exception:
        _fail("funding_set_invalid")
    if copy.lifecycle_state is not CovenantFundingSetLifecycle.EFFECTIVE:
        _fail("funding_set_not_effective")
    return copy


def _source_outpoints(
    evidence: CanonicalSponsoredScriptEvidenceV2,
    registration: TrustedCovenantRegistration,
    funding: CanonicalCovenantFundingSet,
) -> tuple[V2AdmissionOutpoint, V2AdmissionOutpoint]:
    pair = registration.mirrored_pair
    if (
        pair.subject_pubkey != evidence.child_compressed_pubkey
        or pair.counterparty_pubkey != evidence.sponsor_compressed_pubkey
        or pair.earlier_leg.raw_script_hex != evidence.earlier_raw_script_hex
        or pair.later_leg.raw_script_hex != evidence.later_raw_script_hex
    ):
        _fail("source_pair_mismatch")
    if len(funding.recognized_outpoints) != 2:
        _fail("funding_set_not_exact_two")
    if len(registration.outpoints) != 2:
        _fail("registration_not_exact_two")
    # Domain source and funding-set outpoints use distinct dataclass types.
    # Compare all six scalar binding fields, not their Python object identity.
    supplied = {
        (x.direction, x.txid, x.vout, x.amount_sats, x.witness_script_sha256, x.descriptor_sha256)
        for x in funding.recognized_outpoints
    }
    anchors = {
        (x.direction, x.txid, x.vout, x.amount_sats, x.witness_script_sha256, x.descriptor_sha256)
        for x in registration.outpoints
    }
    if supplied != anchors:
        _fail("funding_set_exact_anchor_mismatch")
    ordered = []
    for leg_order, script_sha in (
        ("earlier", evidence.earlier_script_sha256),
        ("later", evidence.later_script_sha256),
    ):
        matched = [x for x in registration.outpoints if x.witness_script_sha256 == script_sha]
        if len(matched) != 1:
            _fail("registration_script_not_unique")
        item = matched[0]
        ordered.append(
            V2AdmissionOutpoint(
                leg_order, item.direction, item.txid, item.vout, item.amount_sats,
                item.witness_script_sha256, item.descriptor_sha256
            )
        )
    a, b = ordered
    if a.amount_sats != b.amount_sats:
        _fail("unequal_mirrored_sats")
    return a, b


def _basis(
    evidence: CanonicalSponsoredScriptEvidenceV2,
    basis: object,
) -> tuple[SponsorBasisV2, str, str]:
    if evidence.sponsor_depth == 0:
        if type(basis) is not CanonicalGenesisEvaluation:
            _fail("genesis_basis_type")
        try:
            genesis = CanonicalGenesisEvaluation(
                *(getattr(basis, f.name) for f in fields(CanonicalGenesisEvaluation))
            )
        except Exception:
            _fail("genesis_basis_invalid")
        if (
            genesis.state is not CanonicalGenesisEvaluationState.GENESIS_ACTIVE
            or genesis.compressed_public_key != evidence.sponsor_compressed_pubkey
            or genesis.selected_effective_record_id is None
        ):
            _fail("genesis_basis_inactive")
        return (
            SponsorBasisV2.GENESIS, genesis.selected_effective_record_id,
            genesis.selected_effective_record_sha256
        )
    if type(basis) is not CanonicalAdmissionProposalV2:
        _fail("parent_proposal_type")
    try:
        parent = CanonicalAdmissionProposalV2(
            *(getattr(basis, f.name) for f in fields(CanonicalAdmissionProposalV2))
        )
    except Exception:
        _fail("parent_proposal_invalid")
    prev = parent.script_evidence
    if (
        prev.child_depth != evidence.sponsor_depth
        or prev.child_compressed_pubkey != evidence.sponsor_compressed_pubkey
        or prev.child_xonly_pubkey != evidence.sponsor_xonly_pubkey
        or prev.graph_or_protocol_id != evidence.graph_or_protocol_id
        or prev.child_xonly_pubkey == evidence.child_xonly_pubkey
        or prev.sponsor_xonly_pubkey == evidence.child_xonly_pubkey
    ):
        _fail("parent_proposal_identity_or_depth")
    # A parent PROPOSAL is not proof of current Full, and does not authorize
    # successor creation. This is only an immutable lineage reference.
    return SponsorBasisV2.PARENT_PROPOSAL, parent.proposal_id, canonical_admission_proposal_v2_sha256(parent)


def _checked_observation(
    observation: object, registration: TrustedCovenantRegistration,
    *,
    now: datetime
) -> CovenantRelationEvaluation:
    if type(observation) is not CovenantRelationEvaluation:
        _fail("observation_type")
    try:
        value = CovenantRelationEvaluation(
            *(getattr(observation, f.name) for f in fields(CovenantRelationEvaluation))
        )
        expected = trusted_outpoints_from_registration(registration)
    except Exception:
        _fail("observation_invalid")
    if (
        value.subject_pubkey != registration.subject_xonly_pubkey
        or value.counterparty_pubkey != registration.counterparty_xonly_pubkey
        or len(value.observations) != 2
        or not value.observed_at <= now <= value.observed_at + MAX_OBSERVATION_AGE
    ):
        _fail("observation_missing_or_stale")
    observed = {
        (x.direction, x.txid, x.vout, x.amount_sats, x.script_sha256, x.descriptor_sha256):
        (x.unspent, x.confirmations)
        for x in value.observations
    }
    bindings = {
        (x.direction, x.txid, x.vout, x.amount_sats, x.script_sha256, x.descriptor_sha256)
        for x in expected
    }
    if set(observed) != bindings or any(not unspent or conf < 1 for unspent, conf in observed.values()):
        _fail("observation_outpoint_inactive_or_mismatched")
    return value


def validate_canonical_admission_proposal_v2_sources(
    proposal: CanonicalAdmissionProposalV2,
    *,
    registration: TrustedCovenantRegistration,
    funding_set: CanonicalCovenantFundingSet,
    sponsor_basis: object,
    observation: CovenantRelationEvaluation,
    now: datetime,
) -> CanonicalAdmissionProposalV2:
    """Fail-closed consistency over supplied immutable sources. No signature verification."""
    if type(proposal) is not CanonicalAdmissionProposalV2:
        _fail("proposal_type")
    proposal = CanonicalAdmissionProposalV2(
        *(getattr(proposal, f.name) for f in fields(CanonicalAdmissionProposalV2))
    )
    now = _time(now, "now")
    reg = _checked_registration(registration)
    funding = _checked_funding(funding_set, reg)
    evidence = proposal.script_evidence
    a, b = _source_outpoints(evidence, reg, funding)
    kind, basis_id, basis_sha = _basis(evidence, sponsor_basis)
    obs = _checked_observation(observation, reg, now=now)
    if (
        proposal.registration_id != reg.registration_id
        or proposal.registration_sha256 != trusted_registration_sha256(reg)
        or proposal.funding_set_id != funding.funding_set_id
        or proposal.funding_set_sha256 != canonical_covenant_funding_set_sha256(funding)
        or (proposal.basis_kind, proposal.basis_record_id, proposal.basis_record_sha256)
        != (kind, basis_id, basis_sha)
        or proposal.outpoints != (a, b)
        or proposal.mirror_sats_per_leg != a.amount_sats
        or proposal.observation_sha256 != covenant_relation_source_sha256(obs)
        or proposal.observed_at != obs.observed_at
        or proposal.observed_block_height != obs.observed_block_height
        or not obs.observed_at <= proposal.proposed_at <= now
        or reg.registered_at > proposal.proposed_at
        or funding.created_at > proposal.proposed_at
    ):
        _fail("proposal_sources_mismatch")
    return proposal


def create_canonical_admission_proposal_v2(
    *,
    proposal_id: str,
    proposed_at: datetime,
    script_evidence: CanonicalSponsoredScriptEvidenceV2,
    registration: TrustedCovenantRegistration,
    funding_set: CanonicalCovenantFundingSet,
    sponsor_basis: object,
    observation: CovenantRelationEvaluation,
    sponsor_import_event_sha256: str,
    sponsor_key_proof_reference_sha256: str,
    child_acceptance_reference_sha256: str,
) -> CanonicalAdmissionProposalV2:
    """Construct a source-bound, proposed-only object; receipts are unverified references."""
    evidence = _revalidate_script(script_evidence)
    reg = _checked_registration(registration)
    funding = _checked_funding(funding_set, reg)
    outpoints = _source_outpoints(evidence, reg, funding)
    kind, basis_id, basis_sha = _basis(evidence, sponsor_basis)
    created = _time(proposed_at, "proposed_at")
    observed = _checked_observation(observation, reg, now=created)
    proposal = CanonicalAdmissionProposalV2(
        SCHEMA, VERSION, BOUNDARY, proposal_id, created,
        kind, basis_id, basis_sha, evidence,
        canonical_sponsored_script_evidence_v2_sha256(evidence),
        reg.registration_id, trusted_registration_sha256(reg),
        funding.funding_set_id, canonical_covenant_funding_set_sha256(funding),
        covenant_relation_source_sha256(observed), observed.observed_at,
        observed.observed_block_height, outpoints[0].amount_sats, outpoints,
        sponsor_import_event_sha256, sponsor_key_proof_reference_sha256,
        child_acceptance_reference_sha256,
    )
    return validate_canonical_admission_proposal_v2_sources(
        proposal, registration=reg, funding_set=funding, sponsor_basis=sponsor_basis,
        observation=observed, now=created
    )
