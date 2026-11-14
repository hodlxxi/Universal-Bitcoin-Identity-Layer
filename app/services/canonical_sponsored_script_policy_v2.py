"""Versioned, read-only Canon V2 script-role evidence for sponsored Human Membership.

V1 admission-edge semantics are deliberately immutable. V2 adopts the
published/actually funded Alice/Bob unilateral ordering: sponsor EARLY,
child MIDDLE, sponsor LATE, for any supported child depth.

This verifier proves *script shape only*. It cannot prove UTXOs, identity,
sponsor Full, child acceptance, parent lineage or an entitlement grant.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields

from app.services.canonical_admission_edge import (
    GENESIS_COMPRESSED_KEY,
    GENESIS_PARTICIPANT_ID,
    GRAPH_ID,
    HUMAN_PROFILE,
    NETWORK,
    cascade_heights,
)
from app.services.mirrored_covenant_pair import (
    CovenantDeltaProfile,
    CovenantTemplateFamily,
    InvalidMirroredCovenantPair,
    ValidatedMirroredCovenantPair,
    mirrored_covenant_pair_sha256,
    validate_mirrored_covenant_pair,
)

SCHEMA = "hodlxxi.canonical_sponsored_script_evidence.v2"
POLICY_VERSION = "hodlxxi.canonical_sponsored_script_policy.v2"
ORIENTATION = "sponsor_early_child_middle_sponsor_late"
BOUNDARY = "script_evidence_only_no_entitlement"
_COMPRESSED = re.compile(r"(?:02|03)[0-9a-f]{64}\Z")


class InvalidCanonicalSponsoredScriptPolicyV2(ValueError):
    """An input fails the explicit V2 role/schedule policy."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _fail(reason: str) -> None:
    raise InvalidCanonicalSponsoredScriptPolicyV2(reason)


def _validated_v2_pair(
    first_script_hex: str,
    second_script_hex: str,
    *,
    sponsor_compressed_pubkey: str,
    sponsor_depth: int,
) -> tuple[ValidatedMirroredCovenantPair, tuple[int, int, int]]:
    if (
        type(sponsor_compressed_pubkey) is not str
        or _COMPRESSED.fullmatch(sponsor_compressed_pubkey) is None
        or type(sponsor_depth) is not int
        or sponsor_depth < 0
    ):
        _fail("invalid_sponsor_identity_or_depth")
    if sponsor_depth == 0 and sponsor_compressed_pubkey != GENESIS_COMPRESSED_KEY:
        _fail("non_genesis_root")
    try:
        expected = cascade_heights(sponsor_depth + 1)
    except ValueError:
        _fail("depth_outside_cascade")
    try:
        pair = validate_mirrored_covenant_pair(
            first_script_hex,
            second_script_hex,
            subject_pubkey=sponsor_compressed_pubkey,
            allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,),
        )
    except (InvalidMirroredCovenantPair, ValueError, TypeError):
        _fail("invalid_or_unsupported_mirror")
    if (
        pair.template_family is not CovenantTemplateFamily.CLTV_ONLY
        or pair.delta_profile is not CovenantDeltaProfile.LEGACY_777
    ):
        _fail("unsupported_covenant_template")
    early, middle, late = expected
    if (
        pair.earlier_leg.receiver_height,
        pair.earlier_leg.sender_height,
        pair.later_leg.receiver_height,
        pair.later_leg.sender_height,
    ) != (early, middle, middle, late):
        _fail("cascade_schedule_mismatch")

    child = pair.counterparty_pubkey
    if (
        pair.earlier_leg.receiver_pubkey,
        pair.earlier_leg.sender_pubkey,
        pair.later_leg.receiver_pubkey,
        pair.later_leg.sender_pubkey,
    ) != (sponsor_compressed_pubkey, child, child, sponsor_compressed_pubkey):
        _fail("v2_unilateral_role_mismatch")
    return pair, expected


@dataclass(frozen=True, slots=True)
class CanonicalSponsoredScriptEvidenceV2:
    schema: str
    policy_version: str
    graph_or_protocol_id: str
    network: str
    human_profile: str
    orientation: str
    authorization_boundary: str
    sponsor_participant_id: str
    sponsor_compressed_pubkey: str
    sponsor_xonly_pubkey: str
    sponsor_depth: int
    child_participant_id: str
    child_compressed_pubkey: str
    child_xonly_pubkey: str
    child_depth: int
    early_height: int
    middle_height: int
    late_height: int
    earlier_raw_script_hex: str
    later_raw_script_hex: str
    earlier_script_sha256: str
    later_script_sha256: str
    pair_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.schema) is not str
            or self.schema != SCHEMA
            or type(self.policy_version) is not str
            or self.policy_version != POLICY_VERSION
            or type(self.graph_or_protocol_id) is not str
            or self.graph_or_protocol_id != GRAPH_ID
            or type(self.network) is not str
            or self.network != NETWORK
            or type(self.human_profile) is not str
            or self.human_profile != HUMAN_PROFILE
            or type(self.orientation) is not str
            or self.orientation != ORIENTATION
            or type(self.authorization_boundary) is not str
            or self.authorization_boundary != BOUNDARY
        ):
            _fail("fixed_v2_policy")
        pair, (early, middle, late) = _validated_v2_pair(
            self.earlier_raw_script_hex,
            self.later_raw_script_hex,
            sponsor_compressed_pubkey=self.sponsor_compressed_pubkey,
            sponsor_depth=self.sponsor_depth,
        )
        if (
            type(self.sponsor_participant_id) is not str
            or type(self.sponsor_xonly_pubkey) is not str
            or type(self.child_participant_id) is not str
            or type(self.child_compressed_pubkey) is not str
            or type(self.child_xonly_pubkey) is not str
            or type(self.child_depth) is not int
            or type(self.early_height) is not int
            or type(self.middle_height) is not int
            or type(self.late_height) is not int
            or type(self.earlier_script_sha256) is not str
            or type(self.later_script_sha256) is not str
            or type(self.pair_sha256) is not str
        ):
            _fail("invalid_evidence_field_type")
        expected_sponsor_id = self.sponsor_compressed_pubkey[2:]
        if self.sponsor_depth == 0:
            expected_sponsor_id = GENESIS_PARTICIPANT_ID
        if (
            self.sponsor_participant_id != expected_sponsor_id
            or self.sponsor_xonly_pubkey != pair.subject_xonly_pubkey
            or self.child_participant_id != pair.counterparty_xonly_pubkey
            or self.child_compressed_pubkey != pair.counterparty_pubkey
            or self.child_xonly_pubkey != pair.counterparty_xonly_pubkey
            or self.child_depth != self.sponsor_depth + 1
            or (self.early_height, self.middle_height, self.late_height) != (early, middle, late)
            or self.earlier_raw_script_hex != pair.earlier_leg.raw_script_hex
            or self.later_raw_script_hex != pair.later_leg.raw_script_hex
            or self.earlier_script_sha256 != pair.earlier_leg.script_sha256
            or self.later_script_sha256 != pair.later_leg.script_sha256
            or self.pair_sha256 != mirrored_covenant_pair_sha256(pair)
        ):
            _fail("v2_evidence_binding_mismatch")

    @property
    def grants_full(self) -> bool:
        """An on-chain script is never identity, approval or Full membership."""
        return False


def validate_canonical_sponsored_scripts_v2(
    first_script_hex: str,
    second_script_hex: str,
    *,
    sponsor_compressed_pubkey: str,
    sponsor_depth: int,
) -> CanonicalSponsoredScriptEvidenceV2:
    """Validate fixed V2 sponsor/child branches, independent of script input order.

    Accepts only an exact pair and an explicitly supplied sponsor depth.
    The depth and sponsor Full authority are NOT inferred or attested here.
    """
    pair, (early, middle, late) = _validated_v2_pair(
        first_script_hex,
        second_script_hex,
        sponsor_compressed_pubkey=sponsor_compressed_pubkey,
        sponsor_depth=sponsor_depth,
    )
    return CanonicalSponsoredScriptEvidenceV2(
        SCHEMA,
        POLICY_VERSION,
        GRAPH_ID,
        NETWORK,
        HUMAN_PROFILE,
        ORIENTATION,
        BOUNDARY,
        GENESIS_PARTICIPANT_ID if sponsor_depth == 0 else pair.subject_xonly_pubkey,
        pair.subject_pubkey,
        pair.subject_xonly_pubkey,
        sponsor_depth,
        pair.counterparty_xonly_pubkey,
        pair.counterparty_pubkey,
        pair.counterparty_xonly_pubkey,
        sponsor_depth + 1,
        early,
        middle,
        late,
        pair.earlier_leg.raw_script_hex,
        pair.later_leg.raw_script_hex,
        pair.earlier_leg.script_sha256,
        pair.later_leg.script_sha256,
        mirrored_covenant_pair_sha256(pair),
    )


def canonical_sponsored_script_evidence_v2_bytes(
    evidence: CanonicalSponsoredScriptEvidenceV2,
) -> bytes:
    """Deterministic, strictly revalidated bytes for future provenance linkage."""
    if type(evidence) is not CanonicalSponsoredScriptEvidenceV2:
        _fail("invalid_v2_evidence_type")
    values = tuple(getattr(evidence, field.name) for field in fields(CanonicalSponsoredScriptEvidenceV2))
    validated = CanonicalSponsoredScriptEvidenceV2(*values)
    payload = {field.name: getattr(validated, field.name) for field in fields(validated)}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return encoded.encode("ascii")


def canonical_sponsored_script_evidence_v2_sha256(
    evidence: CanonicalSponsoredScriptEvidenceV2,
) -> str:
    payload = canonical_sponsored_script_evidence_v2_bytes(evidence)
    return hashlib.sha256(payload).hexdigest()
