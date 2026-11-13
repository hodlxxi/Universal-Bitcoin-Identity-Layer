"""Multi-UTXO mirrored funding V2, a read-only source-bound preflight.

The existing V1 registration and V2 proposal bind EXACTLY TWO outpoints.
Real funded mirrors can have several P2WSH outputs per side and unequal
balances. This separate V2 bundle models them without downgrading V1 or
claiming effective admission/Full. A caller-supplied observation or RPC
injected by an untrusted caller is NOT independent Bitcoin authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone

from app.services.canonical_sponsored_script_policy_v2 import (
    CanonicalSponsoredScriptEvidenceV2,
    canonical_sponsored_script_evidence_v2_sha256,
)
from app.services.covenant_relation import (
    MAX_BITCOIN_SATS,
    CovenantDirection,
    CovenantRelationEvaluation,
    CovenantRelationObservation,
    covenant_relation_source_sha256,
)
from app.services.trusted_covenant_observation import (
    TrustedBitcoinCovenantObservationAdapter,
    TrustedCovenantOutpoint,
)
from app.services.trusted_covenant_registration import p2wsh_script_pubkey_sha256

SCHEMA = "hodlxxi.canonical_multi_outpoint_mirror.v2"
OBSERVATION_SCHEMA = "hodlxxi.canonical_multi_outpoint_snapshot.v2"
BOUNDARY = "source_bound_preflight_no_current_full_or_admission"
MAX_OUTPOINTS = 256
MAX_AGE = timedelta(seconds=120)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class InvalidCanonicalMultiOutpointMirrorV2(ValueError):
    """Malformed mirror, mismatched outpoints or stale/failed observation."""


def _fail(reason: str) -> None:
    raise InvalidCanonicalMultiOutpointMirrorV2(reason)


def _utc_second(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail("timestamp")
    at = value.astimezone(timezone.utc)
    if at.microsecond:
        _fail("timestamp_second_precision")
    return at


def _checked_script_evidence(value: object) -> CanonicalSponsoredScriptEvidenceV2:
    if type(value) is not CanonicalSponsoredScriptEvidenceV2:
        _fail("script_policy_type")
    try:
        return CanonicalSponsoredScriptEvidenceV2(
            *(getattr(value, f.name) for f in fields(CanonicalSponsoredScriptEvidenceV2))
        )
    except Exception:
        _fail("script_policy_invalid")


def _expected_script_sha(evidence: CanonicalSponsoredScriptEvidenceV2, direction: CovenantDirection) -> str:
    # For the child as subject, the EARLIER leg has direction OUTGOING;
    # the LATER leg is INCOMING. The Bitcoin Core gettxout adapter stores
    # SHA256 of native P2WSH scriptPubKey, NOT hash of the witness script.
    witness_hash = (
        evidence.earlier_script_sha256
        if direction is CovenantDirection.OUTGOING
        else evidence.later_script_sha256
    )
    return p2wsh_script_pubkey_sha256(witness_hash)


def _sort(item: TrustedCovenantOutpoint) -> tuple:
    return (item.direction.value, item.txid, item.vout)


@dataclass(frozen=True, slots=True)
class CanonicalMultiOutpointMirrorV2:
    schema: str
    authorization_boundary: str
    script_evidence: CanonicalSponsoredScriptEvidenceV2
    script_evidence_sha256: str
    outpoints: tuple[TrustedCovenantOutpoint, ...]

    def __post_init__(self) -> None:
        if (
            type(self.schema) is not str
            or self.schema != SCHEMA
            or type(self.authorization_boundary) is not str
            or self.authorization_boundary != BOUNDARY
        ):
            _fail("schema_or_boundary")
        evidence = _checked_script_evidence(self.script_evidence)
        if (
            type(self.script_evidence_sha256) is not str
            or self.script_evidence_sha256 != canonical_sponsored_script_evidence_v2_sha256(evidence)
        ):
            _fail("script_policy_digest")
        if type(self.outpoints) is not tuple or not 2 <= len(self.outpoints) <= MAX_OUTPOINTS:
            _fail("outpoint_population")
        checked = []
        seen = set()
        sums = {CovenantDirection.INCOMING: 0, CovenantDirection.OUTGOING: 0}
        for item in self.outpoints:
            if type(item) is not TrustedCovenantOutpoint:
                _fail("outpoint_type")
            try:
                x = TrustedCovenantOutpoint(*(getattr(item, f.name) for f in fields(TrustedCovenantOutpoint)))
            except Exception:
                _fail("outpoint_invalid")
            if (
                x.subject_pubkey != evidence.child_xonly_pubkey
                or x.counterparty_pubkey != evidence.sponsor_xonly_pubkey
                or x.script_sha256 != _expected_script_sha(evidence, x.direction)
            ):
                _fail("outpoint_identity_or_script")
            key = (x.txid, x.vout)
            if key in seen:
                _fail("outpoint_duplicate")
            seen.add(key)
            sums[x.direction] += x.amount_sats
            if sums[x.direction] > MAX_BITCOIN_SATS:
                _fail("side_sum_overflow")
            checked.append(x)
        if not sums[CovenantDirection.OUTGOING] or not sums[CovenantDirection.INCOMING]:
            _fail("missing_mirror_side")
        object.__setattr__(self, "script_evidence", evidence)
        object.__setattr__(self, "outpoints", tuple(sorted(checked, key=_sort)))

    @property
    def grants_full(self) -> bool:
        return False

    @property
    def is_effective(self) -> bool:
        return False


def create_canonical_multi_outpoint_mirror_v2(
    evidence: CanonicalSponsoredScriptEvidenceV2,
    outpoints: tuple[TrustedCovenantOutpoint, ...],
) -> CanonicalMultiOutpointMirrorV2:
    evidence = _checked_script_evidence(evidence)
    return CanonicalMultiOutpointMirrorV2(
        SCHEMA,
        BOUNDARY,
        evidence,
        canonical_sponsored_script_evidence_v2_sha256(evidence),
        outpoints,
    )


def canonical_multi_outpoint_mirror_v2_bytes(value: CanonicalMultiOutpointMirrorV2) -> bytes:
    if type(value) is not CanonicalMultiOutpointMirrorV2:
        _fail("bundle_type")
    checked = CanonicalMultiOutpointMirrorV2(*(getattr(value, f.name) for f in fields(CanonicalMultiOutpointMirrorV2)))
    body = {
        "schema": checked.schema,
        "authorization_boundary": checked.authorization_boundary,
        "script_evidence": {f.name: getattr(checked.script_evidence, f.name)
                            for f in fields(CanonicalSponsoredScriptEvidenceV2)},
        "script_evidence_sha256": checked.script_evidence_sha256,
        "outpoints": [
            {
                f.name: (getattr(item, f.name).value if f.name == "direction" else getattr(item, f.name))
                for f in fields(TrustedCovenantOutpoint)
            }
            for item in checked.outpoints
        ],
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_multi_outpoint_mirror_v2_sha256(value: CanonicalMultiOutpointMirrorV2) -> str:
    return hashlib.sha256(canonical_multi_outpoint_mirror_v2_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class CanonicalMultiOutpointSnapshotV2:
    schema: str
    authorization_boundary: str
    bundle_sha256: str
    observation_sha256: str
    observed_at: datetime
    observed_block_height: int
    earlier_sats: int
    later_sats: int
    trust_ceiling_sats: int
    outpoint_count: int

    def __post_init__(self) -> None:
        if self.schema != OBSERVATION_SCHEMA or self.authorization_boundary != BOUNDARY:
            _fail("snapshot_schema")
        for digest in (self.bundle_sha256, self.observation_sha256):
            if type(digest) is not str or _HEX64.fullmatch(digest) is None:
                _fail("snapshot_digest")
        _utc_second(self.observed_at)
        if (
            type(self.observed_block_height) is not int
            or self.observed_block_height < 0
            or type(self.earlier_sats) is not int
            or type(self.later_sats) is not int
            or type(self.trust_ceiling_sats) is not int
            or not 1 <= self.earlier_sats <= MAX_BITCOIN_SATS
            or not 1 <= self.later_sats <= MAX_BITCOIN_SATS
            or self.trust_ceiling_sats != min(self.earlier_sats, self.later_sats)
            or type(self.outpoint_count) is not int
            or not 2 <= self.outpoint_count <= MAX_OUTPOINTS
        ):
            _fail("snapshot_amount_or_count")

    @property
    def grants_full(self) -> bool:
        return False

    @property
    def source_is_authoritative(self) -> bool:
        return False


def validate_canonical_multi_outpoint_snapshot_v2(
    bundle: CanonicalMultiOutpointMirrorV2,
    observation: CovenantRelationEvaluation,
    *,
    now: datetime,
) -> CanonicalMultiOutpointSnapshotV2:
    if type(bundle) is not CanonicalMultiOutpointMirrorV2:
        _fail("bundle_type")
    checked = CanonicalMultiOutpointMirrorV2(*(getattr(bundle, f.name) for f in fields(CanonicalMultiOutpointMirrorV2)))
    if type(observation) is not CovenantRelationEvaluation:
        _fail("observation_type")
    try:
        actual = CovenantRelationEvaluation(*(getattr(observation, f.name) for f in fields(CovenantRelationEvaluation)))
    except Exception:
        _fail("observation_invalid")
    current = _utc_second(now)
    if (
        actual.subject_pubkey != checked.script_evidence.child_xonly_pubkey
        or actual.counterparty_pubkey != checked.script_evidence.sponsor_xonly_pubkey
        or not actual.observed_at <= current <= actual.observed_at + MAX_AGE
        or len(actual.observations) != len(checked.outpoints)
    ):
        _fail("stale_or_incomplete_observation")
    anchors = {
        (x.direction, x.txid, x.vout, x.amount_sats, x.script_sha256, x.descriptor_sha256)
        for x in checked.outpoints
    }
    observed = {
        (x.direction, x.txid, x.vout, x.amount_sats, x.script_sha256, x.descriptor_sha256)
        for x in actual.observations
    }
    if len(observed) != len(checked.outpoints) or observed != anchors:
        _fail("outpoint_observation_mismatch")
    if any(
        type(item) is not CovenantRelationObservation
        or not item.unspent
        or item.confirmations < 1
        for item in actual.observations
    ):
        _fail("outpoint_spent_or_unconfirmed")
    earlier_sats = sum(x.amount_sats for x in checked.outpoints if x.direction is CovenantDirection.OUTGOING)
    later_sats = sum(x.amount_sats for x in checked.outpoints if x.direction is CovenantDirection.INCOMING)
    return CanonicalMultiOutpointSnapshotV2(
        OBSERVATION_SCHEMA,
        BOUNDARY,
        canonical_multi_outpoint_mirror_v2_sha256(checked),
        covenant_relation_source_sha256(actual),
        actual.observed_at,
        actual.observed_block_height,
        earlier_sats,
        later_sats,
        min(earlier_sats, later_sats),
        len(checked.outpoints),
    )


def observe_canonical_multi_outpoint_mirror_v2(
    bundle: CanonicalMultiOutpointMirrorV2,
    *,
    bitcoin_rpc: object,
    now: datetime,
) -> CanonicalMultiOutpointSnapshotV2:
    """Read exact native P2WSH UTXOs via injected Bitcoin Core-style RPC.

    Adapter checks hash/height stability and P2WSH, but RPC provenance is
    caller-injected; gettxout(..., False) also does NOT prove absence of
    unconfirmed mempool spends. Neither this method nor returned snapshots
    may be used to grant Full or register an effective edge.
    """
    checked_at = _utc_second(now)
    if type(bundle) is not CanonicalMultiOutpointMirrorV2:
        _fail("bundle_type")
    try:
        observation = TrustedBitcoinCovenantObservationAdapter(
            bitcoin_rpc, clock=lambda: checked_at
        ).observe(bundle.outpoints)
    except Exception:
        _fail("bitcoin_observation_unavailable")
    return validate_canonical_multi_outpoint_snapshot_v2(bundle, observation, now=checked_at)
