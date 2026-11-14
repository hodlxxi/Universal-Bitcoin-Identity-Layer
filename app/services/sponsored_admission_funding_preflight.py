"""Read-only exact-UTXO observation preflight for sponsored admission.

This module does not create or infer sponsor authority, child consent,
registrations, admission edges, or current Full entitlement. The caller supplies
two explicitly selected outpoints; a wallet-global scan is not authoritative.
The observation is one transient snapshot, not a durable admission proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from app.services.canonical_admission_edge import MIN_CONFIRMATIONS
from app.services.covenant_relation import MAX_BITCOIN_SATS, MAX_VOUT, CovenantDirection
from app.services.mirrored_covenant_pair import CovenantDeltaProfile, validate_mirrored_covenant_pair
from app.services.sponsored_admission_import_preflight import assess_sponsored_imported_pair
from app.services.trusted_covenant_observation import (
    TRUSTED_OUTPOINT_SCHEMA,
    TrustedBitcoinCovenantObservationAdapter,
    TrustedCovenantOutpoint,
)
from app.services.trusted_covenant_registration import p2wsh_script_pubkey_sha256

SCHEMA = "hodlxxi.sponsored_admission_funding_preflight.v1"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_STRUCTURAL_CANDIDATES = frozenset(("canonical_script_shape_only", "reverse_branch_roles_requires_policy_review"))


@dataclass(frozen=True, slots=True)
class CandidateOutpoint:
    """Explicit txid:vout plus expected integer sats from the import candidate."""

    txid: str
    vout: int
    amount_sats: int

    def __post_init__(self) -> None:
        if type(self.txid) is not str or _HEX64.fullmatch(self.txid) is None:
            raise ValueError("candidate txid must be canonical lowercase 64-hex")
        if type(self.vout) is not int or not 0 <= self.vout <= MAX_VOUT:
            raise ValueError("candidate vout must be an exact unsigned 32-bit integer")
        if type(self.amount_sats) is not int or not 1 <= self.amount_sats <= MAX_BITCOIN_SATS:
            raise ValueError("candidate amount must be positive exact integer satoshis")


@dataclass(frozen=True, slots=True)
class SponsoredAdmissionFundingPreflight:
    schema: str
    status: str
    structural_status: str
    sponsor_xonly_pubkey: str
    candidate_child_xonly_pubkey: str | None
    pair_sha256: str | None
    child_depth: int
    observed_at: datetime | None
    observed_block_height: int | None
    mirror_sats_per_leg: int | None

    @property
    def grants_full(self) -> bool:
        """A verified UTXO snapshot cannot confer participant entitlement."""
        return False


def assess_sponsored_funding_snapshot(
    first_script_hex: str,
    second_script_hex: str,
    *,
    sponsor_compressed_pubkey: str,
    sponsor_depth: int,
    earlier_outpoint: CandidateOutpoint,
    later_outpoint: CandidateOutpoint,
    rpc: object,
    clock: Callable[[], datetime] | None = None,
) -> SponsoredAdmissionFundingPreflight:
    """Observe two exact P2WSH outpoints under one bounded chain snapshot.

    This read-only preflight is independent of descriptor provenance and
    authorization. The existing trusted observation adapter verifies txout
    amount, scriptPubKey binding, confirmations and stable best-block height
    and hash. It intentionally does not perform DB writes or grant Full.
    """
    structure = assess_sponsored_imported_pair(
        first_script_hex,
        second_script_hex,
        sponsor_compressed_pubkey=sponsor_compressed_pubkey,
        sponsor_depth=sponsor_depth,
    )

    def result(
        status: str,
        observed_at: datetime | None = None,
        block_height: int | None = None,
        sats: int | None = None,
    ) -> SponsoredAdmissionFundingPreflight:
        return SponsoredAdmissionFundingPreflight(
            SCHEMA,
            status,
            structure.status,
            structure.sponsor_xonly_pubkey,
            structure.candidate_child_xonly_pubkey,
            structure.pair_sha256,
            structure.child_depth,
            observed_at,
            block_height,
            sats,
        )

    if structure.status not in _STRUCTURAL_CANDIDATES:
        return result("structural_candidate_rejected")
    if type(earlier_outpoint) is not CandidateOutpoint or type(later_outpoint) is not CandidateOutpoint:
        return result("invalid_outpoint_binding")
    if (earlier_outpoint.txid, earlier_outpoint.vout) == (
        later_outpoint.txid,
        later_outpoint.vout,
    ) or earlier_outpoint.amount_sats != later_outpoint.amount_sats:
        return result("invalid_outpoint_binding")

    try:
        # Reuse the authoritative parser rather than binding arbitrary hashes.
        pair = validate_mirrored_covenant_pair(
            first_script_hex,
            second_script_hex,
            subject_pubkey=sponsor_compressed_pubkey,
            allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,),
        )
        if pair.counterparty_xonly_pubkey != structure.candidate_child_xonly_pubkey:
            return result("structural_candidate_rejected")

        def trusted(leg, outpoint: CandidateOutpoint) -> TrustedCovenantOutpoint:
            direction = (
                CovenantDirection.INCOMING
                if leg.receiver_pubkey == sponsor_compressed_pubkey
                else CovenantDirection.OUTGOING
            )
            return TrustedCovenantOutpoint(
                TRUSTED_OUTPOINT_SCHEMA,
                pair.subject_xonly_pubkey,
                pair.counterparty_xonly_pubkey,
                direction,
                outpoint.txid,
                outpoint.vout,
                outpoint.amount_sats,
                p2wsh_script_pubkey_sha256(leg.script_sha256),
                None,
            )

        definitions = (
            trusted(pair.earlier_leg, earlier_outpoint),
            trusted(pair.later_leg, later_outpoint),
        )
        observation = TrustedBitcoinCovenantObservationAdapter(rpc, clock=clock).observe(definitions)
        if (
            len(observation.observations) != 2
            or {item.direction for item in observation.observations}
            != {CovenantDirection.INCOMING, CovenantDirection.OUTGOING}
            or any(
                item.unspent is not True or item.confirmations < MIN_CONFIRMATIONS for item in observation.observations
            )
        ):
            return result("missing_or_insufficient_qualifying_utxo")
        return result(
            "two_exact_utxos_observed_no_admission",
            observation.observed_at,
            observation.observed_block_height,
            earlier_outpoint.amount_sats,
        )
    except Exception:
        # Even RPC failures, inconsistent chain snapshots and malformed
        # dependencies must remain non-authoritative and fail closed.
        return result("observation_unavailable")
