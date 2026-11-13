"""Read-only structural preflight for a sponsored CLTV descriptor-import pair.

This is NOT an entitlement, admission edge, registration, or Bitcoin observation.
The imported descriptor is public/watch-only; it never proves key possession,
UTXO funding, sponsor authorization, or the child's consent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.canonical_admission_edge import (
    GENESIS_COMPRESSED_KEY,
    cascade_heights,
)
from app.services.mirrored_covenant_pair import (
    CovenantDeltaProfile,
    CovenantTemplateFamily,
    InvalidMirroredCovenantPair,
    mirrored_covenant_pair_sha256,
    validate_mirrored_covenant_pair,
)

SCHEMA = "hodlxxi.sponsored_admission_import_preflight.v1"
_COMPRESSED_KEY = re.compile(r"(?:02|03)[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class SponsoredAdmissionImportPreflight:
    schema: str
    status: str
    sponsor_xonly_pubkey: str
    candidate_child_xonly_pubkey: str | None
    child_depth: int
    pair_sha256: str | None

    @property
    def grants_full(self) -> bool:
        """Deliberately incapable of granting an entitlement."""
        return False


def assess_sponsored_imported_pair(
    first_script_hex: str,
    second_script_hex: str,
    *,
    sponsor_compressed_pubkey: str,
    sponsor_depth: int,
) -> SponsoredAdmissionImportPreflight:
    """Distinguish canonical admission branch roles from reversed real-world pairs.

    Structural assessment only: no Bitcoin RPC, DB, wallet, session, side
    effects, or runtime role mutation. The caller must independently prove the
    sponsor's current canonical Full, exact unspent/confirmed funding,
    registration/lineage and authorization, and authorized import provenance.
    """
    if (
        type(sponsor_compressed_pubkey) is not str
        or _COMPRESSED_KEY.fullmatch(sponsor_compressed_pubkey) is None
        or type(sponsor_depth) is not int
        or sponsor_depth < 0
    ):
        raise ValueError("invalid explicit sponsor or depth")
    child_depth = sponsor_depth + 1
    sponsor_xonly = sponsor_compressed_pubkey[2:]
    if sponsor_depth == 0 and sponsor_compressed_pubkey != GENESIS_COMPRESSED_KEY:
        return SponsoredAdmissionImportPreflight(SCHEMA, "non_genesis_root", sponsor_xonly, None, child_depth, None)
    try:
        expected_heights = cascade_heights(child_depth)
        pair = validate_mirrored_covenant_pair(
            first_script_hex,
            second_script_hex,
            subject_pubkey=sponsor_compressed_pubkey,
            allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,),
        )
    except (InvalidMirroredCovenantPair, ValueError, TypeError):
        return SponsoredAdmissionImportPreflight(
            SCHEMA,
            "invalid_or_unsupported_pair",
            sponsor_xonly,
            None,
            child_depth,
            None,
        )
    child = pair.counterparty_pubkey
    digest = mirrored_covenant_pair_sha256(pair)
    earlier, later = pair.earlier_leg, pair.later_leg
    if pair.template_family is not CovenantTemplateFamily.CLTV_ONLY:
        status = "wrong_covenant_template"
    elif (
        earlier.receiver_height,
        earlier.sender_height,
        later.receiver_height,
        later.sender_height,
    ) != (
        expected_heights[0],
        expected_heights[1],
        expected_heights[1],
        expected_heights[2],
    ):
        status = "wrong_admission_schedule"
    elif (
        earlier.receiver_pubkey == child
        and earlier.sender_pubkey == sponsor_compressed_pubkey
        and later.receiver_pubkey == sponsor_compressed_pubkey
        and later.sender_pubkey == child
    ):
        status = "canonical_script_shape_only"
    elif (
        earlier.receiver_pubkey == sponsor_compressed_pubkey
        and earlier.sender_pubkey == child
        and later.receiver_pubkey == child
        and later.sender_pubkey == sponsor_compressed_pubkey
    ):
        status = "reverse_branch_roles_requires_policy_review"
    else:
        status = "invalid_admission_roles"
    return SponsoredAdmissionImportPreflight(
        SCHEMA,
        status,
        sponsor_xonly,
        pair.counterparty_xonly_pubkey,
        child_depth,
        digest,
    )
