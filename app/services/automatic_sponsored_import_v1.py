"""Automatic sponsored import correlation, without a second signature ceremony.

This is the *actual* post-import ingress. It records authenticated Current-Full
sponsor scripts, correlates a canonical pair in either import order, and
persists a pending admission candidate. No pair, balance, descriptor or
PENDING record can grant Current Full. A separate verified, atomic server-owned
UTXO and effective-admission coordinator must consume the candidate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth_api_core import canonical_xonly_pubkey
from app.services.canonical_admission_edge import GENESIS_COMPRESSED_KEY
from app.services.canonical_sponsored_script_policy_v2 import (
    InvalidCanonicalSponsoredScriptPolicyV2,
    validate_canonical_sponsored_scripts_v2,
)
from app.services.current_entitlement_evidence_storage import (
    SqlAlchemyTransactionBoundCurrentFullVerifier,
)
from app.services.mirrored_covenant_pair import (
    InvalidMirroredCovenantPair,
    parse_covenant_leg,
)

SCHEMA = "hodlxxi.auto_sponsored_import.v1"
_HEX = re.compile(r"[0-9a-f]{2,2048}\Z")
_SUBJECT = re.compile(r"[0-9a-f]{64}\Z")


class AutomaticSponsoredImportUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("automatic sponsored import unavailable")


@dataclass(frozen=True, slots=True)
class AutomaticSponsoredImportResult:
    status: str
    candidate_child_xonly: str | None
    child_depth: int | None

    @property
    def grants_full(self) -> bool:
        return False


def _script_for_subject(value: str, sponsor_xonly: str):
    if type(value) is not str or _HEX.fullmatch(value) is None or len(value) % 2:
        return None
    try:
        leg = parse_covenant_leg(value)
    except (InvalidMirroredCovenantPair, ValueError, TypeError):
        return None
    if leg.receiver_xonly_pubkey == sponsor_xonly:
        return leg, leg.receiver_pubkey
    if leg.sender_xonly_pubkey == sponsor_xonly:
        return leg, leg.sender_pubkey
    return None


def match_imported_sponsored_pair(
    new_script_hex: str,
    previous_script_hexes: tuple[str, ...],
    *,
    sponsor_xonly_pubkey: str,
    sponsor_depth: int,
):
    """Return one *structural* Canon V2 match, never a Full grant.

    Scripts may arrive independently, and either mirror may be first. Only
    canonical scripts sharing the exact compressed sponsor pubkey and a
    depth-specific 777-block window can match.
    """
    if (
        type(sponsor_xonly_pubkey) is not str
        or _SUBJECT.fullmatch(sponsor_xonly_pubkey) is None
        or type(sponsor_depth) is not int
        or sponsor_depth < 0
        or type(previous_script_hexes) is not tuple
        or len(previous_script_hexes) > 2048
    ):
        raise ValueError("invalid automatic import matching context")
    incoming = _script_for_subject(new_script_hex, sponsor_xonly_pubkey)
    if incoming is None:
        return None
    leg, sponsor_pubkey = incoming
    matches = []
    for old in previous_script_hexes:
        if old == leg.raw_script_hex:
            continue
        previous = _script_for_subject(old, sponsor_xonly_pubkey)
        if previous is None or previous[1] != sponsor_pubkey:
            continue
        try:
            evidence = validate_canonical_sponsored_scripts_v2(
                leg.raw_script_hex,
                previous[0].raw_script_hex,
                sponsor_compressed_pubkey=sponsor_pubkey,
                sponsor_depth=sponsor_depth,
            )
        except (InvalidCanonicalSponsoredScriptPolicyV2, ValueError, TypeError):
            continue
        matches.append(evidence)
    unique = {item.pair_sha256: item for item in matches}
    if len(unique) > 1:
        raise ValueError("ambiguous mirrored import")
    return next(iter(unique.values()), None)


def _sponsor_depth(db: Session, sponsor_xonly: str) -> int:
    if sponsor_xonly == GENESIS_COMPRESSED_KEY[2:]:
        return 0
    rows = db.execute(
        text(
            "SELECT child_depth FROM public.canonical_multileg_effective_edges_v2 "
            "WHERE child_xonly_pubkey = :subject FOR SHARE"
        ),
        {"subject": sponsor_xonly},
    ).scalars().all()
    if len(rows) != 1 or type(rows[0]) is not int or not 1 <= rows[0] <= 2287:
        raise AutomaticSponsoredImportUnavailable()
    return rows[0]


def record_successful_sponsored_import(
    session_factory,
    *,
    sponsor_session_pubkey: str,
    raw_script_hex: str,
    now: datetime,
) -> AutomaticSponsoredImportResult:
    """Store a post-wallet-import script only for a freshly verified Full sponsor.

    Caller MUST obtain sponsor_session_pubkey from the trusted signed browser
    session, never JSON. Called only after Bitcoin Core confirms import success.
    Database migration must already be applied to a fenced staging database.
    Any failure rolls back the journal transaction and never creates a grant.
    """
    if (
        not callable(session_factory)
        or type(now) is not datetime
        or now.tzinfo is None
        or now.utcoffset() is None
        or now.microsecond
    ):
        raise AutomaticSponsoredImportUnavailable()
    db = None
    try:
        sponsor_xonly = canonical_xonly_pubkey(sponsor_session_pubkey)
        if not isinstance(sponsor_xonly, str) or _SUBJECT.fullmatch(sponsor_xonly) is None:
            raise ValueError
        parsed = _script_for_subject(raw_script_hex, sponsor_xonly)
        if parsed is None:
            return AutomaticSponsoredImportResult("ignored_noncanonical_or_unrelated", None, None)

        db = session_factory()
        if not isinstance(db, Session) or db.get_bind().dialect.name != "postgresql":
            raise ValueError
        with db.begin():
            verified = SqlAlchemyTransactionBoundCurrentFullVerifier(db).verify_in_transaction(
                sponsor_xonly, now=now.astimezone(timezone.utc)
            )
            if verified.subject != sponsor_xonly:
                raise ValueError
            depth = _sponsor_depth(db, sponsor_xonly)
            leg, sponsor_compressed = parsed
            if depth == 0 and sponsor_compressed != GENESIS_COMPRESSED_KEY:
                raise ValueError

            # The subject lock acquired by verify_in_transaction serializes
            # concurrent imports by the same sponsor.
            db.execute(
                text(
                    "INSERT INTO public.canonical_auto_import_scripts_v1 "
                    "(sponsor_xonly_pubkey, script_sha256, script_hex) "
                    "VALUES (:sponsor, :sha, :script) "
                    "ON CONFLICT (sponsor_xonly_pubkey, script_sha256) DO NOTHING"
                ),
                {
                    "sponsor": sponsor_xonly,
                    "sha": leg.script_sha256,
                    "script": leg.raw_script_hex,
                },
            )
            scripts = tuple(
                db.execute(
                    text(
                        "SELECT script_hex FROM public.canonical_auto_import_scripts_v1 "
                        "WHERE sponsor_xonly_pubkey = :sponsor ORDER BY script_sha256 LIMIT 2049"
                    ),
                    {"sponsor": sponsor_xonly},
                ).scalars().all()
            )
            if len(scripts) > 2048:
                raise ValueError
            match = match_imported_sponsored_pair(
                leg.raw_script_hex,
                scripts,
                sponsor_xonly_pubkey=sponsor_xonly,
                sponsor_depth=depth,
            )
            if match is None:
                result = AutomaticSponsoredImportResult("waiting_for_mirror", None, depth + 1)
            else:
                db.execute(
                    text(
                        "INSERT INTO public.canonical_auto_import_pairs_v1 "
                        "(pair_sha256, sponsor_xonly_pubkey, child_xonly_pubkey, "
                        "child_depth, earlier_script_sha256, later_script_sha256) "
                        "VALUES (:pair, :sponsor, :child, :depth, :early, :late) "
                        "ON CONFLICT (pair_sha256) DO NOTHING"
                    ),
                    {
                        "pair": match.pair_sha256,
                        "sponsor": sponsor_xonly,
                        "child": match.child_xonly_pubkey,
                        "depth": match.child_depth,
                        "early": match.earlier_script_sha256,
                        "late": match.later_script_sha256,
                    },
                )
                result = AutomaticSponsoredImportResult(
                    "pending_confirmed_utxo_verification",
                    match.child_xonly_pubkey,
                    match.child_depth,
                )
        return result
    except Exception:
        raise AutomaticSponsoredImportUnavailable() from None
    finally:
        if db is not None:
            db.close()
