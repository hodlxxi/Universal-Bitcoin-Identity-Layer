"""Automatic sponsored import correlation, without a second signature ceremony.

This is the *actual* post-import ingress. It records authenticated Current-Full
sponsor scripts, correlates a canonical pair in either import order, and
persists a pending admission candidate. No pair, balance, descriptor or
PENDING record can grant Current Full. A separate verified, atomic server-owned
UTXO and effective-admission coordinator must consume the candidate.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

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
    rows = (
        db.execute(
            text(
                "SELECT child_depth FROM public.canonical_multileg_effective_edges_v2 "
                "WHERE child_xonly_pubkey = :subject FOR SHARE"
            ),
            {"subject": sponsor_xonly},
        )
        .scalars()
        .all()
    )
    if len(rows) != 1 or type(rows[0]) is not int or not 1 <= rows[0] <= 2287:
        raise AutomaticSponsoredImportUnavailable()
    return rows[0]


def prepare_authenticated_sponsored_import(
    session_factory, *, sponsor_session_pubkey: str, raw_script_hex: str, now: datetime
) -> str | None:
    """Commit sponsor provenance BEFORE Core; an intent never asserts success.

    Only the authenticated route supplies the session key. Recovery must use
    this durable record, never a wallet label or a caller-supplied sponsor.
    Exact retries reuse a live intent under the Current-Full subject lock.
    """
    db = None
    try:
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None or now.microsecond:
            raise ValueError
        now = now.astimezone(timezone.utc)
        sponsor = canonical_xonly_pubkey(sponsor_session_pubkey)
        if not isinstance(sponsor, str) or _SUBJECT.fullmatch(sponsor) is None:
            raise ValueError
        parsed = _script_for_subject(raw_script_hex, sponsor)
        if parsed is None:
            return None
        leg, compressed = parsed
        db = session_factory()
        if not isinstance(db, Session) or db.get_bind().dialect.name != "postgresql":
            raise ValueError
        with db.begin():
            proof = SqlAlchemyTransactionBoundCurrentFullVerifier(db).verify_with_evidence_in_transaction(
                sponsor, now=now
            )
            if proof.verified_entitlement.subject != sponsor:
                raise ValueError
            depth = _sponsor_depth(db, sponsor)
            if depth == 0 and compressed != GENESIS_COMPRESSED_KEY:
                raise ValueError
            params = {"sponsor": sponsor, "sha": leg.script_sha256, "now": now, "depth": depth}
            existing = db.execute(
                text(
                    "SELECT intent_id FROM public.canonical_auto_import_intents_v1 "
                    "WHERE sponsor_xonly_pubkey=:sponsor AND script_sha256=:sha "
                    "AND sponsor_depth=:depth AND authorized_at<=:now AND recover_until>:now "
                    "ORDER BY authorized_at DESC, intent_id LIMIT 1"
                ),
                params,
            ).scalar_one_or_none()
            if existing is not None:
                return str(existing)
            count = db.execute(
                text(
                    "SELECT count(*) FROM public.canonical_auto_import_intents_v1 "
                    "WHERE sponsor_xonly_pubkey=:sponsor AND recover_until>:now"
                ),
                params,
            ).scalar_one()
            if count >= 2048:
                raise ValueError
            intent = str(uuid.uuid4())
            db.execute(
                text(
                    "INSERT INTO public.canonical_auto_import_intents_v1 "
                    "(intent_id,sponsor_xonly_pubkey,script_sha256,script_hex,sponsor_depth,"
                    "sponsor_evidence_id,sponsor_evidence_sha256,authorized_at,recover_until) "
                    "VALUES (:id,:sponsor,:sha,:script,:depth,:eid,:evidence,:now,:until)"
                ),
                {
                    **params,
                    "id": intent,
                    "script": leg.raw_script_hex,
                    "eid": proof.evidence_id,
                    "evidence": proof.source_evidence_sha256,
                    "until": now + timedelta(days=7),
                },
            )
        return intent
    except Exception:
        raise AutomaticSponsoredImportUnavailable() from None
    finally:
        if db is not None:
            db.close()


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

            # A Core import or an imported wallet label cannot invent a sponsor.
            # The intent was committed by the authenticated route before RPC.
            provenance = db.execute(
                text(
                    "SELECT intent_id FROM public.canonical_auto_import_intents_v1 "
                    "WHERE sponsor_xonly_pubkey=:sponsor AND script_sha256=:sha "
                    "AND script_hex=:script AND sponsor_depth=:depth "
                    "AND authorized_at<=:now AND recover_until>:now LIMIT 1"
                ),
                {
                    "sponsor": sponsor_xonly,
                    "sha": leg.script_sha256,
                    "script": leg.raw_script_hex,
                    "depth": depth,
                    "now": now,
                },
            ).scalar_one_or_none()
            if provenance is None:
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
                )
                .scalars()
                .all()
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


def recover_authenticated_sponsored_imports(
    session_factory, *, trusted_wallet_rpc, now: datetime, maximum: int = 100
) -> tuple[AutomaticSponsoredImportResult, ...]:
    """Recover post-Core journal failures from durable authenticated intents.

    The server-owned watch-only wallet must contain BOTH exact descriptors.
    A wallet label, balance, script discovered without an intent, or an expired
    intent cannot supply sponsorship. Each write rechecks current Full and depth.
    This bounded recovery stage grants no authority; funding remains independent.
    """
    try:
        if (
            type(now) is not datetime
            or now.tzinfo is None
            or now.utcoffset() is None
            or now.microsecond
            or type(maximum) is not int
            or not 1 <= maximum <= 256
        ):
            raise ValueError
        info = trusted_wallet_rpc.getwalletinfo()
        if (
            type(info) is not dict
            or info.get("private_keys_enabled") is not False
            or info.get("descriptors") is not True
        ):
            raise ValueError
        imported = trusted_wallet_rpc.listdescriptors(False)
        if (
            type(imported) is not dict
            or type(imported.get("descriptors")) is not list
            or len(imported["descriptors"]) > 8192
        ):
            raise ValueError
        descriptors = set()
        for item in imported["descriptors"]:
            if type(item) is not dict or type(item.get("desc")) is not str or len(item["desc"]) > 4096:
                raise ValueError
            descriptors.add(item["desc"])
        with session_factory() as db:
            if not isinstance(db, Session) or db.get_bind().dialect.name != "postgresql":
                raise ValueError
            rows = (
                db.execute(
                    text(
                        "SELECT DISTINCT i.sponsor_xonly_pubkey,i.script_hex FROM public.canonical_auto_import_intents_v1 i "
                        "WHERE i.authorized_at<=:now AND i.recover_until>:now AND NOT EXISTS ("
                        "SELECT 1 FROM public.canonical_auto_import_scripts_v1 s WHERE "
                        "s.sponsor_xonly_pubkey=i.sponsor_xonly_pubkey AND s.script_sha256=i.script_sha256) "
                        "ORDER BY i.sponsor_xonly_pubkey,i.script_hex LIMIT :maximum"
                    ),
                    {"now": now, "maximum": maximum},
                )
                .mappings()
                .all()
            )
        results = []
        for row in rows:
            script = row["script_hex"]
            raw = trusted_wallet_rpc.getdescriptorinfo(f"raw({script})")["descriptor"]
            if raw not in descriptors:
                continue
            segwit = trusted_wallet_rpc.decodescript(script).get("segwit", {})
            # Exact native P2WSH is derived locally, never from wallet labels.
            expected = "0020" + hashlib.sha256(bytes.fromhex(script)).hexdigest()
            if segwit.get("hex") != expected or type(segwit.get("address")) is not str:
                raise ValueError
            address_descriptor = trusted_wallet_rpc.getdescriptorinfo(f"addr({segwit['address']})")["descriptor"]
            if address_descriptor not in descriptors:
                continue
            results.append(
                record_successful_sponsored_import(
                    session_factory, sponsor_session_pubkey=row["sponsor_xonly_pubkey"], raw_script_hex=script, now=now
                )
            )
        return tuple(results)
    except Exception:
        raise AutomaticSponsoredImportUnavailable() from None
