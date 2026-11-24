"""Server-owned automatic import -> EFFECTIVE -> short-lived eligibility.

Only committed authenticated import provenance enters this owner. HTTP callers
cannot supply outpoints, Bitcoin clients, chain receipts, clocks or Full flags.
No participant signature is invented, and no account/session is created here.
The caller owns the single PostgreSQL commit. Signed admission stays separate.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import CanonicalGenesisRecordRow
from app.services import canonical_v2_server_bitcoin_collateral as bitcoin
from app.services.action_authorization import IdentityClass
from app.services.automatic_sponsored_authority_v1 import SOURCE, VERSION
from app.services.canonical_genesis_record import (
    GRAPH_ID,
    XONLY_KEY,
    CanonicalGenesisEvaluationState,
    evaluate_canonical_genesis,
)
from app.services.canonical_genesis_record_storage import _from_row as genesis_from_row
from app.services.canonical_multi_outpoint_mirror_v2 import (
    canonical_multi_outpoint_mirror_v2_bytes,
    canonical_multi_outpoint_mirror_v2_sha256,
    create_canonical_multi_outpoint_mirror_v2,
)
from app.services.canonical_sponsored_script_policy_v2 import validate_canonical_sponsored_scripts_v2
from app.services.covenant_relation import CovenantDirection
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.current_entitlement_evidence_storage import (
    SqlAlchemyCurrentEntitlementEvidenceRepository,
    SqlAlchemyTransactionBoundCurrentFullVerifier,
    _lock_subject_for_evidence_change,
)
from app.services.trusted_covenant_observation import TRUSTED_OUTPOINT_SCHEMA, TrustedCovenantOutpoint

TTL = timedelta(seconds=120)
_SUBJECT = re.compile(r"[0-9a-f]{64}\Z")


class AutomaticAdmissionUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("automatic sponsored admission unavailable")


@dataclass(frozen=True, slots=True)
class AutomaticAdmissionResult:
    state: str
    pair_sha256: str
    child_xonly_pubkey: str
    child_depth: int
    eligible: bool
    evidence_id: str | None


def _clock():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _pair(db, pair_sha256):
    if type(pair_sha256) is not str or _SUBJECT.fullmatch(pair_sha256) is None:
        raise AutomaticAdmissionUnavailable()
    rows = (
        db.execute(
            text(
                "SELECT p.*,e.script_hex AS early_script,l.script_hex AS late_script "
                "FROM public.canonical_auto_import_pairs_v1 p "
                "JOIN public.canonical_auto_import_scripts_v1 e ON e.sponsor_xonly_pubkey=p.sponsor_xonly_pubkey AND e.script_sha256=p.earlier_script_sha256 "
                "JOIN public.canonical_auto_import_scripts_v1 l ON l.sponsor_xonly_pubkey=p.sponsor_xonly_pubkey AND l.script_sha256=p.later_script_sha256 "
                "WHERE p.pair_sha256=:pair"
            ),
            {"pair": pair_sha256},
        )
        .mappings()
        .all()
    )
    if len(rows) != 1:
        raise AutomaticAdmissionUnavailable()
    row = rows[0]
    from app.services.mirrored_covenant_pair import parse_covenant_leg

    leg = parse_covenant_leg(row["early_script"])
    sponsor = leg.receiver_pubkey if leg.receiver_xonly_pubkey == row["sponsor_xonly_pubkey"] else leg.sender_pubkey
    policy = validate_canonical_sponsored_scripts_v2(
        row["early_script"],
        row["late_script"],
        sponsor_compressed_pubkey=sponsor,
        sponsor_depth=row["child_depth"] - 1,
    )
    if (
        policy.pair_sha256 != pair_sha256
        or policy.child_xonly_pubkey != row["child_xonly_pubkey"]
        or policy.sponsor_xonly_pubkey != row["sponsor_xonly_pubkey"]
    ):
        raise AutomaticAdmissionUnavailable()
    return row, policy


def _stored_bundle(db, edge):
    raw = json.loads(edge["bundle_json"])
    policy = validate_canonical_sponsored_scripts_v2(
        raw["script_evidence"]["earlier_raw_script_hex"],
        raw["script_evidence"]["later_raw_script_hex"],
        sponsor_compressed_pubkey=raw["script_evidence"]["sponsor_compressed_pubkey"],
        sponsor_depth=raw["script_evidence"]["sponsor_depth"],
    )
    points = tuple(
        TrustedCovenantOutpoint(
            p["schema"],
            p["subject_pubkey"],
            p["counterparty_pubkey"],
            CovenantDirection(p["direction"]),
            p["txid"],
            p["vout"],
            p["amount_sats"],
            p["script_sha256"],
            p["descriptor_sha256"],
        )
        for p in raw["outpoints"]
    )
    bundle = create_canonical_multi_outpoint_mirror_v2(policy, points)
    if (
        canonical_multi_outpoint_mirror_v2_bytes(bundle).decode("ascii") != edge["bundle_json"]
        or canonical_multi_outpoint_mirror_v2_sha256(bundle) != edge["bundle_sha256"]
        or policy.pair_sha256 != edge["pair_sha256"]
    ):
        raise AutomaticAdmissionUnavailable()
    return bundle


def _num(number):
    data = bytearray()
    while number:
        data.append(number & 255)
        number >>= 8
    if not data:
        return b"\x00"
    if data[-1] & 128:
        data.append(0)
    return bytes((len(data),)) + data


def _signed_bundle(db, edge_id):
    from app.services.canonical_admission_edge import cascade_heights

    header = (
        db.execute(
            text(
                "SELECT c.* FROM public.canonical_multileg_admission_candidates_v2 c "
                "JOIN public.canonical_multileg_effective_edges_v2 e USING(proposal_id) WHERE e.proposal_id=:id"
            ),
            {"id": edge_id},
        )
        .mappings()
        .one()
    )
    heights = cascade_heights(header["child_depth"])

    def leg(receiver, sender, first, last):
        return (
            b"\x63"
            + _num(first)
            + b"\xb1\x75\x21"
            + bytes.fromhex(receiver)
            + b"\xac\x67"
            + _num(last)
            + b"\xb1\x75\x21"
            + bytes.fromhex(sender)
            + b"\xac\x68"
        ).hex()

    sponsor, child = header["sponsor_compressed_pubkey"], header["child_compressed_pubkey"]
    policy = validate_canonical_sponsored_scripts_v2(
        leg(sponsor, child, heights[0], heights[1]),
        leg(child, sponsor, heights[1], heights[2]),
        sponsor_compressed_pubkey=sponsor,
        sponsor_depth=header["sponsor_depth"],
    )
    rows = (
        db.execute(
            text("SELECT * FROM public.canonical_multileg_candidate_outpoints_v2 WHERE proposal_id=:id"),
            {"id": edge_id},
        )
        .mappings()
        .all()
    )
    bundle = create_canonical_multi_outpoint_mirror_v2(
        policy,
        tuple(
            TrustedCovenantOutpoint(
                TRUSTED_OUTPOINT_SCHEMA,
                child[2:],
                sponsor[2:],
                CovenantDirection.OUTGOING if p["leg_order"] == "earlier" else CovenantDirection.INCOMING,
                p["txid"],
                p["vout"],
                p["amount_sats"],
                p["script_pubkey_sha256"],
                p["descriptor_sha256"],
            )
            for p in rows
        ),
    )
    if canonical_multi_outpoint_mirror_v2_sha256(bundle) != header["mirror_sha256"]:
        raise AutomaticAdmissionUnavailable()
    return bundle


def _ancestry(db, subject):
    """Read immutable exact parents; never accept a proposal as EFFECTIVE."""
    nodes, seen = [], set()
    while subject != XONLY_KEY:
        if subject in seen or len(nodes) >= 2287:
            raise AutomaticAdmissionUnavailable()
        seen.add(subject)
        rows = (
            db.execute(
                text("SELECT * FROM public.canonical_effective_authority_edges_v1 WHERE child_xonly_pubkey=:subject"),
                {"subject": subject},
            )
            .mappings()
            .all()
        )
        if len(rows) != 1:
            raise AutomaticAdmissionUnavailable()
        node = rows[0]
        if nodes and (
            nodes[-1]["parent_kind"] != node["kind"]
            or nodes[-1]["parent_id"] != node["edge_id"]
            or nodes[-1]["child_depth"] != node["child_depth"] + 1
        ):
            raise AutomaticAdmissionUnavailable()
        nodes.append(node)
        subject = node["sponsor_xonly_pubkey"]
    if nodes and (nodes[-1]["child_depth"] != 1 or nodes[-1]["parent_id"] is not None):
        raise AutomaticAdmissionUnavailable()
    return nodes


def _genesis(db, now):
    # The publisher cannot mutate the registry. The deferred admission trigger
    # locks and rechecks the authoritative genesis when creating a new edge.
    rows = db.scalars(
        select(CanonicalGenesisRecordRow).where(CanonicalGenesisRecordRow.graph_or_protocol_id == GRAPH_ID)
    ).all()
    result = evaluate_canonical_genesis(
        tuple(genesis_from_row(row) for row in rows), graph_or_protocol_id=GRAPH_ID, evaluated_at=now
    )
    if result.state is not CanonicalGenesisEvaluationState.GENESIS_ACTIVE:
        raise AutomaticAdmissionUnavailable()
    return result.selected_effective_record_id


def _validate_ancestry(db, nodes, now):
    genesis_id = _genesis(db, now)
    verifier = SqlAlchemyTransactionBoundCurrentFullVerifier(db)
    subjects = [XONLY_KEY] + [node["child_xonly_pubkey"] for node in reversed(nodes)]
    expiry = min(verifier.verify_in_transaction(subject, now=now).expires_at for subject in subjects)
    for node in reversed(nodes):
        if node["kind"] == "automatic":
            edge = (
                db.execute(
                    text("SELECT * FROM public.canonical_auto_effective_edges_v1 WHERE pair_sha256=:id FOR SHARE"),
                    {"id": node["edge_id"]},
                )
                .mappings()
                .one()
            )
            if (
                edge["genesis_record_id"] != genesis_id
                or db.execute(
                    text("SELECT 1 FROM public.canonical_auto_admission_revocations_v1 WHERE pair_sha256=:id"),
                    {"id": node["edge_id"]},
                ).first()
            ):
                raise AutomaticAdmissionUnavailable()
            bundle = _stored_bundle(db, edge)
        else:
            if node["child_depth"] == 1 and node["genesis_record_id"] != genesis_id:
                raise AutomaticAdmissionUnavailable()
            bundle = _signed_bundle(db, node["edge_id"])
        bitcoin.observe_server_bitcoin_collateral_v2(bundle)
    return genesis_id, expiry


def _evidence(db, pair, scan, *, eligible, valid_until, bundle=None):
    now = _clock()
    created_at = datetime.now(timezone.utc)
    previous_created = db.execute(
        text(
            "SELECT max(created_at) FROM public.current_entitlement_evidence WHERE subject_pubkey=:subject AND observed_at=:at"
        ),
        {"subject": pair["child_xonly_pubkey"], "at": now},
    ).scalar_one()
    if previous_created is not None:
        created_at = max(created_at, previous_created + timedelta(microseconds=1))
    created_at = max(created_at, now)
    receipt = {
        "schema": VERSION,
        "pair": pair["pair_sha256"],
        "eligible": eligible,
        "bundle_sha256": canonical_multi_outpoint_mirror_v2_sha256(bundle) if bundle else None,
        "network": scan.network if scan else None,
        "observed_at": now.isoformat(),
        "valid_until": valid_until.isoformat(),
        "tip": scan.scan.best_block_hash if scan else None,
        "mempool_sequence": scan.scan.mempool_sequence if scan else None,
    }
    receipt_wire = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(receipt_wire.encode("ascii")).hexdigest()
    eid = str(uuid.uuid4())
    evidence = CurrentEntitlementEvidenceRecord(
        eid,
        CONTRACT_VERSION,
        pair["child_xonly_pubkey"],
        IdentityClass.FULL if eligible else IdentityClass.LIMITED,
        eligible,
        SOURCE,
        VERSION,
        digest,
        now,
        valid_until,
        None,
        created_at,
    )
    SqlAlchemyCurrentEntitlementEvidenceRepository.append_in_transaction(db, evidence)
    return evidence, receipt_wire


def _record_observation(db, pair_sha256, evidence, scan, receipt_wire):
    db.execute(
        text(
            "INSERT INTO public.canonical_auto_entitlement_observations_v1 "
            "(evidence_id,pair_sha256,source_evidence_sha256,current_eligible,checked_tip_hash,checked_mempool_sequence,observed_at,valid_until,receipt_json) "
            "VALUES(:eid,:pair,:sha,:eligible,:tip,:sequence,:at,:until,:receipt)"
        ),
        {
            "eid": evidence.evidence_id,
            "receipt": receipt_wire,
            "pair": pair_sha256,
            "sha": evidence.source_evidence_sha256,
            "eligible": evidence.current_full_relation_satisfied,
            "tip": scan.scan.best_block_hash if scan else None,
            "sequence": scan.scan.mempool_sequence if scan else None,
            "at": evidence.observed_at,
            "until": evidence.valid_until,
        },
    )


def _intents(db, pair, now):
    ids = []
    for sha in (pair["earlier_script_sha256"], pair["later_script_sha256"]):
        intent = db.execute(
            text(
                "SELECT intent_id FROM public.canonical_auto_import_intents_v1 "
                "WHERE sponsor_xonly_pubkey=:sponsor AND sponsor_depth=:depth AND script_sha256=:sha "
                "AND authorized_at<=:now AND recover_until>:now ORDER BY authorized_at DESC,intent_id LIMIT 1 FOR SHARE"
            ),
            {
                "sponsor": pair["sponsor_xonly_pubkey"],
                "depth": pair["child_depth"] - 1,
                "sha": sha,
                "now": now,
            },
        ).scalar_one_or_none()
        if intent is None:
            raise AutomaticAdmissionUnavailable()
        ids.append(intent)
    return ids


def admit_automatic_pair_in_transaction(db, pair_sha256, *, discovered_bundle=None):
    """Caller-owned transaction; provisional result until that caller commits.

    discovered_bundle is an INTERNAL server-resolver result, not an HTTP field.
    Every output is checked again by the server-owned observer under the locks.
    Passing a fabricated bundle cannot substitute for the Core check.
    """
    if not isinstance(db, Session) or db.get_bind().dialect.name != "postgresql" or not db.in_transaction():
        raise AutomaticAdmissionUnavailable()
    pair, policy = _pair(db, pair_sha256)
    nodes = _ancestry(db, pair["sponsor_xonly_pubkey"])
    if pair["child_depth"] != (nodes[0]["child_depth"] + 1 if nodes else 1):
        raise AutomaticAdmissionUnavailable()
    subjects = {XONLY_KEY, pair["sponsor_xonly_pubkey"], pair["child_xonly_pubkey"]}
    subjects.update(node["child_xonly_pubkey"] for node in nodes)
    for subject in sorted(subjects):
        _lock_subject_for_evidence_change(db, subject)
    # Re-read after lock waits. History is immutable; new conflicting claims
    # are rejected by the same global child/outpoint keys as signed admission.
    if _ancestry(db, pair["sponsor_xonly_pubkey"]) != nodes:
        raise AutomaticAdmissionUnavailable()
    edge = (
        db.execute(
            text("SELECT * FROM public.canonical_auto_effective_edges_v1 WHERE pair_sha256=:pair FOR SHARE"),
            {"pair": pair_sha256},
        )
        .mappings()
        .one_or_none()
    )
    now = _clock()
    try:
        if db.execute(
            text("SELECT 1 FROM public.canonical_auto_admission_revocations_v1 WHERE pair_sha256=:pair"),
            {"pair": pair_sha256},
        ).first():
            raise AutomaticAdmissionUnavailable()
        genesis_id, parent_expiry = _validate_ancestry(db, nodes, now)
        if edge is None:
            intents = _intents(db, pair, now)
            bundle = (
                discovered_bundle
                if discovered_bundle is not None
                else bitcoin.discover_server_imported_collateral_v1(policy)
            )
        else:
            bundle = _stored_bundle(db, edge)
        if bundle.script_evidence != policy:
            raise AutomaticAdmissionUnavailable()
        scan = bitcoin.observe_server_bitcoin_collateral_v2(bundle)
        now = _clock()
        if not scan.observed_at <= now <= scan.observed_at + timedelta(seconds=60):
            raise AutomaticAdmissionUnavailable()
        # Fresh Current Full after all RPC/lock waits, on this same connection.
        verifier = SqlAlchemyTransactionBoundCurrentFullVerifier(db)
        parent_expiry = min(
            parent_expiry,
            *(
                verifier.verify_in_transaction(subject, now=now).expires_at
                for subject in subjects
                if subject != pair["child_xonly_pubkey"]
            ),
        )
        valid_until = min(now + TTL, parent_expiry)
        if valid_until <= now:
            raise AutomaticAdmissionUnavailable()
    except Exception:
        if edge is None:
            raise AutomaticAdmissionUnavailable() from None
        evidence, receipt = _evidence(db, pair, None, eligible=False, valid_until=_clock() + TTL)
        _record_observation(db, pair_sha256, evidence, None, receipt)
        return AutomaticAdmissionResult(
            "limited",
            pair_sha256,
            pair["child_xonly_pubkey"],
            pair["child_depth"],
            False,
            evidence.evidence_id,
        )
    # Exact successful retry does not manufacture duplicate evidence. A later
    # fresh scan renews eligibility only when the existing interval is ageing.
    latest = (
        db.execute(
            text(
                "SELECT * FROM public.current_entitlement_evidence WHERE subject_pubkey=:subject "
                "ORDER BY observed_at DESC,created_at DESC,evidence_id DESC LIMIT 1"
            ),
            {"subject": pair["child_xonly_pubkey"]},
        )
        .mappings()
        .one_or_none()
    )
    if (
        edge is not None
        and latest
        and latest["evidence_source"] == SOURCE
        and latest["current_full_relation_satisfied"]
        and latest["revoked_at"] is None
        and latest["valid_until"] > now + timedelta(seconds=60)
        and latest["valid_until"] <= parent_expiry
    ):
        return AutomaticAdmissionResult(
            "effective_eligible",
            pair_sha256,
            pair["child_xonly_pubkey"],
            pair["child_depth"],
            True,
            latest["evidence_id"],
        )
    evidence, receipt = _evidence(db, pair, scan, eligible=True, valid_until=valid_until, bundle=bundle)
    if edge is None:
        snapshot = scan.scan.snapshot
        parent = nodes[0] if nodes else None
        db.execute(
            text(
                "INSERT INTO public.canonical_auto_effective_edges_v1 "
                "(pair_sha256,sponsor_xonly_pubkey,child_xonly_pubkey,child_depth,genesis_record_id,"
                "parent_auto_pair_sha256,parent_signed_proposal_id,earlier_intent_id,later_intent_id,bundle_sha256,bundle_json,"
                "initial_evidence_id,network,earlier_sats,later_sats,trust_ceiling_sats,outpoint_count,effective_at) "
                "VALUES(:pair,:sponsor,:child,:depth,:genesis,:parent_auto,:parent_signed,:early,:late,:bundle_sha,:bundle,"
                ":eid,:network,:early_sats,:late_sats,:ceiling,:count,:at)"
            ),
            {
                "pair": pair_sha256,
                "sponsor": pair["sponsor_xonly_pubkey"],
                "child": pair["child_xonly_pubkey"],
                "depth": pair["child_depth"],
                "genesis": genesis_id,
                "parent_auto": parent["edge_id"] if parent and parent["kind"] == "automatic" else None,
                "parent_signed": parent["edge_id"] if parent and parent["kind"] == "multileg" else None,
                "early": intents[0],
                "late": intents[1],
                "bundle_sha": canonical_multi_outpoint_mirror_v2_sha256(bundle),
                "bundle": canonical_multi_outpoint_mirror_v2_bytes(bundle).decode("ascii"),
                "eid": evidence.evidence_id,
                "network": scan.network,
                "early_sats": snapshot.earlier_sats,
                "late_sats": snapshot.later_sats,
                "ceiling": snapshot.trust_ceiling_sats,
                "count": snapshot.outpoint_count,
                "at": now,
            },
        )
        for point in sorted(bundle.outpoints, key=lambda p: (p.txid, p.vout)):
            db.execute(
                text(
                    "INSERT INTO public.canonical_auto_effective_outpoints_v1 "
                    "(pair_sha256,txid,vout,leg_order,amount_sats,script_pubkey_sha256) VALUES(:pair,:txid,:vout,:leg,:sats,:script)"
                ),
                {
                    "pair": pair_sha256,
                    "txid": point.txid,
                    "vout": point.vout,
                    "leg": "earlier" if point.direction is CovenantDirection.OUTGOING else "later",
                    "sats": point.amount_sats,
                    "script": point.script_sha256,
                },
            )
    _record_observation(db, pair_sha256, evidence, scan, receipt)
    return AutomaticAdmissionResult(
        "effective_eligible",
        pair_sha256,
        pair["child_xonly_pubkey"],
        pair["child_depth"],
        True,
        evidence.evidence_id,
    )


def coordinate_automatic_pair(session_factory, pair_sha256):
    """Own exactly one commit around all claims, EFFECTIVE and Full evidence."""
    try:
        with session_factory() as db:
            with db.begin():
                result = admit_automatic_pair_in_transaction(db, pair_sha256)
            return result
    except Exception:
        raise AutomaticAdmissionUnavailable() from None


def refresh_automatic_imports(session_factory, *, maximum=256):
    if type(maximum) is not int or not 1 <= maximum <= 256:
        raise AutomaticAdmissionUnavailable()
    with session_factory() as db, db.begin():
        cursor = db.execute(
            text(
                "SELECT child_depth,pair_sha256 FROM public.canonical_auto_refresh_progress_v1 WHERE singleton FOR UPDATE"
            )
        ).one()
        query = text(
            "SELECT child_depth,pair_sha256 FROM public.canonical_auto_import_pairs_v1 WHERE (child_depth,pair_sha256)>(:depth,:pair) ORDER BY child_depth,pair_sha256 LIMIT :maximum"
        )
        rows = db.execute(query, dict(depth=cursor.child_depth, pair=cursor.pair_sha256, maximum=maximum)).all()
        if not rows:
            rows = db.execute(query, dict(depth=0, pair="", maximum=maximum)).all()
        if rows:
            db.execute(
                text(
                    "UPDATE public.canonical_auto_refresh_progress_v1 SET child_depth=:depth,pair_sha256=:pair WHERE singleton"
                ),
                dict(depth=rows[-1].child_depth, pair=rows[-1].pair_sha256),
            )
    counts = {"effective_eligible": 0, "limited": 0, "pending": 0}
    for _, pair_sha in rows:
        try:
            result = coordinate_automatic_pair(session_factory, pair_sha)
            counts[result.state] += 1
        except AutomaticAdmissionUnavailable:
            counts["pending"] += 1
    return counts
