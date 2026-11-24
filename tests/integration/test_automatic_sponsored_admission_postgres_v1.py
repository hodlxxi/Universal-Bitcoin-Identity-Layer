"""Atomic automatic admission on explicitly disposable PG16; synthetic Core here.

The separate regtest module exercises the same owner against real Bitcoin Core.
None of these fixtures is an assertion about live Alice/Bob authority.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import os
from pathlib import Path
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.models import (
    CanonicalGenesisRecordRow,
    CurrentEntitlementEvidence,
    OAuthBrowserGeneration,
    OAuthClient,
    User,
)
from app.services.action_authorization import IdentityClass
from app.services.automatic_sponsored_admission_v1 import (
    AutomaticAdmissionUnavailable,
    admit_automatic_pair_in_transaction,
    coordinate_automatic_pair,
)
from app.services.automatic_sponsored_import_v1 import (
    prepare_authenticated_sponsored_import,
    record_successful_sponsored_import,
)
from app.services.canonical_genesis_record import GRAPH_ID, XONLY_KEY, parse_canonical_genesis_record
from app.services.canonical_genesis_record_storage import SqlAlchemyCanonicalGenesisRecordRepository
from app.services.current_entitlement import EntitlementDenied, resolve_runtime_current_entitlement
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.current_entitlement_evidence_storage import SqlAlchemyCurrentEntitlementEvidenceRepository
from tests.integration.canon_v2_disposable_pg import disposable_postgres_engine
from tests.unit.test_automatic_sponsored_import_v1 import ALICE, BOB, CHARLIE, EARLY, LATE, _leg

MIGRATIONS = (
    "2026-11-13_canonical_admission_consent_challenge_v2.sql",
    "2026-11-13_canonical_admission_candidate_registry_v2.sql",
    "2026-11-13_canonical_multileg_consent_challenge_v2.sql",
    "2026-11-13_canonical_multileg_admission_candidates_v2.sql",
    "2026-11-13_canonical_multileg_candidate_expiry_v2.sql",
    "2026-11-13_canonical_global_outpoint_claims_v2.sql",
    "2026-11-15_canonical_multileg_issuer_generation_binding_v2.sql",
    "2026-11-14_canonical_multileg_effective_edge_v2.sql",
    "2026-11-15_canonical_auto_sponsored_import_v1.sql",
    "2026-11-15_canonical_auto_sponsored_import_v1_intents.sql",
    "2026-11-15_canonical_auto_sponsored_import_v2_effective.sql",
)


@pytest.fixture(scope="module")
def automatic_engine():
    url = os.environ.get("CANON_V2_TEST_DATABASE_URL")
    if not url or os.environ.get("CANON_V2_DISPOSABLE_PG_ACK") != "1":
        pytest.skip("explicit disposable PostgreSQL required")
    engine = disposable_postgres_engine(url)
    created = False
    try:
        with engine.begin() as connection:
            if connection.execute(text("SELECT count(*) FROM pg_tables WHERE schemaname='public'")).scalar_one():
                raise RuntimeError("disposable_database_must_be_empty")
            for model in (
                User,
                CurrentEntitlementEvidence,
                OAuthClient,
                OAuthBrowserGeneration,
                CanonicalGenesisRecordRow,
            ):
                model.__table__.create(connection)
            for name in MIGRATIONS:
                connection.exec_driver_sql(
                    (Path("migrations") / name).read_text(), execution_options={"no_parameters": True}
                )
        created = True
        yield engine
    finally:
        if created:
            # Only a marked, acknowledged disposable database reached this path.
            with engine.begin() as connection:
                connection.exec_driver_sql("DROP SCHEMA public CASCADE")
                connection.exec_driver_sql("CREATE SCHEMA public")
        engine.dispose()


def stamp():
    return datetime.now(timezone.utc).replace(microsecond=0)


def seed_root(engine):
    record = parse_canonical_genesis_record(Path("docs/data/e923_canonical_genesis_record_v1.json").read_bytes())
    SqlAlchemyCanonicalGenesisRecordRepository(sessionmaker(engine)).append(record)
    now = stamp()
    with Session(engine) as db:
        with db.begin():
            db.add(User(pubkey=XONLY_KEY, is_active=True, metadata_json={}))
            db.add(
                CurrentEntitlementEvidence(
                    evidence_id=str(uuid.uuid4()),
                    contract_version=CONTRACT_VERSION,
                    subject_pubkey=XONLY_KEY,
                    identity_class="full",
                    current_full_relation_satisfied=True,
                    evidence_source="isolated_root_fixture",
                    evidence_version="v1",
                    source_evidence_sha256="f" * 64,
                    observed_at=now - timedelta(seconds=1),
                    valid_until=now + timedelta(seconds=600),
                    created_at=now,
                    revoked_at=None,
                )
            )


@pytest.fixture
def auto_db(automatic_engine, monkeypatch):
    with automatic_engine.begin() as connection:
        connection.exec_driver_sql(
            "TRUNCATE public.users,public.current_entitlement_evidence,public.canonical_genesis_records, "
            "public.canonical_auto_import_scripts_v1,public.canonical_auto_import_pairs_v1,public.canonical_auto_import_intents_v1, "
            "public.canonical_authority_child_claims_v1 CASCADE"
        )
    seed_root(automatic_engine)
    import app.database as database

    monkeypatch.setattr(database, "get_session", sessionmaker(automatic_engine))
    return automatic_engine


class Core:
    """Node-shaped test double only, never a detached caller-provided grant."""

    def __init__(self):
        self.coins = {}
        self.spent = set()
        self.unconfirmed = False
        self.tip = "a" * 64
        self.sequence = 1
        self.height = 100

    def fund(self, early, late, amounts=((6666,), (6666,))):
        for leg, values in zip((early, late), amounts):
            script = "0020" + hashlib.sha256(bytes.fromhex(leg)).hexdigest()
            for value in values:
                txid = hashlib.sha256((str(len(self.coins)) + script).encode()).hexdigest()
                self.coins[(txid, 0)] = {
                    "txid": txid,
                    "vout": 0,
                    "scriptPubKey": script,
                    "amount": Decimal(value) / 100_000_000,
                    "height": 1,
                }

    def getblockchaininfo(self):
        return {
            "chain": "regtest",
            "blocks": self.height,
            "headers": self.height,
            "bestblockhash": self.tip,
            "initialblockdownload": False,
        }

    def getblockcount(self):
        return self.height

    def getbestblockhash(self):
        return self.tip

    def getrawmempool(self, verbose, sequence):
        assert verbose is False and sequence is True
        return {"txids": [], "mempool_sequence": self.sequence}

    def scantxoutset(self, action, descriptors):
        assert action == "start"
        scripts = {d["desc"][4:-1] for d in descriptors}
        return {
            "success": True,
            "height": self.height,
            "bestblock": self.tip,
            "unspents": [v for k, v in self.coins.items() if v["scriptPubKey"] in scripts and k not in self.spent],
        }

    def gettxout(self, txid, vout, include_mempool):
        assert include_mempool is True
        coin = self.coins.get((txid, vout))
        if coin is None or (txid, vout) in self.spent:
            return None
        return {
            "bestblock": self.tip,
            "confirmations": 0 if self.unconfirmed else 10,
            "value": coin["amount"],
            "scriptPubKey": {"hex": coin["scriptPubKey"]},
        }


@pytest.fixture
def core(monkeypatch):
    from app.services import canonical_v2_server_bitcoin_collateral as bitcoin

    node = Core()
    monkeypatch.setenv("CANON_V2_BITCOIN_CHAIN", "regtest")
    monkeypatch.setattr(bitcoin, "_new_rpc", lambda: node)
    return node


def imported(engine, sponsor=ALICE, scripts=(EARLY, LATE)):
    result = None
    for script in scripts:
        prepare_authenticated_sponsored_import(
            sessionmaker(engine), sponsor_session_pubkey=sponsor, raw_script_hex=script, now=stamp()
        )
        result = record_successful_sponsored_import(
            sessionmaker(engine), sponsor_session_pubkey=sponsor, raw_script_hex=script, now=stamp()
        )
    return result.pair_sha256


def counts(engine):
    with engine.connect() as db:
        return tuple(
            db.execute(text("SELECT count(*) FROM public." + name)).scalar_one()
            for name in (
                "canonical_auto_effective_edges_v1",
                "canonical_auto_effective_outpoints_v1",
                "canonical_authority_child_claims_v1",
                "canonical_global_outpoint_claims_v2",
                "canonical_auto_entitlement_observations_v1",
            )
        )


def test_atomic_confirmed_admission_precedes_account_access_and_retry_is_exact(auto_db, core):
    core.fund(EARLY, LATE)
    pair = imported(auto_db)
    first = coordinate_automatic_pair(sessionmaker(auto_db), pair)
    assert first.eligible and counts(auto_db) == (1, 2, 1, 2, 1)
    with pytest.raises(EntitlementDenied):
        resolve_runtime_current_entitlement(BOB[2:])
    with Session(auto_db) as db, db.begin():
        db.add(User(pubkey=BOB[2:], is_active=True, metadata_json={}))
    assert resolve_runtime_current_entitlement(BOB[2:]).current_full_relation_satisfied
    assert coordinate_automatic_pair(sessionmaker(auto_db), pair) == first
    assert counts(auto_db) == (1, 2, 1, 2, 1)


def test_rollback_rewinds_full_edge_and_all_global_claims(auto_db, core):
    core.fund(EARLY, LATE)
    pair = imported(auto_db)
    with pytest.raises(RuntimeError), Session(auto_db) as db, db.begin():
        result = admit_automatic_pair_in_transaction(db, pair)
        assert result.eligible
        raise RuntimeError("synthetic owner rollback")
    assert counts(auto_db) == (0, 0, 0, 0, 0)
    with auto_db.connect() as db:
        assert db.execute(text("SELECT count(*) FROM current_entitlement_evidence")).scalar_one() == 1


def test_concurrent_same_claim_is_idempotent(auto_db, core):
    core.fund(EARLY, LATE)
    pair = imported(auto_db)
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = tuple(executor.map(lambda _: coordinate_automatic_pair(sessionmaker(auto_db), pair), range(3)))
    assert all(r == results[0] for r in results) and counts(auto_db) == (1, 2, 1, 2, 1)


def test_bob_sponsors_charlie_through_same_import_flow_at_depth_two(auto_db, core):
    core.fund(EARLY, LATE)
    parent = coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db))
    with Session(auto_db) as db, db.begin():
        db.add(User(pubkey=BOB[2:], is_active=True, metadata_json={}))
    early = _leg(BOB, CHARLIE, 1776223, 1777000)
    late = _leg(CHARLIE, BOB, 1777000, 1777777)
    core.fund(early, late)
    child = coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db, BOB, (early, late)))
    assert parent.eligible and child.eligible and child.child_depth == 2
    assert counts(auto_db) == (2, 4, 2, 4, 2)


def test_spend_invalidates_current_full_without_erasing_effective_history(auto_db, core):
    core.fund(EARLY, LATE)
    pair = imported(auto_db)
    coordinate_automatic_pair(sessionmaker(auto_db), pair)
    with Session(auto_db) as db, db.begin():
        db.add(User(pubkey=BOB[2:], is_active=True, metadata_json={}))
    core.spent.add(next(iter(core.coins)))
    result = coordinate_automatic_pair(sessionmaker(auto_db), pair)
    assert not result.eligible
    assert not resolve_runtime_current_entitlement(BOB[2:]).current_full_relation_satisfied
    assert counts(auto_db) == (1, 2, 1, 2, 2)


def test_unconfirmed_pair_never_grants_full(auto_db, core):
    core.fund(EARLY, LATE)
    core.unconfirmed = True
    with pytest.raises(AutomaticAdmissionUnavailable):
        coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db))
    assert counts(auto_db) == (0, 0, 0, 0, 0)


def test_evidence_append_participates_in_callers_rollback(auto_db):
    now = stamp()
    item = CurrentEntitlementEvidenceRecord(
        str(uuid.uuid4()),
        CONTRACT_VERSION,
        BOB[2:],
        IdentityClass.LIMITED,
        False,
        "isolated_atomic_writer",
        "v1",
        "e" * 64,
        now,
        now + timedelta(seconds=60),
        None,
        now,
    )
    with pytest.raises(RuntimeError), Session(auto_db) as db, db.begin():
        SqlAlchemyCurrentEntitlementEvidenceRepository.append_in_transaction(db, item)
        raise RuntimeError("synthetic rollback")
    with auto_db.connect() as db:
        assert (
            db.execute(
                text("SELECT count(*) FROM current_entitlement_evidence WHERE evidence_id=:id"),
                {"id": item.evidence_id},
            ).scalar_one()
            == 0
        )


def test_full_expires_under_the_existing_authority_resolver(auto_db, core):
    core.fund(EARLY, LATE)
    result = coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db))
    with Session(auto_db) as db, db.begin():
        db.add(User(pubkey=BOB[2:], is_active=True, metadata_json={}))
    with auto_db.connect() as db:
        deadline = db.execute(
            text("SELECT valid_until FROM current_entitlement_evidence WHERE evidence_id=:id"),
            {"id": result.evidence_id},
        ).scalar_one()
    assert not resolve_runtime_current_entitlement(BOB[2:], clock=lambda: deadline).current_full_relation_satisfied
    assert counts(auto_db) == (1, 2, 1, 2, 1)


def test_competing_funded_sponsors_cannot_reassign_the_same_child(auto_db, core):
    dave = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    core.fund(EARLY, LATE)
    coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db))
    alice_carol = (_leg(ALICE, CHARLIE, 1777000, 1777777), _leg(CHARLIE, ALICE, 1777777, 1778554))
    core.fund(*alice_carol)
    coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db, ALICE, alice_carol))
    with Session(auto_db) as db, db.begin():
        db.add_all(
            [
                User(pubkey=BOB[2:], is_active=True, metadata_json={}),
                User(pubkey=CHARLIE[2:], is_active=True, metadata_json={}),
            ]
        )
    candidates = []
    for sponsor in (BOB, CHARLIE):
        scripts = (_leg(sponsor, dave, 1776223, 1777000), _leg(dave, sponsor, 1777000, 1777777))
        core.fund(*scripts)
        candidates.append(imported(auto_db, sponsor, scripts))

    def attempt(pair):
        try:
            return coordinate_automatic_pair(sessionmaker(auto_db), pair)
        except AutomaticAdmissionUnavailable:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(attempt, candidates))
    assert sum(result is not None for result in results) == 1
    assert counts(auto_db) == (3, 6, 3, 6, 3)
    with auto_db.connect() as db:
        assert (
            db.execute(
                text("SELECT count(*) FROM current_entitlement_evidence WHERE subject_pubkey=:child"),
                {"child": dave[2:]},
            ).scalar_one()
            == 1
        )


def test_conflicting_outpoint_rolls_back_the_second_child(auto_db, core):
    core.fund(EARLY, LATE)
    sessions = sessionmaker(auto_db)
    coordinate_automatic_pair(sessions, imported(auto_db))
    already_claimed = next(iter(core.coins))

    scripts = (_leg(ALICE, CHARLIE, 1777000, 1777777), _leg(CHARLIE, ALICE, 1777777, 1778554))
    core.fund(*scripts)
    conflicting, _ = tuple(core.coins)[-2:]
    # A contradictory node observation cannot release an existing global claim.
    core.coins[already_claimed] = {
        **core.coins.pop(conflicting),
        "txid": already_claimed[0],
        "vout": already_claimed[1],
    }
    pair = imported(auto_db, ALICE, scripts)
    with pytest.raises(DBAPIError) as collision:
        with sessions() as db, db.begin():
            admit_automatic_pair_in_transaction(db, pair)
    assert collision.value.orig.pgcode == "23505"
    assert counts(auto_db) == (1, 2, 1, 2, 1)


def test_multileg_totals_and_exact_minimum_are_bound_in_atomic_receipt(auto_db, core):
    core.fund(EARLY, LATE, amounts=((3000, 4000), (2000, 3000, 4000)))
    result = coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db))
    with auto_db.connect() as db:
        row = db.execute(
            text(
                "SELECT earlier_sats,later_sats,trust_ceiling_sats,outpoint_count FROM canonical_auto_effective_edges_v1"
            )
        ).one()
        assert tuple(row) == (7000, 9000, 7000, 5)
        assert (
            db.execute(
                text(
                    "SELECT receipt_json::jsonb->>'bundle_sha256' FROM canonical_auto_entitlement_observations_v1 WHERE evidence_id=:id"
                ),
                {"id": result.evidence_id},
            ).scalar_one()
            is not None
        )


@pytest.mark.parametrize(
    "table",
    [
        "canonical_auto_effective_edges_v1",
        "canonical_auto_effective_outpoints_v1",
        "canonical_auto_entitlement_observations_v1",
        "canonical_authority_child_claims_v1",
        "canonical_global_outpoint_claims_v2",
    ],
)
def test_effective_history_and_active_claims_cannot_be_deleted(auto_db, core, table):
    core.fund(EARLY, LATE)
    coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db))
    with pytest.raises(DBAPIError), auto_db.begin() as db:
        db.execute(text("DELETE FROM public." + table))
    assert counts(auto_db) == (1, 2, 1, 2, 1)


def test_revoked_parent_fails_closed_for_child_and_directory_population(auto_db, core):
    core.fund(EARLY, LATE)
    parent = coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db))
    with Session(auto_db) as db, db.begin():
        db.add(User(pubkey=BOB[2:], is_active=True, metadata_json={}))
    scripts = (_leg(BOB, CHARLIE, 1776223, 1777000), _leg(CHARLIE, BOB, 1777000, 1777777))
    core.fund(*scripts)
    coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db, BOB, scripts))
    with Session(auto_db) as db, db.begin():
        db.add(User(pubkey=CHARLIE[2:], is_active=True, metadata_json={}))
        db.execute(
            text("INSERT INTO canonical_auto_admission_revocations_v1 VALUES(:pair,:at,'sponsorship_revoked')"),
            {"pair": parent.pair_sha256, "at": stamp()},
        )
    assert not resolve_runtime_current_entitlement(BOB[2:]).current_full_relation_satisfied
    assert not resolve_runtime_current_entitlement(CHARLIE[2:]).current_full_relation_satisfied
    population = SqlAlchemyCurrentEntitlementEvidenceRepository(sessionmaker(auto_db)).get_latest_population(10)
    assert all(
        not item.current_full_relation_satisfied
        for item in population.records
        if item.subject_pubkey in (BOB[2:], CHARLIE[2:])
    )


def test_expired_pending_import_provenance_cannot_grant(auto_db, core, monkeypatch):
    import app.services.automatic_sponsored_admission_v1 as owner

    core.fund(EARLY, LATE)
    pair = imported(auto_db)
    monkeypatch.setattr(owner, "_clock", lambda: stamp() + timedelta(days=8))
    with pytest.raises(AutomaticAdmissionUnavailable):
        coordinate_automatic_pair(sessionmaker(auto_db), pair)
    assert counts(auto_db) == (0, 0, 0, 0, 0)


def test_nonowner_runtime_grants_can_admit_without_mutation_or_ddl(auto_db, core):
    core.fund(EARLY, LATE)
    pair = imported(auto_db)
    with auto_db.begin() as db:
        db.execute(text("CREATE ROLE hodlxxi_auto_test_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE"))
        db.execute(text("GRANT USAGE ON SCHEMA public TO hodlxxi_auto_test_runtime"))
        db.execute(text("GRANT SELECT ON ALL TABLES IN SCHEMA public TO hodlxxi_auto_test_runtime"))
        db.execute(
            text(
                "GRANT INSERT ON current_entitlement_evidence,canonical_auto_effective_edges_v1,canonical_auto_effective_outpoints_v1,canonical_auto_entitlement_observations_v1 TO hodlxxi_auto_test_runtime"
            )
        )
        # SELECT FOR SHARE requires UPDATE privilege. Immutable triggers still
        # forbid mutation; indexes/claims are owned by the migration owner.
        db.execute(
            text(
                "GRANT UPDATE(id) ON users TO hodlxxi_auto_test_runtime; GRANT UPDATE(record_id) ON canonical_genesis_records TO hodlxxi_auto_test_runtime; GRANT UPDATE(pair_sha256) ON canonical_auto_effective_edges_v1 TO hodlxxi_auto_test_runtime; GRANT UPDATE(intent_id) ON canonical_auto_import_intents_v1 TO hodlxxi_auto_test_runtime"
            )
        )
        db.execute(text("GRANT UPDATE(evidence_id) ON current_entitlement_evidence TO hodlxxi_auto_test_runtime"))
    try:
        with Session(auto_db) as db, db.begin():
            db.execute(text("SET LOCAL ROLE hodlxxi_auto_test_runtime"))
            assert admit_automatic_pair_in_transaction(db, pair).eligible
        for command in (
            "TRUNCATE canonical_auto_effective_edges_v1 CASCADE",
            "DROP TABLE canonical_auto_effective_outpoints_v1",
            "DELETE FROM canonical_authority_child_claims_v1",
            "INSERT INTO canonical_auto_admission_revocations_v1 SELECT pair_sha256,now(),'sponsorship_revoked' FROM canonical_auto_effective_edges_v1",
        ):
            with pytest.raises(DBAPIError), auto_db.begin() as db:
                db.execute(text("SET LOCAL ROLE hodlxxi_auto_test_runtime"))
                db.execute(text(command))
    finally:
        with auto_db.begin() as db:
            db.execute(text("DROP OWNED BY hodlxxi_auto_test_runtime"))
            db.execute(text("DROP ROLE hodlxxi_auto_test_runtime"))


def test_bounded_refresh_cursor_visits_pending_pairs_then_wraps(auto_db, core):
    from app.services.automatic_sponsored_admission_v1 import refresh_automatic_imports

    first = imported(auto_db)
    scripts = (_leg(ALICE, CHARLIE, 1777000, 1777777), _leg(CHARLIE, ALICE, 1777777, 1778554))
    second = imported(auto_db, ALICE, scripts)
    visited = []
    for _ in range(3):
        assert refresh_automatic_imports(sessionmaker(auto_db), maximum=1) == dict(
            effective_eligible=0, limited=0, pending=1
        )
        with auto_db.connect() as db:
            visited.append(db.execute(text("SELECT pair_sha256 FROM canonical_auto_refresh_progress_v1")).scalar_one())
    assert visited[0] != visited[1] and visited[0] == visited[2]
    assert set(visited) == {first, second}


def test_three_generations_publish_current_authority(auto_db, core, client):
    dave = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

    def authority(key):
        response = client.get(f"/agent/authority/current/{key[2:]}.json")
        assert response.status_code == 200
        assertion = response.get_json()
        assert assertion["subject"] == key[2:]
        assert assertion["valid"] is True
        return assertion["identity_class"], assertion["current_full_relation_satisfied"]

    assert authority(ALICE) == ("full", True)
    for depth, (sponsor, child) in enumerate(((ALICE, BOB), (BOB, CHARLIE), (CHARLIE, dave)), start=1):
        with Session(auto_db) as db, db.begin():
            db.add(User(pubkey=child[2:], is_active=True, metadata_json={}))
        assert authority(child) == ("limited", False)
        middle = 1777777 - 777 * (depth - 1)
        scripts = (_leg(sponsor, child, middle - 777, middle), _leg(child, sponsor, middle, middle + 777))
        pair = imported(auto_db, sponsor, scripts)
        assert authority(child) == ("limited", False)
        core.fund(*scripts)
        result = coordinate_automatic_pair(sessionmaker(auto_db), pair)
        assert result.eligible and result.child_depth == depth
        assert authority(child) == ("full", True)
    with Session(auto_db) as db, db.begin():
        db.execute(
            text(
                "INSERT INTO canonical_auto_admission_revocations_v1 (pair_sha256,revoked_at,reason) "
                "SELECT pair_sha256,:at,'sponsorship_revoked' FROM canonical_auto_effective_edges_v1 WHERE child_depth=1"
            ),
            {"at": stamp()},
        )
    for descendant in (BOB, CHARLIE, dave):
        assert authority(descendant) == ("limited", False)


def test_verified_legacy_and_nostr_share_one_admitted_subject(auto_db, core, app, monkeypatch):
    import base64
    import json

    from coincurve import PrivateKey, PublicKey

    from app.blueprints import auth
    from app.utils import derive_legacy_address_from_pubkey

    key = PrivateKey()
    compressed = key.public_key.format().hex()
    subject = compressed[2:]

    def message_hash(challenge):
        data = challenge.encode()
        assert len(data) < 253
        wire = b"\x18Bitcoin Signed Message:\n" + bytes([len(data)]) + data
        return hashlib.sha256(hashlib.sha256(wire).digest()).digest()

    class LocalVerifier:
        def verifymessage(self, address, signature, challenge):
            compact = base64.b64decode(signature, validate=True)
            sig = compact[1:] + bytes([compact[0] - 31])
            public = PublicKey.from_signature_and_message(sig, message_hash(challenge), hasher=None)
            return derive_legacy_address_from_pubkey(public.format().hex()) == address

    monkeypatch.setattr(auth, "get_rpc_connection", LocalVerifier)
    for expected in ("limited", "full"):
        legacy = app.test_client()
        assert legacy.get("/login").status_code == 200
        with legacy.session_transaction() as cookie:
            challenge = cookie["challenge"]
        sig = key.sign_recoverable(message_hash(challenge), hasher=None)
        signature = base64.b64encode(bytes([31 + sig[-1]]) + sig[:-1]).decode()
        response = legacy.post(
            "/verify_signature", json={"pubkey": compressed, "signature": signature, "challenge": challenge}
        )
        assert response.status_code == 200 and response.get_json()["access_level"] == expected

        nostr = app.test_client()
        claim = nostr.post("/api/challenge", json={"pubkey": subject, "method": "nostr"}).get_json()
        now = int(stamp().timestamp())
        tags = [["challenge", claim["challenge"]]]
        digest = hashlib.sha256(json.dumps([0, subject, now, 22242, tags, ""], separators=(",", ":")).encode()).digest()
        event = {
            "id": digest.hex(),
            "pubkey": subject,
            "created_at": now,
            "kind": 22242,
            "tags": tags,
            "content": "",
            "sig": key.sign_schnorr(digest).hex(),
        }
        response = nostr.post("/api/verify", json={"challenge_id": claim["challenge_id"], "nostr_event": event})
        assert response.status_code == 200 and response.get_json()["access_level"] == expected
        for browser in (legacy, nostr):
            response = browser.get("/home")
            assert response.status_code == 200
            assert f'data-access-level="{expected}"' in response.get_data(as_text=True)

        if expected == "limited":
            legs = (_leg(ALICE, compressed, 1777000, 1777777), _leg(compressed, ALICE, 1777777, 1778554))
            core.fund(*legs)
            assert coordinate_automatic_pair(sessionmaker(auto_db), imported(auto_db, ALICE, legs)).eligible
