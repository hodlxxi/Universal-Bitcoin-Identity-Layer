"""Disposable PostgreSQL tests: a UTXO cannot be claimed in both V2 formats.

All signers, Bitcoin observations and Current Full records are synthetic fixtures.
These tests NEVER establish EFFECTIVE/Full or authorize production migration.
"""

from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.services.canonical_admission_candidate_registry_v2 import (
    CanonicalAdmissionCandidateUnavailableV2,
)
from app.services.canonical_multi_outpoint_mirror_v2 import (
    create_canonical_multi_outpoint_mirror_v2,
)
from app.services.canonical_multileg_candidate_registry_v2 import (
    CanonicalMultiLegCandidateUnavailableV2,
)
from app.services.covenant_relation import CovenantDirection
from tests.integration.test_canonical_admission_candidate_postgres_v2 import (
    _issue as issue_strict,
    _reserve as reserve_strict,
    _seed_full,
)
from tests.integration.test_canonical_multileg_candidate_expiration_postgres_v2 import (
    OLD,
    OLD_ID,
    _expire,
    _full_at,
    _issue_at,
    _propose,
    _reserve_at,
)
from tests.integration.test_canonical_multileg_candidate_postgres_v2 import (
    _issue as issue_multi,
    _nonce_consumed,
    _reserve as reserve_multi,
    postgres_engine as multileg_postgres_engine,
)
from tests.unit.test_canonical_admission_edge_v2 import _root
from tests.unit.test_canonical_admission_proposal_v2 import ALICE, BOB, NOW
from tests.unit.test_canonical_multi_outpoint_admission_proposal_v2 import _new
from tests.unit.test_canonical_multi_outpoint_mirror_v2 import _bundle

GLOBAL = "public.canonical_global_outpoint_claims_v2"
LIVE = "public.canonical_multileg_live_outpoint_claims_v2"
STRICT_OUTPOINTS = "public.canonical_admission_candidate_outpoints_v2"
MULTI_OUTPOINTS = "public.canonical_multileg_candidate_outpoints_v2"
MIGRATIONS = (
    Path("migrations/2026-11-13_canonical_admission_consent_challenge_v2.sql"),
    Path("migrations/2026-11-13_canonical_admission_candidate_registry_v2.sql"),
    Path("migrations/2026-11-13_canonical_global_outpoint_claims_v2.sql"),
)
FUNCTIONS = (
    "claim_global_strict_two_outpoint_v2",
    "claim_global_multileg_outpoint_v2",
    "guard_global_outpoint_claim_v2",
    "release_global_multileg_outpoint_v2",
    "validate_global_multileg_release_v2",
)


@pytest.fixture(scope="module")
def shared_pg(multileg_postgres_engine):
    """Inherit the explicit loopback-only, disposable PG16 guard from #584."""
    engine = multileg_postgres_engine
    with engine.begin() as connection:
        for migration in MIGRATIONS:
            connection.exec_driver_sql(migration.read_text())
    yield engine
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "DROP TRIGGER trg_cgoc_release_audit " "ON public.canonical_multileg_live_outpoint_claims_v2"
        )
        connection.exec_driver_sql(
            "DROP TRIGGER trg_cgoc_release_multileg " "ON public.canonical_multileg_live_outpoint_claims_v2"
        )
        connection.exec_driver_sql(
            "DROP TRIGGER trg_cgoc_claim_multileg " "ON public.canonical_multileg_live_outpoint_claims_v2"
        )
        connection.exec_driver_sql(f"DROP TABLE {GLOBAL}")
        connection.exec_driver_sql(f"DROP TABLE {STRICT_OUTPOINTS}")
        connection.exec_driver_sql("DROP TABLE public.canonical_admission_candidates_v2")
        connection.exec_driver_sql("DROP TABLE public.canonical_admission_consent_challenges_v2")
        for name in FUNCTIONS:
            connection.exec_driver_sql(f"DROP FUNCTION public.{name}()")
        connection.exec_driver_sql("DROP FUNCTION public.guard_canonical_admission_candidate_v2()")
        connection.exec_driver_sql("DROP FUNCTION public.guard_canonical_admission_consent_challenge_v2()")


@pytest.fixture
def db(shared_pg):
    """TRUNCATE CASCADE is confined to this completely disposable CI database."""
    with shared_pg.begin() as connection:
        connection.exec_driver_sql(
            "TRUNCATE public.canonical_admission_candidate_outpoints_v2, "
            "public.canonical_admission_candidates_v2, "
            "public.canonical_admission_consent_challenges_v2, "
            "public.canonical_multileg_candidate_outpoints_v2, "
            "public.canonical_multileg_admission_candidates_v2, "
            "public.canonical_multileg_consent_challenges_v2, "
            "public.current_entitlement_evidence, public.users CASCADE"
        )
    yield shared_pg


def _global_rows(engine):
    with engine.connect() as connection:
        return (
            connection.execute(
                text(
                    f"SELECT claim_kind, txid, vout, strict_edge_id, multileg_proposal_id "
                    f"FROM {GLOBAL} ORDER BY claim_kind, txid, vout"
                )
            )
            .mappings()
            .all()
        )


def _overlapping_mirror():
    """3+2 signed multi-leg set with both strict-two UTXOs among its five."""
    original = _bundle()
    outputs = []
    early_set = False
    late_set = False
    for item in original.outpoints:
        if item.direction is CovenantDirection.OUTGOING and not early_set:
            outputs.append(replace(item, txid="a" * 64, vout=0))
            early_set = True
        elif item.direction is CovenantDirection.INCOMING and not late_set:
            outputs.append(replace(item, txid="b" * 64, vout=1))
            late_set = True
        else:
            outputs.append(item)
    assert early_set and late_set
    return create_canonical_multi_outpoint_mirror_v2(original.script_evidence, tuple(outputs))


def _strict(engine):
    proposal, node = _root()
    nonce = issue_strict(engine, proposal, ALICE)
    return proposal, nonce, node


def test_separate_utxos_across_two_candidate_formats_are_all_claimed(db):
    _seed_full(db, ALICE)
    strict, strict_nonce, strict_node = _strict(db)
    reserve_strict(db, strict_node, (strict_node,), strict_nonce)
    multi = _new()
    multi_nonce = issue_multi(db, multi)
    reserve_multi(db, multi, multi_nonce)
    rows = _global_rows(db)
    assert len(rows) == 7
    assert sum(row["claim_kind"] == "strict_two" for row in rows) == 2
    assert sum(row["claim_kind"] == "multileg" for row in rows) == 5
    assert all(row["strict_edge_id"] == strict.proposal_id for row in rows if row["claim_kind"] == "strict_two")


def test_existing_strict_two_reservation_rejects_signed_multileg_overlap(db):
    _seed_full(db, ALICE)
    strict, strict_nonce, strict_node = _strict(db)
    reserve_strict(db, strict_node, (strict_node,), strict_nonce)
    multi = _new(_overlapping_mirror())
    nonce = issue_multi(db, multi)
    with pytest.raises(CanonicalMultiLegCandidateUnavailableV2):
        reserve_multi(db, multi, nonce)
    assert _nonce_consumed(db, nonce) is None
    assert len(_global_rows(db)) == 2


def test_existing_multileg_reservation_rejects_strict_two_overlap(db):
    _seed_full(db, ALICE)
    multi = _new(_overlapping_mirror())
    nonce = issue_multi(db, multi)
    reserve_multi(db, multi, nonce)
    strict, strict_nonce, strict_node = _strict(db)
    with pytest.raises(CanonicalAdmissionCandidateUnavailableV2):
        reserve_strict(db, strict_node, (strict_node,), strict_nonce)
    with db.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT consumed_at FROM public.canonical_admission_consent_challenges_v2 "
                    "WHERE challenge_sha256=:sha"
                ),
                {"sha": strict_nonce.challenge_sha256},
            ).scalar_one()
            is None
        )
    assert len(_global_rows(db)) == 5


def test_expiration_releases_only_matching_multileg_claims_and_keeps_history(db):
    mirror = _overlapping_mirror()
    old_proposal, observation = _propose(mirror, OLD, OLD_ID)
    _full_at(db, ALICE, OLD, "00000000-0000-4000-8000-0000000000e1")
    old_nonce = _issue_at(db, old_proposal, ALICE, OLD)
    _reserve_at(db, old_proposal, observation, old_nonce, OLD, ALICE, BOB)
    assert len(_global_rows(db)) == 5
    receipt = _expire(db, old_proposal.proposal_id)
    assert receipt.released_outpoints == 5
    assert len(_global_rows(db)) == 0

    _full_at(db, ALICE, NOW, "00000000-0000-4000-8000-0000000000e2", new_user=False)
    strict, nonce, node = _strict(db)
    reserve_strict(db, node, (node,), nonce)
    rows = _global_rows(db)
    assert len(rows) == 2
    assert all(row["claim_kind"] == "strict_two" for row in rows)
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT COUNT(*) FROM {MULTI_OUTPOINTS}")).scalar_one() == 5
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM public.canonical_multileg_candidate_expirations_v2")
            ).scalar_one()
            == 1
        )


def test_manual_live_delete_without_immutable_expiry_event_rolls_back(db):
    _seed_full(db, ALICE)
    multi = _new()
    nonce = issue_multi(db, multi)
    reserve_multi(db, multi, nonce)
    row = _global_rows(db)[0]
    with pytest.raises(DBAPIError):
        with db.begin() as connection:
            connection.execute(
                text(f"DELETE FROM {LIVE} WHERE txid=:txid AND vout=:vout"),
                {"txid": row["txid"], "vout": row["vout"]},
            )
    assert len(_global_rows(db)) == 5
    with db.connect() as connection:
        assert connection.execute(text(f"SELECT COUNT(*) FROM {LIVE}")).scalar_one() == 5


def test_global_claims_cannot_be_directly_deleted_or_updated(db):
    _seed_full(db, ALICE)
    strict, nonce, node = _strict(db)
    reserve_strict(db, node, (node,), nonce)
    for statement in (
        f"DELETE FROM {GLOBAL}",
        f"UPDATE {GLOBAL} SET claim_kind=claim_kind",
    ):
        with pytest.raises(DBAPIError):
            with db.begin() as connection:
                connection.execute(text(statement))
    assert len(_global_rows(db)) == 2
