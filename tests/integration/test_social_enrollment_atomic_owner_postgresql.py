"""Disposable PostgreSQL 16 proof for the enrollment atomic owner.

The inherited fixture accepts only an explicitly acknowledged temporary
PostgreSQL 16 cluster on isolated loopback TCP with Unix sockets disabled.
No configured application database is consulted.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.services import social_device_challenge_store as challenge_storage
from app.services import social_device_ed25519_association_storage as association_storage
from app.services import social_enrollment_atomic_owner as atomic
from app.services import social_enrollment_receipt_storage as receipt_storage
from app.services import social_enrollment_transition_authority as transition
from tests.integration.test_social_current_admission_authority_postgresql import (
    OAUTH_ISSUER,
    authority_live,
    authority_ready,
)
from tests.integration.test_social_enrollment_transition_authority_storage_postgresql import (
    adapter as transition_adapter,
)
from tests.integration.test_social_enrollment_transition_authority_storage_postgresql import (
    build_transition,
    transition_live,
)
from tests.integration.test_social_session_issuance_postgresql import generation_factory as generation_factory
from tests.integration.test_social_session_issuance_postgresql import ingress_live as ingress_live
from tests.integration.test_social_session_issuance_postgresql import issuance_ready as issuance_ready
from tests.integration.test_social_session_issuance_postgresql import live as live
from tests.integration.test_social_session_issuance_postgresql import material as material
from tests.integration.test_social_session_issuance_postgresql import mobile_factory as mobile_factory
from tests.integration.test_social_session_issuance_postgresql import replay_ready as replay_ready
from tests.integration.test_social_session_issuance_postgresql import state as state

ROOT = Path(__file__).parents[2]
RECEIPT_MIGRATION = ROOT / "migrations/2026-09-23_social_device_admission_receipt_consumption_v1.sql"
PREFIX = "HODLXXI_ENROLLMENT_ATOMIC_OWNER_TEST_"
ACK = "DISPOSABLE-SOCIAL-ENROLLMENT-ATOMIC-OWNER-POSTGRES-V1"
ERROR = "^social enrollment atomic owner unavailable$"


def _apply(connection, path: Path) -> None:
    with connection.connection.driver_connection.cursor() as cursor:
        cursor.execute(path.read_text(encoding="ascii"))


@pytest.fixture(scope="module")
def postgres_factory():
    """Build the prerequisite stack only on the explicit isolated TCP target."""

    dsn = os.environ.get(PREFIX + "DSN")
    if not dsn:
        pytest.skip("explicit disposable enrollment atomic-owner PostgreSQL target not provided")
    assert os.environ.get(PREFIX + "ACK") == ACK
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("hodlxxi-enrollment-atomic-owner-v1.")
    assert data.name == "data" and (data / "PG_VERSION").read_text().strip() == "16"
    port = int(os.environ[PREFIX + "PORT"])
    url = make_url(dsn)
    assert url.drivername == "postgresql+psycopg2"
    assert url.host == "127.0.0.1" and url.port == port and 49152 <= port <= 65535
    assert url.database == "hodlxxi_enrollment_atomic_owner_test"
    assert url.username == "enrollment_atomic_owner_test"
    assert url.password is None and not url.query

    engine = create_engine(url, future=True, poolclass=NullPool, hide_parameters=True)
    with engine.connect() as connection:
        identity = connection.execute(
            text(
                "SELECT current_database(), current_setting('data_directory'), "
                "current_setting('port'), current_setting('listen_addresses'), "
                "current_setting('unix_socket_directories'), version()"
            )
        ).one()
        assert identity[0] == url.database
        assert Path(identity[1]).resolve() == data
        assert int(identity[2]) == port
        assert identity[3:5] == ("127.0.0.1", "")
        assert identity[5].startswith("PostgreSQL 16.")

    prerequisite = """
    CREATE TABLE users (
      id VARCHAR(36) PRIMARY KEY,
      pubkey VARCHAR(66) NOT NULL UNIQUE,
      created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
      last_login TIMESTAMP WITHOUT TIME ZONE,
      metadata JSON,
      is_active BOOLEAN NOT NULL
    );
    CREATE INDEX idx_user_pubkey ON users (pubkey);
    CREATE TABLE current_entitlement_evidence (
      evidence_id VARCHAR(36) PRIMARY KEY,
      contract_version VARCHAR(64) NOT NULL,
      subject_pubkey VARCHAR(64) NOT NULL,
      identity_class VARCHAR(7) NOT NULL,
      current_full_relation_satisfied BOOLEAN NOT NULL,
      evidence_source VARCHAR(128) NOT NULL,
      evidence_version VARCHAR(64) NOT NULL,
      source_evidence_sha256 VARCHAR(64) NOT NULL,
      observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
      valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
      revoked_at TIMESTAMP WITH TIME ZONE,
      created_at TIMESTAMP WITH TIME ZONE NOT NULL
    );
    """
    with engine.begin() as connection:
        connection.exec_driver_sql(prerequisite)
        _apply(connection, ROOT / "migrations/2026-09-04_social_messaging_device_bindings_v1.sql")
        _apply(
            connection,
            ROOT / "migrations/2026-09-10_social_messaging_device_binding_authorization_v1.sql",
        )
    factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    try:
        yield engine, factory
    finally:
        engine.dispose()


def _apply_receipt_migration(state) -> None:
    engine = state["factory"].kw["bind"]
    with engine.begin() as connection:
        _apply(connection, RECEIPT_MIGRATION)


def _prepare(transition_live, kind="initial", **kwargs):
    prepared = build_transition(transition_live, kind, **kwargs)
    _apply_receipt_migration(prepared)
    return prepared


def _owner(db, state):
    return atomic.SqlAlchemyTransactionBoundEnrollmentAtomicOwner(
        db,
        device_issuance_id=state["issuance_id"],
        device_client_id=state["device_client_id"],
        oauth_issuer=OAUTH_ISSUER,
        approver_oauth_session_id=state["approver_session_id"],
        approver_client_id=state["approver_client_id"],
    )


def _execute(db, state):
    return _owner(db, state).execute_enrollment_activate(
        state["value"],
        state["statement"],
        observed_at=state["observed_ms"],
        decided_at=state["observed_ms"] + 1,
    )


def _counts_in_transaction(db, challenge_id):
    challenge_state = db.execute(
        select(challenge_storage.SocialDeviceAdmissionChallengeRow.state).where(
            challenge_storage.SocialDeviceAdmissionChallengeRow.challenge_id == challenge_id
        )
    ).scalar_one()
    receipt_count = db.execute(
        select(func.count())
        .select_from(receipt_storage.SocialEnrollmentAdmissionReceiptRow)
        .where(receipt_storage.SocialEnrollmentAdmissionReceiptRow.challenge_id == challenge_id)
    ).scalar_one()
    effect_count = db.execute(
        select(func.count())
        .select_from(association_storage.SocialDeviceEd25519AssociationEvent)
        .where(association_storage.SocialDeviceEd25519AssociationEvent.enrollment_challenge_id == challenge_id)
    ).scalar_one()
    return challenge_state, receipt_count, effect_count


def _durable_counts(state):
    with state["factory"].begin() as db:
        return _counts_in_transaction(db, state["value"].context.challenge_id)


def _execute_effect(db, state, authority):
    store = association_storage.SqlAlchemyEd25519AssociationStore(db)
    kwargs = {
        "input_wire": state["value"].wire,
        "statement": state["statement"],
        "now": state["observed_ms"] + 1,
    }
    if authority.transition_kind == "initial":
        return store.establish_initial(**kwargs)
    if authority.transition_kind == "rotate":
        return store.rotate(
            **kwargs,
            expected_predecessor=authority.pre_effect_association_id,
            expected_epoch=authority.pre_effect_authority_epoch,
        )
    return store.reenroll(
        **kwargs,
        expected_predecessor=authority.pre_effect_association_id,
        expected_epoch=authority.pre_effect_authority_epoch,
    )


@pytest.mark.parametrize(
    ("kind", "prior_state"),
    (("initial", None), ("rotate", "rotated"), ("reenroll", "revoked")),
)
def test_all_three_transitions_commit_effect_receipt_and_consumption_together(transition_live, kind, prior_state):
    state = _prepare(transition_live, kind)
    with state["factory"].begin() as db:
        result = _execute(db, state)
        assert type(result) is atomic.ProvisionalEnrollmentActivationV1
        assert result.publication_status == "provisional_until_caller_commit"
        assert result.authority.transition_kind == kind
        assert result.effect == transition.prepared_enrollment_effect_v1(result.authority)
        assert result.association.state == "active"
        assert result.receipt.receipt.status == "committed"
        assert result.consumed_challenge.state == "consumed"
        assert _counts_in_transaction(db, result.authority.challenge_id) == ("consumed", 1, 1)

    assert _durable_counts(state) == ("consumed", 1, 1)
    with state["factory"].begin() as db:
        snapshot = association_storage.SqlAlchemyEd25519AssociationStore(db).lock_history(
            state["subject"], state["device_id"]
        )
        assert snapshot.current.association_id == result.authority.proposed_association_id
        assert snapshot.current.state == "active"
        assert snapshot.authority_epoch == result.authority.proposed_authority_epoch
        if prior_state is not None:
            assert snapshot.history[-2].association_id == result.authority.pre_effect_association_id
            assert snapshot.history[-2].state == prior_state


def test_owner_never_completes_or_closes_the_caller_transaction(transition_live):
    state = _prepare(transition_live)
    with state["factory"]() as db:
        transaction = db.begin()
        calls = []
        originals = db.commit, db.rollback, db.close
        db.commit = lambda: calls.append("commit")
        db.rollback = lambda: calls.append("rollback")
        db.close = lambda: calls.append("close")
        result = _execute(db, state)
        assert result.publication_status == "provisional_until_caller_commit"
        assert calls == []
        assert transaction.is_active and db.in_transaction()
        db.commit, db.rollback, db.close = originals
        transaction.commit()
    assert _durable_counts(state) == ("consumed", 1, 1)


def test_rollback_after_effect_before_receipt_leaves_no_partial_state(transition_live, monkeypatch):
    state = _prepare(transition_live)

    def fail_receipt(*_args, **_kwargs):
        raise RuntimeError("synthetic receipt failure")

    monkeypatch.setattr(atomic.SqlAlchemyEnrollmentAdmissionReceiptStore, "store_committed", fail_receipt)
    with state["factory"]() as db:
        transaction = db.begin()
        with pytest.raises(atomic.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
            _execute(db, state)
        assert transaction.is_active
        assert _counts_in_transaction(db, state["value"].context.challenge_id) == ("issued", 0, 1)
        transaction.rollback()
    assert _durable_counts(state) == ("issued", 0, 0)


def test_rollback_after_receipt_before_consumption_leaves_no_partial_state(transition_live, monkeypatch):
    state = _prepare(transition_live)

    def fail_consumption(*_args, **_kwargs):
        raise RuntimeError("synthetic consumption failure")

    monkeypatch.setattr(atomic.SqlAlchemyDeviceChallengeStore, "record_enrollment_consumed", fail_consumption)
    with state["factory"]() as db:
        transaction = db.begin()
        with pytest.raises(atomic.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
            _execute(db, state)
        assert transaction.is_active
        assert _counts_in_transaction(db, state["value"].context.challenge_id) == ("issued", 1, 1)
        transaction.rollback()
    assert _durable_counts(state) == ("issued", 0, 0)


def test_challenge_primitive_failure_rolls_back_effect_and_receipt(transition_live, monkeypatch):
    state = _prepare(transition_live)
    expires_at = json.loads(state["value"].challenge_wire)["expiresAt"]
    original = atomic.SqlAlchemyDeviceChallengeStore.record_enrollment_consumed

    def consume_at_expiry(self, authority, *, observed_at):
        return original(self, authority, observed_at=expires_at)

    monkeypatch.setattr(atomic.SqlAlchemyDeviceChallengeStore, "record_enrollment_consumed", consume_at_expiry)
    with state["factory"]() as db:
        transaction = db.begin()
        with pytest.raises(atomic.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
            _execute(db, state)
        assert transaction.is_active
        assert _counts_in_transaction(db, state["value"].context.challenge_id) == ("issued", 1, 1)
        transaction.rollback()
    assert _durable_counts(state) == ("issued", 0, 0)


def test_receipt_effect_mismatch_poisoning_requires_full_rollback(transition_live, monkeypatch):
    state = _prepare(transition_live)
    original = atomic.SqlAlchemyEnrollmentAdmissionReceiptStore.store_committed

    def mismatched_receipt(self, authority, **kwargs):
        stored = original(self, authority, **kwargs)
        return replace(stored, effect_digest="01" * 32)

    monkeypatch.setattr(atomic.SqlAlchemyEnrollmentAdmissionReceiptStore, "store_committed", mismatched_receipt)
    with state["factory"]() as db:
        transaction = db.begin()
        instance = _owner(db, state)
        for _attempt in range(2):
            with pytest.raises(atomic.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
                instance.execute_enrollment_activate(
                    state["value"],
                    state["statement"],
                    observed_at=state["observed_ms"],
                    decided_at=state["observed_ms"] + 1,
                )
        assert _counts_in_transaction(db, state["value"].context.challenge_id) == ("issued", 1, 1)
        transaction.rollback()
    assert _durable_counts(state) == ("issued", 0, 0)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("associationId", "11" * 32),
        ("associationVersion", 99),
        ("predecessorAssociationId", "12" * 32),
        ("authorityEpoch", 99),
    ),
)
def test_wrong_proposed_association_fields_are_denied_before_mutation(transition_live, field, replacement):
    state = _prepare(transition_live, "rotate", context_updates={field: replacement})
    with state["factory"]() as db:
        transaction = db.begin()
        with pytest.raises(atomic.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
            _execute(db, state)
        transaction.rollback()
    assert _durable_counts(state) == ("issued", 0, 0)


def test_expired_challenge_is_denied_before_mutation(transition_live):
    state = _prepare(transition_live)
    expires_at = json.loads(state["value"].challenge_wire)["expiresAt"]
    with state["factory"]() as db:
        transaction = db.begin()
        with pytest.raises(atomic.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
            _owner(db, state).execute_enrollment_activate(
                state["value"],
                state["statement"],
                observed_at=expires_at,
                decided_at=expires_at,
            )
        transaction.rollback()
    assert _durable_counts(state) == ("issued", 0, 0)


def test_already_consumed_duplicate_and_replay_are_denied_without_partial_state(transition_live):
    state = _prepare(transition_live)
    with state["factory"].begin() as db:
        committed = _execute(db, state)
    for _attempt in range(2):
        with state["factory"]() as db:
            transaction = db.begin()
            with pytest.raises(atomic.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
                _execute(db, state)
            transaction.rollback()
    assert _durable_counts(state) == ("consumed", 1, 1)
    assert committed.receipt.bearer_authority == committed.receipt.reexecution_authority == "none"


def test_replaced_caller_transaction_is_denied(transition_live):
    state = _prepare(transition_live)
    with state["factory"]() as db:
        original = db.begin()
        instance = _owner(db, state)
        original.rollback()
        replacement = db.begin()
        with pytest.raises(atomic.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
            instance.execute_enrollment_activate(
                state["value"],
                state["statement"],
                observed_at=state["observed_ms"],
                decided_at=state["observed_ms"] + 1,
            )
        assert replacement.is_active and db.in_transaction()
        replacement.rollback()
    assert _durable_counts(state) == ("issued", 0, 0)


def test_same_challenge_concurrency_has_one_complete_winner_and_no_loser_rows(transition_live):
    state = _prepare(transition_live)

    def contender():
        try:
            with state["factory"].begin() as db:
                result = _execute(db, state)
            return result.publication_status
        except Exception:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _item: contender(), range(2)))
    assert sorted(outcomes) == ["denied", "provisional_until_caller_commit"]
    assert _durable_counts(state) == ("consumed", 1, 1)


@pytest.mark.parametrize("subset", ("effect", "receipt", "consumption"))
def test_commit_time_database_invariant_rejects_manual_incomplete_subsets(transition_live, subset):
    state = _prepare(transition_live)
    with pytest.raises(Exception):
        with state["factory"].begin() as db:
            authority = transition_adapter(db, state).lock_transition_authority(
                state["value"],
                state["statement"],
                observed_at=state["observed_ms"],
            )
            if subset == "effect":
                _execute_effect(db, state, authority)
            elif subset == "receipt":
                receipt_storage.SqlAlchemyEnrollmentAdmissionReceiptStore(db).store_committed(
                    authority,
                    proposed_association_id=authority.proposed_association_id,
                    decided_at=state["observed_ms"] + 1,
                )
            else:
                db.execute(
                    update(challenge_storage.SocialDeviceAdmissionChallengeRow)
                    .where(challenge_storage.SocialDeviceAdmissionChallengeRow.challenge_id == authority.challenge_id)
                    .values(state="consumed")
                )
    assert _durable_counts(state) == ("issued", 0, 0)


def test_recovery_history_grants_neither_bearer_nor_reexecution_authority(transition_live):
    state = _prepare(transition_live)
    with state["factory"].begin() as db:
        committed = _execute(db, state)
    with state["factory"].begin() as db:
        recovered = receipt_storage.SqlAlchemyEnrollmentAdmissionReceiptStore(db).read_by_challenge_id(
            committed.authority.challenge_id
        )
    assert recovered == committed.receipt
    assert recovered.bearer_authority == "none"
    assert recovered.reexecution_authority == "none"
    assert not hasattr(recovered, "execute")
    with state["factory"]() as db:
        transaction = db.begin()
        with pytest.raises(atomic.SocialEnrollmentAtomicOwnerUnavailable, match=ERROR):
            _execute(db, state)
        transaction.rollback()
    assert _durable_counts(state) == ("consumed", 1, 1)
