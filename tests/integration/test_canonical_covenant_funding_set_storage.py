from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import BigInteger, Integer, create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.models import Base, CanonicalCovenantFundingOutpointRow, CanonicalCovenantFundingSetRow
from app.services.canonical_covenant_funding_set import (
    CovenantFundingSetLifecycle,
    RecognizedCovenantFundingOutpoint,
    canonical_covenant_funding_set_bytes,
    create_canonical_covenant_funding_set,
)
from app.services.canonical_covenant_funding_set_storage import (
    CanonicalCovenantFundingSetStorageError,
    SqlAlchemyCanonicalCovenantFundingSetRepository,
)
from app.services.covenant_relation import CovenantDirection
from app.services.mirrored_covenant_pair import CovenantDeltaProfile, validate_mirrored_covenant_pair
from app.services.trusted_covenant_registration import (
    RegisteredCovenantOutpoint,
    TrustedCovenantRegistrationLifecycle,
    create_trusted_covenant_registration,
)

SUBJECT = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
LEG1 = "6303681d1bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac670371201bb17521032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8cac68"
LEG2 = "630371201bb17521032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8cac67037a231bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac68"
NOW = datetime(2026, 8, 12, tzinfo=timezone.utc)


def registration(state=TrustedCovenantRegistrationLifecycle.ACTIVE):
    p = validate_mirrored_covenant_pair(
        LEG1, LEG2, subject_pubkey=SUBJECT, allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,)
    )
    return create_trusted_covenant_registration(
        p,
        (
            RegisteredCovenantOutpoint(CovenantDirection.INCOMING, "a" * 64, 0, 100000, p.incoming_leg_script_sha256),
            RegisteredCovenantOutpoint(CovenantDirection.OUTGOING, "b" * 64, 1, 100000, p.outgoing_leg_script_sha256),
        ),
        registration_id="00000000-0000-4000-8000-000000000001",
        lifecycle_state=state,
        registered_at=NOW,
        lifecycle_changed_at=NOW,
    )


class Registrations:
    def __init__(self, value):
        self.value = value

    def get(self, identifier):
        return self.value if identifier == self.value.registration_id else None


def funding(identifier="00000000-0000-4000-8000-000000000010", state=CovenantFundingSetLifecycle.EFFECTIVE):
    reg = registration()
    p = reg.mirrored_pair
    return create_canonical_covenant_funding_set(
        funding_set_id=identifier,
        trusted_registration=reg,
        lifecycle_state=state,
        created_at=NOW,
        lifecycle_changed_at=NOW,
        effective_at=(
            NOW if state in (CovenantFundingSetLifecycle.EFFECTIVE, CovenantFundingSetLifecycle.SUPERSEDED) else None
        ),
        superseded_by_funding_set_id=(
            "00000000-0000-4000-8000-000000000099" if state is CovenantFundingSetLifecycle.SUPERSEDED else None
        ),
        recognized_outpoints=(
            RecognizedCovenantFundingOutpoint(
                CovenantDirection.INCOMING, "a" * 64, 0, 100000, p.incoming_leg_script_sha256
            ),
            RecognizedCovenantFundingOutpoint(
                CovenantDirection.OUTGOING, "b" * 64, 1, 100000, p.outgoing_leg_script_sha256
            ),
            RecognizedCovenantFundingOutpoint(
                CovenantDirection.OUTGOING, "c" * 64, 2, 50000, p.outgoing_leg_script_sha256
            ),
        ),
    )


@pytest.fixture
def store(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'funding.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return (
        engine,
        factory,
        SqlAlchemyCanonicalCovenantFundingSetRepository(
            factory, trusted_registration_repository=Registrations(registration())
        ),
    )


def test_append_get_list_and_resolve(store):
    _, _, repo = store
    expected = funding()
    repo.append(expected)
    assert repo.get(expected.funding_set_id) == expected
    assert repo.list_by_registration(expected.trusted_registration_id) == (expected,)
    assert repo.resolve_effective(expected.trusted_registration_id) == expected


def test_list_revalidates_effective_authority_and_sanitizes_failure(store):
    _, _, repo = store
    expected = funding()
    repo.append(expected)
    assert repo.list_by_registration(expected.trusted_registration_id) == (expected,)

    repo._trusted_registration_repository.value = registration(TrustedCovenantRegistrationLifecycle.REVOKED)
    with pytest.raises(CanonicalCovenantFundingSetStorageError) as error:
        repo.list_by_registration(expected.trusted_registration_id)
    assert str(error.value) == "canonical covenant funding set storage unavailable"
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__


def test_list_preserves_historical_records_without_active_authority(store):
    _, _, repo = store
    expected = tuple(
        funding(f"00000000-0000-4000-8000-{number:012d}", state)
        for number, state in enumerate(
            (
                CovenantFundingSetLifecycle.PROPOSED,
                CovenantFundingSetLifecycle.DISPUTED,
                CovenantFundingSetLifecycle.REVOKED,
                CovenantFundingSetLifecycle.SUPERSEDED,
            ),
            20,
        )
    )
    for value in expected:
        repo.append(value)

    repo._trusted_registration_repository.value = registration(TrustedCovenantRegistrationLifecycle.REVOKED)
    assert repo.list_by_registration(registration().registration_id) == expected


def test_unique_effective_and_historical_coexistence(store):
    _, _, repo = store
    repo.append(funding())
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.append(funding("00000000-0000-4000-8000-000000000011"))
    for number, state in enumerate(
        (
            CovenantFundingSetLifecycle.PROPOSED,
            CovenantFundingSetLifecycle.DISPUTED,
            CovenantFundingSetLifecycle.REVOKED,
            CovenantFundingSetLifecycle.SUPERSEDED,
        ),
        20,
    ):
        repo.append(funding(f"00000000-0000-4000-8000-{number:012d}", state))
    assert len(repo.list_by_registration(registration().registration_id)) == 5


def test_zero_effective_and_tampered_scalar_or_child_fail_closed(store):
    _, factory, repo = store
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.resolve_effective(registration().registration_id)
    value = funding()
    repo.append(value)
    with factory() as session:
        session.execute(text("UPDATE canonical_covenant_funding_sets SET pair_sha256 = :x"), {"x": "f" * 64})
        session.commit()
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.get(value.funding_set_id)


def test_boundary_vout_persists_and_database_rejects_non_hex(store):
    _, factory, repo = store
    value = funding()
    p = registration().mirrored_pair
    boundary = RecognizedCovenantFundingOutpoint(
        CovenantDirection.INCOMING, "f" * 64, 4294967295, 1, p.incoming_leg_script_sha256
    )
    value = type(value)(
        *(getattr(value, f) for f in list(type(value).__dataclass_fields__)[:-1]),
        value.recognized_outpoints + (boundary,),
    )
    repo.append(value)
    assert next(x.vout for x in repo.get(value.funding_set_id).recognized_outpoints if x.txid == "f" * 64) == 4294967295
    with factory() as session:
        session.execute(text("PRAGMA foreign_keys=ON"))
        with pytest.raises(IntegrityError):
            session.execute(
                text("UPDATE canonical_covenant_funding_outpoints SET txid = :x WHERE txid = :old"),
                {"x": "g" * 64, "old": "f" * 64},
            )
            session.commit()
        session.rollback()


def test_missing_extra_and_noncanonical_child_rows_fail_closed(store):
    _, factory, repo = store
    value = funding()
    repo.append(value)
    with factory() as session:
        session.execute(text("DELETE FROM canonical_covenant_funding_outpoints WHERE txid = :x"), {"x": "c" * 64})
        session.commit()
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.get(value.funding_set_id)
    with factory() as session:
        session.execute(
            text(
                "INSERT INTO canonical_covenant_funding_outpoints (funding_set_id,direction,txid,vout,amount_sats,witness_script_sha256) VALUES (:set_id,'outgoing',:txid,9,1,:script)"
            ),
            {
                "set_id": value.funding_set_id,
                "txid": "f" * 64,
                "script": registration().mirrored_pair.outgoing_leg_script_sha256,
            },
        )
        session.commit()
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.get(value.funding_set_id)
    with factory() as session:
        session.execute(text("DELETE FROM canonical_covenant_funding_outpoints WHERE txid = :x"), {"x": "f" * 64})
        session.execute(
            text("UPDATE canonical_covenant_funding_outpoints SET direction = 'incoming' WHERE txid = :x"),
            {"x": "b" * 64},
        )
        session.commit()
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.get(value.funding_set_id)


def test_canonical_json_tamper_and_authoritative_source_change_fail_closed(store):
    _, factory, repo = store
    value = funding()
    repo.append(value)
    with factory() as session:
        session.execute(
            text("UPDATE canonical_covenant_funding_sets SET canonical_record_json = canonical_record_json || ' '")
        )
        session.commit()
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.get(value.funding_set_id)
    with factory() as session:
        session.execute(
            text("UPDATE canonical_covenant_funding_sets SET canonical_record_json = :canonical"),
            {"canonical": canonical_covenant_funding_set_bytes(value).decode("ascii")},
        )
        session.commit()
    repo._trusted_registration_repository.value = registration(TrustedCovenantRegistrationLifecycle.REVOKED)
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.get(value.funding_set_id)
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.resolve_effective(value.trusted_registration_id)
    with factory() as session:
        session.execute(text("UPDATE canonical_covenant_funding_sets SET pair_sha256 = :x"), {"x": value.pair_sha256})
        session.execute(
            text("UPDATE canonical_covenant_funding_outpoints SET amount_sats = amount_sats + 1 WHERE txid = :x"),
            {"x": "c" * 64},
        )
        session.commit()
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.get(value.funding_set_id)


def test_model_migration_parity_and_partial_index():
    assert {"canonical_covenant_funding_sets", "canonical_covenant_funding_outpoints"} <= set(Base.metadata.tables)
    index = {x.name: x for x in CanonicalCovenantFundingSetRow.__table__.indexes}[
        "uq_funding_set_effective_registration"
    ]
    assert (
        index.unique
        and index.dialect_options["sqlite"]["where"] is not None
        and index.dialect_options["postgresql"]["where"] is not None
    )
    sql = Path("migrations/2026-08-12_canonical_covenant_funding_set_v1.sql").read_text()
    assert "uq_funding_set_effective_registration" in sql and "WHERE lifecycle_state = 'effective'" in sql
    assert isinstance(CanonicalCovenantFundingOutpointRow.__table__.c.id.type, BigInteger)
    assert isinstance(
        CanonicalCovenantFundingOutpointRow.__table__.c.id.type.dialect_impl(create_engine("sqlite://").dialect),
        Integer,
    )
    assert isinstance(CanonicalCovenantFundingOutpointRow.__table__.c.vout.type, BigInteger)
    assert set(CanonicalCovenantFundingSetRow.__table__.columns.keys()) == {
        "funding_set_id",
        "schema",
        "funding_set_version",
        "trusted_registration_id",
        "trusted_registration_sha256",
        "pair_sha256",
        "subject_xonly_pubkey",
        "counterparty_xonly_pubkey",
        "lifecycle_state",
        "created_at",
        "lifecycle_changed_at",
        "effective_at",
        "superseded_by_funding_set_id",
        "canonical_funding_set_sha256",
        "canonical_record_json",
    }
    assert set(CanonicalCovenantFundingOutpointRow.__table__.columns.keys()) == {
        "id",
        "funding_set_id",
        "direction",
        "txid",
        "vout",
        "amount_sats",
        "witness_script_sha256",
        "descriptor_sha256",
    }
    parent_constraints = {x.name for x in CanonicalCovenantFundingSetRow.__table__.constraints}
    child_constraints = {x.name for x in CanonicalCovenantFundingOutpointRow.__table__.constraints}
    assert {
        "ck_funding_set_source_digests",
        "ck_funding_set_participants",
        "ck_funding_set_digest",
    } <= parent_constraints
    assert {
        "ck_funding_outpoint_txid",
        "ck_funding_outpoint_script",
        "ck_funding_outpoint_descriptor",
    } <= child_constraints
    assert "id BIGSERIAL PRIMARY KEY" in sql and "vout BIGINT" in sql
    assert "txid ~ '^[0-9a-f]{64}$'" in sql
    for name in (
        parent_constraints
        | child_constraints
        | {
            "uq_funding_outpoint_identity",
            "uq_funding_set_effective_registration",
            "idx_funding_set_registration",
            "idx_funding_outpoint_set",
        }
    ):
        if name is not None:
            assert name in sql


@pytest.mark.parametrize("effective", (NOW - timedelta(seconds=1), NOW + timedelta(seconds=1)))
def test_database_rejects_disputed_effective_time_outside_lifecycle_bounds(store, effective):
    _, factory, repo = store
    value = funding()
    repo.append(value)
    with factory() as session:
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "UPDATE canonical_covenant_funding_sets SET lifecycle_state = 'disputed', effective_at = :effective"
                ),
                {"effective": effective},
            )
            session.commit()
        session.rollback()


def test_effective_ambiguity_and_write_failure_are_sanitized(monkeypatch):
    value = funding()
    repo = SqlAlchemyCanonicalCovenantFundingSetRepository(
        lambda: None, trusted_registration_repository=Registrations(registration())
    )
    monkeypatch.setattr(repo, "_rows", lambda filters: (value, value))
    with pytest.raises(CanonicalCovenantFundingSetStorageError):
        repo.resolve_effective(value.trusted_registration_id)

    class FailedSession:
        rolled_back = False
        closed = False

        def add(self, row):
            pass

        def commit(self):
            raise RuntimeError("database detail must be hidden")

        def rollback(self):
            self.rolled_back = True

        def close(self):
            self.closed = True

    failed = FailedSession()
    repo = SqlAlchemyCanonicalCovenantFundingSetRepository(
        lambda: failed, trusted_registration_repository=Registrations(registration())
    )
    with pytest.raises(CanonicalCovenantFundingSetStorageError) as error:
        repo.append(value)
    assert str(error.value) == "canonical covenant funding set storage unavailable"
    assert failed.rolled_back and failed.closed
