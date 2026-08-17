from dataclasses import replace
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.models import Base, TrustedCovenantRegisteredOutpoint, TrustedCovenantRegistration
from app.services.covenant_relation import CovenantDirection
from app.services.mirrored_covenant_pair import CovenantDeltaProfile, validate_mirrored_covenant_pair
from app.services.trusted_covenant_registration import (
    InvalidTrustedCovenantRegistration,
    RegisteredCovenantOutpoint,
    TrustedCovenantRegistrationLifecycle,
    create_trusted_covenant_registration,
)
from app.services.trusted_covenant_registration_storage import (
    SqlAlchemyTrustedCovenantRegistrationRepository,
    TrustedCovenantRegistrationStorageError,
)

OPERATOR = "023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923"
LEGACY_1 = "6303681d1bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac670371201bb17521032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8cac68"
LEGACY_2 = "630371201bb17521032f664095c520438506ddea8f584be08aeef210bc7ec37817a56478a489b72a8cac67037a231bb17521023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923ac68"
NOW = datetime(2026, 7, 25, 12, tzinfo=timezone.utc)


def item(identifier="00000000-0000-4000-8000-000000000001", state=TrustedCovenantRegistrationLifecycle.ACTIVE, tx="a"):
    pair = validate_mirrored_covenant_pair(
        LEGACY_1, LEGACY_2, subject_pubkey=OPERATOR, allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,)
    )
    return create_trusted_covenant_registration(
        pair,
        (
            RegisteredCovenantOutpoint(CovenantDirection.INCOMING, tx * 64, 0, 10, pair.incoming_leg_script_sha256),
            RegisteredCovenantOutpoint(
                CovenantDirection.OUTGOING, chr(ord(tx) + 1) * 64, 1, 20, pair.outgoing_leg_script_sha256
            ),
        ),
        registration_id=identifier,
        lifecycle_state=state,
        registered_at=NOW,
        lifecycle_changed_at=NOW,
    )


@pytest.fixture
def storage(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'registrations.db'}")
    Base.metadata.create_all(engine)
    repository = SqlAlchemyTrustedCovenantRegistrationRepository(sessionmaker(bind=engine, expire_on_commit=False))
    return engine, repository


def test_metadata_tables_indexes_constraints():
    assert set(TrustedCovenantRegistration.__table__.columns) >= {
        TrustedCovenantRegistration.__table__.c.registration_id,
        TrustedCovenantRegistration.__table__.c.earlier_leg_script_hex,
        TrustedCovenantRegistration.__table__.c.later_leg_script_hex,
    }
    registration_constraints = {constraint.name for constraint in TrustedCovenantRegistration.__table__.constraints}
    assert {
        "ck_trusted_registration_distinct_participants",
        "ck_trusted_registration_distinct_scripts",
    } <= registration_constraints
    assert {index.name: index.unique for index in TrustedCovenantRegistration.__table__.indexes}[
        "idx_trusted_registration_pair"
    ] is False
    assert TrustedCovenantRegistration.__table__.c.pair_sha256.unique is not True
    assert TrustedCovenantRegisteredOutpoint.__table__.c.witness_script_sha256 is not None
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    assert {
        "trusted_covenant_registrations",
        "trusted_covenant_registered_outpoints",
    } <= set(inspect(engine).get_table_names())


def test_append_get_and_active_materialization_round_trip(storage):
    _, repository = storage
    expected = item()
    repository.append(expected)
    assert repository.get(expected.registration_id) == expected
    outpoints = repository.get_active_outpoints(expected.registration_id)
    assert tuple(outpoint.direction for outpoint in outpoints) == (
        CovenantDirection.INCOMING,
        CovenantDirection.OUTGOING,
    )
    assert repository.get("00000000-0000-4000-8000-000000000099") is None


def test_duplicate_id_hash_and_global_outpoint_are_generic(storage):
    _, repository = storage
    expected = item()
    repository.append(expected)
    for duplicate in (
        expected,
        item("00000000-0000-4000-8000-000000000002"),
    ):
        with pytest.raises(TrustedCovenantRegistrationStorageError, match="storage unavailable") as error:
            repository.append(duplicate)
        assert "UNIQUE" not in str(error.value)


def test_same_pair_hash_can_be_registered_again_at_four_distinct_outpoints(storage):
    _, repository = storage
    first = item()
    second = item("00000000-0000-4000-8000-000000000002", tx="c")
    assert first.pair_sha256 == second.pair_sha256
    repository.append(first)
    repository.append(second)
    assert repository.get(first.registration_id) == first
    assert repository.get(second.registration_id) == second


def test_child_uniqueness_failure_rolls_back_parent_and_partial_children(storage):
    engine, repository = storage
    valid = item()
    repository.append(valid)
    failed = item("00000000-0000-4000-8000-000000000002", tx="c")
    failed = replace(
        failed,
        outpoints=(
            replace(failed.outpoints[0], txid=valid.outpoints[0].txid, vout=valid.outpoints[0].vout),
            failed.outpoints[1],
        ),
    )
    with pytest.raises(TrustedCovenantRegistrationStorageError):
        repository.append(failed)
    with engine.connect() as connection:
        parent_count = connection.execute(text("SELECT count(*) FROM trusted_covenant_registrations")).scalar_one()
        child_count = connection.execute(
            text("SELECT count(*) FROM trusted_covenant_registered_outpoints")
        ).scalar_one()
        failed_parent_count = connection.execute(
            text("SELECT count(*) FROM trusted_covenant_registrations WHERE registration_id=:id"),
            {"id": failed.registration_id},
        ).scalar_one()
    assert (parent_count, child_count, failed_parent_count) == (1, 2, 0)
    assert repository.get(valid.registration_id) == valid
    assert repository.get(failed.registration_id) is None


@pytest.mark.parametrize("mutation", ("missing", "extra", "script", "hash"))
def test_malformed_rows_fail_closed(storage, mutation):
    engine, repository = storage
    expected = item()
    repository.append(expected)
    with engine.begin() as connection:
        connection.execute(text("PRAGMA foreign_keys = OFF"))
        connection.execute(text("PRAGMA ignore_check_constraints = ON"))
        if mutation == "missing":
            connection.execute(
                text(
                    "DELETE FROM trusted_covenant_registered_outpoints WHERE id = "
                    "(SELECT min(id) FROM trusted_covenant_registered_outpoints)"
                )
            )
        elif mutation == "extra":
            connection.execute(
                text(
                    "INSERT INTO trusted_covenant_registered_outpoints "
                    "(registration_id,direction,txid,vout,amount_sats,witness_script_sha256) "
                    "VALUES (:id,'sideways',:txid,4,1,:script)"
                ),
                {
                    "id": expected.registration_id,
                    "txid": "f" * 64,
                    "script": expected.outpoints[0].witness_script_sha256,
                },
            )
        elif mutation == "script":
            connection.execute(
                text("UPDATE trusted_covenant_registrations SET earlier_leg_script_hex='00' WHERE registration_id=:id"),
                {"id": expected.registration_id},
            )
        else:
            connection.execute(
                text("UPDATE trusted_covenant_registrations SET registration_sha256=:hash WHERE registration_id=:id"),
                {"id": expected.registration_id, "hash": "f" * 64},
            )
    with pytest.raises(TrustedCovenantRegistrationStorageError):
        repository.get(expected.registration_id)


def test_non_active_never_materializes(storage):
    _, repository = storage
    revoked = item(state=TrustedCovenantRegistrationLifecycle.REVOKED)
    repository.append(revoked)
    with pytest.raises(InvalidTrustedCovenantRegistration):
        repository.get_active_outpoints(revoked.registration_id)
