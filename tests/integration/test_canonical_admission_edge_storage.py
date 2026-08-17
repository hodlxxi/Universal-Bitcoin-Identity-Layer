import importlib.util
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.models import Base, CanonicalAdmissionEdgeLegRow, CanonicalAdmissionEdgeRow
from app.services.canonical_admission_edge_storage import (
    CanonicalAdmissionEdgeStorageError,
    SqlAlchemyCanonicalAdmissionEdgeRepository,
)

spec = importlib.util.spec_from_file_location("admission_fixtures", Path("tests/unit/test_canonical_admission_edge.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


@pytest.fixture
def store():
    engine = create_engine("sqlite:///:memory:")
    event.listen(engine, "connect", lambda connection, _: connection.execute("PRAGMA foreign_keys=ON"))
    Base.metadata.create_all(engine)
    return SqlAlchemyCanonicalAdmissionEdgeRepository(sessionmaker(bind=engine))


def test_append_round_trip_and_deterministic_lookups(store):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    assert store.get(item.edge_id) == item
    assert store.list_for_graph(item.graph_or_protocol_id) == (item,)
    assert store.list_for_child(item.graph_or_protocol_id, item.child_x_only_public_key) == (item,)
    assert store.list_for_sponsor(item.graph_or_protocol_id, item.sponsor_x_only_public_key) == (item,)
    assert store.get_effective_for_child(item.graph_or_protocol_id, item.child_x_only_public_key) == item


def test_duplicate_append_rolls_back_with_bounded_error(store):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with pytest.raises(CanonicalAdmissionEdgeStorageError) as caught:
        store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    assert str(caught.value) == "canonical admission edge storage unavailable"
    assert store.list_for_graph(item.graph_or_protocol_id) == (item,)


def test_tampered_parent_and_leg_rows_fail_closed(store):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    factory = store._session_factory
    with factory() as session:
        session.query(CanonicalAdmissionEdgeRow).filter_by(edge_id=item.edge_id).update(
            {"validator_version": "tampered.validator.v1"}
        )
        session.commit()
    with pytest.raises(CanonicalAdmissionEdgeStorageError):
        store.get(item.edge_id)

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    second = SqlAlchemyCanonicalAdmissionEdgeRepository(sessionmaker(bind=engine))
    second.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with second._session_factory() as session:
        session.query(CanonicalAdmissionEdgeLegRow).filter_by(edge_id=item.edge_id).first().amount_sats += 1
        session.commit()
    with pytest.raises(CanonicalAdmissionEdgeStorageError):
        second.get(item.edge_id)


def test_missing_leg_fails_closed(store):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with store._session_factory() as session:
        session.delete(session.query(CanonicalAdmissionEdgeLegRow).filter_by(edge_id=item.edge_id).first())
        session.commit()
    with pytest.raises(CanonicalAdmissionEdgeStorageError):
        store.get(item.edge_id)


@pytest.mark.parametrize(
    ("column", "value"),
    (
        ("canonical_record_json", "{}"),
        ("canonical_edge_sha256", "0" * 64),
    ),
)
def test_tampered_canonical_parent_fields_fail_closed(store, column, value):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with store._session_factory() as session:
        session.query(CanonicalAdmissionEdgeRow).filter_by(edge_id=item.edge_id).update({column: value})
        session.commit()
    with pytest.raises(CanonicalAdmissionEdgeStorageError):
        store.get(item.edge_id)


@pytest.mark.parametrize(
    ("column", "value"),
    (
        ("txid", "9" * 64),
        ("amount_sats", 999),
        ("direction", "unknown"),
    ),
)
def test_tampered_leg_rows_fail_closed(store, column, value):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with store._session_factory() as session:
        row = session.query(CanonicalAdmissionEdgeLegRow).filter_by(edge_id=item.edge_id).first()
        if column == "direction":
            # SQLite checks prevent an unknown direction, proving the database layer.
            row.direction = value
            with pytest.raises(IntegrityError):
                session.commit()
            return
        setattr(row, column, value)
        session.commit()
    with pytest.raises(CanonicalAdmissionEdgeStorageError):
        store.get(item.edge_id)


def test_source_revalidation_precedes_append(store):
    item, reg = fixtures.edge(), fixtures.registration()
    with pytest.raises(CanonicalAdmissionEdgeStorageError):
        store.append(
            item,
            trusted_registration=replace(reg, registration_id="00000000-0000-4000-8000-000000000099"),
            genesis_evaluation=fixtures.genesis(),
        )
    assert store.list_for_graph(item.graph_or_protocol_id) == ()


def test_database_rejects_arbitrary_participant_alias(store):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with store._session_factory() as session:
        with pytest.raises(IntegrityError):
            session.query(CanonicalAdmissionEdgeRow).filter_by(edge_id=item.edge_id).update(
                {"child_participant_id": "1" * 64}
            )


def test_duplicate_registration_digest_and_global_outpoint_constraints(store):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with store._session_factory() as session:
        row = session.query(CanonicalAdmissionEdgeRow).filter_by(edge_id=item.edge_id).one()
        clone = CanonicalAdmissionEdgeRow(
            **{
                column.name: getattr(row, column.name)
                for column in CanonicalAdmissionEdgeRow.__table__.columns
                if column.name not in {"edge_id", "trusted_registration_id", "canonical_edge_sha256"}
            },
            edge_id="00000000-0000-4000-8000-000000000099",
            trusted_registration_id="00000000-0000-4000-8000-000000000098",
            canonical_edge_sha256="9" * 64,
        )
        session.add(clone)
        with pytest.raises(IntegrityError):
            session.commit()


def test_parent_delete_is_restricted_and_cannot_erase_leg_history(store):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with store._session_factory() as session:
        parent = session.query(CanonicalAdmissionEdgeRow).filter_by(edge_id=item.edge_id).one()
        session.delete(parent)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        assert session.query(CanonicalAdmissionEdgeLegRow).filter_by(edge_id=item.edge_id).count() == 2


def test_relationship_and_repository_are_append_only():
    cascade = CanonicalAdmissionEdgeRow.legs.property.cascade
    assert "delete-orphan" not in cascade
    assert "delete" not in cascade
    for name in ("update", "delete"):
        assert not hasattr(SqlAlchemyCanonicalAdmissionEdgeRepository, name)


def test_third_leg_database_rejected_by_direction_uniqueness(store):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with store._session_factory() as session:
        original = session.query(CanonicalAdmissionEdgeLegRow).filter_by(edge_id=item.edge_id).first()
        session.add(
            CanonicalAdmissionEdgeLegRow(
                **{
                    column.name: getattr(original, column.name)
                    for column in CanonicalAdmissionEdgeLegRow.__table__.columns
                    if column.name != "id"
                }
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()


def _parent_clone(row, *, suffix, **changes):
    values = {column.name: getattr(row, column.name) for column in CanonicalAdmissionEdgeRow.__table__.columns}
    values.update(
        edge_id=f"00000000-0000-4000-8000-{suffix:012d}",
        trusted_registration_id=f"10000000-0000-4000-8000-{suffix:012d}",
        trusted_registration_sha256=f"{suffix:064x}",
        canonical_edge_sha256=f"{suffix + 100:064x}",
        canonical_record_json=f'{{"synthetic_clone":{suffix}}}',
    )
    values.update(changes)
    return CanonicalAdmissionEdgeRow(**values)


@pytest.mark.parametrize("same_field", ("child_participant_id", "child_x_only_public_key"))
def test_second_effective_edge_for_same_child_identity_rejected(store, same_field):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with store._session_factory() as session:
        row = session.query(CanonicalAdmissionEdgeRow).filter_by(edge_id=item.edge_id).one()
        changes = {
            "child_participant_id": row.child_participant_id,
            "child_x_only_public_key": row.child_x_only_public_key,
        }
        # The adopted convention ties both columns, so each partial index protects
        # the same authoritative identity independently.
        clone = _parent_clone(row, suffix=201, **changes)
        session.add(clone)
        with pytest.raises(IntegrityError):
            session.commit()


def test_one_sponsor_may_have_two_distinct_effective_children(store):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with store._session_factory() as session:
        row = session.query(CanonicalAdmissionEdgeRow).filter_by(edge_id=item.edge_id).one()
        other_key = fixtures.GRANDCHILD[2:]
        clone = _parent_clone(
            row,
            suffix=202,
            child_participant_id=other_key,
            child_compressed_public_key=fixtures.GRANDCHILD,
            child_x_only_public_key=other_key,
        )
        session.add(clone)
        session.commit()
        assert (
            session.query(CanonicalAdmissionEdgeRow)
            .filter_by(
                sponsor_x_only_public_key=row.sponsor_x_only_public_key,
                lifecycle_state="effective",
            )
            .count()
            == 2
        )


@pytest.mark.parametrize(
    "state",
    ("proposed", "disputed", "revoked", "superseded"),
)
def test_historical_non_effective_rows_are_append_preserved(store, state):
    item, reg, genesis = fixtures.edge(), fixtures.registration(), fixtures.genesis()
    store.append(item, trusted_registration=reg, genesis_evaluation=genesis)
    with store._session_factory() as session:
        row = session.query(CanonicalAdmissionEdgeRow).filter_by(edge_id=item.edge_id).one()
        changes = dict(lifecycle_state=state, effective_at=None)
        if state == "proposed":
            changes["superseded_by_edge_id"] = None
        elif state == "superseded":
            changes["superseded_by_edge_id"] = "00000000-0000-4000-8000-000000000299"
        else:
            changes["superseded_by_edge_id"] = None
        session.add(_parent_clone(row, suffix=210 + len(state), **changes))
        session.commit()
        assert session.query(CanonicalAdmissionEdgeRow).filter_by(lifecycle_state=state).count() == 1
