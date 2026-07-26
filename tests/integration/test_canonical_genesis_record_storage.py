from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.models import Base, CanonicalGenesisRecordRow
from app.services.canonical_genesis_record import parse_canonical_genesis_record
from app.services.canonical_genesis_record_storage import (
    CanonicalGenesisRecordStorageError,
    SqlAlchemyCanonicalGenesisRecordRepository,
)


def item():
    return parse_canonical_genesis_record(Path("docs/data/e923_canonical_genesis_record_v1.json").read_bytes())


@pytest.fixture
def storage():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine, SqlAlchemyCanonicalGenesisRecordRepository(sessionmaker(bind=engine, expire_on_commit=False))


def test_append_get_list_round_trip_and_no_autoinsert(storage):
    _, repository = storage
    expected = item()
    assert repository.get(expected.record_id) is None
    assert repository.list_for_graph(expected.graph_or_protocol_id) == ()
    repository.append(expected)
    assert repository.get(expected.record_id) == expected
    assert repository.list_for_graph(expected.graph_or_protocol_id) == (expected,)


def test_multiple_history_allowed_and_ordered(storage):
    _, repository = storage
    first = item()
    second = replace(first, record_id="e9230000-0000-4000-8000-000000000002")
    repository.append(second)
    repository.append(first)
    assert repository.list_for_graph(first.graph_or_protocol_id) == (first, second)


@pytest.mark.parametrize("column", ("canonical_record_sha256", "canonical_record_json", "network"))
def test_malformed_persistence_fails_closed(storage, column):
    engine, repository = storage
    expected = item()
    repository.append(expected)
    with engine.begin() as connection:
        connection.execute(text("PRAGMA ignore_check_constraints = ON"))
        if column == "canonical_record_json":
            connection.execute(text("UPDATE canonical_genesis_records SET canonical_record_json='{}'"))
        elif column == "network":
            connection.execute(text("UPDATE canonical_genesis_records SET graph_or_protocol_id='other'"))
        else:
            connection.execute(
                text("UPDATE canonical_genesis_records " "SET canonical_record_sha256=:digest"),
                {"digest": "f" * 64},
            )
    with pytest.raises(CanonicalGenesisRecordStorageError):
        repository.get(expected.record_id)


def test_duplicate_id_rolls_back_without_raw_details(storage):
    _, repository = storage
    expected = item()
    repository.append(expected)
    with pytest.raises(CanonicalGenesisRecordStorageError, match="storage unavailable") as error:
        repository.append(expected)
    assert "UNIQUE" not in str(error.value)
    assert repository.list_for_graph(expected.graph_or_protocol_id) == (expected,)


def test_duplicate_digest_database_constraint_rolls_back_and_preserves_first(storage):
    engine, repository = storage
    expected = item()
    repository.append(expected)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    first = session.query(CanonicalGenesisRecordRow).one()
    values = {column.name: getattr(first, column.name) for column in CanonicalGenesisRecordRow.__table__.columns}
    values["record_id"] = "e9230000-0000-4000-8000-000000000002"
    session.add(CanonicalGenesisRecordRow(**values))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    assert session.query(CanonicalGenesisRecordRow).count() == 1
    assert session.query(CanonicalGenesisRecordRow).one().record_id == expected.record_id
    session.close()
    assert repository.get(expected.record_id) == expected
    assert repository.get(values["record_id"]) is None


def test_database_rejects_revoked_record_with_successor(storage):
    engine, repository = storage
    expected = item()
    repository.append(expected)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    first = session.query(CanonicalGenesisRecordRow).one()
    values = {column.name: getattr(first, column.name) for column in CanonicalGenesisRecordRow.__table__.columns}
    values.update(
        record_id="e9230000-0000-4000-8000-000000000002",
        lifecycle_state="revoked",
        superseded_by_record_id="e9230000-0000-4000-8000-000000000003",
        canonical_record_sha256="f" * 64,
    )
    session.add(CanonicalGenesisRecordRow(**values))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    assert session.query(CanonicalGenesisRecordRow).count() == 1
    session.close()


def test_commit_failure_rolls_back_and_closes():
    class Session:
        rolled_back = False
        closed = False

        def add(self, _row):
            pass

        def commit(self):
            raise RuntimeError("database detail")

        def rollback(self):
            self.rolled_back = True

        def close(self):
            self.closed = True

    session = Session()
    repository = SqlAlchemyCanonicalGenesisRecordRepository(lambda: session)
    with pytest.raises(CanonicalGenesisRecordStorageError) as error:
        repository.append(item())
    assert "database detail" not in str(error.value)
    assert session.rolled_back and session.closed
