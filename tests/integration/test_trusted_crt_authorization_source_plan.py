from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.models import Base
from app.services.canonical_admission_edge_storage import SqlAlchemyCanonicalAdmissionEdgeRepository
from app.services.canonical_genesis_record import parse_canonical_genesis_record
from app.services.canonical_genesis_record_storage import SqlAlchemyCanonicalGenesisRecordRepository
from app.services.trusted_covenant_registration_storage import SqlAlchemyTrustedCovenantRegistrationRepository
from app.services.trusted_crt_authorization_source_plan import (
    TrustedCrtAuthorizationSourcePlanAdapter,
    TrustedCrtSourceResolutionState,
)
from tests.unit.test_canonical_admission_edge import edge, genesis, registration


def test_in_memory_sqlalchemy_exact_read_only_resolution():
    engine = create_engine("sqlite:///:memory:")
    event.listen(engine, "connect", lambda connection, _: connection.execute("PRAGMA foreign_keys=ON"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    genesis_repository = SqlAlchemyCanonicalGenesisRecordRepository(factory)
    edge_repository = SqlAlchemyCanonicalAdmissionEdgeRepository(factory)
    registration_repository = SqlAlchemyTrustedCovenantRegistrationRepository(factory)
    genesis_record = parse_canonical_genesis_record(
        Path("docs/data/e923_canonical_genesis_record_v1.json").read_bytes()
    )
    registration_record = registration()
    edge_record = edge(registration_record)
    genesis_repository.append(genesis_record)
    registration_repository.append(registration_record)
    edge_repository.append(edge_record, trusted_registration=registration_record, genesis_evaluation=genesis())
    before = {table.name: _count(factory, table) for table in Base.metadata.sorted_tables}
    result = TrustedCrtAuthorizationSourcePlanAdapter(
        genesis_repository=genesis_repository,
        admission_edge_repository=edge_repository,
        trusted_registration_repository=registration_repository,
    ).resolve(participant_id=edge_record.child_participant_id, target_edge_id=edge_record.edge_id)
    after = {table.name: _count(factory, table) for table in Base.metadata.sorted_tables}
    assert result.state is TrustedCrtSourceResolutionState.READY
    assert result.plan.genesis_records == (genesis_record,)
    assert result.plan.lineage_sources[0].edge == edge_record
    assert before == after


def _count(factory, table):
    with factory() as session:
        return session.query(table).count()
