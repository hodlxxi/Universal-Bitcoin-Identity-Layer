"""Disposable PostgreSQL proof for V2 atomic-acceptance durability.

The target must be an explicit freshly created PostgreSQL 16 cluster on
127.0.0.1 and a high port, with Unix sockets disabled. DATABASE_URL and every
configured persistent database are intentionally ignored. The synthetic role
must have only LOGIN plus the predefined read-only pg_read_all_settings role;
the latter is required solely to bind the target to the disposable data path.
An optional direct superuser DSN is accepted only for the hostile SUPPORT
mutation, which PostgreSQL does not permit the function owner to perform.
"""

from __future__ import annotations

import copy
import os
import re
import struct
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.services import social_messaging_device_verification_deadline_evidence_v1 as deadline
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_contract as contract
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as storage
from app.services import social_preaccepted_enrollment_verification_statement_v2 as verification
from tests.unit import test_social_preaccepted_enrollment_v2_atomic_acceptance_contract as vectors
from tests.unit.test_social_preaccepted_enrollment_v2_atomic_acceptance_storage import (
    accepted_row,
    changed_observation_challenge_revision_accepted_row,
    changed_observation_time_accepted_row,
    forged_evidence_mismatched_accepted_row,
    forged_statement_signature_accepted_row,
    pending_row,
)

ROOT = Path(__file__).parents[2]
MIGRATION = ROOT / "migrations/2026-10-02_social_preaccepted_enrollment_v2_atomic_acceptance_storage_v1.sql"
PREFIX = "HODLXXI_SOCIAL_V2_ATOMIC_ACCEPTANCE_POSTGRES_"
ACK = "DISPOSABLE-SOCIAL-V2-ATOMIC-ACCEPTANCE-POSTGRES-V1"
ERROR = "^social preaccepted enrollment v2 atomic acceptance storage unavailable$"
RESERVATION_ID = contract.parse_atomic_acceptance_reservation_v1(
    vectors.VECTOR["pendingReservationWire"]
).reservation_id
MIGRATION_ROLE = "social_v2_atomic_acceptance_migration_owner"
RUNTIME_ROLE = "social_v2_atomic_acceptance_runtime"

_LIVE_GUARD_DEFINITION_PAYLOAD_SHAPE = {
    "function": {
        "allArgumentTypes": None,
        "argumentCount": None,
        "argumentDefaults": None,
        "argumentModes": None,
        "argumentNames": None,
        "argumentTypeOids": None,
        "binary": None,
        "config": None,
        "cost": None,
        "defaultArgumentCount": None,
        "kind": None,
        "language": None,
        "leakproof": None,
        "name": None,
        "parallel": None,
        "returnType": None,
        "returnsSet": None,
        "rows": None,
        "securityDefiner": None,
        "source": None,
        "sqlBody": None,
        "strict": None,
        "supportFunctionOid": None,
        "transformTypes": None,
        "variadicTypeOid": None,
        "volatility": None,
    },
    "relation": {
        "accessMethod": None,
        "checkConstraintCount": None,
        "columnCount": None,
        "forceRowSecurity": None,
        "hasIndexes": None,
        "hasRules": None,
        "hasSubclasses": None,
        "hasTriggers": None,
        "isPartition": None,
        "isPopulated": None,
        "isShared": None,
        "kind": None,
        "name": None,
        "ofTypeOid": None,
        "options": None,
        "partitionBound": None,
        "persistence": None,
        "replicaIdentity": None,
        "rowSecurity": None,
        "tablespaceOid": None,
        "toast": {
            "accessMethod": None,
            "checkConstraintCount": None,
            "columnCount": None,
            "forceRowSecurity": None,
            "hasIndexes": None,
            "hasRules": None,
            "hasSubclasses": None,
            "hasTriggers": None,
            "isPartition": None,
            "isPopulated": None,
            "isShared": None,
            "kind": None,
            "nameMatchesRelationOid": None,
            "namespace": None,
            "ofTypeOid": None,
            "options": None,
            "partitionBound": None,
            "persistence": None,
            "replicaIdentity": None,
            "rowSecurity": None,
            "rowTypeOid": None,
            "tablespaceOid": None,
        },
    },
    "triggers": [
        {
            "argumentCount": None,
            "argumentsHex": None,
            "attributes": None,
            "constraintIndexOid": None,
            "constraintOid": None,
            "constraintRelationOid": None,
            "deferrable": None,
            "enabled": None,
            "functionMatches": None,
            "initiallyDeferred": None,
            "internal": None,
            "name": None,
            "newTable": None,
            "oldTable": None,
            "parentOid": None,
            "qualification": None,
            "type": None,
        },
        {
            "argumentCount": None,
            "argumentsHex": None,
            "attributes": None,
            "constraintIndexOid": None,
            "constraintOid": None,
            "constraintRelationOid": None,
            "deferrable": None,
            "enabled": None,
            "functionMatches": None,
            "initiallyDeferred": None,
            "internal": None,
            "name": None,
            "newTable": None,
            "oldTable": None,
            "parentOid": None,
            "qualification": None,
            "type": None,
        },
    ],
}


def _recursive_payload_key_shape(value: object) -> object:
    if type(value) is dict:
        return {key: _recursive_payload_key_shape(item) for key, item in value.items()}  # type: ignore[union-attr]
    if type(value) is list and value and all(type(item) is dict for item in value):
        return [_recursive_payload_key_shape(item) for item in value]
    return None


def _assert_live_guard_definition_payload_shape(payload: object) -> None:
    assert _recursive_payload_key_shape(payload) == _LIVE_GUARD_DEFINITION_PAYLOAD_SHAPE


def _migration_for_schema(schema: str) -> str:
    storage._test_only_qualified_table(schema)
    source = MIGRATION.read_text(encoding="ascii")
    production_prefix = f'"{storage.SCHEMA}".'
    assert production_prefix in source
    return source.replace(production_prefix, f'"{schema}".')


def _apply(connection, *, schema: str) -> None:
    with connection.connection.driver_connection.cursor() as cursor:
        cursor.execute(_migration_for_schema(schema))


def _restore_guard_function(connection, *, schema: str) -> None:
    migration = _migration_for_schema(schema)
    definition = re.search(
        rf'CREATE FUNCTION "{schema}"\."{storage.GUARD_FUNCTION}"\(\).*?\$\$;',
        migration,
        re.DOTALL,
    )
    assert definition is not None
    statement = definition.group(0).replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
    with connection.connection.driver_connection.cursor() as cursor:
        cursor.execute(statement)


def _exact_trigger_definition(schema: str, name: str) -> str:
    if name == storage.GUARD_TRIGGER:
        return (
            f'CREATE TRIGGER "{name}" BEFORE INSERT OR UPDATE OR DELETE '
            f'ON "{schema}"."{storage.TABLE}" FOR EACH ROW '
            f'EXECUTE FUNCTION "{schema}"."{storage.GUARD_FUNCTION}"()'
        )
    assert name == storage.NO_TRUNCATE_TRIGGER
    return (
        f'CREATE TRIGGER "{name}" BEFORE TRUNCATE '
        f'ON "{schema}"."{storage.TABLE}" FOR EACH STATEMENT '
        f'EXECUTE FUNCTION "{schema}"."{storage.GUARD_FUNCTION}"()'
    )


def _relation_oid(connection, schema: str):
    return connection.execute(
        text(
            "SELECT relation.oid::bigint FROM pg_catalog.pg_class AS relation "
            "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = :schema AND relation.relname = :table AND relation.relkind = 'r'"
        ),
        {"schema": schema, "table": storage.TABLE},
    ).scalar_one_or_none()


def _function_oid(connection, schema: str):
    return connection.execute(
        text(
            "SELECT function.oid::bigint FROM pg_catalog.pg_proc AS function "
            "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = function.pronamespace "
            "WHERE namespace.nspname = :schema AND function.proname = :function "
            "AND function.pronargs = 0"
        ),
        {"function": storage.GUARD_FUNCTION, "schema": schema},
    ).scalar_one_or_none()


def _trigger_oid(connection, schema: str, name: str):
    return connection.execute(
        text(
            "SELECT trigger.oid::bigint FROM pg_catalog.pg_trigger AS trigger "
            "JOIN pg_catalog.pg_class AS relation ON relation.oid = trigger.tgrelid "
            "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = :schema AND relation.relname = :table "
            "AND trigger.tgname = :trigger"
        ),
        {"schema": schema, "table": storage.TABLE, "trigger": name},
    ).scalar_one_or_none()


@pytest.fixture(scope="module")
def postgres_target():
    runtime_dsn = os.environ.get(PREFIX + "DSN")
    migration_dsn = os.environ.get(PREFIX + "MIGRATION_DSN")
    superuser_dsn = os.environ.get(PREFIX + "SUPERUSER_DSN")
    if not runtime_dsn or not migration_dsn:
        pytest.skip("explicit disposable V2 atomic-acceptance PostgreSQL target not provided")
    assert os.environ.get(PREFIX + "ACK") == ACK
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("hodlxxi-social-v2-atomic-acceptance-")
    assert data.name == "data" and (data / "PG_VERSION").read_text().strip() == "16"
    port = int(os.environ[PREFIX + "PORT"])
    runtime_url = make_url(runtime_dsn)
    migration_url = make_url(migration_dsn)
    assert runtime_url.drivername == migration_url.drivername == "postgresql+psycopg2"
    assert runtime_url.host == migration_url.host == "127.0.0.1"
    assert runtime_url.port == migration_url.port == port and 49152 <= port <= 65535
    assert runtime_url.database == migration_url.database == "hodlxxi_social_v2_atomic_acceptance_test"
    assert runtime_url.username == RUNTIME_ROLE
    assert migration_url.username == MIGRATION_ROLE
    assert runtime_url.password is migration_url.password is None
    assert not runtime_url.query and not migration_url.query
    superuser_url = make_url(superuser_dsn) if superuser_dsn else None
    if superuser_url is not None:
        assert superuser_url.drivername == "postgresql+psycopg2"
        assert superuser_url.host == "127.0.0.1"
        assert superuser_url.port == port
        assert superuser_url.database == runtime_url.database
        assert superuser_url.password is None and not superuser_url.query
    runtime_engine = create_engine(runtime_url, poolclass=NullPool, hide_parameters=True)
    migration_engine = create_engine(migration_url, poolclass=NullPool, hide_parameters=True)
    superuser_engine = (
        create_engine(superuser_url, poolclass=NullPool, hide_parameters=True) if superuser_url is not None else None
    )
    try:
        with runtime_engine.connect() as connection:
            assert connection.execute(
                text("SELECT pg_catalog.pg_has_role(current_user, 'pg_read_all_settings', 'member')")
            ).scalar_one()
            identity = connection.execute(
                text(
                    "SELECT current_database(), current_setting('data_directory'), "
                    "current_setting('port'), current_setting('listen_addresses'), "
                    "current_setting('unix_socket_directories'), version()"
                )
            ).one()
            assert identity[0] == runtime_url.database
            assert Path(identity[1]).resolve() == data
            assert int(identity[2]) == port
            assert identity[3:5] == ("127.0.0.1", "")
            assert identity[5].startswith("PostgreSQL 16.")
            role = connection.execute(
                text(
                    "SELECT current_user, session_user, rolsuper, rolcreaterole, rolcreatedb, "
                    "rolcanlogin, rolreplication, rolbypassrls, "
                    "ARRAY(SELECT candidate.rolname FROM pg_catalog.pg_roles AS candidate "
                    "WHERE candidate.oid <> runtime.oid "
                    "AND pg_catalog.pg_has_role(runtime.oid, candidate.oid, 'MEMBER') "
                    "ORDER BY candidate.rolname) "
                    "FROM pg_catalog.pg_roles AS runtime WHERE runtime.rolname = current_user"
                )
            ).one()
            assert role == (
                RUNTIME_ROLE,
                RUNTIME_ROLE,
                False,
                False,
                False,
                True,
                False,
                False,
                ["pg_read_all_settings"],
            )
        with migration_engine.connect() as connection:
            assert connection.execute(text("SELECT current_user, session_user")).one() == (
                MIGRATION_ROLE,
                MIGRATION_ROLE,
            )
        if superuser_engine is not None:
            with superuser_engine.connect() as connection:
                assert connection.execute(
                    text(
                        "SELECT current_user = session_user, role.rolsuper "
                        "FROM pg_catalog.pg_roles AS role WHERE role.rolname = current_user"
                    )
                ).one() == (True, True)
        yield runtime_engine, migration_engine, superuser_engine
    finally:
        runtime_engine.dispose()
        migration_engine.dispose()
        if superuser_engine is not None:
            superuser_engine.dispose()


@pytest.fixture
def database(postgres_target):
    runtime_engine, migration_engine, _superuser_engine = postgres_target
    schema = "social_v2_atomic_acceptance_" + uuid.uuid4().hex
    with migration_engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}" AUTHORIZATION "{MIGRATION_ROLE}"')
    engine = create_engine(
        runtime_engine.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"options": "-c statement_timeout=15000 -c lock_timeout=10000"},
    )
    try:
        with migration_engine.connect() as connection:
            transaction = connection.begin()
            _apply(connection, schema=schema)
            assert _relation_oid(connection, schema) is not None
            transaction.rollback()
            assert _relation_oid(connection, schema) is None
            connection.rollback()
        with migration_engine.begin() as connection:
            _apply(connection, schema=schema)
            connection.exec_driver_sql(f'REVOKE ALL PRIVILEGES ON SCHEMA "{schema}" FROM PUBLIC')
            connection.exec_driver_sql(f'REVOKE ALL PRIVILEGES ON SCHEMA "{schema}" FROM "{RUNTIME_ROLE}"')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO "{RUNTIME_ROLE}"')
            connection.exec_driver_sql(
                f'GRANT SELECT, INSERT, UPDATE ON TABLE "{schema}"."{storage.TABLE}" TO "{RUNTIME_ROLE}"'
            )
            connection.exec_driver_sql(
                f'REVOKE ALL PRIVILEGES ON FUNCTION "{schema}"."{storage.GUARD_FUNCTION}"() ' f'FROM "{RUNTIME_ROLE}"'
            )
        yield engine, sessionmaker(engine, expire_on_commit=False), schema, migration_engine
    finally:
        engine.dispose()
        with migration_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')


def _owner(session, schema: str):
    return storage.SqlAlchemyTransactionBoundAtomicAcceptanceStorage._for_test_schema(
        session,
        schema=schema,
    )


def _reserve(session, schema: str, *, now=None):
    return _owner(session, schema).reserve_pending(
        evidence_compact_jws=vectors.evidence_compact(),
        evidence_config=vectors.evidence_config(),
        expected_input_wire=vectors.INPUT_WIRE,
        observed_at=vectors.EVIDENCE["deadlines"]["observedAt"],
        challenge_revision=1,
        now=now,
    )


def _finalize(session, schema: str, *, observation=None, statement=None, decided_at=None):
    return _owner(session, schema).finalize_accepted(
        RESERVATION_ID,
        finalization_observation_wire=observation or vectors.VECTOR["finalizationObservationWire"],
        expected_input_wire=vectors.INPUT_WIRE,
        expected_context_wire=vectors.CONTEXT_WIRE,
        evidence_compact_jws=vectors.evidence_compact(),
        evidence_config=vectors.evidence_config(),
        statement_compact_jws=statement or vectors.STATEMENT["vector"]["compactJws"],
        statement_config=vectors.statement_config(),
        decided_at=vectors.VECTOR["decidedAt"] if decided_at is None else decided_at,
    )


def _count(factory, schema: str) -> int:
    table = storage._test_only_qualified_table(schema)
    with factory.begin() as session:
        return session.scalar(select(func.count()).select_from(table))


def test_exact_pending_and_accepted_retry_return_one_durable_identity(database):
    _engine, factory, schema, _migration_engine = database
    with factory.begin() as session:
        first = _reserve(session, schema)
    with factory.begin() as session:
        pending_retry = _reserve(session, schema, now=first.reservation.created_at + 1)
    assert pending_retry.reservation.wire == first.reservation.wire
    assert pending_retry.evidence_compact_jws == first.evidence_compact_jws

    with factory.begin() as session:
        accepted = _finalize(session, schema)
    with factory.begin() as session:
        retry = _owner(session, schema).reconcile_exact(
            accepted.reservation.reservation_id,
            expected_input_wire=vectors.INPUT_WIRE,
            evidence_compact_jws=vectors.evidence_compact(),
            evidence_config=vectors.evidence_config(),
            statement_config=vectors.statement_config(),
            statement_compact_jws=vectors.STATEMENT["vector"]["compactJws"],
            now=accepted.reservation.decided_at + 1,
        )
    assert retry.reservation.wire == accepted.reservation.wire
    assert retry.effect.wire == accepted.effect.wire
    assert retry.receipt.wire == accepted.receipt.wire
    assert _count(factory, schema) == 1


def test_changed_input_statement_observation_effect_or_receipt_identity_denies(database):
    _engine, factory, schema, _migration_engine = database
    with factory.begin() as session:
        pending = _reserve(session, schema)
    changed_input = vectors.INPUT_WIRE[:-1] + (" " if vectors.INPUT_WIRE[-1] != " " else "x")
    with factory.begin() as session:
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            _owner(session, schema).reconcile_exact(
                pending.reservation.reservation_id,
                expected_input_wire=changed_input,
                evidence_compact_jws=vectors.evidence_compact(),
                evidence_config=vectors.evidence_config(),
                now=pending.reservation.created_at,
            )
    with factory.begin() as session:
        accepted = _finalize(session, schema)
    changed_observation = vectors.changed_wire(
        vectors.VECTOR["finalizationObservationWire"],
        associationState="active",
    )
    original_statement = vectors.STATEMENT["vector"]["compactJws"]
    changed_statement = original_statement[:-1] + ("A" if original_statement[-1] != "A" else "B")
    with factory.begin() as session:
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            _finalize(session, schema, observation=changed_observation)
    with factory.begin() as session:
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            _owner(session, schema).reconcile_exact(
                accepted.reservation.reservation_id,
                expected_input_wire=vectors.INPUT_WIRE,
                evidence_compact_jws=vectors.evidence_compact(),
                evidence_config=vectors.evidence_config(),
                statement_config=vectors.statement_config(),
                statement_compact_jws=changed_statement,
                now=accepted.reservation.decided_at,
            )
    with pytest.raises(Exception):
        with factory.begin() as session:
            session.execute(
                update(storage._test_only_qualified_table(schema)).values(effect_wire="{}", receipt_wire="{}")
            )
    assert _count(factory, schema) == 1


def test_full_proof_forgery_with_recomputed_effect_and_receipt_fails_both_boundaries(database):
    _engine, factory, schema, _migration_engine = database
    forged = forged_evidence_mismatched_accepted_row()
    with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
        storage.parse_stored_atomic_acceptance_v1(
            forged,
            evidence_config=vectors.evidence_config(),
            statement_config=vectors.statement_config(),
        )
    with factory.begin() as session:
        pending = _reserve(session, schema)
    table = storage._test_only_qualified_table(schema)
    with pytest.raises(Exception):
        with factory.begin() as session:
            session.execute(
                update(table).where(table.c.reservation_id == pending.reservation.reservation_id).values(**forged)
            )
    with factory.begin() as session:
        row = session.execute(select(table)).mappings().one()
        stored = storage.parse_stored_atomic_acceptance_v1(
            row,
            evidence_config=vectors.evidence_config(),
        )
    assert stored.reservation.state == "pending"


@pytest.mark.parametrize(
    "builder",
    (
        changed_observation_challenge_revision_accepted_row,
        changed_observation_time_accepted_row,
    ),
)
def test_postgresql_retains_complete_observation_binding(database, builder):
    _engine, factory, schema, _migration_engine = database
    with factory.begin() as session:
        pending = _reserve(session, schema)
    corrupt = builder()
    table = storage._test_only_qualified_table(schema)
    with pytest.raises(Exception):
        with factory.begin() as session:
            session.execute(
                update(table).where(table.c.reservation_id == pending.reservation.reservation_id).values(**corrupt)
            )
    with factory.begin() as session:
        assert session.scalar(select(table.c.state)) == "pending"


def test_direct_sql_forged_statement_row_is_rejected_by_both_application_verifiers(database):
    _engine, factory, schema, _migration_engine = database
    forged = forged_statement_signature_accepted_row()
    authenticated_evidence = deadline.verify_messaging_device_verification_deadline_evidence_v1(
        vectors.evidence_compact(),
        config=vectors.evidence_config(),
        expected_input_wire=vectors.INPUT_WIRE,
        now=vectors.VECTOR["decidedAt"],
    )
    claims = authenticated_evidence.claims
    with pytest.raises(verification.SocialPreacceptedEnrollmentVerificationStatementV2Denied):
        verification.verify_social_preaccepted_enrollment_verification_statement_v2(
            forged["statement_compact_jws"],
            config=vectors.statement_config(),
            expected_context_wire=vectors.CONTEXT_WIRE,
            expected_input_wire=vectors.INPUT_WIRE,
            now=vectors.VECTOR["decidedAt"],
            phone_session_expires_at_ms=claims.phone_session_expires_at,
            approver_session_expires_at_ms=claims.approver_session_expires_at,
            full_expires_at_ms=claims.full_expires_at,
            x25519_binding_expires_at_ms=claims.x25519_binding_expires_at,
        )
    with factory.begin() as session:
        pending = _reserve(session, schema)
    table = storage._test_only_qualified_table(schema)
    with factory.begin() as session:
        session.execute(
            update(table).where(table.c.reservation_id == pending.reservation.reservation_id).values(**forged)
        )
    with factory.begin() as session:
        row = session.execute(select(table)).mappings().one()
        assert row["state"] == "accepted"
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            storage.parse_stored_atomic_acceptance_v1(
                row,
                evidence_config=vectors.evidence_config(),
                statement_config=vectors.statement_config(),
            )


def test_leading_ascii_space_observation_is_rejected_by_postgresql(database):
    _engine, factory, schema, _migration_engine = database
    with factory.begin() as session:
        pending = _reserve(session, schema)
    noncanonical = accepted_row()
    noncanonical["finalization_observation_wire"] = " " + str(noncanonical["finalization_observation_wire"])
    table = storage._test_only_qualified_table(schema)
    with pytest.raises(Exception):
        with factory.begin() as session:
            session.execute(
                update(table).where(table.c.reservation_id == pending.reservation.reservation_id).values(**noncanonical)
            )
    assert _count(factory, schema) == 1


def test_hostile_search_path_and_shadow_relation_functions_cannot_redirect_guard(database):
    engine, factory, schema, migration_engine = database
    shadow = "shadow_" + uuid.uuid4().hex
    table_name = storage.TABLE
    function_name = storage.GUARD_FUNCTION
    with migration_engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{shadow}"')
        connection.exec_driver_sql(
            f'CREATE TABLE "{shadow}"."{table_name}" ' f'(LIKE "{schema}"."{table_name}" INCLUDING ALL)'
        )
        connection.exec_driver_sql(
            f'CREATE FUNCTION "{shadow}"."{function_name}"() RETURNS trigger '
            "LANGUAGE plpgsql SET search_path = pg_catalog "
            "AS $$ BEGIN IF TG_OP = 'DELETE' THEN RETURN OLD; END IF; RETURN NEW; END $$"
        )
        connection.exec_driver_sql(
            f'CREATE TRIGGER "{storage.GUARD_TRIGGER}" BEFORE INSERT OR UPDATE OR DELETE '
            f'ON "{shadow}"."{table_name}" FOR EACH ROW '
            f'EXECUTE FUNCTION "{shadow}"."{function_name}"()'
        )
        connection.exec_driver_sql(
            f'CREATE TRIGGER "{storage.NO_TRUNCATE_TRIGGER}" BEFORE TRUNCATE '
            f'ON "{shadow}"."{table_name}" FOR EACH STATEMENT '
            f'EXECUTE FUNCTION "{shadow}"."{function_name}"()'
        )
    try:
        with factory.begin() as session:
            session.execute(text(f'SET LOCAL search_path = "{shadow}", "{schema}", pg_catalog'))
            with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
                storage.SqlAlchemyTransactionBoundAtomicAcceptanceStorage(session)
        with factory.begin() as session:
            session.execute(text(f'SET LOCAL search_path = "{shadow}", "{schema}", pg_catalog'))
            owner = _owner(session, schema)
            stored = owner.reserve_pending(
                evidence_compact_jws=vectors.evidence_compact(),
                evidence_config=vectors.evidence_config(),
                expected_input_wire=vectors.INPUT_WIRE,
                observed_at=vectors.EVIDENCE["deadlines"]["observedAt"],
                challenge_revision=1,
            )
            target_oid = _relation_oid(session.connection(), schema)
            shadow_oid = _relation_oid(session.connection(), shadow)
            function_oids = dict(
                session.execute(
                    text(
                        "SELECT namespace.nspname, function.oid::bigint "
                        "FROM pg_catalog.pg_proc AS function "
                        "JOIN pg_catalog.pg_namespace AS namespace "
                        "ON namespace.oid = function.pronamespace "
                        "WHERE namespace.nspname IN (:target, :shadow) "
                        "AND function.proname = :function"
                    ),
                    {"function": function_name, "shadow": shadow, "target": schema},
                ).all()
            )
            assert owner._relation_oid == target_oid != shadow_oid
            assert owner._trigger_function_oid == function_oids[schema] != function_oids[shadow]
            assert stored.reservation.reservation_id == RESERVATION_ID
            target_count = session.scalar(select(func.count()).select_from(storage._test_only_qualified_table(schema)))
            assert target_count == 1
        with migration_engine.connect() as connection:
            shadow_count = connection.scalar(
                select(func.count()).select_from(storage._test_only_qualified_table(shadow))
            )
            assert shadow_count == 0
    finally:
        with migration_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{shadow}" CASCADE')


def test_runtime_role_is_least_privilege_and_cannot_attempt_authoritative_ddl(database):
    engine, factory, schema, migration_engine = database
    with factory.begin() as session:
        owner = _owner(session, schema)
        owners = session.execute(
            text(
                "SELECT relation_owner.rolname, function_owner.rolname, "
                "pg_catalog.pg_has_role(current_user, relation_owner.oid, 'MEMBER'), "
                "pg_catalog.pg_has_role(current_user, function_owner.oid, 'MEMBER') "
                "FROM pg_catalog.pg_roles AS relation_owner, pg_catalog.pg_roles AS function_owner "
                "WHERE relation_owner.oid = CAST(:relation_owner_oid AS oid) "
                "AND function_owner.oid = CAST(:function_owner_oid AS oid)"
            ),
            {
                "function_owner_oid": owner._trigger_function_owner_oid,
                "relation_owner_oid": owner._relation_owner_oid,
            },
        ).one()
        assert owners == (MIGRATION_ROLE, MIGRATION_ROLE, False, False)
        privileges = session.execute(
            text(
                "SELECT pg_catalog.has_schema_privilege(current_user, :schema, 'USAGE'), "
                "pg_catalog.has_schema_privilege(current_user, :schema, 'CREATE'), "
                "pg_catalog.has_table_privilege(current_user, :table, 'SELECT'), "
                "pg_catalog.has_table_privilege(current_user, :table, 'INSERT'), "
                "pg_catalog.has_table_privilege(current_user, :table, 'UPDATE'), "
                "pg_catalog.has_table_privilege(current_user, :table, 'DELETE'), "
                "pg_catalog.has_table_privilege(current_user, :table, 'TRUNCATE'), "
                "pg_catalog.has_table_privilege(current_user, :table, 'TRIGGER'), "
                "pg_catalog.has_function_privilege(current_user, :function, 'EXECUTE')"
            ),
            {
                "function": f'"{schema}"."{storage.GUARD_FUNCTION}"()',
                "schema": schema,
                "table": f'"{schema}"."{storage.TABLE}"',
            },
        ).one()
        assert privileges == (True, False, True, True, True, False, False, False, False)
    with pytest.raises(Exception):
        with engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE TABLE "{schema}"."runtime_ddl_denied" (id INTEGER)')
    with pytest.raises(Exception):
        with engine.begin() as connection:
            connection.exec_driver_sql(
                f'CREATE OR REPLACE FUNCTION "{schema}"."{storage.GUARD_FUNCTION}"() RETURNS trigger '
                "LANGUAGE plpgsql SET search_path = pg_catalog AS $$ BEGIN RETURN NEW; END $$"
            )
    runtime_definition_ddl = (
        f'ALTER FUNCTION "{schema}"."{storage.GUARD_FUNCTION}"() COST 1',
        f'ALTER TABLE "{schema}"."{storage.TABLE}" SET (fillfactor=80)',
        f'DROP TRIGGER "{storage.GUARD_TRIGGER}" ON "{schema}"."{storage.TABLE}"',
    )
    for statement in runtime_definition_ddl:
        with pytest.raises(Exception):
            with engine.begin() as connection:
                connection.exec_driver_sql(statement)
    with factory.begin() as session:
        _owner(session, schema)._check_transaction()
    with migration_engine.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_catalog.pg_class AS relation "
                    "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = :schema AND relation.relname = 'runtime_ddl_denied'"
                ),
                {"schema": schema},
            ).scalar_one()
            == 0
        )


def test_recheck_denies_same_oid_trigger_replacement_with_qualification(database):
    _engine, factory, schema, migration_engine = database
    with factory.begin() as session:
        owner = _owner(session, schema)
        original_oid = _trigger_oid(session.connection(), schema, storage.GUARD_TRIGGER)
        with migration_engine.begin() as connection:
            connection.exec_driver_sql(
                f'CREATE OR REPLACE TRIGGER "{storage.GUARD_TRIGGER}" '
                f'BEFORE INSERT OR UPDATE OR DELETE ON "{schema}"."{storage.TABLE}" '
                f'FOR EACH ROW WHEN (false) EXECUTE FUNCTION "{schema}"."{storage.GUARD_FUNCTION}"()'
            )
            assert _trigger_oid(connection, schema, storage.GUARD_TRIGGER) == original_oid
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            owner.reserve_pending(
                evidence_compact_jws=vectors.evidence_compact(),
                evidence_config=vectors.evidence_config(),
                expected_input_wire=vectors.INPUT_WIRE,
                observed_at=vectors.EVIDENCE["deadlines"]["observedAt"],
                challenge_revision=1,
            )


def test_recheck_denies_same_oid_permissive_function_replacement(database):
    _engine, factory, schema, migration_engine = database
    with factory.begin() as session:
        owner = _owner(session, schema)
        original_oid = _function_oid(session.connection(), schema)
        with migration_engine.begin() as connection:
            connection.exec_driver_sql(
                f'CREATE OR REPLACE FUNCTION "{schema}"."{storage.GUARD_FUNCTION}"() RETURNS trigger '
                "LANGUAGE plpgsql SET search_path = pg_catalog "
                "AS $$ BEGIN IF TG_OP = 'DELETE' THEN RETURN OLD; END IF; RETURN NEW; END $$"
            )
            assert _function_oid(connection, schema) == original_oid
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            owner.reserve_pending(
                evidence_compact_jws=vectors.evidence_compact(),
                evidence_config=vectors.evidence_config(),
                expected_input_wire=vectors.INPUT_WIRE,
                observed_at=vectors.EVIDENCE["deadlines"]["observedAt"],
                challenge_revision=1,
            )


def test_complete_catalog_payload_and_cached_identities_are_canonical(database):
    _engine, factory, schema, _migration_engine = database
    with factory.begin() as session:
        owner = _owner(session, schema)
        catalog = session.execute(
            text(
                "SELECT pg_catalog.encode(pg_catalog.float4send(function.procost), 'hex'), "
                "pg_catalog.encode(pg_catalog.float4send(function.prorows), 'hex'), "
                "function.prosupport::oid::bigint, relation.reloptions, toast.reloptions "
                "FROM pg_catalog.pg_proc AS function "
                "JOIN pg_catalog.pg_namespace AS function_namespace "
                "ON function_namespace.oid = function.pronamespace "
                "JOIN pg_catalog.pg_class AS relation ON relation.oid = CAST(:relation_oid AS oid) "
                "JOIN pg_catalog.pg_class AS toast ON toast.oid = relation.reltoastrelid "
                "WHERE function_namespace.nspname = :schema "
                "AND function.proname = :function AND function.pronargs = 0"
            ),
            {
                "function": storage.GUARD_FUNCTION,
                "relation_oid": owner._relation_oid,
                "schema": schema,
            },
        ).one()
        assert catalog == ("42c80000", "00000000", 0, None, None)
        assert owner._relation_type_oid is not None and owner._relation_type_oid > 0
        assert owner._toast_relation_oid is not None and owner._toast_relation_oid > 0
        assert owner._toast_relation_owner_oid == owner._relation_owner_oid
        assert owner._trigger_oids == tuple(
            (name, _trigger_oid(session.connection(), schema, name))
            for name in sorted((storage.GUARD_TRIGGER, storage.NO_TRUNCATE_TRIGGER))
        )
        assert owner._guard_definition_sha256 == storage.GUARD_DEFINITION_SHA256
        owner._check_transaction()


def test_function_cost_mutation_is_rejected_and_rollback_preserves_owner(database):
    _engine, factory, schema, migration_engine = database
    qualified_function = f'"{schema}"."{storage.GUARD_FUNCTION}"()'
    with factory() as session:
        transaction = session.begin()
        owner = _owner(session, schema)
        function_oid = owner._trigger_function_oid
        with migration_engine.connect() as connection:
            mutation = connection.begin()
            connection.exec_driver_sql(f"ALTER FUNCTION {qualified_function} COST 1")
            assert _function_oid(connection, schema) == function_oid
            mutation.rollback()
        owner._check_transaction()
        transaction.rollback()
    with factory() as session:
        transaction = session.begin()
        owner = _owner(session, schema)
        with migration_engine.begin() as connection:
            connection.exec_driver_sql(f"ALTER FUNCTION {qualified_function} COST 1")
            assert _function_oid(connection, schema) == function_oid
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            owner._check_transaction()
        transaction.rollback()
    with migration_engine.begin() as connection:
        connection.exec_driver_sql(f"ALTER FUNCTION {qualified_function} COST 100")
    with factory.begin() as session:
        _owner(session, schema)._check_transaction()


def test_float4send_attestation_rejects_colliding_committed_cost_under_negative_guc(database):
    _engine, factory, schema, migration_engine = database
    qualified_function = f'"{schema}"."{storage.GUARD_FUNCTION}"()'
    migration = MIGRATION.read_text(encoding="ascii")
    migration_cost_match = re.search(
        rf'CREATE FUNCTION "{storage.SCHEMA}"\."{storage.GUARD_FUNCTION}"\(\)' r".*?\nCOST ([0-9]+)\n",
        migration,
        re.DOTALL,
    )
    assert migration_cost_match is not None
    migration_cost = int(migration_cost_match.group(1))
    migration_rows = 0
    expected_cost_hex = struct.pack("!f", migration_cost).hex()
    expected_rows_hex = struct.pack("!f", migration_rows).hex()
    mutated_cost = 100.1
    mutated_cost_hex = struct.pack("!f", mutated_cost).hex()
    assert (migration_cost, expected_cost_hex, expected_rows_hex) == (100, "42c80000", "00000000")
    assert mutated_cost_hex == "42c83333" != expected_cost_hex

    with factory() as session:
        transaction = session.begin()
        owner = _owner(session, schema)
        try:
            with migration_engine.begin() as connection:
                connection.exec_driver_sql(f"ALTER FUNCTION {qualified_function} COST {mutated_cost}")
            connection = session.connection()
            connection.exec_driver_sql("SET LOCAL extra_float_digits = -3")
            observed = connection.execute(
                text(
                    "SELECT current_setting('extra_float_digits'), function.procost::text, "
                    "CAST(:migration_cost AS real)::text, "
                    "pg_catalog.encode(pg_catalog.float4send(function.procost), 'hex'), "
                    "pg_catalog.encode(pg_catalog.float4send(CAST(:migration_cost AS real)), 'hex'), "
                    "pg_catalog.encode(pg_catalog.float4send(function.prorows), 'hex') "
                    "FROM pg_catalog.pg_proc AS function "
                    "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = function.pronamespace "
                    "WHERE namespace.nspname = :schema AND function.proname = :function "
                    "AND function.pronargs = 0"
                ),
                {
                    "function": storage.GUARD_FUNCTION,
                    "migration_cost": migration_cost,
                    "schema": schema,
                },
            ).one()
            assert observed == (
                "-3",
                "100",
                "100",
                mutated_cost_hex,
                expected_cost_hex,
                expected_rows_hex,
            )
            with pytest.raises(
                storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable,
                match=ERROR,
            ):
                owner._check_transaction()
        finally:
            transaction.rollback()
            with migration_engine.begin() as connection:
                connection.exec_driver_sql(f"ALTER FUNCTION {qualified_function} COST {migration_cost}")

    with factory.begin() as session:
        session.connection().exec_driver_sql("SET LOCAL extra_float_digits = -3")
        restored = _owner(session, schema)
        assert restored._guard_definition_sha256 == storage.GUARD_DEFINITION_SHA256
        restored._check_transaction()


def test_trigger_function_rows_is_fixed_zero_for_non_set_returning_function(database):
    _engine, factory, schema, migration_engine = database
    qualified_function = f'"{schema}"."{storage.GUARD_FUNCTION}"()'
    with factory() as session:
        transaction = session.begin()
        owner = _owner(session, schema)
        with pytest.raises(Exception, match="ROWS is not applicable"):
            with migration_engine.begin() as connection:
                connection.exec_driver_sql(f"ALTER FUNCTION {qualified_function} ROWS 1")
        owner._check_transaction()
        transaction.rollback()
    with migration_engine.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT function.prorows::text FROM pg_catalog.pg_proc AS function "
                    "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = function.pronamespace "
                    "WHERE namespace.nspname = :schema AND function.proname = :function "
                    "AND function.pronargs = 0"
                ),
                {"function": storage.GUARD_FUNCTION, "schema": schema},
            ).scalar_one()
            == "0"
        )


def test_function_support_mutation_is_rejected_and_rollback_preserves_owner(database, postgres_target):
    _engine, factory, schema, _migration_engine = database
    superuser_engine = postgres_target[2]
    if superuser_engine is None:
        pytest.skip("explicit disposable superuser target not provided for SUPPORT mutation")
    qualified_function = f'"{schema}"."{storage.GUARD_FUNCTION}"()'
    hostile = f"ALTER FUNCTION {qualified_function} SUPPORT pg_catalog.textlike_support"
    with factory() as session:
        transaction = session.begin()
        owner = _owner(session, schema)
        function_oid = owner._trigger_function_oid
        with superuser_engine.connect() as connection:
            mutation = connection.begin()
            connection.exec_driver_sql(hostile)
            assert _function_oid(connection, schema) == function_oid
            mutation.rollback()
        owner._check_transaction()
        transaction.rollback()
    with factory() as session:
        transaction = session.begin()
        owner = _owner(session, schema)
        with superuser_engine.begin() as connection:
            connection.exec_driver_sql(hostile)
            assert _function_oid(connection, schema) == function_oid
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            owner._check_transaction()
        transaction.rollback()
    with superuser_engine.begin() as connection:
        _restore_guard_function(connection, schema=schema)
    with factory.begin() as session:
        restored = _owner(session, schema)
        assert restored._trigger_function_oid == function_oid
        restored._check_transaction()


def test_relation_and_toast_options_are_rejected_and_each_rollback_preserves_owner(database):
    _engine, factory, schema, migration_engine = database
    qualified_table = f'"{schema}"."{storage.TABLE}"'
    mutations = (
        ("fillfactor=80", "fillfactor"),
        ("autovacuum_enabled=false", "autovacuum_enabled"),
        ("toast.autovacuum_enabled=false", "toast.autovacuum_enabled"),
    )
    with factory() as session:
        transaction = session.begin()
        owner = _owner(session, schema)
        for setting, _option in mutations:
            with migration_engine.connect() as connection:
                mutation = connection.begin()
                connection.exec_driver_sql(f"ALTER TABLE {qualified_table} SET ({setting})")
                mutation.rollback()
            owner._check_transaction()
        transaction.rollback()
    for setting, option in mutations:
        with factory() as session:
            transaction = session.begin()
            owner = _owner(session, schema)
            with migration_engine.begin() as connection:
                connection.exec_driver_sql(f"ALTER TABLE {qualified_table} SET ({setting})")
            with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
                owner._check_transaction()
            transaction.rollback()
        with migration_engine.begin() as connection:
            connection.exec_driver_sql(f"ALTER TABLE {qualified_table} RESET ({option})")
        with factory.begin() as session:
            _owner(session, schema)._check_transaction()


@pytest.mark.parametrize("trigger_name", (storage.GUARD_TRIGGER, storage.NO_TRUNCATE_TRIGGER))
def test_exact_trigger_drop_recreate_changes_cached_oid_and_rollback_preserves_owner(database, trigger_name):
    _engine, factory, schema, migration_engine = database
    qualified_table = f'"{schema}"."{storage.TABLE}"'
    create_trigger = _exact_trigger_definition(schema, trigger_name)
    with factory() as session:
        transaction = session.begin()
        owner = _owner(session, schema)
        original_oid = _trigger_oid(session.connection(), schema, trigger_name)
        with migration_engine.connect() as connection:
            mutation = connection.begin()
            connection.exec_driver_sql(f'DROP TRIGGER "{trigger_name}" ON {qualified_table}')
            connection.exec_driver_sql(create_trigger)
            assert _trigger_oid(connection, schema, trigger_name) != original_oid
            mutation.rollback()
        assert _trigger_oid(session.connection(), schema, trigger_name) == original_oid
        owner._check_transaction()
        transaction.rollback()
    with factory() as session:
        transaction = session.begin()
        owner = _owner(session, schema)
        with migration_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP TRIGGER "{trigger_name}" ON {qualified_table}')
            connection.exec_driver_sql(create_trigger)
            assert _trigger_oid(connection, schema, trigger_name) != original_oid
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            owner._check_transaction()
        transaction.rollback()


def test_literal_live_payload_shape_catches_removed_relation_access_method(database, monkeypatch):
    _engine, factory, schema, _migration_engine = database
    canonical_payload = storage._catalog_guard_definition_payload
    captured_payloads = []

    def capture(rows):
        payload = canonical_payload(rows)
        captured_payloads.append(copy.deepcopy(payload))
        return payload

    monkeypatch.setattr(storage, "_catalog_guard_definition_payload", capture)
    with factory.begin() as session:
        _owner(session, schema)
    monkeypatch.setattr(storage, "_catalog_guard_definition_payload", canonical_payload)
    assert len(captured_payloads) == 1
    live_payload = captured_payloads[0]
    _assert_live_guard_definition_payload_shape(live_payload)
    removed = copy.deepcopy(live_payload)
    assert "accessMethod" in removed["relation"]
    del removed["relation"]["accessMethod"]
    with pytest.raises(AssertionError):
        _assert_live_guard_definition_payload_shape(removed)


def test_each_new_canonical_payload_field_mismatch_denies_construction(database, monkeypatch):
    _engine, factory, schema, _migration_engine = database
    mutations = (
        (("function", "cost"), "3f800000"),
        (("function", "rows"), "3f800000"),
        (("function", "supportFunctionOid"), 1023),
        (("relation", "accessMethod"), "hostile"),
        (("relation", "checkConstraintCount"), 19),
        (("relation", "columnCount"), 30),
        (("relation", "hasIndexes"), False),
        (("relation", "hasRules"), True),
        (("relation", "hasSubclasses"), True),
        (("relation", "hasTriggers"), False),
        (("relation", "isPartition"), True),
        (("relation", "isPopulated"), False),
        (("relation", "isShared"), True),
        (("relation", "ofTypeOid"), 1),
        (("relation", "options"), []),
        (("relation", "partitionBound"), "hostile"),
        (("relation", "replicaIdentity"), "n"),
        (("relation", "tablespaceOid"), 1),
        (("relation", "toast", "accessMethod"), "hostile"),
        (("relation", "toast", "checkConstraintCount"), 1),
        (("relation", "toast", "columnCount"), 2),
        (("relation", "toast", "forceRowSecurity"), True),
        (("relation", "toast", "hasIndexes"), False),
        (("relation", "toast", "hasRules"), True),
        (("relation", "toast", "hasSubclasses"), True),
        (("relation", "toast", "hasTriggers"), True),
        (("relation", "toast", "isPartition"), True),
        (("relation", "toast", "isPopulated"), False),
        (("relation", "toast", "isShared"), True),
        (("relation", "toast", "kind"), "r"),
        (("relation", "toast", "nameMatchesRelationOid"), False),
        (("relation", "toast", "namespace"), "public"),
        (("relation", "toast", "ofTypeOid"), 1),
        (("relation", "toast", "options"), []),
        (("relation", "toast", "partitionBound"), "hostile"),
        (("relation", "toast", "persistence"), "u"),
        (("relation", "toast", "replicaIdentity"), "d"),
        (("relation", "toast", "rowSecurity"), True),
        (("relation", "toast", "rowTypeOid"), 1),
        (("relation", "toast", "tablespaceOid"), 1),
    )
    canonical_payload = storage._catalog_guard_definition_payload
    with factory.begin() as session:
        captured_payloads = []

        def capture(rows):
            payload = canonical_payload(rows)
            captured_payloads.append(copy.deepcopy(payload))
            return payload

        monkeypatch.setattr(storage, "_catalog_guard_definition_payload", capture)
        _owner(session, schema)._check_transaction()
        monkeypatch.setattr(storage, "_catalog_guard_definition_payload", canonical_payload)
        assert len(captured_payloads) == 2
        live_payload = captured_payloads[0]
        assert captured_payloads[1] == live_payload
        _assert_live_guard_definition_payload_shape(live_payload)
        for path, replacement in mutations:
            payload = copy.deepcopy(live_payload)
            target = payload
            for component in path[:-1]:
                assert type(target) is dict
                assert component in target
                target = target[component]
            assert type(target) is dict
            assert path[-1] in target
            target[path[-1]] = replacement

            def mismatched(_rows, payload=payload):
                return payload

            monkeypatch.setattr(storage, "_catalog_guard_definition_payload", mismatched)
            with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
                _owner(session, schema)
            monkeypatch.setattr(storage, "_catalog_guard_definition_payload", canonical_payload)
        _owner(session, schema)._check_transaction()


def test_expected_definition_digest_mismatch_denies_construction(database, monkeypatch):
    _engine, factory, schema, _migration_engine = database
    monkeypatch.setattr(storage, "GUARD_DEFINITION_SHA256", "0" * 64)
    with factory.begin() as session:
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            _owner(session, schema)


def test_concurrent_first_writers_converge_on_one_locked_row(database):
    _engine, factory, schema, _migration_engine = database
    barrier = threading.Barrier(8)

    def worker(_index):
        barrier.wait()
        with factory.begin() as session:
            return _reserve(session, schema).reservation.reservation_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(8)))
    assert results == [RESERVATION_ID] * 8
    assert _count(factory, schema) == 1


def test_competing_accept_and_terminal_cas_has_one_immutable_winner(database):
    _engine, factory, schema, _migration_engine = database
    with factory.begin() as session:
        pending = _reserve(session, schema)
    barrier = threading.Barrier(2)

    def accept():
        try:
            barrier.wait()
            with factory.begin() as session:
                return _finalize(session, schema).reservation.state
        except storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable:
            return "denied"

    def reject():
        try:
            barrier.wait()
            with factory.begin() as session:
                return (
                    _owner(session, schema)
                    .transition_terminal(
                        pending.reservation.reservation_id,
                        expected_input_wire=vectors.INPUT_WIRE,
                        evidence_compact_jws=vectors.evidence_compact(),
                        evidence_config=vectors.evidence_config(),
                        state="rejected",
                        decided_at=vectors.VECTOR["decidedAt"],
                    )
                    .reservation.state
                )
        except storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(accept), pool.submit(reject)]
        outcomes = [item.result() for item in results]
    assert outcomes.count("denied") == 1
    assert len(set(outcomes) & {"accepted", "rejected"}) == 1
    table = storage._test_only_qualified_table(schema)
    with factory.begin() as session:
        state = session.scalar(select(table.c.state))
    assert state in {"accepted", "rejected"} and state in outcomes


@pytest.mark.parametrize("state", ("rejected", "expired", "cancelled"))
def test_terminal_decisions_are_immutable_and_expiry_never_releases_device_id(database, state):
    _engine, factory, schema, _migration_engine = database
    with factory.begin() as session:
        pending = _reserve(session, schema)
    decided = pending.reservation.expires_at if state == "expired" else vectors.VECTOR["decidedAt"]
    with factory.begin() as session:
        terminal = _owner(session, schema).transition_terminal(
            pending.reservation.reservation_id,
            expected_input_wire=vectors.INPUT_WIRE,
            evidence_compact_jws=vectors.evidence_compact(),
            evidence_config=vectors.evidence_config(),
            state=state,
            decided_at=decided,
        )
    with factory.begin() as session:
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            _owner(session, schema).transition_terminal(
                terminal.reservation.reservation_id,
                expected_input_wire=vectors.INPUT_WIRE,
                evidence_compact_jws=vectors.evidence_compact(),
                evidence_config=vectors.evidence_config(),
                state="cancelled" if state != "cancelled" else "rejected",
                decided_at=decided,
            )
    with factory.begin() as session:
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            _reserve(session, schema, now=decided)
    table = storage._test_only_qualified_table(schema)
    with pytest.raises(IntegrityError):
        with factory.begin() as session:
            session.execute(table.insert().values(**pending_row()))
    assert _count(factory, schema) == 1


def test_missing_ambiguous_and_corrupt_state_fail_closed(database):
    _engine, factory, schema, migration_engine = database
    with factory.begin() as session:
        pending = _reserve(session, schema)
    with factory.begin() as session:
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            _owner(session, schema).reconcile_exact(
                "ff" * 32,
                expected_input_wire=vectors.INPUT_WIRE,
                evidence_compact_jws=vectors.evidence_compact(),
                evidence_config=vectors.evidence_config(),
                now=pending.reservation.created_at,
            )
    # Database uniqueness refuses two rows claiming the same request/device,
    # so ambiguous collision state cannot be created through the writer.
    table = storage._test_only_qualified_table(schema)
    with pytest.raises(IntegrityError):
        with factory.begin() as session:
            session.execute(table.insert().values(**pending_row()))
    # Simulate physical/operator corruption only after disabling the guard;
    # the adapter must still reject the row when the guard is restored.
    with migration_engine.begin() as connection:
        connection.exec_driver_sql(f'ALTER TABLE "{schema}"."{storage.TABLE}" DISABLE TRIGGER USER')
        connection.exec_driver_sql(f'UPDATE "{schema}"."{storage.TABLE}" SET reservation_wire = \'{{}}\'')
        connection.exec_driver_sql(f'ALTER TABLE "{schema}"."{storage.TABLE}" ENABLE TRIGGER USER')
    with factory.begin() as session:
        with pytest.raises(storage.SocialPreacceptedEnrollmentV2AtomicAcceptanceStorageUnavailable, match=ERROR):
            _owner(session, schema).reconcile_exact(
                pending.reservation.reservation_id,
                expected_input_wire=vectors.INPUT_WIRE,
                evidence_compact_jws=vectors.evidence_compact(),
                evidence_config=vectors.evidence_config(),
                now=pending.reservation.created_at,
            )


def test_caller_rollback_removes_first_write_and_reverts_transition(database):
    _engine, factory, schema, _migration_engine = database
    with factory() as session:
        transaction = session.begin()
        _reserve(session, schema)
        transaction.rollback()
    assert _count(factory, schema) == 0
    with factory.begin() as session:
        pending = _reserve(session, schema)
    with factory() as session:
        transaction = session.begin()
        accepted = _finalize(session, schema)
        assert accepted.reservation.state == "accepted"
        transaction.rollback()
    table = storage._test_only_qualified_table(schema)
    with factory.begin() as session:
        row = session.execute(select(table)).mappings().one()
        stored = storage.parse_stored_atomic_acceptance_v1(
            row,
            evidence_config=vectors.evidence_config(),
        )
    assert stored.reservation.state == "pending"
    assert stored.reservation.reservation_id == pending.reservation.reservation_id


def test_accepted_history_is_evidence_not_current_or_version_order_authority(database):
    _engine, factory, schema, _migration_engine = database
    with factory.begin() as session:
        _reserve(session, schema)
    with factory.begin() as session:
        accepted = _finalize(session, schema)
    assert accepted.current_authority == "not_established_by_storage"
    assert accepted.final_admission == "denied"
    assert accepted.effect is not None and accepted.receipt is not None
    source = (ROOT / "app/services/social_preaccepted_enrollment_v2_atomic_acceptance_storage.py").read_text("ascii")
    assert "ORDER BY" not in source and "MAX(" not in source
    assert "current_authority: str = field(default=CURRENT_AUTHORITY" in source
