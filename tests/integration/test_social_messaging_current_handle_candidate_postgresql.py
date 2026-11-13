"""Guarded disposable PostgreSQL race tests for current-handle candidates.

The suite requires an explicit synthetic PostgreSQL 16 target in a unique
temporary data directory on a high loopback TCP port with Unix sockets
disabled.  It never reads DATABASE_URL and never falls back to port 5432.

These tests replace only the already-covered admission-authority producer with
a transaction-pinned synthetic producer so they can isolate the new
namespace/history/binding wait edges.  The production adapter constructs the
real producer directly; its independent PostgreSQL suite remains the
compatibility proof for the complete admission lock order.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from queue import Queue

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.services import social_current_admission_authority as current_authority
from app.services import social_messaging_active_alias_namespace_storage as active_namespace
from app.services import social_messaging_current_handle_candidate as candidate
from app.services import social_messaging_device_admission_contract as admission
from app.services import social_messaging_device_proof_profile as profile
from app.services import social_messaging_recipient_routing as routing
from app.services import social_messaging_recipient_routing_storage as routing_storage
from app.services.social_messaging_device_contract import messaging_device_binding_id
from app.services.social_messaging_device_storage import SocialMessagingDeviceBindingRow

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "HODLXXI_CURRENT_HANDLE_CANDIDATE_TEST_"
ACK = "DISPOSABLE-SOCIAL-CURRENT-HANDLE-CANDIDATE-POSTGRES-V1"
ALIAS_SECRET = bytes(range(32))
ROTATED_SECRET = bytes(reversed(range(32)))
VIEWER = "02" * 32
ERROR = "^social messaging current handle candidate unavailable$"
MIGRATIONS = (
    ROOT / "migrations/2026-09-04_social_messaging_device_bindings_v1.sql",
    ROOT / "migrations/2026-09-24_social_messaging_recipient_routing_registry_v1.sql",
    ROOT / "migrations/2026-09-24_social_messaging_active_alias_namespace_v1.sql",
)


class SyntheticTransactionBoundAdmissionAuthority:
    """Test-only producer for the candidate's post-admission lock edges."""

    def __init__(self, session, **_kwargs):
        self._session = session
        self._transaction = session.get_transaction()
        self._nested = session.get_nested_transaction()

    def lock_current_authority(self, context, *, observed_at):
        if (
            self._transaction is None
            or not self._transaction.is_active
            or self._session.get_transaction() is not self._transaction
            or self._session.get_nested_transaction() is not self._nested
            or admission.parse_verification_context_v1(context.wire) != context
        ):
            raise admission.SocialMessagingDeviceAdmissionUnavailable()
        current_authority._observed(observed_at)
        return admission.CurrentAdmissionAuthorityV1(
            context_digest=admission.verification_context_digest_v1(context.wire),
            authority_epoch=context.authority_epoch,
            locked_deadline_ms=observed_at + 60_000,
            full_proof_id=context.full_proof_id,
            approver_full_proof_id=None,
        )


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def apply_sql(connection, path):
    with connection.connection.driver_connection.cursor() as cursor:
        cursor.execute(path.read_text(encoding="ascii"))


@pytest.fixture(scope="module")
def postgres_target():
    dsn = os.environ.get(PREFIX + "DSN")
    if not dsn:
        pytest.skip("explicit disposable current-handle candidate PostgreSQL target not provided")
    assert os.environ.get(PREFIX + "ACK") == ACK
    data = Path(os.environ[PREFIX + "DATA"]).resolve()
    assert data.parent.parent == Path("/tmp")
    assert data.parent.name.startswith("hodlxxi-current-handle-candidate-")
    assert data.name == "data" and (data / "PG_VERSION").read_text().strip() == "16"
    port = int(os.environ[PREFIX + "PORT"])
    url = make_url(dsn)
    assert url.drivername == "postgresql+psycopg2"
    assert url.host == "127.0.0.1" and url.port == port and 49152 <= port <= 65535
    assert url.database == "hodlxxi_current_handle_candidate_test"
    assert url.username == "current_handle_candidate_test"
    assert url.password is None and not url.query
    engine = create_engine(url, poolclass=NullPool, hide_parameters=True)
    try:
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT current_database(), current_setting('data_directory'), "
                    "current_setting('port'), current_setting('listen_addresses'), "
                    "current_setting('unix_socket_directories'), version()"
                )
            ).one()
            assert row[0] == url.database
            assert Path(row[1]).resolve() == data
            assert int(row[2]) == port
            assert row[3:5] == ("127.0.0.1", "")
            assert row[5].startswith("PostgreSQL 16.")
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def database(postgres_target, monkeypatch):
    monkeypatch.setattr(
        candidate.current_authority,
        "SqlAlchemyTransactionBoundAdmissionAuthority",
        SyntheticTransactionBoundAdmissionAuthority,
    )
    schema = "current_handle_" + uuid.uuid4().hex
    with postgres_target.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    engine = create_engine(
        postgres_target.url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"options": f"-c search_path={schema} -c statement_timeout=10000 -c lock_timeout=5000"},
    )
    try:
        with engine.begin() as connection:
            for migration in MIGRATIONS:
                apply_sql(connection, migration)
        yield engine, sessionmaker(engine, expire_on_commit=False)
    finally:
        engine.dispose()
        with postgres_target.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')


def make_binding(*, parsed, now_ms, public_key="31" * 32, version=1, prior=None, request="41" * 32):
    observed = datetime.fromtimestamp(now_ms / 1000, timezone.utc)
    valid_from = observed - timedelta(seconds=60)
    expires_at = observed + timedelta(minutes=10)
    operation = "register" if version == 1 else "rotate"
    binding_id = messaging_device_binding_id(
        subject=parsed.context.subject,
        device_id=parsed.context.device_id,
        public_key=public_key,
        binding_version=version,
        valid_from=valid_from,
        expires_at=expires_at,
        operation=operation,
        prior_binding_id=prior,
        request_id=request,
    )
    values = {
        "binding_id": binding_id,
        "record_schema": "hodlxxi.social_messaging_device_binding_record.v1",
        "subject_pubkey": parsed.context.subject,
        "device_id": parsed.context.device_id,
        "algorithm": "x25519-v1",
        "public_key": public_key,
        "binding_version": version,
        "valid_from": valid_from,
        "expires_at": expires_at,
        "operation": operation,
        "prior_binding_id": prior,
        "request_id": request,
        "active": True,
        "retired_at": None,
        "created_at": valid_from,
    }
    return values


def request_wire(source, *, binding, handle):
    context = json.loads(source["contextWire"])
    context.update(
        bindingId=binding["binding_id"],
        bindingVersion=binding["binding_version"],
        x25519PublicKeyCommitment=profile.x25519_public_key_commitment_v1(binding["public_key"]),
    )
    context_wire = canonical(context)
    request = json.loads(source["actualRequestWire"])
    request.update(
        subject=context["subject"],
        deviceId=context["deviceId"],
        bindingId=context["bindingId"],
        bindingVersion=context["bindingVersion"],
        sessionBinding=context["sessionBinding"],
        recipientHandle=handle,
    )
    actual_request_wire = canonical(request)
    challenge = json.loads(source["challengeWire"])
    challenge["request"] = actual_request_wire
    return admission.canonical_verification_input_v1_bytes(
        context=context_wire,
        challenge=canonical(challenge),
        proof=source["proofWire"],
        approval_event=None,
        actual_request=actual_request_wire,
        routing_request=None,
    ).decode("ascii")


def retain_owner(session, *, parsed, binding, handle, alias_version, now_ms):
    route = routing.RecipientRoutingSnapshotRoute(
        device_handle=handle,
        device_id=parsed.context.device_id,
        binding_id=binding["binding_id"],
        binding_version=binding["binding_version"],
        authorization_proof_id=(
            "hodlxxi-binding-authorization-v1-sha256:"
            + hashlib.sha256((handle + binding["binding_id"]).encode("ascii")).hexdigest()
        ),
        authorization_valid_from=now_ms - 1_000,
        authorization_expires_at=now_ms + 120_000,
    )
    snapshot = routing.RecipientRoutingSnapshot(
        schema=routing.SNAPSHOT_SCHEMA,
        version=1,
        source=routing.SOURCE,
        viewer_subject=VIEWER,
        recipient_subject=parsed.context.subject,
        alias_version=alias_version,
        recipient_package_snapshot_id=(
            "sha256:" + hashlib.sha256((handle + str(alias_version)).encode("ascii")).hexdigest()
        ),
        issued_at=now_ms,
        expires_at=now_ms + 60_000,
        complete=True,
        routes=(route,),
    )
    routing_storage.SqlAlchemyRecipientRoutingRepository(session).retain_snapshot(snapshot)


def provision(factory):
    source = json.loads((ROOT / "tests/fixtures/social_device_admission_v1.json").read_text(encoding="ascii"))[
        "vectors"
    ]["recipientSelfRead"]
    fixture_parsed = admission.parse_verification_input_v1(source["inputWire"])
    now_ms = source["now"]
    binding = make_binding(parsed=fixture_parsed, now_ms=now_ms)
    handle_v1 = routing.derive_recipient_device_handle(
        viewer=VIEWER,
        target=fixture_parsed.context.subject,
        binding_id=binding["binding_id"],
        alias_secret=ALIAS_SECRET,
        alias_version=1,
    )
    handle_v2 = routing.derive_recipient_device_handle(
        viewer=VIEWER,
        target=fixture_parsed.context.subject,
        binding_id=binding["binding_id"],
        alias_secret=ROTATED_SECRET,
        alias_version=2,
    )
    wire_v1 = request_wire(source, binding=binding, handle=handle_v1)
    wire_v2 = request_wire(source, binding=binding, handle=handle_v2)
    parsed = admission.parse_verification_input_v1(wire_v1)
    with factory.begin() as session:
        session.execute(SocialMessagingDeviceBindingRow.__table__.insert().values(**binding))
        session.execute(
            active_namespace.SocialMessagingActiveAliasNamespaceRow.__table__.insert().values(
                alias_version=1,
                secret_commitment=active_namespace.active_alias_namespace_secret_commitment(
                    alias_secret=ALIAS_SECRET,
                    alias_version=1,
                ),
                lifecycle_state=active_namespace.ACTIVE_NAMESPACE_STATE,
            )
        )
        retain_owner(
            session,
            parsed=parsed,
            binding=binding,
            handle=handle_v1,
            alias_version=1,
            now_ms=now_ms,
        )
        retain_owner(
            session,
            parsed=parsed,
            binding=binding,
            handle=handle_v2,
            alias_version=2,
            now_ms=now_ms,
        )
    return {
        "binding": binding,
        "handle_v1": handle_v1,
        "handle_v2": handle_v2,
        "now_ms": now_ms,
        "wire_v1": wire_v1,
        "wire_v2": wire_v2,
    }


def checker(session, *, secret, version):
    return candidate.SqlAlchemyTransactionBoundCurrentHandleCandidate(
        session,
        device_issuance_id="11" * 32,
        device_client_id="social-viewer-v1",
        oauth_issuer="https://identity.example",
        configured_alias_secret=secret,
        configured_alias_version=version,
    )


def rotate_namespace(session):
    table = active_namespace.SocialMessagingActiveAliasNamespaceRow.__table__
    session.execute(
        table.update()
        .where(table.c.alias_version == 1)
        .values(lifecycle_state=active_namespace.RETIRED_NAMESPACE_STATE)
    )
    session.execute(
        table.insert().values(
            alias_version=2,
            secret_commitment=active_namespace.active_alias_namespace_secret_commitment(
                alias_secret=ROTATED_SECRET,
                alias_version=2,
            ),
            lifecycle_state=active_namespace.ACTIVE_NAMESPACE_STATE,
        )
    )


def wait_until_blocked(engine, waiter, blocker):
    deadline = time.monotonic() + 4
    with engine.connect() as connection:
        while time.monotonic() < deadline:
            blockers = connection.execute(text("SELECT pg_blocking_pids(:pid)"), {"pid": waiter}).scalar_one()
            if blocker in blockers:
                return
            time.sleep(0.01)
    pytest.fail("synthetic current-handle contender did not wait on the expected lock")


def test_candidate_is_provisional_non_authorizing_and_does_not_mutate(database):
    _engine, factory = database
    state = provision(factory)
    with factory() as session:
        transaction = session.begin()
        result = checker(session, secret=ALIAS_SECRET, version=1).check_recipient_self_read_candidate(
            state["wire_v1"],
            observed_at=state["now_ms"],
        )
        assert result.requested_handle == state["handle_v1"]
        assert result.authorization == result.recipient_self_read == "not_granted"
        assert result.ciphertext == "not_returned"
        assert transaction.is_active and session.in_transaction()
        transaction.rollback()
    with factory() as session:
        assert session.execute(select(SocialMessagingDeviceBindingRow)).scalars().one().active is True
        assert len(session.execute(select(routing_storage.RecipientRoutingHandleOwnerRow)).scalars().all()) == 2


def test_candidate_refreshes_preloaded_binding_after_committed_retirement(database):
    _engine, factory = database
    state = provision(factory)
    binding_id = state["binding"]["binding_id"]
    observed = datetime.fromtimestamp(state["now_ms"] / 1000, timezone.utc)

    with factory() as reader_session:
        transaction = reader_session.begin()
        cached_row = reader_session.execute(
            select(SocialMessagingDeviceBindingRow).where(SocialMessagingDeviceBindingRow.binding_id == binding_id)
        ).scalar_one()
        assert cached_row.active is True

        with factory.begin() as writer_session:
            writer_row = writer_session.execute(
                select(SocialMessagingDeviceBindingRow)
                .where(SocialMessagingDeviceBindingRow.binding_id == binding_id)
                .with_for_update()
            ).scalar_one()
            writer_row.active = False
            writer_row.retired_at = observed

        assert cached_row.active is True
        with pytest.raises(candidate.SocialMessagingCurrentHandleCandidateUnavailable, match=ERROR):
            checker(reader_session, secret=ALIAS_SECRET, version=1).check_recipient_self_read_candidate(
                state["wire_v1"],
                observed_at=state["now_ms"],
            )
        assert cached_row.active is False
        transaction.rollback()


def test_waiting_candidate_rechecks_committed_namespace_rotation(database):
    engine, factory = database
    state = provision(factory)
    pids = Queue()

    def read_stale():
        with factory() as session:
            transaction = session.begin()
            pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
            try:
                checker(session, secret=ALIAS_SECRET, version=1).check_recipient_self_read_candidate(
                    state["wire_v1"],
                    observed_at=state["now_ms"],
                )
            except candidate.SocialMessagingCurrentHandleCandidateUnavailable:
                transaction.rollback()
                return "denied"
            transaction.rollback()
            return "unexpected-success"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as writer_session:
            transaction = writer_session.begin()
            rotate_namespace(writer_session)
            blocker = writer_session.execute(text("SELECT pg_backend_pid()")).scalar_one()
            future = pool.submit(read_stale)
            wait_until_blocked(engine, pids.get(timeout=5), blocker)
            assert not future.done()
            transaction.commit()
        assert future.result(timeout=10) == "denied"

    with factory.begin() as session:
        with pytest.raises(candidate.SocialMessagingCurrentHandleCandidateUnavailable, match=ERROR):
            checker(session, secret=ROTATED_SECRET, version=2).check_recipient_self_read_candidate(
                state["wire_v1"],
                observed_at=state["now_ms"],
            )
    with factory.begin() as session:
        result = checker(session, secret=ROTATED_SECRET, version=2).check_recipient_self_read_candidate(
            state["wire_v2"],
            observed_at=state["now_ms"],
        )
        assert result.requested_handle == state["handle_v2"]


def test_candidate_waiting_on_history_lock_rechecks_binding_rotation(database):
    engine, factory = database
    state = provision(factory)
    pids = Queue()

    def read_old_binding():
        with factory() as session:
            transaction = session.begin()
            pids.put(session.execute(text("SELECT pg_backend_pid()")).scalar_one())
            try:
                checker(session, secret=ALIAS_SECRET, version=1).check_recipient_self_read_candidate(
                    state["wire_v1"],
                    observed_at=state["now_ms"],
                )
            except candidate.SocialMessagingCurrentHandleCandidateUnavailable:
                transaction.rollback()
                return "denied"
            transaction.rollback()
            return "unexpected-success"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as writer_session:
            transaction = writer_session.begin()
            handle_table = routing_storage.RecipientRoutingHandleOwnerRow.__table__
            writer_session.execute(
                select(handle_table)
                .where(handle_table.c.device_handle == state["handle_v1"])
                .with_for_update(of=handle_table)
            ).one()
            observed = datetime.fromtimestamp(state["now_ms"] / 1000, timezone.utc)
            binding_table = SocialMessagingDeviceBindingRow.__table__
            writer_session.execute(
                binding_table.update()
                .where(binding_table.c.binding_id == state["binding"]["binding_id"])
                .values(active=False, retired_at=observed)
            )
            successor = make_binding(
                parsed=admission.parse_verification_input_v1(state["wire_v1"]),
                now_ms=state["now_ms"],
                public_key="32" * 32,
                version=2,
                prior=state["binding"]["binding_id"],
                request="42" * 32,
            )
            writer_session.execute(binding_table.insert().values(**successor))
            blocker = writer_session.execute(text("SELECT pg_backend_pid()")).scalar_one()
            future = pool.submit(read_old_binding)
            wait_until_blocked(engine, pids.get(timeout=5), blocker)
            assert not future.done()
            transaction.commit()
        assert future.result(timeout=10) == "denied"

    with factory() as session:
        rows = session.execute(
            select(SocialMessagingDeviceBindingRow).order_by(SocialMessagingDeviceBindingRow.binding_version)
        ).scalars()
        assert [row.active for row in rows] == [False, True]
