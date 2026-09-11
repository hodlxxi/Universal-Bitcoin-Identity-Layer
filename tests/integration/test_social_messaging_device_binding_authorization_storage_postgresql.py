from __future__ import annotations

import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from coincurve import PrivateKey, PublicKeyXOnly
from sqlalchemy import create_engine, func, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

import app.services.social_messaging_device_binding_authorization_storage as authorization_storage
from app.models import CurrentEntitlementEvidence, User
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION
from app.services.current_entitlement_evidence_storage import _lock_subject_for_evidence_change, _subject_lock_keys
from app.services.social_messaging_device_binding_authorization import (
    ADOPTION_SCHEMA,
    AUTHORIZATION_SCHEMA,
    MAX_AUTHORIZATION_WINDOW_SECONDS,
    SIGNATURE_FORMAT,
    DeviceBindingAdoptionClaim,
    DeviceBindingAuthorizationClaim,
    DeviceBindingAuthorizationUnavailable,
    IdentitySignedDeviceBindingAdoption,
    IdentitySignedDeviceBindingAuthorization,
    adoption_digest,
    adoption_event_id,
    authorization_digest,
    authorization_event_id,
    canonical_adoption_json,
    canonical_authorization_json,
)
from app.services.social_messaging_device_binding_authorization_storage import (
    SocialMessagingDeviceBindingAuthorizationEvidenceRow,
    SocialMessagingDeviceBindingAuthorizationReplayRow,
    SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage,
)
from app.services.social_messaging_device_contract import (
    BINDING_RECORD_SCHEMA,
    BINDING_RECORD_VERSION,
    MAX_ACTIVE_DEVICES,
    MessagingDeviceCommand,
)
from app.services.social_messaging_device_storage import (
    SocialMessagingDeviceBindingRow,
    SqlAlchemySocialMessagingDeviceRepository,
)

ACKNOWLEDGEMENT = "DISPOSABLE-SOCIAL-BINDING-AUTHORIZATION-POSTGRES-V1"
ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
LIFETIME = timedelta(days=30)


def identity(value: int) -> tuple[PrivateKey, str]:
    key = PrivateKey(value.to_bytes(32, "big"))
    return key, PublicKeyXOnly.from_secret(key.secret).format().hex()


def hex_id(value: int) -> str:
    return f"{value:064x}"


def xkey(value: int) -> str:
    assert 2 <= value < 0x80
    return f"{value:02x}" * 32


def lifecycle_payload(
    key: PrivateKey,
    subject: str,
    *,
    operation: str,
    device: int,
    public_key: str,
    version: int,
    valid_from: datetime,
    binding_expires_at: datetime,
    prior: str | None,
    request: int,
) -> str:
    claim = DeviceBindingAuthorizationClaim(
        schema=AUTHORIZATION_SCHEMA,
        version=1,
        binding_record_schema=BINDING_RECORD_SCHEMA,
        binding_record_version=BINDING_RECORD_VERSION,
        operation=operation,
        subject=subject,
        device_id=hex_id(device),
        algorithm="x25519-v1",
        public_key=public_key,
        binding_version=version,
        binding_valid_from=valid_from,
        binding_expires_at=binding_expires_at,
        prior_binding_id=prior,
        request_id=hex_id(request),
        issued_at=valid_from,
        expires_at=valid_from + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS),
    )
    digest = authorization_digest(claim)
    signature = key.sign_schnorr(bytes.fromhex(authorization_event_id(claim)), b"\x00" * 32).hex()
    return canonical_authorization_json(
        IdentitySignedDeviceBindingAuthorization(
            claim,
            digest,
            SIGNATURE_FORMAT,
            signature,
        )
    )


def adoption_payload(key: PrivateKey, binding, *, request: int, issued_at: datetime) -> str:
    claim = DeviceBindingAdoptionClaim(
        schema=ADOPTION_SCHEMA,
        version=1,
        action="adopt",
        request_id=hex_id(request),
        binding=binding,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS),
    )
    digest = adoption_digest(claim)
    signature = key.sign_schnorr(bytes.fromhex(adoption_event_id(claim)), b"\x00" * 32).hex()
    return canonical_adoption_json(
        IdentitySignedDeviceBindingAdoption(
            claim,
            digest,
            SIGNATURE_FORMAT,
            signature,
        )
    )


def _apply_sql(connection, path: Path) -> None:
    raw = connection.connection.driver_connection
    with raw.cursor() as cursor:
        cursor.execute(path.read_text(encoding="ascii"))


@pytest.fixture(scope="module")
def postgres_factory():
    dsn = os.getenv("HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_DSN")
    if not dsn:
        pytest.skip("disposable Social binding authorization PostgreSQL DSN not provided")
    if os.getenv("HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_ACK") != ACKNOWLEDGEMENT:
        pytest.fail("disposable PostgreSQL acknowledgement is required")

    expected_data = os.environ["HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_DATA"]
    expected_socket = os.environ["HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_SOCKET"]
    expected_port = int(os.environ["HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_PORT"])
    url = make_url(dsn)
    assert url.get_backend_name() == "postgresql"
    assert url.password is None
    assert url.database == "hodlxxi_social_binding_authorization_test"
    assert url.host in (None, "")
    assert url.query.get("host") == expected_socket
    assert int(url.query.get("port", "0")) == expected_port != 5432

    engine = create_engine(dsn, future=True, poolclass=NullPool)
    with engine.connect() as connection:
        identity_row = connection.execute(
            text(
                "SELECT current_database(), current_setting('data_directory'), "
                "current_setting('port'), current_setting('unix_socket_directories'), "
                "current_setting('listen_addresses'), pg_postmaster_start_time(), version()"
            )
        ).one()
        assert identity_row[0] == "hodlxxi_social_binding_authorization_test"
        assert Path(identity_row[1]).resolve() == Path(expected_data).resolve()
        assert int(identity_row[2]) == expected_port
        assert identity_row[3] == expected_socket
        assert identity_row[4] == ""
        assert identity_row[5] is not None
        assert identity_row[6].startswith("PostgreSQL 16.")

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
        _apply_sql(
            connection,
            ROOT / "migrations/2026-09-04_social_messaging_device_bindings_v1.sql",
        )
        _apply_sql(
            connection,
            ROOT / "migrations/2026-09-10_social_messaging_device_binding_authorization_v1.sql",
        )

    factory = sessionmaker(bind=engine, future=True, expire_on_commit=False)
    try:
        yield engine, factory
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def clean_database(postgres_factory):
    engine, _factory = postgres_factory
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "TRUNCATE TABLE "
            "social_messaging_device_binding_authorization_replay, "
            "social_messaging_device_binding_authorization_evidence, "
            "social_messaging_device_bindings, current_entitlement_evidence, users CASCADE"
        )


def seed_full(factory, subject: str, *, active: bool = True) -> None:
    with factory.begin() as session:
        session.add(
            User(
                id=str(uuid.uuid4()),
                pubkey=subject,
                created_at=NOW.replace(tzinfo=None),
                is_active=active,
            )
        )
        session.add(
            CurrentEntitlementEvidence(
                evidence_id=str(uuid.uuid4()),
                contract_version=CONTRACT_VERSION,
                subject_pubkey=subject,
                identity_class=IdentityClass.FULL.value,
                current_full_relation_satisfied=True,
                evidence_source="synthetic_disposable_postgresql_rehearsal",
                evidence_version="v1",
                source_evidence_sha256="ab" * 32,
                observed_at=NOW - timedelta(minutes=5),
                valid_until=NOW + timedelta(minutes=10),
                revoked_at=None,
                created_at=NOW - timedelta(minutes=5),
            )
        )


def authorize(factory, payload: str, subject: str, *, now: datetime):
    with factory() as session:
        with session.begin():
            return authorize_in_session(session, payload, subject, clock=lambda: now)


def adopt(factory, payload: str, subject: str, *, now: datetime):
    with factory() as session:
        with session.begin():
            return adopt_in_session(session, payload, subject, clock=lambda: now)


def authorize_in_session(session, payload: str, subject: str, *, clock):
    return SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(
        session,
        clock=clock,
    ).authorize_lifecycle(payload, authenticated_subject=subject)


def adopt_in_session(session, payload: str, subject: str, *, clock):
    return SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(
        session,
        clock=clock,
    ).adopt_legacy(payload, authenticated_subject=subject)


def counts(factory) -> tuple[int, int, int]:
    with factory() as session:
        return (
            session.query(SocialMessagingDeviceBindingRow).count(),
            session.query(SocialMessagingDeviceBindingAuthorizationEvidenceRow).count(),
            session.query(SocialMessagingDeviceBindingAuthorizationReplayRow).count(),
        )


def attempt(callable_):
    try:
        return True, callable_()
    except DeviceBindingAuthorizationUnavailable:
        return False, None


class MutableClock:
    def __init__(self, value: datetime):
        self._value = value
        self._calls = 0
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            self._calls += 1
            return self._value

    def set(self, value: datetime) -> None:
        with self._lock:
            self._value = value

    @property
    def calls(self) -> int:
        with self._lock:
            return self._calls


def _assert_backend_waiting_on_advisory_lock(
    factory,
    backend_pid: int,
    blocker_pids: tuple[int, ...],
) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with factory() as session:
            waiting = session.execute(
                text(
                    "SELECT wait_event_type, wait_event, pg_blocking_pids(pid) "
                    "FROM pg_stat_activity WHERE pid = :pid"
                ),
                {"pid": backend_pid},
            ).one_or_none()
        if (
            waiting is not None
            and waiting[0] == "Lock"
            and waiting[1] == "advisory"
            and set(waiting[2]).intersection(blocker_pids)
        ):
            return
    pytest.fail(f"backend {backend_pid} did not reach its advisory-lock wait")


def _assert_backend_waiting_on_user_row_lock(
    factory,
    backend_pid: int,
    blocker_pids: tuple[int, ...],
) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with factory() as session:
            waiting = session.execute(
                text(
                    "SELECT wait_event_type, wait_event, pg_blocking_pids(pid), query "
                    "FROM pg_stat_activity WHERE pid = :pid"
                ),
                {"pid": backend_pid},
            ).one_or_none()
        if (
            waiting is not None
            and waiting[0] == "Lock"
            and waiting[1] in {"transactionid", "tuple"}
            and set(waiting[2]).intersection(blocker_pids)
            and "from users" in waiting[3].lower()
            and "for update" in waiting[3].lower()
        ):
            return
    pytest.fail(f"backend {backend_pid} did not reach its User-row lock wait")


def _submit_waiting_attempt(
    pool,
    factory,
    blocker_pids: tuple[int, ...],
    operation,
    *,
    assert_waiting=_assert_backend_waiting_on_advisory_lock,
):
    started = threading.Event()
    backend_pid = []

    def run():
        try:
            with factory() as session:
                with session.begin():
                    backend_pid.append(session.execute(select(func.pg_backend_pid())).scalar_one())
                    started.set()
                    return True, operation(session)
        except DeviceBindingAuthorizationUnavailable:
            return False, None

    future = pool.submit(run)
    assert started.wait(timeout=10)
    assert len(backend_pid) == 1
    assert_waiting(factory, backend_pid[0], blocker_pids)
    return future, backend_pid[0]


def _acquire_advisory_lock(session, keys: tuple[int, int]) -> None:
    session.execute(select(func.pg_advisory_xact_lock(*keys)))


def _lock_user_row_without_subject_advisory_lock(session, subject: str) -> int:
    user_id = session.execute(select(User.id).where(User.pubkey == subject).with_for_update()).scalar_one()
    backend_pid = session.execute(select(func.pg_backend_pid())).scalar_one()
    advisory_locks = session.execute(
        text("SELECT count(*) FROM pg_locks WHERE pid = :pid AND locktype = 'advisory'"),
        {"pid": backend_pid},
    ).scalar_one()
    assert user_id is not None
    assert advisory_locks == 0
    return backend_pid


def _run_blocked_pair(factory, keys, first_operation, second_operation):
    with ThreadPoolExecutor(max_workers=2) as pool:
        with factory() as blocker:
            with blocker.begin():
                _acquire_advisory_lock(blocker, keys)
                blocker_pid = blocker.execute(select(func.pg_backend_pid())).scalar_one()
                first, first_pid = _submit_waiting_attempt(
                    pool,
                    factory,
                    (blocker_pid,),
                    first_operation,
                )
                second, _second_pid = _submit_waiting_attempt(
                    pool,
                    factory,
                    (blocker_pid, first_pid),
                    second_operation,
                )
        return first.result(timeout=10), second.result(timeout=10)


def register_payload(key, subject, *, device, public_key, request, now=NOW):
    return lifecycle_payload(
        key,
        subject,
        operation="register",
        device=device,
        public_key=public_key,
        version=1,
        valid_from=now,
        binding_expires_at=now + LIFETIME,
        prior=None,
        request=request,
    )


def test_clean_migrations_constraints_indexes_and_foreign_keys(postgres_factory):
    engine, _factory = postgres_factory
    inspector = inspect(engine)
    assert {
        "social_messaging_device_binding_authorization_evidence",
        "social_messaging_device_binding_authorization_replay",
    } <= set(inspector.get_table_names())
    evidence_uniques = {
        item["name"]
        for item in inspector.get_unique_constraints("social_messaging_device_binding_authorization_evidence")
    }
    assert "uq_social_device_authorization_evidence_request" in evidence_uniques
    assert "uq_social_device_authorization_evidence_digest" in evidence_uniques
    assert {
        item["name"] for item in inspector.get_foreign_keys("social_messaging_device_binding_authorization_replay")
    } == {"fk_social_device_authorization_replay_evidence"}
    assert "uq_social_messaging_device_historical_public_key" in {
        item["name"] for item in inspector.get_indexes("social_messaging_device_bindings")
    }


def test_register_rotate_revoke_exact_retry_and_conflicting_replay(postgres_factory):
    _engine, factory = postgres_factory
    key, subject = identity(3)
    seed_full(factory, subject)

    register = register_payload(key, subject, device=1, public_key=xkey(9), request=101)
    first = authorize(factory, register, subject, now=NOW)
    assert authorize(factory, register, subject, now=NOW) == first
    assert counts(factory) == (1, 1, 1)

    conflicting = register_payload(key, subject, device=2, public_key=xkey(10), request=101)
    assert attempt(lambda: authorize(factory, conflicting, subject, now=NOW))[0] is False
    assert counts(factory) == (1, 1, 1)

    rotate_time = NOW + timedelta(seconds=10)
    rotate = lifecycle_payload(
        key,
        subject,
        operation="rotate",
        device=1,
        public_key=xkey(10),
        version=2,
        valid_from=rotate_time,
        binding_expires_at=first.binding.expires_at,
        prior=first.binding.binding_id,
        request=102,
    )
    second = authorize(factory, rotate, subject, now=rotate_time)
    assert second.binding.prior_binding_id == first.binding.binding_id

    revoke_time = NOW + timedelta(seconds=20)
    revoke = lifecycle_payload(
        key,
        subject,
        operation="revoke",
        device=1,
        public_key=second.binding.public_key,
        version=3,
        valid_from=revoke_time,
        binding_expires_at=second.binding.expires_at,
        prior=second.binding.binding_id,
        request=103,
    )
    revoked = authorize(factory, revoke, subject, now=revoke_time)
    assert revoked.binding.active is False
    assert counts(factory) == (3, 3, 3)
    with factory() as session:
        rows = (
            session.execute(
                select(SocialMessagingDeviceBindingRow).order_by(SocialMessagingDeviceBindingRow.binding_version)
            )
            .scalars()
            .all()
        )
    assert [row.valid_from for row in rows] == [NOW, rotate_time, revoke_time]
    assert [row.expires_at for row in rows] == [first.binding.expires_at] * 3

    other_key, other_subject = identity(16)
    seed_full(factory, other_subject)
    reused_history = register_payload(
        other_key,
        other_subject,
        device=2,
        public_key=first.binding.public_key,
        request=104,
        now=revoke_time,
    )
    assert attempt(lambda: authorize(factory, reused_history, other_subject, now=revoke_time))[0] is False
    assert counts(factory) == (3, 3, 3)


def test_concurrent_exact_retry_waits_on_request_lock_and_retains_one_result(postgres_factory):
    _engine, factory = postgres_factory
    key, subject = identity(17)
    seed_full(factory, subject)
    payload = register_payload(key, subject, device=1, public_key=xkey(76), request=1101)
    expected = authorize(factory, payload, subject, now=NOW)

    def operation(session):
        return authorize_in_session(
            session,
            payload,
            subject,
            clock=lambda: NOW,
        )

    first, second = _run_blocked_pair(
        factory,
        authorization_storage._lock_keys(
            authorization_storage._REQUEST_LOCK_DOMAIN,
            hex_id(1101),
        ),
        operation,
        operation,
    )

    assert first == (True, expected)
    assert second == (True, expected)
    assert counts(factory) == (1, 1, 1)


def test_conflicting_request_id_race_has_ordered_complete_winner(postgres_factory):
    _engine, factory = postgres_factory
    key, subject = identity(18)
    seed_full(factory, subject)
    winner_payload = register_payload(
        key,
        subject,
        device=1,
        public_key=xkey(77),
        request=1102,
    )
    loser_payload = register_payload(
        key,
        subject,
        device=2,
        public_key=xkey(78),
        request=1102,
    )

    first, second = _run_blocked_pair(
        factory,
        authorization_storage._lock_keys(
            authorization_storage._REQUEST_LOCK_DOMAIN,
            hex_id(1102),
        ),
        lambda session: authorize_in_session(
            session,
            winner_payload,
            subject,
            clock=lambda: NOW,
        ),
        lambda session: authorize_in_session(
            session,
            loser_payload,
            subject,
            clock=lambda: NOW,
        ),
    )

    assert first[0] is True
    assert first[1].binding.device_id == hex_id(1)
    assert second == (False, None)
    assert authorize(factory, winner_payload, subject, now=NOW) == first[1]
    assert attempt(lambda: authorize(factory, loser_payload, subject, now=NOW)) == (False, None)
    assert counts(factory) == (1, 1, 1)


def test_binding_id_collision_rolls_back_without_evidence_or_replay(postgres_factory):
    _engine, factory = postgres_factory
    key, subject = identity(4)
    seed_full(factory, subject)
    payload = register_payload(key, subject, device=1, public_key=xkey(11), request=201)

    SqlAlchemySocialMessagingDeviceRepository(
        factory,
        binding_lifetime_seconds=int(LIFETIME.total_seconds()),
    ).apply(
        MessagingDeviceCommand("register", hex_id(1), xkey(11), None, hex_id(201)),
        subject=subject,
        now=NOW,
    )
    assert attempt(lambda: authorize(factory, payload, subject, now=NOW))[0] is False
    assert counts(factory) == (1, 0, 0)


def test_duplicate_public_key_race_has_ordered_complete_winner(postgres_factory):
    _engine, factory = postgres_factory
    key_a, subject_a = identity(5)
    key_b, subject_b = identity(6)
    seed_full(factory, subject_a)
    seed_full(factory, subject_b)
    shared_key = xkey(12)
    winner_payload = register_payload(
        key_a,
        subject_a,
        device=1,
        public_key=shared_key,
        request=301,
    )
    loser_payload = register_payload(
        key_b,
        subject_b,
        device=1,
        public_key=shared_key,
        request=302,
    )

    first, second = _run_blocked_pair(
        factory,
        authorization_storage._lock_keys(
            authorization_storage._PUBLIC_KEY_GUARD_DOMAIN,
            "global",
        ),
        lambda session: authorize_in_session(
            session,
            winner_payload,
            subject_a,
            clock=lambda: NOW,
        ),
        lambda session: authorize_in_session(
            session,
            loser_payload,
            subject_b,
            clock=lambda: NOW,
        ),
    )

    assert first[0] is True
    assert first[1].binding.subject == subject_a
    assert second == (False, None)
    assert authorize(factory, winner_payload, subject_a, now=NOW) == first[1]
    assert attempt(lambda: authorize(factory, loser_payload, subject_b, now=NOW)) == (False, None)
    assert counts(factory) == (1, 1, 1)


def test_concurrent_sixteenth_device_capacity_race(postgres_factory):
    _engine, factory = postgres_factory
    key, subject = identity(7)
    seed_full(factory, subject)
    for index in range(MAX_ACTIVE_DEVICES - 1):
        authorize(
            factory,
            register_payload(
                key,
                subject,
                device=index + 1,
                public_key=xkey(20 + index),
                request=400 + index,
            ),
            subject,
            now=NOW,
        )
    contenders = (
        register_payload(key, subject, device=100, public_key=xkey(50), request=500),
        register_payload(key, subject, device=101, public_key=xkey(51), request=501),
    )
    first, second = _run_blocked_pair(
        factory,
        _subject_lock_keys(subject),
        lambda session: authorize_in_session(
            session,
            contenders[0],
            subject,
            clock=lambda: NOW,
        ),
        lambda session: authorize_in_session(
            session,
            contenders[1],
            subject,
            clock=lambda: NOW,
        ),
    )

    assert first[0] is True
    assert first[1].binding.device_id == hex_id(100)
    assert second == (False, None)
    assert authorize(factory, contenders[0], subject, now=NOW) == first[1]
    assert attempt(lambda: authorize(factory, contenders[1], subject, now=NOW)) == (False, None)
    assert counts(factory) == (MAX_ACTIVE_DEVICES, MAX_ACTIVE_DEVICES, MAX_ACTIVE_DEVICES)
    with factory() as session:
        active_devices = session.execute(
            select(SocialMessagingDeviceBindingRow.device_id)
            .where(SocialMessagingDeviceBindingRow.active.is_(True))
            .order_by(SocialMessagingDeviceBindingRow.device_id)
        ).scalars()
        assert set(active_devices) == {hex_id(index + 1) for index in range(15)} | {hex_id(100)}


@pytest.mark.parametrize("second_action", ["rotate", "revoke"])
def test_rotate_races_rotate_or_revoke_with_ordered_winner(postgres_factory, second_action):
    _engine, factory = postgres_factory
    key, subject = identity(8 if second_action == "rotate" else 9)
    seed_full(factory, subject)
    first = authorize(
        factory,
        register_payload(key, subject, device=1, public_key=xkey(60), request=601),
        subject,
        now=NOW,
    )
    edge_time = NOW + timedelta(seconds=10)
    first_rotate = lifecycle_payload(
        key,
        subject,
        operation="rotate",
        device=1,
        public_key=xkey(61),
        version=2,
        valid_from=edge_time,
        binding_expires_at=first.binding.expires_at,
        prior=first.binding.binding_id,
        request=602,
    )
    second = lifecycle_payload(
        key,
        subject,
        operation=second_action,
        device=1,
        public_key=xkey(62) if second_action == "rotate" else first.binding.public_key,
        version=2,
        valid_from=edge_time,
        binding_expires_at=first.binding.expires_at,
        prior=first.binding.binding_id,
        request=603,
    )
    first_result, second_result = _run_blocked_pair(
        factory,
        _subject_lock_keys(subject),
        lambda session: authorize_in_session(
            session,
            first_rotate,
            subject,
            clock=lambda: edge_time,
        ),
        lambda session: authorize_in_session(
            session,
            second,
            subject,
            clock=lambda: edge_time,
        ),
    )

    assert first_result[0] is True
    assert first_result[1].binding.public_key == xkey(61)
    assert second_result == (False, None)
    assert authorize(factory, first_rotate, subject, now=edge_time) == first_result[1]
    assert attempt(lambda: authorize(factory, second, subject, now=edge_time)) == (False, None)
    assert counts(factory) == (2, 2, 2)
    with factory() as session:
        rows = (
            session.execute(
                select(SocialMessagingDeviceBindingRow).order_by(SocialMessagingDeviceBindingRow.binding_version)
            )
            .scalars()
            .all()
        )
    assert [row.active for row in rows] == [False, True]
    assert [row.public_key for row in rows] == [xkey(60), xkey(61)]


def test_adoption_is_evidence_only_and_current_full_inactivation_wins_race(postgres_factory):
    _engine, factory = postgres_factory
    key, subject = identity(10)
    seed_full(factory, subject)
    repository = SqlAlchemySocialMessagingDeviceRepository(
        factory,
        binding_lifetime_seconds=int(LIFETIME.total_seconds()),
    )
    legacy = repository.apply(
        MessagingDeviceCommand("register", hex_id(1), xkey(70), None, hex_id(701)),
        subject=subject,
        now=NOW,
    )
    payload = adoption_payload(key, legacy, request=702, issued_at=NOW + timedelta(seconds=1))

    with factory() as session:
        before = (
            session.execute(
                select(SocialMessagingDeviceBindingRow).where(
                    SocialMessagingDeviceBindingRow.binding_id == legacy.binding_id
                )
            )
            .scalar_one()
            .__dict__.copy()
        )
        before.pop("_sa_instance_state")
    adopted = adopt(factory, payload, subject, now=NOW + timedelta(seconds=1))
    with factory() as session:
        after = (
            session.execute(
                select(SocialMessagingDeviceBindingRow).where(
                    SocialMessagingDeviceBindingRow.binding_id == legacy.binding_id
                )
            )
            .scalar_one()
            .__dict__.copy()
        )
        after.pop("_sa_instance_state")
    assert adopted.binding == legacy
    assert after == before
    assert counts(factory) == (1, 1, 1)
    assert adopt(factory, payload, subject, now=NOW + timedelta(seconds=1)) == adopted
    assert counts(factory) == (1, 1, 1)

    key_two, subject_two = identity(11)
    seed_full(factory, subject_two)
    legacy_two = repository.apply(
        MessagingDeviceCommand("register", hex_id(2), xkey(71), None, hex_id(703)),
        subject=subject_two,
        now=NOW,
    )
    payload_two = adoption_payload(
        key_two,
        legacy_two,
        request=704,
        issued_at=NOW + timedelta(seconds=1),
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as blocker:
            with blocker.begin():
                _lock_subject_for_evidence_change(blocker, subject_two)
                blocker.execute(User.__table__.update().where(User.pubkey == subject_two).values(is_active=False))
                blocker_pid = blocker.execute(select(func.pg_backend_pid())).scalar_one()
                adoption, _adoption_pid = _submit_waiting_attempt(
                    pool,
                    factory,
                    (blocker_pid,),
                    lambda session: adopt_in_session(
                        session,
                        payload_two,
                        subject_two,
                        clock=lambda: NOW + timedelta(seconds=1),
                    ),
                )
        assert adoption.result(timeout=10) == (False, None)
    assert counts(factory) == (2, 1, 1)
    with factory() as session:
        assert session.execute(select(User.is_active).where(User.pubkey == subject_two)).scalar_one() is False
        assert (
            session.execute(
                select(SocialMessagingDeviceBindingRow.active).where(
                    SocialMessagingDeviceBindingRow.binding_id == legacy_two.binding_id
                )
            ).scalar_one()
            is True
        )


def test_lifecycle_expiring_during_request_lock_wait_fails_without_partial_rows(postgres_factory):
    _engine, factory = postgres_factory
    key, subject = identity(19)
    seed_full(factory, subject)
    payload = register_payload(key, subject, device=1, public_key=xkey(79), request=1201)
    clock = MutableClock(NOW)
    before = counts(factory)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as blocker:
            with blocker.begin():
                _acquire_advisory_lock(
                    blocker,
                    authorization_storage._lock_keys(
                        authorization_storage._REQUEST_LOCK_DOMAIN,
                        hex_id(1201),
                    ),
                )
                blocker_pid = blocker.execute(select(func.pg_backend_pid())).scalar_one()
                authorization, _authorization_pid = _submit_waiting_attempt(
                    pool,
                    factory,
                    (blocker_pid,),
                    lambda session: authorize_in_session(
                        session,
                        payload,
                        subject,
                        clock=clock,
                    ),
                )
                assert clock.calls == 0
                clock.set(NOW + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS))
        assert authorization.result(timeout=10) == (False, None)

    assert clock.calls == 1
    assert counts(factory) == before == (0, 0, 0)


def test_adoption_expiring_during_request_lock_wait_fails_without_partial_rows(postgres_factory):
    _engine, factory = postgres_factory
    key, subject = identity(20)
    seed_full(factory, subject)
    legacy = SqlAlchemySocialMessagingDeviceRepository(
        factory,
        binding_lifetime_seconds=int(LIFETIME.total_seconds()),
    ).apply(
        MessagingDeviceCommand("register", hex_id(1), xkey(80), None, hex_id(1202)),
        subject=subject,
        now=NOW,
    )
    issued_at = NOW + timedelta(seconds=1)
    payload = adoption_payload(key, legacy, request=1203, issued_at=issued_at)
    clock = MutableClock(issued_at)
    before = counts(factory)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as blocker:
            with blocker.begin():
                _acquire_advisory_lock(
                    blocker,
                    authorization_storage._lock_keys(
                        authorization_storage._REQUEST_LOCK_DOMAIN,
                        hex_id(1203),
                    ),
                )
                blocker_pid = blocker.execute(select(func.pg_backend_pid())).scalar_one()
                adoption, _adoption_pid = _submit_waiting_attempt(
                    pool,
                    factory,
                    (blocker_pid,),
                    lambda session: adopt_in_session(
                        session,
                        payload,
                        subject,
                        clock=clock,
                    ),
                )
                assert clock.calls == 0
                clock.set(issued_at + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS))
        assert adoption.result(timeout=10) == (False, None)

    assert clock.calls == 1
    assert counts(factory) == before == (1, 0, 0)


def test_lifecycle_expiring_during_legacy_user_row_wait_fails_without_partial_rows(
    postgres_factory,
):
    _engine, factory = postgres_factory
    key, subject = identity(21)
    seed_full(factory, subject)
    payload = register_payload(key, subject, device=1, public_key=xkey(81), request=1204)
    clock = MutableClock(NOW)
    before = counts(factory)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as blocker:
            with blocker.begin():
                blocker_pid = _lock_user_row_without_subject_advisory_lock(blocker, subject)
                authorization, _authorization_pid = _submit_waiting_attempt(
                    pool,
                    factory,
                    (blocker_pid,),
                    lambda session: authorize_in_session(
                        session,
                        payload,
                        subject,
                        clock=clock,
                    ),
                    assert_waiting=_assert_backend_waiting_on_user_row_lock,
                )
                assert clock.calls == 0
                clock.set(NOW + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS))
        assert authorization.result(timeout=10) == (False, None)

    assert clock.calls == 1
    assert counts(factory) == before == (0, 0, 0)


def test_adoption_expiring_during_legacy_user_row_wait_fails_without_partial_rows(
    postgres_factory,
):
    _engine, factory = postgres_factory
    key, subject = identity(22)
    seed_full(factory, subject)
    legacy = SqlAlchemySocialMessagingDeviceRepository(
        factory,
        binding_lifetime_seconds=int(LIFETIME.total_seconds()),
    ).apply(
        MessagingDeviceCommand("register", hex_id(1), xkey(82), None, hex_id(1205)),
        subject=subject,
        now=NOW,
    )
    issued_at = NOW + timedelta(seconds=1)
    payload = adoption_payload(key, legacy, request=1206, issued_at=issued_at)
    clock = MutableClock(issued_at)
    before = counts(factory)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory() as blocker:
            with blocker.begin():
                blocker_pid = _lock_user_row_without_subject_advisory_lock(blocker, subject)
                adoption, _adoption_pid = _submit_waiting_attempt(
                    pool,
                    factory,
                    (blocker_pid,),
                    lambda session: adopt_in_session(
                        session,
                        payload,
                        subject,
                        clock=clock,
                    ),
                    assert_waiting=_assert_backend_waiting_on_user_row_lock,
                )
                assert clock.calls == 0
                clock.set(issued_at + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS))
        assert adoption.result(timeout=10) == (False, None)

    assert clock.calls == 1
    assert counts(factory) == before == (1, 0, 0)


def test_global_request_id_cannot_cross_lifecycle_and_adoption(postgres_factory):
    _engine, factory = postgres_factory
    lifecycle_key, lifecycle_subject = identity(14)
    adoption_key, adoption_subject = identity(15)
    seed_full(factory, lifecycle_subject)
    seed_full(factory, adoption_subject)
    authorize(
        factory,
        register_payload(
            lifecycle_key,
            lifecycle_subject,
            device=1,
            public_key=xkey(74),
            request=1001,
        ),
        lifecycle_subject,
        now=NOW,
    )
    legacy = SqlAlchemySocialMessagingDeviceRepository(
        factory,
        binding_lifetime_seconds=int(LIFETIME.total_seconds()),
    ).apply(
        MessagingDeviceCommand("register", hex_id(2), xkey(75), None, hex_id(1002)),
        subject=adoption_subject,
        now=NOW,
    )
    cross_type = adoption_payload(
        adoption_key,
        legacy,
        request=1001,
        issued_at=NOW + timedelta(seconds=1),
    )

    assert (
        attempt(
            lambda: adopt(
                factory,
                cross_type,
                adoption_subject,
                now=NOW + timedelta(seconds=1),
            )
        )[0]
        is False
    )
    assert counts(factory) == (2, 1, 1)


def test_injected_failure_after_binding_mutation_rolls_everything_back(postgres_factory, monkeypatch):
    _engine, factory = postgres_factory
    key, subject = identity(12)
    seed_full(factory, subject)
    payload = register_payload(key, subject, device=1, public_key=xkey(72), request=801)

    def fail_after_binding_mutation(self, evidence, *, now):
        raise RuntimeError("synthetic injected failure")

    monkeypatch.setattr(
        "app.services.social_messaging_device_binding_authorization_storage._TransactionPorts.persist",
        fail_after_binding_mutation,
    )
    assert attempt(lambda: authorize(factory, payload, subject, now=NOW))[0] is False
    assert counts(factory) == (0, 0, 0)


def test_immutable_evidence_and_replay_reject_updates(postgres_factory):
    _engine, factory = postgres_factory
    key, subject = identity(13)
    seed_full(factory, subject)
    authorize(
        factory,
        register_payload(key, subject, device=1, public_key=xkey(73), request=901),
        subject,
        now=NOW,
    )

    with pytest.raises(Exception):
        with factory.begin() as session:
            session.execute(
                text("UPDATE social_messaging_device_binding_authorization_evidence " "SET action = 'rotate'")
            )
    with pytest.raises(Exception):
        with factory.begin() as session:
            session.execute(text("DELETE FROM social_messaging_device_binding_authorization_replay"))
    assert counts(factory) == (1, 1, 1)
