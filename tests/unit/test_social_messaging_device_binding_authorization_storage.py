from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

import app.services.social_messaging_device_binding_authorization_storage as storage
from app.services.social_messaging_device_storage import SqlAlchemyTransactionBoundSocialMessagingDeviceStorage

SUBJECT = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
DEVICE = "22" * 32
REQUEST = "33" * 32
KEY_A = "09" + "00" * 31
KEY_B = "0a" + "00" * 31


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one(self):
        return self._value


class _Session:
    def __init__(self, *, dialect="postgresql", active=True, isolation="read committed"):
        self.bind = SimpleNamespace(dialect=SimpleNamespace(name=dialect))
        self.active = active
        self.isolation = isolation
        self.statements = []

    def get_bind(self):
        return self.bind

    def in_transaction(self):
        return self.active

    def execute(self, statement):
        self.statements.append(statement)
        if str(statement) == "SHOW transaction_isolation":
            return _ScalarResult(self.isolation)
        return _ScalarResult(None)

    def add(self, _value):
        pass

    def flush(self):
        pass


def test_storage_requires_active_postgresql_read_committed_transaction():
    value = storage.SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(_Session())
    assert value._session.in_transaction() is True

    for session in (
        _Session(dialect="sqlite"),
        _Session(active=False),
        _Session(isolation="repeatable read"),
    ):
        with pytest.raises(ValueError):
            storage.SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(session)


def test_lock_order_includes_subject_user_row_before_device_guard_and_sorted_keys(monkeypatch):
    events = []
    session = _Session()
    value = storage.SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(session)

    monkeypatch.setattr(
        storage,
        "_advisory_lock",
        lambda _session, domain, key: events.append((domain, key)),
    )
    monkeypatch.setattr(
        storage,
        "_lock_subject_for_evidence_change",
        lambda _session, subject: events.append(("current-full-subject", subject)),
    )
    monkeypatch.setattr(
        storage,
        "_lock_subject_user",
        lambda _session, subject: events.append(("subject-user-row", subject)),
    )

    value._lock_operation(
        request_id=REQUEST,
        subject=SUBJECT,
        device_id=DEVICE,
        public_keys=(KEY_B, KEY_A, KEY_B),
    )

    assert events == [
        (storage._REQUEST_LOCK_DOMAIN, REQUEST),
        ("current-full-subject", SUBJECT),
        ("subject-user-row", SUBJECT),
        (storage._DEVICE_LOCK_DOMAIN, SUBJECT + ":" + DEVICE),
        (storage._PUBLIC_KEY_GUARD_DOMAIN, "global"),
        (storage._PUBLIC_KEY_LOCK_DOMAIN, KEY_A),
        (storage._PUBLIC_KEY_LOCK_DOMAIN, KEY_B),
    ]


def test_lock_sql_uses_transaction_level_postgresql_advisory_lock():
    session = _Session()
    storage._advisory_lock(session, storage._REQUEST_LOCK_DOMAIN, REQUEST)
    compiled = str(session.statements[-1].compile(dialect=postgresql.dialect()))
    assert "pg_advisory_xact_lock" in compiled


def test_transaction_bound_binding_adapter_has_no_transaction_lifecycle_methods():
    adapter = SqlAlchemyTransactionBoundSocialMessagingDeviceStorage(_Session())
    assert not hasattr(adapter, "begin")
    assert not hasattr(adapter, "commit")
    assert not hasattr(adapter, "rollback")
    assert not hasattr(adapter, "close")


def test_lifecycle_clock_is_sampled_once_only_after_all_operation_locks(monkeypatch):
    events = []
    result = object()
    authorization = SimpleNamespace(
        claim=SimpleNamespace(
            request_id=REQUEST,
            subject=SUBJECT,
            device_id=DEVICE,
            public_key=KEY_A,
        )
    )

    def clock():
        assert events == ["locks-returned"]
        events.append("clock")
        return storage.datetime(2026, 9, 10, tzinfo=storage.timezone.utc)

    class Ports:
        def __init__(self, *_args, **_kwargs):
            assert events == ["locks-returned", "clock"]

        def get(self, _request_id):
            return object()

    class Coordinator:
        def __init__(self, **kwargs):
            self.clock = kwargs["clock"]

        def authorize(self, *_args, **_kwargs):
            assert self.clock() == storage.datetime(2026, 9, 10, tzinfo=storage.timezone.utc)
            return result

    value = storage.SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(
        _Session(),
        clock=clock,
    )
    monkeypatch.setattr(
        value,
        "_lock_operation",
        lambda **_kwargs: events.append("locks-returned"),
    )
    monkeypatch.setattr(
        storage,
        "parse_and_verify_device_binding_authorization",
        lambda *_args, **_kwargs: authorization,
    )
    monkeypatch.setattr(storage, "_TransactionPorts", Ports)
    monkeypatch.setattr(storage, "SocialMessagingDeviceBindingAuthorizationV1", Coordinator)

    assert value.authorize_lifecycle("payload", authenticated_subject=SUBJECT) is result
    assert events == ["locks-returned", "clock"]


def test_adoption_clock_is_sampled_once_only_after_all_operation_locks(monkeypatch):
    events = []
    result = object()
    adoption = SimpleNamespace(
        claim=SimpleNamespace(
            request_id=REQUEST,
            binding=SimpleNamespace(subject=SUBJECT, device_id=DEVICE, public_key=KEY_A),
        )
    )

    def clock():
        assert events == ["locks-returned"]
        events.append("clock")
        return storage.datetime(2026, 9, 10, tzinfo=storage.timezone.utc)

    class Ports:
        def __init__(self, *_args, **_kwargs):
            assert events == ["locks-returned", "clock"]

        def get(self, _request_id):
            return object()

    class Coordinator:
        def __init__(self, **kwargs):
            self.clock = kwargs["clock"]

        def adopt(self, *_args, **_kwargs):
            assert self.clock() == storage.datetime(2026, 9, 10, tzinfo=storage.timezone.utc)
            return result

    value = storage.SqlAlchemySocialMessagingDeviceBindingAuthorizationStorage(
        _Session(),
        clock=clock,
    )
    monkeypatch.setattr(
        value,
        "_lock_operation",
        lambda **_kwargs: events.append("locks-returned"),
    )
    monkeypatch.setattr(
        storage,
        "parse_and_verify_device_binding_adoption",
        lambda *_args, **_kwargs: adoption,
    )
    monkeypatch.setattr(storage, "_TransactionPorts", Ports)
    monkeypatch.setattr(
        storage,
        "SqlAlchemyTransactionBoundCurrentFullVerifier",
        lambda _session: object(),
    )
    monkeypatch.setattr(storage, "SocialMessagingLegacyBindingAdoptionV1", Coordinator)

    assert value.adopt_legacy("payload", authenticated_subject=SUBJECT) is result
    assert events == ["locks-returned", "clock"]


def test_authorization_models_compile_bounded_postgresql_contracts():
    evidence = str(
        CreateTable(storage.SocialMessagingDeviceBindingAuthorizationEvidenceRow.__table__).compile(
            dialect=postgresql.dialect()
        )
    )
    replay = str(
        CreateTable(storage.SocialMessagingDeviceBindingAuthorizationReplayRow.__table__).compile(
            dialect=postgresql.dialect()
        )
    )

    assert "PRIMARY KEY (binding_id)" in evidence
    assert "octet_length(canonical_payload) BETWEEN 1 AND 8192" in evidence
    assert "DEFERRABLE INITIALLY DEFERRED" in evidence
    assert "PRIMARY KEY (request_id)" in replay
    assert "result_proof_id" in replay
    assert "fk_social_device_authorization_replay_evidence" in replay
