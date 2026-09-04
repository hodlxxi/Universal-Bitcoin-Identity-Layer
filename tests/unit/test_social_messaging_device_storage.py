from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.models import User
from app.services.social_messaging_device_contract import (
    MAX_ACTIVE_DEVICES,
    MessagingDeviceAuthorityUnavailable,
    MessagingDeviceCommand,
)
from app.services.social_messaging_device_storage import (
    SocialMessagingDeviceBindingRow,
    SqlAlchemySocialMessagingDeviceRepository,
)

SUBJECT = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
OTHER_SUBJECT = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
NOW = datetime(2026, 9, 4, 23, 0, 0, tzinfo=timezone.utc)
LIFETIME = 30 * 24 * 60 * 60


def hex_id(value: int) -> str:
    return f"{value:064x}"


def xkey(byte: int) -> str:
    assert 2 <= byte < 0x80
    return f"{byte:02x}" * 32


def register(device: int, key: int, request: int) -> MessagingDeviceCommand:
    return MessagingDeviceCommand(
        "register",
        hex_id(device),
        xkey(key),
        None,
        hex_id(request),
    )


def rotate(
    device: int,
    key: int,
    prior: str,
    request: int,
) -> MessagingDeviceCommand:
    return MessagingDeviceCommand(
        "rotate",
        hex_id(device),
        xkey(key),
        prior,
        hex_id(request),
    )


def revoke(device: int, prior: str, request: int) -> MessagingDeviceCommand:
    return MessagingDeviceCommand(
        "revoke",
        hex_id(device),
        None,
        prior,
        hex_id(request),
    )


@pytest.fixture
def storage():
    engine = create_engine("sqlite:///:memory:", future=True)
    User.__table__.create(engine)
    SocialMessagingDeviceBindingRow.__table__.create(engine)
    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        session.add_all(
            [
                User(id="user-a", pubkey=SUBJECT, created_at=NOW, is_active=True),
                User(id="user-b", pubkey=OTHER_SUBJECT, created_at=NOW, is_active=True),
            ]
        )
        session.commit()
    repository = SqlAlchemySocialMessagingDeviceRepository(
        Session,
        binding_lifetime_seconds=LIFETIME,
    )
    return engine, Session, repository


def test_two_devices_for_one_subject_are_independently_active(storage):
    _engine, _Session, repository = storage
    first = repository.apply(register(1, 0x11, 101), subject=SUBJECT, now=NOW)
    second = repository.apply(register(2, 0x12, 102), subject=SUBJECT, now=NOW)

    assert first.binding_version == 1
    assert second.binding_version == 1
    assert first.binding_id != second.binding_id
    assert first.active is True and second.active is True

    current = repository.current_for_subject(
        SUBJECT,
        now=NOW,
        maximum=MAX_ACTIVE_DEVICES,
    )
    assert [item.device_id for item in current] == [hex_id(1), hex_id(2)]


def test_rotate_requires_exact_current_binding_and_retires_predecessor(storage):
    _engine, Session, repository = storage
    first = repository.apply(register(1, 0x11, 101), subject=SUBJECT, now=NOW)

    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        repository.apply(
            rotate(1, 0x12, hex_id(999), 102),
            subject=SUBJECT,
            now=NOW,
        )

    second = repository.apply(
        rotate(1, 0x12, first.binding_id, 103),
        subject=SUBJECT,
        now=NOW,
    )
    assert second.binding_version == 2
    assert second.prior_binding_id == first.binding_id
    assert second.active is True

    with Session() as session:
        rows = list(
            session.execute(
                select(SocialMessagingDeviceBindingRow).order_by(
                    SocialMessagingDeviceBindingRow.binding_version
                )
            ).scalars()
        )
    assert len(rows) == 2
    assert rows[0].active is False
    assert rows[0].retired_at is not None
    assert rows[1].active is True


def test_revoke_is_terminal_for_current_projection_and_replay_is_idempotent(storage):
    _engine, _Session, repository = storage
    first = repository.apply(register(1, 0x11, 101), subject=SUBJECT, now=NOW)
    command = revoke(1, first.binding_id, 102)
    revoked = repository.apply(command, subject=SUBJECT, now=NOW)
    replay = repository.apply(command, subject=SUBJECT, now=NOW)

    assert revoked == replay
    assert revoked.operation == "revoke"
    assert revoked.binding_version == 2
    assert revoked.prior_binding_id == first.binding_id
    assert revoked.public_key == first.public_key
    assert revoked.active is False
    assert repository.current_for_subject(
        SUBJECT,
        now=NOW,
        maximum=MAX_ACTIVE_DEVICES,
    ) == []


def test_register_replay_is_idempotent_but_request_id_cannot_change_meaning(storage):
    _engine, _Session, repository = storage
    command = register(1, 0x11, 101)
    first = repository.apply(command, subject=SUBJECT, now=NOW)
    replay = repository.apply(command, subject=SUBJECT, now=NOW)
    assert replay == first

    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        repository.apply(
            register(2, 0x12, 101),
            subject=SUBJECT,
            now=NOW,
        )


def test_device_id_cannot_be_re_registered_after_revoke(storage):
    _engine, _Session, repository = storage
    first = repository.apply(register(1, 0x11, 101), subject=SUBJECT, now=NOW)
    repository.apply(revoke(1, first.binding_id, 102), subject=SUBJECT, now=NOW)

    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        repository.apply(register(1, 0x12, 103), subject=SUBJECT, now=NOW)


def test_public_encryption_key_is_never_reused_across_history_or_subjects(storage):
    _engine, _Session, repository = storage
    first = repository.apply(register(1, 0x11, 101), subject=SUBJECT, now=NOW)
    repository.apply(revoke(1, first.binding_id, 102), subject=SUBJECT, now=NOW)

    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        repository.apply(register(2, 0x11, 201), subject=OTHER_SUBJECT, now=NOW)


def test_active_device_cap_is_exactly_sixteen(storage):
    _engine, _Session, repository = storage
    for index in range(MAX_ACTIVE_DEVICES):
        repository.apply(
            register(index + 1, 0x20 + index, 1000 + index),
            subject=SUBJECT,
            now=NOW,
        )

    assert len(
        repository.current_for_subject(
            SUBJECT,
            now=NOW,
            maximum=MAX_ACTIVE_DEVICES,
        )
    ) == MAX_ACTIVE_DEVICES

    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        repository.apply(
            register(99, 0x40, 2000),
            subject=SUBJECT,
            now=NOW,
        )


def test_expired_rows_drop_out_and_are_retired_before_new_registration(storage):
    _engine, Session, repository = storage
    first = repository.apply(register(1, 0x11, 101), subject=SUBJECT, now=NOW)
    later = NOW + timedelta(days=31)

    assert repository.current_for_subject(
        SUBJECT,
        now=later,
        maximum=MAX_ACTIVE_DEVICES,
    ) == []

    repository.apply(register(2, 0x12, 102), subject=SUBJECT, now=later)

    with Session() as session:
        old = session.get(SocialMessagingDeviceBindingRow, first.binding_id)
        assert old is not None
        assert old.active is False
        assert old.retired_at is not None


def test_missing_persisted_subject_fails_closed(storage):
    _engine, _Session, repository = storage
    missing = "c6047f9441ed7d6d3045406e95c07cd85a167316c350aa24d92329b3d1c8b0a2"
    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        repository.apply(register(1, 0x11, 101), subject=missing, now=NOW)


def test_storage_rejects_invalid_lifetime_configuration(storage):
    _engine, Session, _repository = storage
    with pytest.raises(ValueError):
        SqlAlchemySocialMessagingDeviceRepository(
            Session,
            binding_lifetime_seconds=1,
        )
