from datetime import datetime, timezone
import json

from coincurve import PrivateKey, PublicKeyXOnly
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import app.services.social_messaging_device_binding_registry as contract

from app.models import SocialMessagingDeviceBinding
from app.services.social_messaging_device_binding_registry import (
    DeviceBindingRegistryUnavailable,
    parse_and_verify_statement,
    statement_digest,
)
from app.services.social_messaging_device_binding_registry_storage import (
    SqlAlchemySocialMessagingDeviceBindingRepository,
)


NOW = datetime(2026, 9, 4, 8, tzinfo=timezone.utc)

DEVICE_A = "11" * 32
DEVICE_B = "22" * 32

KEY_A = "09" + "00" * 31
KEY_B = "0a" + "00" * 31
KEY_C = "0b" + "00" * 31
KEY_D = "0c" + "00" * 31


def encoded(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def subject_for(private_key):
    return PublicKeyXOnly.from_secret(
        private_key.secret
    ).format().hex()


def statement(
    private_key,
    *,
    device_id=DEVICE_A,
    public_key=KEY_A,
    version=1,
    operation="register",
    prior=None,
    nonce="31" * 32,
):
    subject = subject_for(private_key)

    core = {
        "schema": contract.STATEMENT_SCHEMA,
        "version": 1,
        "subject": subject,
        "deviceId": device_id,
        "algorithm": contract.ALGORITHM,
        "publicKey": public_key,
        "bindingVersion": version,
        "validFrom": "2026-09-04T07:00:00Z",
        "expiresAt": "2027-09-04T07:00:00Z",
        "operation": operation,
        "priorBindingId": prior,
        "nonce": nonce,
    }

    digest = statement_digest(core)

    payload = {
        **core,
        "digest": digest,
        "signatureFormat": contract.SIGNATURE_FORMAT,
        "signature": private_key.sign_schnorr(
            bytes.fromhex(digest),
            b"\x00" * 32,
        ).hex(),
    }

    return parse_and_verify_statement(
        encoded(payload),
        authenticated_subject=subject,
    )


@pytest.fixture
def repository():
    engine = create_engine("sqlite://")

    SocialMessagingDeviceBinding.__table__.create(
        engine
    )

    return SqlAlchemySocialMessagingDeviceBindingRepository(
        sessionmaker(bind=engine)
    )


def rows(repository):
    with repository._session_factory() as session:
        values = (
            session.execute(
                select(SocialMessagingDeviceBinding)
                .order_by(
                    SocialMessagingDeviceBinding.subject_pubkey,
                    SocialMessagingDeviceBinding.device_id,
                    SocialMessagingDeviceBinding.binding_version,
                )
            )
            .scalars()
            .all()
        )

        return [
            (
                row.subject_pubkey,
                row.device_id,
                row.public_key,
                row.binding_version,
                row.operation,
                row.active,
                row.retired_at is not None,
            )
            for row in values
        ]


def test_two_active_devices_for_one_subject(repository):
    private_key = PrivateKey(b"\x01" * 32)

    first = statement(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_A,
        nonce="31" * 32,
    )

    second = statement(
        private_key,
        device_id=DEVICE_B,
        public_key=KEY_B,
        nonce="32" * 32,
    )

    repository.apply(first, NOW)
    repository.apply(second, NOW)

    current = repository.current_for_subject(
        first.subject,
        NOW,
        16,
    )

    assert [
        item.device_id
        for item in current
    ] == [DEVICE_A, DEVICE_B]

    assert all(
        item.subject == first.subject
        for item in current
    )


def test_rotate_one_device_does_not_retire_other(repository):
    private_key = PrivateKey(b"\x01" * 32)

    first = statement(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_A,
        nonce="31" * 32,
    )

    other = statement(
        private_key,
        device_id=DEVICE_B,
        public_key=KEY_B,
        nonce="32" * 32,
    )

    repository.apply(first, NOW)
    repository.apply(other, NOW)

    rotated = statement(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_C,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="33" * 32,
    )

    repository.apply(rotated, NOW)

    current = repository.current_for_subject(
        first.subject,
        NOW,
        16,
    )

    assert {
        (item.device_id, item.public_key)
        for item in current
    } == {
        (DEVICE_A, KEY_C),
        (DEVICE_B, KEY_B),
    }


def test_revoke_one_device_leaves_other_current(repository):
    private_key = PrivateKey(b"\x01" * 32)

    first = statement(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_A,
        nonce="31" * 32,
    )

    other = statement(
        private_key,
        device_id=DEVICE_B,
        public_key=KEY_B,
        nonce="32" * 32,
    )

    repository.apply(first, NOW)
    repository.apply(other, NOW)

    revoked = statement(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_A,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="33" * 32,
    )

    assert repository.apply(revoked, NOW) == revoked

    current = repository.current_for_subject(
        first.subject,
        NOW,
        16,
    )

    assert len(current) == 1
    assert current[0].device_id == DEVICE_B
    assert current[0].public_key == KEY_B


def test_revoke_replay_is_idempotent(repository):
    private_key = PrivateKey(b"\x01" * 32)

    first = statement(
        private_key,
        nonce="31" * 32,
    )

    repository.apply(first, NOW)

    revoked = statement(
        private_key,
        public_key=KEY_A,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="32" * 32,
    )

    repository.apply(revoked, NOW)

    before = rows(repository)

    assert repository.apply(revoked, NOW) == revoked
    assert rows(repository) == before


def test_rotation_cannot_reuse_same_public_key(repository):
    private_key = PrivateKey(b"\x01" * 32)

    first = statement(
        private_key,
        nonce="31" * 32,
    )

    repository.apply(first, NOW)

    bad = statement(
        private_key,
        public_key=KEY_A,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="32" * 32,
    )

    with pytest.raises(DeviceBindingRegistryUnavailable):
        repository.apply(bad, NOW)


def test_revocation_cannot_substitute_public_key(repository):
    private_key = PrivateKey(b"\x01" * 32)

    first = statement(
        private_key,
        nonce="31" * 32,
    )

    repository.apply(first, NOW)

    bad = statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="revoke",
        prior=first.binding_id,
        nonce="32" * 32,
    )

    with pytest.raises(DeviceBindingRegistryUnavailable):
        repository.apply(bad, NOW)


def test_stale_predecessor_is_rejected(repository):
    private_key = PrivateKey(b"\x01" * 32)

    first = statement(
        private_key,
        public_key=KEY_A,
        nonce="31" * 32,
    )

    repository.apply(first, NOW)

    rotated = statement(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="32" * 32,
    )

    repository.apply(rotated, NOW)

    stale = statement(
        private_key,
        public_key=KEY_C,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="33" * 32,
    )

    with pytest.raises(DeviceBindingRegistryUnavailable):
        repository.apply(stale, NOW)


def test_active_public_key_is_globally_unique(repository):
    private_key = PrivateKey(b"\x01" * 32)

    first = statement(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_A,
        nonce="31" * 32,
    )

    duplicate = statement(
        private_key,
        device_id=DEVICE_B,
        public_key=KEY_A,
        nonce="32" * 32,
    )

    repository.apply(first, NOW)

    with pytest.raises(DeviceBindingRegistryUnavailable):
        repository.apply(duplicate, NOW)


def test_maximum_sixteen_current_devices(repository):
    private_key = PrivateKey(b"\x01" * 32)

    subject = subject_for(private_key)

    for index in range(16):
        device = f"{index + 1:064x}"

        public_key = (
            f"{index + 9:02x}"
            + "00" * 31
        )

        item = statement(
            private_key,
            device_id=device,
            public_key=public_key,
            nonce=f"{index + 40:064x}",
        )

        repository.apply(item, NOW)

    assert len(
        repository.current_for_subject(
            subject,
            NOW,
            16,
        )
    ) == 16

    seventeenth = statement(
        private_key,
        device_id=f"{100:064x}",
        public_key=KEY_D,
        nonce=f"{1000:064x}",
    )

    with pytest.raises(DeviceBindingRegistryUnavailable):
        repository.apply(seventeenth, NOW)


def test_register_again_for_same_device_fails(repository):
    private_key = PrivateKey(b"\x01" * 32)

    first = statement(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_A,
        nonce="31" * 32,
    )

    repository.apply(first, NOW)

    second_register = statement(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_B,
        nonce="32" * 32,
    )

    with pytest.raises(DeviceBindingRegistryUnavailable):
        repository.apply(second_register, NOW)
