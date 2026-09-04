from datetime import datetime, timezone
import json
from pathlib import Path

from coincurve import PrivateKey, PublicKeyXOnly
import pytest

import app.services.social_messaging_device_binding_registry as contract

from app.models import SocialMessagingDeviceBinding
from app.services.social_messaging_device_binding_registry import (
    DeviceBindingRegistryUnavailable,
    SocialMessagingDeviceBindingRegistry,
    parse_and_verify_statement,
    statement_digest,
)


NOW = datetime(2026, 9, 4, 8, tzinfo=timezone.utc)

DEVICE_A = "11" * 32
DEVICE_B = "22" * 32

KEY_A = "09" + "00" * 31
KEY_B = "0a" + "00" * 31
KEY_C = "0b" + "00" * 31


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


def signed_payload(
    private_key,
    *,
    device_id=DEVICE_A,
    public_key=KEY_A,
    version=1,
    operation="register",
    prior=None,
    nonce="33" * 32,
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

    return {
        **core,
        "digest": digest,
        "signatureFormat": contract.SIGNATURE_FORMAT,
        "signature": private_key.sign_schnorr(
            bytes.fromhex(digest),
            b"\x00" * 32,
        ).hex(),
    }


def parsed(private_key, **values):
    candidate = signed_payload(private_key, **values)

    return parse_and_verify_statement(
        encoded(candidate),
        authenticated_subject=candidate["subject"],
    )


class StubRepository:
    def __init__(self, records=None):
        self.records = list(records or [])

    def apply(self, statement, _now):
        return statement

    def current_for_subject(
        self,
        subject,
        _now,
        maximum,
    ):
        return [
            record
            for record in self.records
            if record.subject == subject
        ][:maximum]


def test_real_bip340_registration_is_accepted():
    private_key = PrivateKey(b"\x01" * 32)

    statement = parsed(private_key)

    assert statement.device_id == DEVICE_A
    assert statement.public_key == KEY_A
    assert statement.operation == "register"
    assert statement.binding_version == 1


def test_authenticated_subject_mismatch_fails_closed():
    private_key = PrivateKey(b"\x01" * 32)
    other_key = PrivateKey(b"\x02" * 32)

    payload = signed_payload(private_key)

    with pytest.raises(DeviceBindingRegistryUnavailable):
        parse_and_verify_statement(
            encoded(payload),
            authenticated_subject=subject_for(other_key),
        )


def test_digest_and_signature_tampering_fail_closed():
    private_key = PrivateKey(b"\x01" * 32)

    payload = signed_payload(private_key)
    payload["digest"] = "44" * 32

    with pytest.raises(DeviceBindingRegistryUnavailable):
        parse_and_verify_statement(
            encoded(payload),
            authenticated_subject=payload["subject"],
        )

    payload = signed_payload(private_key)
    payload["signature"] = "00" * 64

    with pytest.raises(DeviceBindingRegistryUnavailable):
        parse_and_verify_statement(
            encoded(payload),
            authenticated_subject=payload["subject"],
        )


def test_private_and_unknown_fields_are_rejected():
    private_key = PrivateKey(b"\x01" * 32)

    for name in (
        "privateKey",
        "seed",
        "label",
        "email",
        "phone",
        "userAgent",
    ):
        payload = signed_payload(private_key)
        payload[name] = "forbidden"

        with pytest.raises(DeviceBindingRegistryUnavailable):
            parse_and_verify_statement(
                encoded(payload),
                authenticated_subject=payload["subject"],
            )


def test_noncanonical_json_and_duplicate_keys_fail_closed():
    private_key = PrivateKey(b"\x01" * 32)

    payload = signed_payload(private_key)
    canonical = encoded(payload)

    with pytest.raises(DeviceBindingRegistryUnavailable):
        parse_and_verify_statement(
            canonical + " ",
            authenticated_subject=payload["subject"],
        )

    duplicated = canonical.replace(
        f'"deviceId":"{DEVICE_A}"',
        f'"deviceId":"{DEVICE_B}","deviceId":"{DEVICE_A}"',
    )

    with pytest.raises(DeviceBindingRegistryUnavailable):
        parse_and_verify_statement(
            duplicated,
            authenticated_subject=payload["subject"],
        )


def test_same_subject_can_have_two_devices():
    private_key = PrivateKey(b"\x01" * 32)

    first = parsed(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_A,
        nonce="31" * 32,
    )

    second = parsed(
        private_key,
        device_id=DEVICE_B,
        public_key=KEY_B,
        nonce="32" * 32,
    )

    assert first.subject == second.subject
    assert first.device_id != second.device_id
    assert first.public_key != second.public_key


def test_rotate_and_revoke_statement_shapes():
    private_key = PrivateKey(b"\x01" * 32)

    first = parsed(
        private_key,
        nonce="31" * 32,
    )

    rotated = parsed(
        private_key,
        public_key=KEY_B,
        version=2,
        operation="rotate",
        prior=first.binding_id,
        nonce="32" * 32,
    )

    revoked = parsed(
        private_key,
        public_key=KEY_B,
        version=3,
        operation="revoke",
        prior=rotated.binding_id,
        nonce="33" * 32,
    )

    assert rotated.binding_version == 2
    assert revoked.binding_version == 3

    malformed = signed_payload(
        private_key,
        public_key=KEY_C,
        version=2,
        operation="rotate",
        prior=None,
        nonce="34" * 32,
    )

    with pytest.raises(DeviceBindingRegistryUnavailable):
        parse_and_verify_statement(
            encoded(malformed),
            authenticated_subject=malformed["subject"],
        )


def test_snapshot_returns_multiple_active_devices_without_subject_field():
    private_key = PrivateKey(b"\x01" * 32)

    first = parsed(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_A,
        nonce="31" * 32,
    )

    second = parsed(
        private_key,
        device_id=DEVICE_B,
        public_key=KEY_B,
        nonce="32" * 32,
    )

    repository = StubRepository(
        sorted(
            [second, first],
            key=lambda item: item.device_id,
        )
    )

    registry = SocialMessagingDeviceBindingRegistry(
        repository,
        clock=lambda: NOW,
    )

    result = registry.current_for_subject(first.subject)

    assert result["complete"] is True
    assert len(result["activeDevices"]) == 2
    assert "subject" not in result


def test_snapshot_rejects_duplicate_active_public_key():
    private_key = PrivateKey(b"\x01" * 32)

    first = parsed(
        private_key,
        device_id=DEVICE_A,
        public_key=KEY_A,
        nonce="31" * 32,
    )

    second = parsed(
        private_key,
        device_id=DEVICE_B,
        public_key=KEY_A,
        nonce="32" * 32,
    )

    registry = SocialMessagingDeviceBindingRegistry(
        StubRepository(
            sorted(
                [first, second],
                key=lambda item: item.device_id,
            )
        ),
        clock=lambda: NOW,
    )

    with pytest.raises(DeviceBindingRegistryUnavailable):
        registry.current_for_subject(first.subject)


def test_model_is_multi_device_not_single_subject():
    table = SocialMessagingDeviceBinding.__table__

    active_device = next(
        index
        for index in table.indexes
        if index.name
        == "uq_social_messaging_device_binding_active_device"
    )

    assert active_device.unique is True

    assert [
        column.name
        for column in active_device.columns
    ] == ["subject_pubkey", "device_id"]

    assert not any(
        index.unique
        and [
            column.name
            for column in index.columns
        ] == ["subject_pubkey"]
        for index in table.indexes
    )

    migration = (
        Path(__file__).resolve().parents[2]
        / "migrations"
        / "2026-09-04_social_messaging_device_bindings_v1.sql"
    ).read_text()

    assert (
        "ON social_messaging_device_bindings(subject_pubkey, device_id)"
        in migration
    )

    assert (
        "ON social_messaging_device_bindings(subject_pubkey)\n"
        "WHERE active = true"
        not in migration
    )
