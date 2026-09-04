from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.services.social_messaging_device_contract import (
    ALGORITHM,
    COMMAND_SCHEMA,
    MAX_ACTIVE_DEVICES,
    MessagingDeviceAuthorityUnavailable,
    MessagingDeviceBinding,
    RESULT_SCHEMA,
    SNAPSHOT_SCHEMA,
    SOURCE,
    SocialMessagingDeviceAuthority,
    parse_messaging_device_command,
)

SUBJECT = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
DEVICE = "22" * 32
REQUEST = "33" * 32
BINDING = "44" * 32
PUBLIC_KEY = "11" * 32
NOW = datetime(2026, 9, 4, 22, 0, 0, tzinfo=timezone.utc)


def command(
    operation="register",
    *,
    device_id=DEVICE,
    public_key=PUBLIC_KEY,
    expected_binding_id=None,
    request_id=REQUEST,
):
    return json.dumps(
        {
            "schema": COMMAND_SCHEMA,
            "version": 1,
            "operation": operation,
            "deviceId": device_id,
            "algorithm": ALGORITHM,
            "publicKey": public_key,
            "expectedBindingId": expected_binding_id,
            "requestId": request_id,
        },
        separators=(",", ":"),
    )


def binding(
    *,
    subject=SUBJECT,
    device_id=DEVICE,
    binding_id=BINDING,
    public_key=PUBLIC_KEY,
    version=1,
    operation="register",
    request_id=REQUEST,
    active=True,
    valid_from=NOW,
    expires_at=NOW + timedelta(days=30),
):
    return MessagingDeviceBinding(
        subject=subject,
        device_id=device_id,
        binding_id=binding_id,
        public_key=public_key,
        binding_version=version,
        valid_from=valid_from,
        expires_at=expires_at,
        operation=operation,
        request_id=request_id,
        active=active,
    )


class Repository:
    def __init__(self, *, applied=None, current=None):
        self.applied = applied
        self.current = [] if current is None else current
        self.calls = []

    def apply(self, value, *, subject, now):
        self.calls.append(("apply", value, subject, now))
        return self.applied

    def current_for_subject(self, subject, *, now, maximum):
        self.calls.append(("current", subject, now, maximum))
        return self.current


def test_register_parser_derives_subject_and_has_no_subject_field():
    subject, parsed = parse_messaging_device_command(
        command(),
        authenticated_subject=SUBJECT,
    )

    assert subject == SUBJECT
    assert parsed.operation == "register"
    assert parsed.device_id == DEVICE
    assert parsed.public_key == PUBLIC_KEY
    assert parsed.expected_binding_id is None
    assert parsed.request_id == REQUEST
    assert not hasattr(parsed, "subject")


def test_parser_rejects_browser_subject_and_duplicate_members():
    with_subject = json.loads(command())
    with_subject["subject"] = SUBJECT

    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        parse_messaging_device_command(
            json.dumps(with_subject, separators=(",", ":")),
            authenticated_subject=SUBJECT,
        )

    duplicate = command()[:-1] + ',"deviceId":"' + DEVICE + '"}'
    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        parse_messaging_device_command(
            duplicate,
            authenticated_subject=SUBJECT,
        )


@pytest.mark.parametrize(
    ("payload", "operation"),
    [
        (
            command(
                "rotate",
                expected_binding_id=BINDING,
                public_key="66" * 32,
            ),
            "rotate",
        ),
        (
            command(
                "revoke",
                expected_binding_id=BINDING,
                public_key=None,
            ),
            "revoke",
        ),
    ],
)
def test_rotate_and_revoke_require_explicit_current_binding(payload, operation):
    _, parsed = parse_messaging_device_command(
        payload,
        authenticated_subject=SUBJECT,
    )
    assert parsed.operation == operation
    assert parsed.expected_binding_id == BINDING

    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        parse_messaging_device_command(
            command(operation, public_key=None if operation == "revoke" else "66" * 32),
            authenticated_subject=SUBJECT,
        )


def test_parser_rejects_low_order_x25519_and_identity_key_reuse():
    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        parse_messaging_device_command(
            command(public_key="00" * 32),
            authenticated_subject=SUBJECT,
        )

    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        parse_messaging_device_command(
            command(public_key=SUBJECT),
            authenticated_subject=SUBJECT,
        )


def test_apply_returns_social_v128c_shape_without_subject():
    repository = Repository(applied=binding())
    authority = SocialMessagingDeviceAuthority(repository, clock=lambda: NOW)

    result = authority.apply(
        command(),
        authenticated_subject=SUBJECT,
    )

    assert result == {
        "schema": RESULT_SCHEMA,
        "version": 1,
        "operation": "register",
        "device": {
            "deviceId": DEVICE,
            "bindingId": BINDING,
            "algorithm": ALGORITHM,
            "version": 1,
            "publicKey": PUBLIC_KEY,
            "validFrom": "2026-09-04T22:00:00Z",
            "expiresAt": "2026-10-04T22:00:00Z",
        },
    }
    assert SUBJECT not in json.dumps(result)


def test_apply_fails_closed_when_repository_changes_authority_or_request():
    wrong = binding(subject="79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    authority = SocialMessagingDeviceAuthority(
        Repository(applied=wrong),
        clock=lambda: NOW,
    )

    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        authority.apply(command(), authenticated_subject=SUBJECT)


def test_current_snapshot_is_complete_bounded_and_subject_private():
    second = binding(
        device_id="55" * 32,
        binding_id="77" * 32,
        public_key="66" * 32,
        version=2,
        operation="rotate",
        request_id="88" * 32,
    )
    repository = Repository(current=[second, binding()])
    authority = SocialMessagingDeviceAuthority(repository, clock=lambda: NOW)

    snapshot = authority.current(authenticated_subject=SUBJECT)

    assert snapshot["schema"] == SNAPSHOT_SCHEMA
    assert snapshot["version"] == 1
    assert snapshot["source"] == SOURCE
    assert snapshot["complete"] is True
    assert snapshot["issuedAt"] == int(NOW.timestamp() * 1000)
    assert snapshot["expiresAt"] == int(
        (NOW + timedelta(seconds=300)).timestamp() * 1000
    )
    assert len(snapshot["activeDevices"]) == 2
    assert [item["deviceId"] for item in snapshot["activeDevices"]] == [
        DEVICE,
        "55" * 32,
    ]
    assert all(
        item["snapshotId"] == snapshot["snapshotId"]
        and item["revoked"] is False
        for item in snapshot["activeDevices"]
    )
    assert SUBJECT not in json.dumps(snapshot)
    assert repository.calls[-1][-1] == MAX_ACTIVE_DEVICES


def test_current_rejects_duplicate_keys_and_oversized_population():
    duplicate_key = binding(
        device_id="55" * 32,
        binding_id="77" * 32,
        request_id="88" * 32,
    )
    authority = SocialMessagingDeviceAuthority(
        Repository(current=[binding(), duplicate_key]),
        clock=lambda: NOW,
    )
    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        authority.current(authenticated_subject=SUBJECT)

    oversized = [
        binding(
            device_id=f"{index + 1:064x}",
            binding_id=f"{index + 100:064x}",
            public_key=f"{index + 2:064x}",
            request_id=f"{index + 200:064x}",
        )
        for index in range(MAX_ACTIVE_DEVICES + 1)
    ]
    authority = SocialMessagingDeviceAuthority(
        Repository(current=oversized),
        clock=lambda: NOW,
    )
    with pytest.raises(MessagingDeviceAuthorityUnavailable):
        authority.current(authenticated_subject=SUBJECT)


def test_current_rejects_revoked_or_expired_repository_rows():
    revoked = binding(operation="revoke", version=2, active=False)
    expired = binding(expires_at=NOW)

    for row in (revoked, expired):
        authority = SocialMessagingDeviceAuthority(
            Repository(current=[row]),
            clock=lambda: NOW,
        )
        with pytest.raises(MessagingDeviceAuthorityUnavailable):
            authority.current(authenticated_subject=SUBJECT)
