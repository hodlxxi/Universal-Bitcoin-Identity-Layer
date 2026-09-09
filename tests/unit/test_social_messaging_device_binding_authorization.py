from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from app.services import social_messaging_device_binding_authorization
from app.services.social_messaging_device_binding_authorization import (
    AUTHORIZATION_SCHEMA,
    MAX_AUTHORIZATION_WINDOW_SECONDS,
    PROOF_ID_PREFIX,
    SIGNATURE_DOMAIN,
    SIGNATURE_FORMAT,
    STATE_SCHEMA,
    AuthorizationReplayRecord,
    AuthorizedDeviceBinding,
    BindingAuthorizationEvidenceState,
    CurrentDeviceBindingState,
    CurrentPublicKeyBindingState,
    CurrentSubjectBindingState,
    DeviceBindingAuthorizationClaim,
    DeviceBindingAuthorizationUnavailable,
    IdentitySignedBindingAuthorizationVerifier,
    IdentitySignedDeviceBindingAuthorization,
    SocialMessagingDeviceBindingAuthorizationV1,
    authorization_digest,
    canonical_authorization_json,
    canonical_authorization_signed_bytes,
    parse_and_verify_device_binding_authorization,
)
from app.services.social_messaging_device_contract import MAX_ACTIVE_DEVICES, MessagingDeviceBinding
from app.services.social_messaging_recipient_routing import VerifiedBindingAuthorization, derive_recipient_device_handle

NOW = datetime(2026, 9, 8, 22, 30, tzinfo=timezone.utc)
IDENTITY_KEY = PrivateKey(bytes.fromhex("00" * 31 + "01"))
OTHER_IDENTITY_KEY = PrivateKey(bytes.fromhex("00" * 31 + "02"))
SUBJECT = PublicKeyXOnly.from_secret(IDENTITY_KEY.secret).format().hex()
OTHER_SUBJECT = PublicKeyXOnly.from_secret(OTHER_IDENTITY_KEY.secret).format().hex()
DEVICE_ID = "22" * 32
REQUEST_ID = "33" * 32
KEY_A = "09" + "00" * 31
KEY_B = "0a" + "00" * 31
KEY_C = "0b" + "00" * 31
ALIAS_SECRET = bytes(range(32))


def claim(**changes):
    values = {
        "schema": AUTHORIZATION_SCHEMA,
        "version": 1,
        "operation": "register",
        "subject": SUBJECT,
        "device_id": DEVICE_ID,
        "algorithm": "x25519-v1",
        "public_key": KEY_A,
        "binding_version": 1,
        "binding_valid_from": NOW - timedelta(seconds=1),
        "binding_expires_at": NOW + timedelta(days=30),
        "prior_binding_id": None,
        "request_id": REQUEST_ID,
        "issued_at": NOW - timedelta(seconds=1),
        "expires_at": NOW + timedelta(seconds=299),
    }
    values.update(changes)
    return DeviceBindingAuthorizationClaim(**values)


def signed(value=None, *, key=IDENTITY_KEY):
    value = value or claim()
    digest = authorization_digest(value)
    signature = key.sign_schnorr(bytes.fromhex(digest), b"\x00" * 32).hex()
    return IdentitySignedDeviceBindingAuthorization(value, digest, SIGNATURE_FORMAT, signature)


def payload(value=None, *, key=IDENTITY_KEY):
    return canonical_authorization_json(signed(value, key=key))


class StateProvider:
    def __init__(self, *, device_records=(), subject_records=(), key_records_by_public_key=None):
        self.device_records = tuple(device_records)
        self.subject_records = tuple(subject_records)
        self.key_records_by_public_key = {
            key: tuple(records) for key, records in (key_records_by_public_key or {}).items()
        }
        self.binding_records = ()
        self.device_override = None
        self.subject_override = None
        self.key_overrides = {}
        self.binding_override = None
        self.calls = []

    def current_for_subject(self, subject, *, now, maximum):
        self.calls.append(("subject", subject, now, maximum))
        if isinstance(self.subject_override, BaseException):
            raise self.subject_override
        if self.subject_override is not None:
            return self.subject_override
        return CurrentSubjectBindingState(
            STATE_SCHEMA,
            1,
            subject,
            True,
            False,
            self.subject_records,
        )

    def current_for_device(self, subject, device_id, *, now, maximum):
        self.calls.append(("device", subject, device_id, now, maximum))
        if isinstance(self.device_override, BaseException):
            raise self.device_override
        if self.device_override is not None:
            return self.device_override
        return CurrentDeviceBindingState(
            STATE_SCHEMA,
            1,
            subject,
            device_id,
            True,
            False,
            self.device_records,
        )

    def current_for_public_key(self, public_key, *, now, maximum):
        self.calls.append(("key", public_key, now, maximum))
        override = self.key_overrides.get(public_key)
        if isinstance(override, BaseException):
            raise override
        if override is not None:
            return override
        return CurrentPublicKeyBindingState(
            STATE_SCHEMA,
            1,
            public_key,
            True,
            False,
            self.key_records_by_public_key.get(public_key, ()),
        )

    def authorization_for_binding(self, binding_id, *, now, maximum):
        self.calls.append(("binding", binding_id, now, maximum))
        if isinstance(self.binding_override, BaseException):
            raise self.binding_override
        if self.binding_override is not None:
            return self.binding_override
        return BindingAuthorizationEvidenceState(
            STATE_SCHEMA,
            1,
            binding_id,
            True,
            False,
            self.binding_records,
        )


class ReplayLedger:
    def __init__(self):
        self.records = {}
        self.get_error = None
        self.record_error = None
        self.record_override = None

    def get(self, request_id):
        if self.get_error:
            raise self.get_error
        return self.records.get(request_id)

    def record(self, record):
        if self.record_error:
            raise self.record_error
        if self.record_override is not None:
            return self.record_override
        existing = self.records.get(record.request_id)
        if existing is not None:
            if existing != record:
                raise RuntimeError("request conflict containing secret provider detail")
            return existing
        self.records[record.request_id] = record
        return record


def service(state=None, replay=None, *, now=NOW):
    return SocialMessagingDeviceBindingAuthorizationV1(
        state_provider=state or StateProvider(),
        replay_ledger=replay or ReplayLedger(),
        clock=lambda: now,
    )


def accept(value=None, *, state=None, replay=None, now=NOW):
    value = value or claim()
    return service(state, replay, now=now).authorize(payload(value), authenticated_subject=value.subject)


def rotate_claim(current, **changes):
    values = {
        "operation": "rotate",
        "public_key": KEY_B,
        "binding_version": current.binding.binding_version + 1,
        "binding_valid_from": NOW,
        "binding_expires_at": current.binding.expires_at,
        "prior_binding_id": current.binding.binding_id,
        "request_id": "44" * 32,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS),
    }
    values.update(changes)
    return claim(**values)


def revoke_claim(current, **changes):
    values = {
        "operation": "revoke",
        "public_key": current.binding.public_key,
        "binding_version": current.binding.binding_version + 1,
        "binding_valid_from": current.binding.valid_from,
        "binding_expires_at": current.binding.expires_at,
        "prior_binding_id": current.binding.binding_id,
        "request_id": "55" * 32,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS),
    }
    values.update(changes)
    return claim(**values)


def state_for_current(current, *, proposed_key=None, subject_records=None, old_key_records=None):
    key_records = {
        current.binding.public_key: (current,) if old_key_records is None else old_key_records,
    }
    if proposed_key is not None and proposed_key != current.binding.public_key:
        key_records[proposed_key] = ()
    return StateProvider(
        device_records=(current,),
        subject_records=(current,) if subject_records is None else subject_records,
        key_records_by_public_key=key_records,
    )


def assert_generic(call):
    with pytest.raises(DeviceBindingAuthorizationUnavailable) as caught:
        call()
    assert str(caught.value) == "social messaging device binding authorization unavailable"
    assert caught.value.__cause__ is None


def canonical_mutation(source, field, value):
    decoded = json.loads(source)
    decoded[field] = value
    return json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def accepted_register():
    return accept()


def accepted_distinct(index, *, device_id=None, public_key=None):
    return accept(
        claim(
            device_id=device_id or f"{index + 100:064x}",
            public_key=public_key or (index + 9).to_bytes(32, "little").hex(),
            request_id=f"{index + 200:064x}",
        )
    )


def test_current_subject_binding_state_is_exported():
    assert "CurrentSubjectBindingState" in social_messaging_device_binding_authorization.__all__


def test_valid_register_derives_binding_and_routing_evidence_from_exact_digest():
    result = accepted_register()

    assert result.binding == MessagingDeviceBinding(
        subject=SUBJECT,
        device_id=DEVICE_ID,
        binding_id=result.authorization.digest,
        public_key=KEY_A,
        binding_version=1,
        valid_from=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(days=30),
        operation="register",
        prior_binding_id=None,
        request_id=REQUEST_ID,
        active=True,
    )
    assert result.verification == VerifiedBindingAuthorization(
        proof_id=PROOF_ID_PREFIX + result.binding.binding_id,
        subject=result.binding.subject,
        device_id=result.binding.device_id,
        binding_id=result.binding.binding_id,
        binding_version=result.binding.binding_version,
        public_key=result.binding.public_key,
        valid_from=result.binding.valid_from,
        expires_at=result.binding.expires_at,
        evidence_valid_from=result.authorization.claim.issued_at,
        evidence_expires_at=result.binding.expires_at,
    )


def test_valid_rotate_binds_exact_prior_and_replacement_key():
    current = accepted_register()
    state = StateProvider(
        device_records=(current,),
        subject_records=(current,),
        key_records_by_public_key={KEY_A: (current,), KEY_B: ()},
    )
    result = accept(rotate_claim(current), state=state)

    assert result.binding.operation == "rotate"
    assert result.binding.prior_binding_id == current.binding.binding_id
    assert result.binding.public_key == KEY_B
    assert result.binding.binding_version == 2
    assert result.binding.active is True
    assert result.verification.evidence_valid_from == result.authorization.claim.issued_at
    assert result.verification.evidence_valid_from == result.binding.valid_from
    assert [call[1] for call in state.calls if call[0] == "key"] == [KEY_A, KEY_B]


def test_valid_revoke_binds_exact_current_and_preserves_its_key_and_interval():
    first = accepted_register()
    rotated = accept(
        rotate_claim(first),
        state=StateProvider(
            device_records=(first,),
            subject_records=(first,),
            key_records_by_public_key={KEY_A: (first,), KEY_B: ()},
        ),
    )
    state = StateProvider(
        device_records=(rotated,),
        subject_records=(rotated,),
        key_records_by_public_key={KEY_B: (rotated,)},
    )
    result = accept(revoke_claim(rotated), state=state)

    assert result.binding.operation == "revoke"
    assert result.binding.prior_binding_id == rotated.binding.binding_id
    assert result.binding.public_key == rotated.binding.public_key
    assert result.binding.valid_from == rotated.binding.valid_from
    assert result.binding.expires_at == rotated.binding.expires_at
    assert result.binding.active is False
    assert [call[1] for call in state.calls if call[0] == "key"] == [KEY_B]


def test_active_register_and_rotate_cannot_predate_signature_issuance():
    assert_generic(
        lambda: accept(
            claim(
                binding_valid_from=NOW - timedelta(seconds=2),
                issued_at=NOW - timedelta(seconds=1),
            )
        )
    )

    current = accepted_register()
    assert_generic(
        lambda: accept(
            rotate_claim(current, binding_valid_from=NOW - timedelta(seconds=1)),
            state=state_for_current(current, proposed_key=KEY_B),
        )
    )


def test_revoke_rejects_issuance_before_predecessor_binding_valid_from():
    current = accepted_register()
    state = state_for_current(current)
    source = json.loads(
        payload(
            revoke_claim(
                current,
                expires_at=NOW + timedelta(seconds=MAX_AUTHORIZATION_WINDOW_SECONDS - 2),
            )
        )
    )
    issued_at = current.binding.valid_from - timedelta(seconds=1)
    source["issuedAt"] = issued_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    authorization = {
        key: value for key, value in source.items() if key not in {"digest", "signature", "signatureFormat"}
    }
    signed_bytes = json.dumps(
        {"authorization": authorization, "domain": SIGNATURE_DOMAIN},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    digest = hashlib.sha256(signed_bytes).hexdigest()
    source["digest"] = digest
    source["signature"] = IDENTITY_KEY.sign_schnorr(bytes.fromhex(digest), b"\x00" * 32).hex()
    encoded = json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    assert_generic(lambda: service(state).authorize(encoded, authenticated_subject=SUBJECT))


def test_exact_canonical_signed_bytes_and_fixed_bip340_vector():
    value = claim()
    expected = (
        b'{"authorization":{"algorithm":"x25519-v1","bindingExpiresAt":"2026-10-08T22:30:00Z",'
        b'"bindingValidFrom":"2026-09-08T22:29:59Z","bindingVersion":1,"deviceId":"'
        + DEVICE_ID.encode("ascii")
        + b'","expiresAt":"2026-09-08T22:34:59Z","issuedAt":"2026-09-08T22:29:59Z",'
        b'"operation":"register","priorBindingId":null,"publicKey":"'
        + KEY_A.encode("ascii")
        + b'","requestId":"'
        + REQUEST_ID.encode("ascii")
        + b'","schema":"hodlxxi.social_messaging_device_binding_authorization.v1","subject":"'
        + SUBJECT.encode("ascii")
        + b'","version":1},"domain":"HODLXXI_SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1"}'
    )
    authorization = signed(value)

    assert canonical_authorization_signed_bytes(value) == expected
    assert hashlib.sha256(expected).hexdigest() == authorization.digest
    assert authorization.digest == "f308fda7f03d3b3aafa107e28aa64a410f57669fe1fe4dfe4b088bb09e1ae5e4"
    assert authorization.signature == (
        "d06cf32d218c0b21b62f21360dc8cc9836d45e3f8786797b54e3ff9c61313fb9"
        "e10d88a9b2d919efc8103983573e1f0aeaf4f455ba0704cefab954ea3c2b1e61"
    )
    parsed = parse_and_verify_device_binding_authorization(
        canonical_authorization_json(authorization),
        authenticated_subject=SUBJECT,
    )
    assert parsed == authorization


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema", "wrong"),
        ("version", 2),
        ("operation", "rotate"),
        ("subject", OTHER_SUBJECT),
        ("deviceId", "23" * 32),
        ("algorithm", "x25519-v2"),
        ("publicKey", KEY_B),
        ("bindingVersion", 2),
        ("bindingValidFrom", "2026-09-08T22:28:59Z"),
        ("bindingExpiresAt", "2026-10-08T22:29:59Z"),
        ("priorBindingId", "66" * 32),
        ("requestId", "34" * 32),
        ("issuedAt", "2026-09-08T22:29:58Z"),
        ("expiresAt", "2026-09-08T22:34:58Z"),
        ("digest", "00" * 32),
        ("signatureFormat", "other"),
        ("signature", "00" * 64),
    ),
)
def test_tampering_every_signed_or_verification_field_fails(field, value):
    assert_generic(
        lambda: parse_and_verify_device_binding_authorization(
            canonical_mutation(payload(), field, value),
            authenticated_subject=SUBJECT,
        )
    )


def test_wrong_signer_and_wrong_authenticated_participant_fail():
    forged = signed(claim(), key=OTHER_IDENTITY_KEY)
    forged_json = json.dumps(
        {
            **json.loads(payload()),
            "signature": forged.signature,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    assert_generic(
        lambda: parse_and_verify_device_binding_authorization(
            forged_json,
            authenticated_subject=SUBJECT,
        )
    )
    assert_generic(
        lambda: parse_and_verify_device_binding_authorization(
            payload(),
            authenticated_subject=OTHER_SUBJECT,
        )
    )


def test_signature_cannot_cross_operation_even_when_other_fields_are_compatible():
    current = accepted_register()
    rotate = rotate_claim(current)
    rotate_payload = payload(rotate)
    assert_generic(
        lambda: service(state_for_current(current, proposed_key=KEY_B)).authorize(
            canonical_mutation(rotate_payload, "operation", "revoke"),
            authenticated_subject=SUBJECT,
        )
    )


@pytest.mark.parametrize(
    "changed",
    (
        {"prior_binding_id": "66" * 32},
        {"binding_version": 3},
        {"public_key": KEY_A},
        {"binding_expires_at": NOW + timedelta(days=31)},
        {"binding_valid_from": NOW - timedelta(minutes=2)},
    ),
)
def test_rotate_rejects_wrong_prior_version_key_or_interval(changed):
    current = accepted_register()
    assert_generic(
        lambda: accept(
            rotate_claim(current, **changed),
            state=state_for_current(current, proposed_key=changed.get("public_key", KEY_B)),
        )
    )


@pytest.mark.parametrize(
    "changed",
    (
        {"prior_binding_id": "66" * 32},
        {"binding_version": 3},
        {"public_key": KEY_C},
        {"binding_valid_from": NOW - timedelta(seconds=2)},
        {"binding_expires_at": NOW + timedelta(days=29)},
    ),
)
def test_revoke_rejects_wrong_current_version_key_or_interval(changed):
    current = accepted_register()
    state = state_for_current(current)
    assert_generic(lambda: accept(revoke_claim(current, **changed), state=state))


def test_binding_id_and_existing_pairwise_handle_change_with_replacement_key():
    first_claim = claim()
    second_claim = replace(first_claim, public_key=KEY_B)
    first = signed(first_claim)
    second = signed(second_claim)
    first_handle = derive_recipient_device_handle(
        viewer=OTHER_SUBJECT,
        target=SUBJECT,
        binding_id=first.binding_id,
        alias_secret=ALIAS_SECRET,
        alias_version=1,
    )
    second_handle = derive_recipient_device_handle(
        viewer=OTHER_SUBJECT,
        target=SUBJECT,
        binding_id=second.binding_id,
        alias_secret=ALIAS_SECRET,
        alias_version=1,
    )

    assert first.binding_id != second.binding_id
    assert first_handle != second_handle
    with_handle = json.loads(payload())
    with_handle["deviceHandle"] = first_handle
    assert_generic(
        lambda: parse_and_verify_device_binding_authorization(
            json.dumps(with_handle, sort_keys=True, separators=(",", ":")),
            authenticated_subject=SUBJECT,
        )
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("subject", SUBJECT.upper()),
        ("deviceId", "AB" * 32),
        ("deviceId", "00" + DEVICE_ID),
        ("requestId", "CD" * 32),
        ("priorBindingId", "AA" * 32),
        ("publicKey", "0A" + "00" * 31),
        ("publicKey", "00" * 32),
        ("publicKey", "09" + "00" * 30 + "80"),
        ("digest", "AA" * 32),
        ("signature", "AA" * 64),
    ),
)
def test_noncanonical_key_signature_and_identifier_encodings_fail(field, value):
    source = payload(rotate_claim(accepted_register())) if field == "priorBindingId" else payload()
    assert_generic(
        lambda: parse_and_verify_device_binding_authorization(
            canonical_mutation(source, field, value),
            authenticated_subject=SUBJECT,
        )
    )


@pytest.mark.parametrize(
    ("issued", "expires", "now"),
    (
        (NOW - timedelta(minutes=5), NOW, NOW),
        (NOW + timedelta(seconds=1), NOW + timedelta(minutes=1), NOW),
        (NOW + timedelta(days=1), NOW + timedelta(days=1, minutes=1), NOW),
    ),
)
def test_expired_premature_and_future_dated_authorizations_fail(issued, expires, now):
    value = claim(issued_at=issued, expires_at=expires)
    assert_generic(lambda: accept(value, now=now))


def test_excessive_authorization_window_and_fractional_external_times_fail():
    source = json.loads(payload())
    source["expiresAt"] = "2026-09-08T22:35:00Z"
    assert_generic(
        lambda: parse_and_verify_device_binding_authorization(
            json.dumps(source, sort_keys=True, separators=(",", ":")),
            authenticated_subject=SUBJECT,
        )
    )
    source = json.loads(payload())
    source["issuedAt"] = "2026-09-08T22:29:59.000000Z"
    assert_generic(
        lambda: parse_and_verify_device_binding_authorization(
            json.dumps(source, sort_keys=True, separators=(",", ":")),
            authenticated_subject=SUBJECT,
        )
    )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.pop("requestId"),
        lambda value: value.update(extra="forbidden"),
        lambda value: value.update(version=True),
        lambda value: value.update(bindingVersion=True),
        lambda value: value.update(deviceId=1),
        lambda value: value.update(publicKey=None),
        lambda value: value.update(priorBindingId=False),
    ),
)
def test_missing_extra_and_wrong_type_inputs_fail(mutation):
    decoded = json.loads(payload())
    mutation(decoded)
    assert_generic(
        lambda: parse_and_verify_device_binding_authorization(
            json.dumps(decoded, sort_keys=True, separators=(",", ":")),
            authenticated_subject=SUBJECT,
        )
    )


@pytest.mark.parametrize(
    "source",
    (
        None,
        {},
        {"accessor": property(lambda self: payload())},
        type("Inherited", (str,), {})(payload()),
        payload() + " ",
        payload().replace(",", ",\n", 1),
        payload().replace('"schema":', '"schema":"duplicate","schema":'),
        payload().replace("hodlxxi", "hodlxx\u00ef", 1),
    ),
)
def test_decoded_inherited_accessor_duplicate_noncanonical_and_unicode_inputs_fail(source):
    assert_generic(
        lambda: parse_and_verify_device_binding_authorization(
            source,
            authenticated_subject=SUBJECT,
        )
    )


def test_exact_retry_is_idempotent_without_reconsulting_changed_current_state():
    state = StateProvider()
    replay = ReplayLedger()
    authority = service(state, replay)
    source = payload()
    first = authority.authorize(source, authenticated_subject=SUBJECT)
    state.device_override = RuntimeError("state unavailable after downstream apply")
    state.subject_override = RuntimeError("state unavailable after downstream apply")
    state.key_overrides[KEY_A] = RuntimeError("state unavailable after downstream apply")

    assert authority.authorize(source, authenticated_subject=SUBJECT) == first
    assert [call[0] for call in state.calls] == ["binding", "device", "subject", "key"]


def test_request_id_reuse_with_altered_signed_content_fails_before_state_lookup():
    state = StateProvider()
    replay = ReplayLedger()
    authority = service(state, replay)
    authority.authorize(payload(), authenticated_subject=SUBJECT)
    altered = claim(public_key=KEY_B)

    assert_generic(lambda: authority.authorize(payload(altered), authenticated_subject=SUBJECT))
    assert [call[0] for call in state.calls] == ["binding", "device", "subject", "key"]


@pytest.mark.parametrize("mode", ("absent", "inactive", "expired", "superseded", "duplicate", "ambiguous"))
def test_rotate_and_revoke_fail_for_nonexact_or_ambiguous_current_state(mode):
    current = accepted_register()
    candidate = rotate_claim(current)
    records = ()
    if mode == "inactive":
        records = (replace(current, binding=replace(current.binding, active=False)),)
    elif mode == "expired":
        old_claim = claim(
            binding_valid_from=NOW - timedelta(minutes=5),
            binding_expires_at=NOW,
            issued_at=NOW - timedelta(minutes=5),
            expires_at=NOW - timedelta(seconds=1),
        )
        expired = accept(
            old_claim,
            now=NOW - timedelta(seconds=2),
        )
        records = (expired,)
        candidate = rotate_claim(expired, binding_expires_at=NOW + timedelta(days=1))
    elif mode == "superseded":
        records = (accept(rotate_claim(current), state=state_for_current(current, proposed_key=KEY_B)),)
    elif mode == "duplicate":
        records = (current, current)
    elif mode == "ambiguous":
        other = accepted_register()
        other_claim = replace(other.authorization.claim, request_id="77" * 32, public_key=KEY_C)
        other = accept(other_claim)
        records = (current, other)

    if len(records) == 1:
        state = state_for_current(records[0], proposed_key=candidate.public_key)
    else:
        state = StateProvider(device_records=records, subject_records=records)
    assert_generic(lambda: accept(candidate, state=state))


@pytest.mark.parametrize("field", ("complete", "truncated", "records", "schema", "version", "subject", "device_id"))
def test_incomplete_truncated_or_malformed_device_provider_output_fails(field):
    value = CurrentDeviceBindingState(STATE_SCHEMA, 1, SUBJECT, DEVICE_ID, True, False, ())
    changes = {
        "complete": False,
        "truncated": True,
        "records": [],
        "schema": "wrong",
        "version": True,
        "subject": OTHER_SUBJECT,
        "device_id": "66" * 32,
    }
    state = StateProvider()
    state.device_override = replace(value, **{field: changes[field]})
    assert_generic(lambda: accept(state=state))


@pytest.mark.parametrize("field", ("complete", "truncated", "records", "schema", "version", "subject"))
def test_incomplete_truncated_or_malformed_subject_provider_output_fails(field):
    value = CurrentSubjectBindingState(STATE_SCHEMA, 1, SUBJECT, True, False, ())
    changes = {
        "complete": False,
        "truncated": True,
        "records": [],
        "schema": "wrong",
        "version": True,
        "subject": OTHER_SUBJECT,
    }
    state = StateProvider()
    state.subject_override = replace(value, **{field: changes[field]})
    assert_generic(lambda: accept(state=state))


def test_subject_state_is_queried_with_overflow_capacity_and_register_enforces_cap():
    records = tuple(accepted_distinct(index) for index in range(MAX_ACTIVE_DEVICES))
    state = StateProvider(subject_records=records)

    assert_generic(lambda: accept(state=state))
    assert [call[-1] for call in state.calls if call[0] == "subject"] == [MAX_ACTIVE_DEVICES + 1]


def test_subject_state_overflow_fails_closed():
    records = tuple(accepted_distinct(index) for index in range(MAX_ACTIVE_DEVICES + 1))
    assert_generic(lambda: accept(state=StateProvider(subject_records=records)))


@pytest.mark.parametrize("duplicate", ("device_id", "binding_id", "public_key"))
def test_subject_state_rejects_duplicate_device_binding_and_public_key(duplicate):
    first = accepted_distinct(1)
    if duplicate == "device_id":
        second = accepted_distinct(2, device_id=first.binding.device_id)
    elif duplicate == "public_key":
        second = accepted_distinct(2, public_key=first.binding.public_key)
    else:
        second = first
    assert_generic(lambda: accept(state=StateProvider(subject_records=(first, second))))


@pytest.mark.parametrize("operation", ("rotate", "revoke"))
def test_lifecycle_requires_exact_current_predecessor_in_complete_subject_state(operation):
    current = accepted_register()
    candidate = rotate_claim(current) if operation == "rotate" else revoke_claim(current)
    state = state_for_current(current, proposed_key=KEY_B, subject_records=())
    assert_generic(lambda: accept(candidate, state=state))


def test_subject_provider_order_is_not_authoritative():
    current = accepted_register()
    other = accepted_distinct(10)
    state = state_for_current(
        current,
        proposed_key=KEY_B,
        subject_records=(other, current),
    )
    assert accept(rotate_claim(current), state=state).binding.prior_binding_id == current.binding.binding_id


@pytest.mark.parametrize("mode", ("oauth_only", "inactive", "expired"))
def test_subject_state_rejects_non_authorization_inactive_and_expired_records(mode):
    current = accepted_register()
    if mode == "oauth_only":
        record = current.binding
    elif mode == "inactive":
        record = replace(current, binding=replace(current.binding, active=False))
    else:
        record = accept(
            claim(
                binding_valid_from=NOW - timedelta(minutes=5),
                binding_expires_at=NOW,
                issued_at=NOW - timedelta(minutes=5),
                expires_at=NOW - timedelta(seconds=1),
            ),
            now=NOW - timedelta(seconds=2),
        )
    assert_generic(lambda: accept(state=StateProvider(subject_records=(record,))))


@pytest.mark.parametrize("field", ("complete", "truncated", "records", "schema", "version", "public_key"))
def test_incomplete_truncated_or_malformed_key_provider_output_fails(field):
    value = CurrentPublicKeyBindingState(STATE_SCHEMA, 1, KEY_A, True, False, ())
    changes = {
        "complete": False,
        "truncated": True,
        "records": [],
        "schema": "wrong",
        "version": True,
        "public_key": KEY_B,
    }
    state = StateProvider()
    state.key_overrides[KEY_A] = replace(value, **{field: changes[field]})
    assert_generic(lambda: accept(state=state))


@pytest.mark.parametrize("operation", ("rotate", "revoke"))
@pytest.mark.parametrize(
    "mode", ("missing", "different", "duplicate", "incomplete", "truncated", "expired", "ambiguous")
)
def test_rotate_and_revoke_require_exact_complete_predecessor_key_ownership(operation, mode):
    current = accepted_register()
    candidate = rotate_claim(current) if operation == "rotate" else revoke_claim(current)
    state = state_for_current(current, proposed_key=KEY_B)
    if mode == "missing":
        state.key_records_by_public_key[KEY_A] = ()
    elif mode == "different":
        state.key_records_by_public_key[KEY_A] = (accepted_distinct(10, public_key=KEY_A),)
    elif mode == "duplicate":
        state.key_records_by_public_key[KEY_A] = (current, current)
    elif mode in {"incomplete", "truncated"}:
        state.key_overrides[KEY_A] = CurrentPublicKeyBindingState(
            STATE_SCHEMA,
            1,
            KEY_A,
            mode != "incomplete",
            mode == "truncated",
            (current,),
        )
    elif mode == "expired":
        expired = accept(
            claim(
                binding_valid_from=NOW - timedelta(minutes=5),
                binding_expires_at=NOW,
                issued_at=NOW - timedelta(minutes=5),
                expires_at=NOW - timedelta(seconds=1),
            ),
            now=NOW - timedelta(seconds=2),
        )
        state.key_records_by_public_key[KEY_A] = (expired,)
    else:
        state.key_records_by_public_key[KEY_A] = (
            current,
            accepted_distinct(10, public_key=KEY_A),
        )

    assert_generic(lambda: accept(candidate, state=state))


def test_register_rejects_existing_device_and_public_key_collision():
    current = accepted_register()
    assert_generic(lambda: accept(state=StateProvider(device_records=(current,), subject_records=(current,))))
    collision = accepted_distinct(10, public_key=KEY_A)
    state = StateProvider(key_records_by_public_key={KEY_A: (collision,)})
    assert_generic(lambda: accept(state=state))


def test_rotate_rejects_global_proposed_public_key_collision():
    current = accepted_register()
    collision = accepted_distinct(10, public_key=KEY_B)
    state = state_for_current(current, proposed_key=KEY_B)
    state.key_records_by_public_key[KEY_B] = (collision,)
    assert_generic(lambda: accept(rotate_claim(current), state=state))


def test_server_derived_binding_identifier_collision_fails_closed():
    collision = accepted_register()
    state = StateProvider()
    state.binding_records = (collision,)
    assert_generic(lambda: accept(state=state))


@pytest.mark.parametrize(
    ("complete", "truncated", "records"), ((False, False, ()), (True, True, ()), (True, False, []))
)
def test_incomplete_truncated_or_wrong_type_binding_id_state_fails(complete, truncated, records):
    state = StateProvider()
    state.binding_override = BindingAuthorizationEvidenceState(
        STATE_SCHEMA,
        1,
        authorization_digest(claim()),
        complete,
        truncated,
        records,
    )
    assert_generic(lambda: accept(state=state))


def test_oauth_only_binding_is_not_identity_authorization_state():
    oauth_only = MessagingDeviceBinding(
        subject=SUBJECT,
        device_id=DEVICE_ID,
        binding_id="88" * 32,
        public_key=KEY_A,
        binding_version=1,
        valid_from=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(days=1),
        operation="register",
        prior_binding_id=None,
        request_id="99" * 32,
        active=True,
    )
    state = StateProvider()
    state.device_override = CurrentDeviceBindingState(
        STATE_SCHEMA,
        1,
        SUBJECT,
        DEVICE_ID,
        True,
        False,
        (oauth_only,),
    )
    assert_generic(lambda: accept(state=state))


class EvidenceProvider:
    def __init__(self, result):
        self.result = result

    def authorization_for_binding(self, binding_id, *, now, maximum):
        if isinstance(self.result, BaseException):
            raise self.result
        if callable(self.result):
            return self.result(binding_id, now, maximum)
        return self.result


def evidence_state(record, **changes):
    values = {
        "schema": STATE_SCHEMA,
        "version": 1,
        "binding_id": record.binding.binding_id,
        "complete": True,
        "truncated": False,
        "records": (record,),
    }
    values.update(changes)
    return BindingAuthorizationEvidenceState(**values)


def test_routing_verifier_port_accepts_exact_current_identity_signed_binding():
    record = accepted_register()
    verifier = IdentitySignedBindingAuthorizationVerifier(EvidenceProvider(evidence_state(record)))

    assert verifier.verify(record.binding, now=NOW) == record.verification


@pytest.mark.parametrize(
    "state",
    (
        lambda record: evidence_state(record, complete=False),
        lambda record: evidence_state(record, truncated=True),
        lambda record: evidence_state(record, records=()),
        lambda record: evidence_state(record, records=(record, record)),
        lambda record: evidence_state(record, binding_id="66" * 32),
        lambda record: {"authorized": True},
    ),
)
def test_routing_verifier_rejects_incomplete_duplicate_or_ambiguous_evidence(state):
    record = accepted_register()
    verifier = IdentitySignedBindingAuthorizationVerifier(EvidenceProvider(state(record)))
    assert_generic(lambda: verifier.verify(record.binding, now=NOW))


def test_routing_verifier_rejects_rotated_revoked_expired_or_different_binding():
    record = accepted_register()
    verifier = IdentitySignedBindingAuthorizationVerifier(EvidenceProvider(evidence_state(record)))
    for invalid, now in (
        (replace(record.binding, binding_id="66" * 32), NOW),
        (replace(record.binding, active=False, operation="revoke"), NOW),
        (record.binding, record.binding.expires_at),
    ):
        assert_generic(lambda invalid=invalid, now=now: verifier.verify(invalid, now=now))


@pytest.mark.parametrize("dependency", ("state_device", "state_subject", "state_key", "replay_get", "replay_record"))
def test_all_dependency_failures_share_one_non_sensitive_public_error(dependency):
    state = StateProvider()
    replay = ReplayLedger()
    if dependency == "state_device":
        state.device_override = RuntimeError("secret database host")
    elif dependency == "state_subject":
        state.subject_override = RuntimeError("secret complete-set provider")
    elif dependency == "state_key":
        state.key_overrides[KEY_A] = RuntimeError("secret provider row")
    elif dependency == "replay_get":
        replay.get_error = RuntimeError("secret replay key")
    else:
        replay.record_error = RuntimeError("secret collision detail")
    assert_generic(lambda: accept(state=state, replay=replay))


def test_replay_provider_must_return_exact_typed_result():
    candidate = accepted_register()
    replay = ReplayLedger()
    replay.records[REQUEST_ID] = AuthorizationReplayRecord(
        REQUEST_ID,
        candidate.authorization.digest,
        replace(candidate, binding=replace(candidate.binding, public_key=KEY_B)),
    )
    assert_generic(lambda: accept(replay=replay))


def test_values_are_frozen_and_no_private_or_secret_material_is_output():
    result = accepted_register()
    with pytest.raises(FrozenInstanceError):
        result.binding.binding_id = "00" * 32
    rendered = repr(result)
    for forbidden in ("private_key", "seed", "bearer", "oauth", "alias_secret"):
        assert forbidden not in rendered.lower()


def test_source_is_dormant_and_has_no_runtime_or_persistence_integration():
    import app.services.social_messaging_device_binding_authorization as module

    source = inspect.getsource(module).lower()
    for forbidden in (
        "flask",
        "sqlalchemy",
        "app.models",
        "app.factory",
        "blueprint",
        "migration",
        "redis",
        "requests.",
        "subprocess",
        "privatekey",
        "sign_schnorr",
        "session[",
    ):
        assert forbidden not in source
