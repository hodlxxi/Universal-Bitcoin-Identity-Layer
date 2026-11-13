from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from app.services import social_messaging_device_verification_deadline_evidence_v1 as contract

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "tests/fixtures/social_messaging_device_verification_deadline_evidence_v1.json"
SOURCE_PATH = ROOT / "tests/fixtures/social_preacceptance_ed25519_handoff_v2.json"
FIXTURE = json.loads(FIXTURE_PATH.read_bytes())
SOURCE = json.loads(SOURCE_PATH.read_bytes())
VECTOR = FIXTURE["vector"]
CONFIG = FIXTURE["configuration"]
TRUST = FIXTURE["trustRecord"]
INPUT_WIRE = SOURCE["vector"]["preacceptedEnrollmentVerificationInputWire"]
DENIED = contract.SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied
ERROR = "^social messaging device verification deadline evidence denied$"


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def compact() -> str:
    return contract.compact_messaging_device_verification_deadline_evidence_v1(
        protected_header_wire=VECTOR["protectedHeaderWire"],
        payload_wire=VECTOR["payloadWire"],
        signature=bytes.fromhex(VECTOR["signature"]),
    )


def trust_record(**changes: object) -> contract.DeadlineEvidenceTrustRecordV1:
    values = {
        "public_jwk": dict(TRUST["jwk"]),
        "trust_revision": TRUST["trustRevision"],
        "not_before": TRUST["notBefore"],
        "not_after": TRUST["notAfter"],
        "revoked_at": TRUST["revokedAt"],
    }
    values.update(changes)
    return contract.DeadlineEvidenceTrustRecordV1(**values)


def configuration(**changes: object) -> contract.MessagingDeviceVerificationDeadlineEvidenceV1Config:
    values = {
        "enabled": True,
        "issuer": CONFIG["issuer"],
        "audience": CONFIG["audience"],
        "client_id": CONFIG["clientId"],
        "service_principal": CONFIG["servicePrincipal"],
        "trust_records": (trust_record(),),
    }
    values.update(changes)
    return contract.MessagingDeviceVerificationDeadlineEvidenceV1Config(**values)


def verify(**changes: object) -> contract.AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1:
    values = {
        "evidence": compact(),
        "config": configuration(),
        "expected_input_wire": INPUT_WIRE,
        "now": FIXTURE["deadlines"]["observedAt"],
    }
    values.update(changes)
    evidence = values.pop("evidence")
    return contract.verify_messaging_device_verification_deadline_evidence_v1(evidence, **values)


def denied(callable_value) -> None:
    with pytest.raises(DENIED, match=ERROR) as failure:
        callable_value()
    assert failure.value.args == (contract.DENIED_MESSAGE,)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


def recalculate_payload(value: dict[str, object]) -> str:
    without = {key: item for key, item in value.items() if key != "jti"}
    value["jti"] = hashlib.sha256(
        contract.EVIDENCE_JTI_DOMAIN.encode("ascii") + b"\0" + canonical(without).encode("ascii")
    ).hexdigest()
    return canonical(value)


def test_golden_fixture_signature_input_trust_and_cross_contract_binding_are_exact():
    fixture_bytes = FIXTURE_PATH.read_bytes()
    assert len(fixture_bytes) == 6_846
    assert hashlib.sha256(fixture_bytes).hexdigest() == (
        "5c2d9fa2c73b295ff6e4d3477c591273ec06251c65551b646468b62a35343dbb"
    )
    assert len(SOURCE_PATH.read_bytes()) == FIXTURE["sourceFixture"]["bytes"] == 32_998
    assert hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest() == FIXTURE["sourceFixture"]["sha256"]
    assert hashlib.sha256(INPUT_WIRE.encode("ascii")).hexdigest() == FIXTURE["sourceFixture"]["verificationInputSha256"]
    assert contract.deadline_evidence_input_payload_digest_v1(INPUT_WIRE) == VECTOR["inputPayloadDigest"]
    assert (
        contract.canonical_messaging_device_verification_deadline_evidence_protected_header_v1_bytes(
            kid=CONFIG["kid"]
        ).decode("ascii")
        == VECTOR["protectedHeaderWire"]
    )
    signing_input = contract.messaging_device_verification_deadline_evidence_signing_input_v1(
        protected_header_wire=VECTOR["protectedHeaderWire"],
        payload_wire=VECTOR["payloadWire"],
    )
    assert signing_input == (
        b64(VECTOR["protectedHeaderWire"].encode("ascii")) + "." + b64(VECTOR["payloadWire"].encode("ascii"))
    ).encode("ascii")
    result = verify()
    projected = dict(contract.project_authenticated_messaging_device_verification_deadline_evidence_v1(result))
    assert projected["authority"] == "not_granted"
    assert projected["reservationPersistence"] == "not_implemented"
    assert projected["privateKeyCustody"] == "not_provisioned"
    assert projected["finalAdmission"] == "denied"
    assert projected["runtimeEnabled"] is False
    assert projected["keyId"] == CONFIG["kid"]
    assert projected["keyFingerprint"] == TRUST["keyFingerprint"]
    assert projected["trustRecordId"] == TRUST["trustRecordId"]
    assert projected["trustRevision"] == TRUST["trustRevision"]
    claims = projected["claims"]
    assert claims.reservation_id == VECTOR["reservationId"]
    assert claims.token_id == VECTOR["jti"]
    assert claims.input_digest == FIXTURE["sourceFixture"]["verificationInputDigest"]
    assert claims.input_payload_digest == VECTOR["inputPayloadDigest"]
    assert not hasattr(result, "__dict__")
    with pytest.raises(FrozenInstanceError):
        result.claims = claims


def test_strict_payload_round_trip_and_raw_values_never_become_authenticated_authority():
    parsed = contract.parse_messaging_device_verification_deadline_evidence_payload_v1(
        VECTOR["payloadWire"], expected_input_wire=INPUT_WIRE
    )
    assert parsed.payload_wire == VECTOR["payloadWire"]
    assert (
        parsed.observed_at
        < parsed.expires_at
        <= min(
            parsed.phone_session_expires_at,
            parsed.approver_session_expires_at,
            parsed.full_expires_at,
            parsed.x25519_binding_expires_at,
        )
    )
    assert parsed.operation == "register"
    assert parsed.association_version == 1
    assert parsed.x25519_binding_version == 1
    assert not hasattr(parsed, "authority")
    denied(lambda: contract.project_authenticated_messaging_device_verification_deadline_evidence_v1(parsed))
    forged = object.__new__(contract.AuthenticatedMessagingDeviceVerificationDeadlineEvidenceV1)
    denied(lambda: contract.project_authenticated_messaging_device_verification_deadline_evidence_v1(forged))


@pytest.mark.parametrize(
    ("field", "bad_value"),
    (
        ("observedAt", True),
        ("expiresAt", 1788906600000.0),
        ("associationVersion", False),
        ("x25519BindingVersion", 1.0),
        ("reservationRevision", True),
        ("fullEvidenceVersion", "full-\N{CYRILLIC SMALL LETTER A}"),
        ("operation", "rotate"),
        ("requestId", "A" * 64),
    ),
)
def test_bool_float_confusable_noncanonical_and_wrong_vocabulary_are_denied(field: str, bad_value: object):
    value = json.loads(VECTOR["payloadWire"])
    value[field] = bad_value
    denied(lambda: contract.parse_messaging_device_verification_deadline_evidence_payload_v1(canonical(value)))


def test_duplicate_unknown_whitespace_oversize_and_noncanonical_jws_segments_are_denied():
    duplicate = VECTOR["payloadWire"].replace("{", '{"acceptanceId":"' + "79" * 32 + '",', 1)
    denied(lambda: contract.parse_messaging_device_verification_deadline_evidence_payload_v1(duplicate))
    value = json.loads(VECTOR["payloadWire"])
    value["unknown"] = 1
    denied(lambda: contract.parse_messaging_device_verification_deadline_evidence_payload_v1(canonical(value)))
    denied(
        lambda: contract.parse_messaging_device_verification_deadline_evidence_payload_v1(
            json.dumps(json.loads(VECTOR["payloadWire"]), sort_keys=True)
        )
    )
    denied(
        lambda: contract.parse_messaging_device_verification_deadline_evidence_payload_v1(
            "{" + '"x":"' + "a" * contract.MAX_PAYLOAD_BYTES + '"}'
        )
    )
    parts = compact().split(".")
    denied(lambda: verify(evidence=parts[0] + "=." + parts[1] + "." + parts[2]))
    denied(lambda: verify(evidence=compact() + ".extra"))


def test_mutation_input_substitution_expiry_and_signature_changes_deny():
    value = json.loads(VECTOR["payloadWire"])
    value["deviceId"] = "44" * 32
    value["reservationId"] = "55" * 32
    payload = recalculate_payload(value)
    changed = ".".join(
        (
            b64(VECTOR["protectedHeaderWire"].encode("ascii")),
            b64(payload.encode("ascii")),
            b64(bytes.fromhex(VECTOR["signature"])),
        )
    )
    denied(lambda: verify(evidence=changed))
    denied(lambda: verify(now=FIXTURE["deadlines"]["evidenceExpiresAt"]))
    denied(lambda: verify(expected_input_wire=INPUT_WIRE.replace("2222", "2223", 1)))
    parts = compact().split(".")
    changed_signature = bytes([bytes.fromhex(VECTOR["signature"])[0] ^ 1]) + bytes.fromhex(VECTOR["signature"])[1:]
    denied(lambda: verify(evidence=parts[0] + "." + parts[1] + "." + b64(changed_signature)))


def test_deadline_bounds_reservation_id_and_jti_are_domain_separated_and_exact():
    for field, value in (
        ("expiresAt", FIXTURE["deadlines"]["observedAt"]),
        ("expiresAt", FIXTURE["deadlines"]["observedAt"] + contract.MAX_EVIDENCE_LIFETIME_MS + 1),
        ("phoneSessionExpiresAt", FIXTURE["deadlines"]["observedAt"]),
        ("reservationId", "00" * 32),
        ("jti", "00" * 32),
    ):
        payload = json.loads(VECTOR["payloadWire"])
        payload[field] = value
        if field != "jti":
            payload_wire = recalculate_payload(payload)
        else:
            payload_wire = canonical(payload)
        denied(
            lambda payload_wire=payload_wire: (
                contract.parse_messaging_device_verification_deadline_evidence_payload_v1(payload_wire)
            )
        )


def test_dedicated_public_jwk_lifecycle_rejects_private_unknown_weak_duplicate_and_revoked_keys():
    private = {**TRUST["jwk"], "d": "AQ"}
    denied(lambda: trust_record(public_jwk=private))
    denied(lambda: trust_record(public_jwk={**TRUST["jwk"], "x5u": "https://keys.example"}))
    denied(lambda: trust_record(public_jwk={**TRUST["jwk"], "n": "AQ"}))
    denied(lambda: trust_record(trust_revision=True))
    denied(lambda: trust_record(not_before=TRUST["notAfter"]))
    denied(lambda: verify(config=configuration(trust_records=(trust_record(revoked_at=1788906599000),))))
    denied(lambda: verify(config=configuration(trust_records=())))
    denied(lambda: configuration(trust_records=(trust_record(), trust_record())))
    other_jwk = {**TRUST["jwk"], "kid": "replacement-deadline-evidence-key-v1"}
    other = trust_record(public_jwk=other_jwk, trust_revision=2)
    assert verify(config=configuration(trust_records=(other, trust_record()))).key_id == CONFIG["kid"]
    denied(lambda: verify(config=configuration(trust_records=(other,))))


def test_empty_config_wrong_metadata_and_disabled_runtime_fail_closed():
    assert contract.RUNTIME_ENABLED is False
    assert contract.MessagingDeviceVerificationDeadlineEvidenceV1Config().enabled is False
    denied(
        lambda: contract.verify_messaging_device_verification_deadline_evidence_v1(
            compact(), expected_input_wire=INPUT_WIRE, now=FIXTURE["deadlines"]["observedAt"]
        )
    )
    for field, value in (
        ("issuer", "https://other.example"),
        ("audience", "https://social.example/internal/v2/social/device-admission/consume"),
        ("client_id", "other-client"),
        ("service_principal", "other-principal"),
        ("enabled", False),
    ):
        denied(lambda field=field, value=value: verify(config=configuration(**{field: value})))
    for enabled in (1, "true", None):
        denied(lambda enabled=enabled: configuration(enabled=enabled))


def test_fixture_contains_no_private_material_and_inputs_are_immutable_copies():
    fixture_text = FIXTURE_PATH.read_text("ascii")
    for forbidden in ('"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"', "privateKey", "seed"):
        assert forbidden not in fixture_text
    supplied = copy.deepcopy(TRUST["jwk"])
    record = trust_record(public_jwk=supplied)
    supplied["kid"] = "mutated"
    assert record.key_id == CONFIG["kid"]
    with pytest.raises(TypeError):
        record.public_jwk["kid"] = "mutated"


def test_public_failures_drop_secret_bearing_nonserializable_and_circular_context():
    secret = '{"privateKey":"do-not-leak-deadline-secret"}'
    circular: list[object] = []
    circular.append(circular)
    for malformed in (secret, object(), circular):
        denied(
            lambda malformed=malformed: (
                contract.parse_messaging_device_verification_deadline_evidence_payload_v1(malformed)
            )
        )
