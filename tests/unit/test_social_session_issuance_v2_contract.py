import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services import social_session_issuance_v2_contract as contract
from app.services.social_messaging_device_verification_deadline_evidence_v1 import (
    EVIDENCE_JTI_DOMAIN,
    SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied,
    parse_messaging_device_verification_deadline_evidence_payload_v1,
)
from tests.unit.test_social_session_issuance_v2_storage import VECTOR


def revision_values():
    return dict(
        operation_id="99" * 32,
        acceptance_wire=VECTOR["acceptanceWire"],
        approval_wire=VECTOR["approvalEventWire"],
        issuance_id="d1" * 32,
        token_id="d2" * 16,
        parent_token_id="a1" * 16,
        parent_session_id="c1" * 32,
        parent_browser_id="b1" * 32,
        client_id="social-client",
        backend_id="backend",
        principal="principal",
        issuer="https://ubid.example",
        delivery="d3" * 32,
        signing_kid="offline-oauth",
        issued_at=1788906600,
        expires_at=1788906899,
    )


def test_hex64_revision_crosses_actual_deadline_evidence_consumer():
    values = revision_values()
    revision = contract.issuance_revision(**values)
    assert revision == "4fac196d86ad3232dab79bd37210d36df007e9a15d510e523c0daafd54e7d35c"
    preimage = contract.revision_preimage(**values)
    assert revision == hashlib.sha256(contract.REVISION_DOMAIN.encode() + b"\0" + preimage).hexdigest()
    assert contract.hex64(revision) == revision
    path = (
        Path(__file__).resolve().parents[2]
        / "tests/fixtures/social_messaging_device_verification_deadline_evidence_v1.json"
    )
    fixture = json.loads(path.read_bytes())
    payload = json.loads(fixture["vector"]["payloadWire"])
    payload["socialSessionIssuanceRevision"] = revision
    without = {k: v for k, v in payload.items() if k != "jti"}
    payload["jti"] = hashlib.sha256(
        EVIDENCE_JTI_DOMAIN.encode() + b"\0" + contract.canonical(without).encode()
    ).hexdigest()
    parsed = parse_messaging_device_verification_deadline_evidence_payload_v1(
        contract.canonical(payload), expected_input_wire=VECTOR["preacceptedEnrollmentVerificationInputWire"]
    )
    assert parsed.social_session_issuance_revision == revision
    payload["socialSessionIssuanceRevision"] = 1
    with pytest.raises(SocialMessagingDeviceVerificationDeadlineEvidenceV1Denied):
        parse_messaging_device_verification_deadline_evidence_payload_v1(contract.canonical(payload))


def test_revision_binds_each_identity_context_and_original_claim_interval():
    values = revision_values()
    revision = contract.issuance_revision(**values)
    for change in (
        dict(issuance_id="e1" * 32),
        dict(token_id="e2" * 16),
        dict(parent_session_id="e6" * 32),
        dict(parent_browser_id="e3" * 32),
        dict(principal="other"),
        dict(delivery="e4" * 32),
        dict(expires_at=1788906898),
    ):
        assert contract.issuance_revision(**(values | change)) != revision
    with pytest.raises(contract.V2IssuanceUnavailable):
        contract.issuance_revision(**(values | dict(operation_id="e5" * 32)))


def test_real_bip340_and_original_phone_proofs_and_exported_record_denial():
    approval = v2.parse_approval_event_v2(VECTOR["approvalEventWire"])
    assert approval.event_id == VECTOR["approvalEventId"]
    envelope = contract.verify_phone(
        VECTOR["authorizationWire"],
        secret="77" * 32,
        possession_proof=VECTOR["pairingPossessionProof"],
        verifier="88" * 32,
        now_ms=1788906600000,
    )
    assert envelope.pre_enrollment.x25519_binding_version == 1
    with pytest.raises(v2.SocialMessagingMobilePreEnrollmentV2Unavailable):
        contract.verify_phone(
            envelope, secret="77" * 32, possession_proof=VECTOR["pairingPossessionProof"], verifier="88" * 32
        )
    broken = json.loads(VECTOR["approvalEventWire"])
    broken["sig"] = ("00" if broken["sig"][:2] != "00" else "01") + broken["sig"][2:]
    with pytest.raises(v2.SocialMessagingMobilePreEnrollmentV2Unavailable):
        v2.parse_approval_event_v2(contract.canonical(broken))
    with pytest.raises(contract.V2IssuanceUnavailable):
        contract.verify_phone(
            VECTOR["authorizationWire"],
            secret="77" * 32,
            possession_proof=VECTOR["pairingPossessionProof"],
            verifier="89" * 32,
        )


def test_exclusive_pairing_deadline_and_exact_integer_floor():
    deadline = 1788906899000
    contract.verify_phone(
        VECTOR["authorizationWire"],
        secret="77" * 32,
        possession_proof=VECTOR["pairingPossessionProof"],
        verifier="88" * 32,
        now_ms=deadline - 1,
    )
    with pytest.raises(v2.SocialMessagingMobilePreEnrollmentV2Unavailable):
        contract.verify_phone(
            VECTOR["authorizationWire"],
            secret="77" * 32,
            possession_proof=VECTOR["pairingPossessionProof"],
            verifier="88" * 32,
            now_ms=deadline,
        )
    precise = datetime(2026, 9, 8, 22, 30, 0, 999999, tzinfo=timezone.utc)
    assert contract.milliseconds(precise) == 1788906600999
    assert contract.milliseconds(precise) // 1000 == 1788906600
    with pytest.raises(contract.V2IssuanceUnavailable):
        contract.trusted_now(lambda: precise.replace(tzinfo=None))


def test_delivery_commitment_domains_and_original_verifier_are_distinct():
    values = dict(
        issuer="https://ubid.example",
        client_id="social-client",
        backend_id="backend",
        principal="principal",
        operation_id="99" * 32,
        verifier="88" * 32,
        delivery_key="55" * 32,
    )
    first = contract.delivery_commitment(**values)
    assert first != v2.phone_exchange_commitment_v2("88" * 32)
    for key, value in (
        ("issuer", "https://other.example"),
        ("principal", "other"),
        ("verifier", "89" * 32),
        ("delivery_key", "56" * 32),
        ("operation_id", "98" * 32),
    ):
        assert contract.delivery_commitment(**(values | {key: value})) != first
