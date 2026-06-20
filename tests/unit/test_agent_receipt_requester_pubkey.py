import hashlib
from datetime import datetime, timezone

from app.agent_signer import canonical_json_bytes, verify_message
from app.blueprints.agent import _build_receipt, _event_attestation
from app.models import AgentEvent, AgentJob

VALID_COMPRESSED_PUBKEY = "02" + "a" * 64
VALID_XONLY_PUBKEY = "b" * 64
VALID_NPUB = "npub1" + "q" * 58


def _job(requester_pubkey=None):
    payload = {"message": "ping"}
    if requester_pubkey is not None:
        payload["requester_pubkey"] = requester_pubkey
    request_json = {"job_type": "ping", "payload": payload}
    return AgentJob(
        id="job-requester-pubkey",
        job_type="ping",
        request_json=request_json,
        request_hash=hashlib.sha256(canonical_json_bytes(request_json)).hexdigest(),
        sats=21,
        payment_request="lnbc21test",
        payment_lookup_id="lookup-test",
        payment_hash="f" * 64,
        status="invoice_pending",
    )


def _assert_signature_verifies(receipt):
    payload = dict(receipt)
    signature = payload.pop("signature")
    assert verify_message(canonical_json_bytes(payload), signature, receipt["agent_pubkey"])


def test_valid_compressed_requester_pubkey_is_included_in_signed_receipt():
    receipt = _build_receipt(_job(VALID_COMPRESSED_PUBKEY), prev_event_hash=None)

    assert receipt["requester_pubkey"] == VALID_COMPRESSED_PUBKEY
    assert receipt["requester_pubkey_proof"] == "self_declared_no_signature"
    assert receipt["signature"]
    _assert_signature_verifies(receipt)


def test_valid_xonly_requester_pubkey_is_accepted():
    receipt = _build_receipt(_job(VALID_XONLY_PUBKEY), prev_event_hash=None)

    assert receipt["requester_pubkey"] == VALID_XONLY_PUBKEY
    assert receipt["requester_pubkey_proof"] == "self_declared_no_signature"
    _assert_signature_verifies(receipt)


def test_valid_npub_requester_pubkey_is_accepted_as_original_label():
    receipt = _build_receipt(_job(VALID_NPUB), prev_event_hash=None)

    assert receipt["requester_pubkey"] == VALID_NPUB
    assert receipt["requester_pubkey_proof"] == "self_declared_no_signature"
    _assert_signature_verifies(receipt)


def test_invalid_requester_pubkey_is_omitted_from_receipt():
    receipt = _build_receipt(_job("definitely not a pubkey"), prev_event_hash=None)

    assert "requester_pubkey" not in receipt
    assert "requester_pubkey_proof" not in receipt
    assert receipt["signature"]
    _assert_signature_verifies(receipt)


def test_short_npub_label_is_omitted_from_receipt():
    receipt = _build_receipt(_job("npub1qqqq"), prev_event_hash=None)

    assert "requester_pubkey" not in receipt
    assert "requester_pubkey_proof" not in receipt
    assert receipt["signature"]
    _assert_signature_verifies(receipt)


def test_existing_receipt_shape_without_requester_pubkey_still_verifies():
    receipt = _build_receipt(_job(), prev_event_hash=None)

    assert "requester_pubkey" not in receipt
    assert "requester_pubkey_proof" not in receipt
    _assert_signature_verifies(receipt)


def test_event_attestation_reflects_requester_pubkey_only_from_signed_event_json():
    receipt = _build_receipt(_job(VALID_COMPRESSED_PUBKEY), prev_event_hash="0" * 64)
    event = AgentEvent(
        job_id="job-requester-pubkey",
        event_hash=hashlib.sha256(canonical_json_bytes(receipt)).hexdigest(),
        prev_event_hash="0" * 64,
        event_json=receipt,
        signature=receipt["signature"],
        created_at=datetime.now(timezone.utc),
    )

    attestation = _event_attestation(event, _job("definitely not a pubkey"))

    assert attestation["requester_pubkey"] == VALID_COMPRESSED_PUBKEY
    assert attestation["requester_pubkey_proof"] == "self_declared_no_signature"


def test_event_attestation_does_not_invent_requester_pubkey_from_job():
    receipt = _build_receipt(_job(), prev_event_hash=None)
    event = AgentEvent(
        job_id="job-requester-pubkey",
        event_hash=hashlib.sha256(canonical_json_bytes(receipt)).hexdigest(),
        prev_event_hash=None,
        event_json=receipt,
        signature=receipt["signature"],
        created_at=datetime.now(timezone.utc),
    )

    attestation = _event_attestation(event, _job(VALID_COMPRESSED_PUBKEY))

    assert "requester_pubkey" not in attestation
    assert "requester_pubkey_proof" not in attestation
