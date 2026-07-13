import hashlib
from datetime import datetime, timezone

import pytest

from app.agent_signer import canonical_json_bytes, verify_message
from app.blueprints.agent import _build_receipt, _event_attestation
from app.models import AgentEvent, AgentJob
from app.services.trust_surface import classify_job_outcomes

VALID_COMPRESSED_PUBKEY = "02" + "a" * 64
VALID_XONLY_PUBKEY = "b" * 64
VALID_NPUB = "npub1" + "q" * 58


def _job(requester_pubkey=None):
    payload = {"message": "ping"}
    if requester_pubkey is not None:
        payload["requester_pubkey"] = requester_pubkey
    request_json = {"job_type": "ping", "payload": payload}
    return AgentJob(
        id="job-trust-surface-schema",
        job_type="ping",
        request_json=request_json,
        request_hash=hashlib.sha256(canonical_json_bytes(request_json)).hexdigest(),
        sats=21,
        payment_request="lnbc21schema",
        payment_lookup_id="lookup-schema",
        payment_hash="f" * 64,
        status="invoice_pending",
    )


def _assert_signature_verifies(receipt):
    payload = dict(receipt)
    signature = payload.pop("signature")
    assert verify_message(canonical_json_bytes(payload), signature, receipt["agent_pubkey"])


def test_classify_job_outcomes_covers_all_persisted_statuses():
    statuses = [
        "done",
        "DONE",
        "invoice_pending",
        "pending",
        "failed",
        "execution_failed",
        "expired",
        "timeout",
        "unknown",
        None,
    ]

    result = classify_job_outcomes(statuses)

    assert result == {
        "completed_jobs": 2,
        "unpaid_or_expired_jobs": 2,
        "execution_failed_jobs": 2,
        "expired_jobs": 2,
        "unclassified_jobs": 2,
    }
    assert sum(result.values()) == len(statuses)


@pytest.mark.parametrize(
    ("requester_pubkey", "expected_format"),
    [
        (VALID_XONLY_PUBKEY, "xonly_secp256k1"),
        (VALID_COMPRESSED_PUBKEY, "compressed_secp256k1"),
        (VALID_NPUB, "nostr_npub"),
    ],
)
def test_new_receipts_declare_requester_pubkey_format(requester_pubkey, expected_format):
    receipt = _build_receipt(_job(requester_pubkey), prev_event_hash=None)

    assert receipt["requester_pubkey"] == requester_pubkey
    assert receipt["requester_pubkey_format"] == expected_format
    assert receipt["requester_pubkey_proof"] == "self_declared_no_signature"
    _assert_signature_verifies(receipt)


def test_receipt_without_requester_key_does_not_invent_format():
    receipt = _build_receipt(_job(), prev_event_hash=None)

    assert "requester_pubkey" not in receipt
    assert "requester_pubkey_format" not in receipt
    _assert_signature_verifies(receipt)


def test_attestation_copies_requester_format_only_from_signed_receipt():
    receipt = _build_receipt(_job(VALID_XONLY_PUBKEY), prev_event_hash="0" * 64)
    event = AgentEvent(
        job_id="job-trust-surface-schema",
        event_hash=hashlib.sha256(canonical_json_bytes(receipt)).hexdigest(),
        prev_event_hash="0" * 64,
        event_json=receipt,
        signature=receipt["signature"],
        created_at=datetime.now(timezone.utc),
    )

    attestation = _event_attestation(event, _job(VALID_COMPRESSED_PUBKEY))

    assert attestation["requester_pubkey"] == VALID_XONLY_PUBKEY
    assert attestation["requester_pubkey_format"] == "xonly_secp256k1"


def test_historical_receipt_without_format_remains_unchanged():
    raw = {
        "event_type": "job_receipt",
        "job_id": "historical-job",
        "job_type": "ping",
        "request_hash": "a" * 64,
        "payment_hash": "b" * 64,
        "result_hash": "c" * 64,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "agent_pubkey": "02" + "d" * 64,
        "prev_event_hash": None,
        "version": "1.0",
        "requester_pubkey": VALID_XONLY_PUBKEY,
        "requester_pubkey_proof": "signature_verified",
        "signature": "historical-signature",
    }
    event = AgentEvent(
        job_id="historical-job",
        event_hash=hashlib.sha256(canonical_json_bytes(raw)).hexdigest(),
        prev_event_hash=None,
        event_json=raw,
        signature=raw["signature"],
        created_at=datetime.now(timezone.utc),
    )

    attestation = _event_attestation(event, None)

    assert attestation["requester_pubkey"] == VALID_XONLY_PUBKEY
    assert "requester_pubkey_format" not in attestation


def test_reputation_declares_total_job_semantics_and_complete_outcome_partition(client):
    response = client.get("/agent/reputation")

    assert response.status_code == 200
    body = response.get_json()

    assert body["total_jobs_semantics"] == "all_persisted_job_requests"
    assert body["completed_jobs"] == body["job_outcomes"]["completed_jobs"]
    assert set(body["job_outcomes"]) == {
        "completed_jobs",
        "unpaid_or_expired_jobs",
        "execution_failed_jobs",
        "expired_jobs",
        "unclassified_jobs",
    }
    assert sum(body["job_outcomes"].values()) == body["total_jobs"]
