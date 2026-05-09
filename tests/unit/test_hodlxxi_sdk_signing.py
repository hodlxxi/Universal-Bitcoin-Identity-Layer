import hashlib

import pytest

from hodlxxi_sdk import AgentReceipt, Challenge, ReceiptError, SigningError, canonical_json, sha256_hex, sign_challenge


def test_canonical_json_is_stable():
    left = {"b": 2, "a": 1}
    right = {"a": 1, "b": 2}
    assert canonical_json(left) == canonical_json(right)
    assert canonical_json(left) == '{"a":1,"b":2}'


def test_sha256_hex_matches_hashlib():
    msg = "hodlxxi"
    assert sha256_hex(msg) == hashlib.sha256(msg.encode()).hexdigest()


def test_challenge_message_and_digest_are_stable():
    challenge = Challenge(challenge="abc123", domain="hodlxxi.com", purpose="agent-auth")

    assert challenge.payload() == {
        "version": "hodlxxi-challenge-v1",
        "domain": "hodlxxi.com",
        "purpose": "agent-auth",
        "challenge": "abc123",
    }
    assert challenge.message() == (
        '{"challenge":"abc123","domain":"hodlxxi.com","purpose":"agent-auth","version":"hodlxxi-challenge-v1"}'
    )
    assert challenge.digest_hex() == hashlib.sha256(challenge.message().encode()).hexdigest()


def test_sign_challenge_uses_caller_signer():
    def fake_signer(message: bytes) -> str:
        assert b"abc123" in message
        return "signature-from-wallet"

    signed = sign_challenge(Challenge("abc123"), fake_signer)

    assert signed["challenge"] == "abc123"
    assert signed["signature"] == "signature-from-wallet"
    assert signed["message_sha256"] == hashlib.sha256(signed["message"].encode()).hexdigest()


def test_sign_challenge_rejects_empty_signature():
    with pytest.raises(SigningError):
        sign_challenge(Challenge("abc123"), lambda _msg: "")


def test_agent_receipt_from_nested_receipt():
    payload = {
        "job_id": "outer-job",
        "status": "invoice_pending",
        "receipt": {
            "job_id": "job-123",
            "status": "done",
            "payment_hash": "hash-123",
            "receipt_id": "receipt-123",
            "signature": "sig-123",
        },
    }

    receipt = AgentReceipt.from_response(payload)

    assert receipt.job_id == "job-123"
    assert receipt.status == "done"
    assert receipt.payment_hash == "hash-123"
    assert receipt.receipt_id == "receipt-123"
    assert receipt.signature == "sig-123"
    assert receipt.is_done is True
    assert receipt.is_signed is True


def test_agent_receipt_from_flat_response():
    receipt = AgentReceipt.from_response({"id": "job-1", "status": "invoice_pending"})

    assert receipt.job_id == "job-1"
    assert receipt.status == "invoice_pending"
    assert receipt.is_done is False
    assert receipt.is_signed is False


def test_agent_receipt_requires_job_and_status():
    with pytest.raises(ReceiptError):
        AgentReceipt.from_response({"status": "done"})

    with pytest.raises(ReceiptError):
        AgentReceipt.from_response({"job_id": "job-1"})
