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


def test_signature_verified_server_proof_upgrades_receipt(monkeypatch):
    import app.blueprints.agent as agent
    from app.models import AgentJob

    monkeypatch.setattr(agent, "sign_message", lambda payload: "sig")
    job = AgentJob(
        id="job-proof",
        job_type="ping",
        request_hash="a" * 64,
        payment_hash="payhash",
        request_json={
            "job_type": "ping",
            "payload": {"message": "hello", "requester_pubkey": "b" * 64, "demo": "human_proof_v2", "demo_nonce": "n"},
            "requester_proof": {
                "level": "signature_verified",
                "method": "nostr",
                "pubkey": "b" * 64,
                "canonical_pubkey": "b" * 64,
                "request_hash": "a" * 64,
                "verified_at": 123,
            },
        },
    )
    receipt = agent._build_receipt(job, None)
    assert receipt["requester_pubkey_proof"] == "signature_verified"
    assert receipt["requester_pubkey_proof_method"] == "nostr"
    assert receipt["requester_pubkey_verified_at"] == 123


def test_tampered_server_proof_does_not_upgrade_receipt(monkeypatch):
    import app.blueprints.agent as agent
    from app.models import AgentJob

    monkeypatch.setattr(agent, "sign_message", lambda payload: "sig")
    job = AgentJob(
        id="job-proof",
        job_type="ping",
        request_hash="a" * 64,
        payment_hash="payhash",
        request_json={
            "job_type": "ping",
            "payload": {"message": "hello", "requester_pubkey": "b" * 64},
            "requester_proof": {
                "level": "signature_verified",
                "method": "nostr",
                "canonical_pubkey": "c" * 64,
                "request_hash": "a" * 64,
                "verified_at": 123,
            },
        },
    )
    receipt = agent._build_receipt(job, None)
    assert receipt["requester_pubkey_proof"] == "self_declared_no_signature"
    assert "requester_pubkey_proof_method" not in receipt


def _receipt_for_server_proof(monkeypatch, proof_overrides=None, payload_overrides=None, request_hash="a" * 64):
    import app.blueprints.agent as agent
    from app.models import AgentJob

    monkeypatch.setattr(agent, "sign_message", lambda payload: "sig")
    payload = {"message": "hello", "requester_pubkey": "b" * 64, "demo": "human_proof_v2", "demo_nonce": "n"}
    if payload_overrides:
        payload.update(payload_overrides)
    proof = {
        "level": "signature_verified",
        "method": "nostr",
        "pubkey": "b" * 64,
        "canonical_pubkey": "b" * 64,
        "request_hash": request_hash,
        "verified_at": 123,
    }
    if proof_overrides:
        proof.update(proof_overrides)
    job = AgentJob(
        id="job-proof-hardening",
        job_type="ping",
        request_hash=request_hash,
        payment_hash="payhash",
        request_json={"job_type": "ping", "payload": payload, "requester_proof": proof},
    )
    return agent._build_receipt(job, None)


def test_receipt_downgrades_wrong_original_proof_pubkey(monkeypatch):
    receipt = _receipt_for_server_proof(monkeypatch, proof_overrides={"pubkey": "c" * 64})
    assert receipt["requester_pubkey_proof"] == "self_declared_no_signature"
    assert "requester_pubkey_proof_method" not in receipt


def test_receipt_downgrades_missing_or_invalid_verified_at(monkeypatch):
    for bad_verified_at in (None, 0, "123"):
        receipt = _receipt_for_server_proof(monkeypatch, proof_overrides={"verified_at": bad_verified_at})
        assert receipt["requester_pubkey_proof"] == "self_declared_no_signature"
        assert "requester_pubkey_proof_method" not in receipt


def test_receipt_downgrades_wrong_demo_version(monkeypatch):
    receipt = _receipt_for_server_proof(monkeypatch, payload_overrides={"demo": "human_proof_v1"})
    assert receipt["requester_pubkey_proof"] == "self_declared_no_signature"
    assert "requester_pubkey_proof_method" not in receipt


def test_new_receipt_v1_additive_fields_are_signed():
    receipt = _build_receipt(_job(VALID_XONLY_PUBKEY), prev_event_hash="0" * 64)

    for key in [
        "schema",
        "receipt_id",
        "runtime",
        "requester_proof",
        "input_hash",
        "amount_sats",
        "invoice_hash",
        "settled",
        "verify_url",
        "attestations_url",
        "reputation_url",
        "chain_health_url",
        "signing_key",
    ]:
        assert key in receipt

    for key in [
        "version",
        "event_type",
        "job_id",
        "job_type",
        "request_hash",
        "payment_hash",
        "result_hash",
        "timestamp",
        "agent_pubkey",
        "prev_event_hash",
        "requester_pubkey",
        "requester_pubkey_proof",
        "signature",
    ]:
        assert key in receipt

    assert receipt["schema"] == "hodlxxi.receipt.v1"
    assert receipt["receipt_id"] == "hodlxxi-receipt-v1:job-requester-pubkey"
    assert receipt["runtime"] == "HODLXXI 21-Sat Proof Runtime"
    assert receipt["requester_proof"] == {
        "level": "self_declared_no_signature",
        "verified": False,
        "pubkey_present": True,
    }
    assert receipt["input_hash"] == receipt["request_hash"]
    assert receipt["amount_sats"] == 21
    assert receipt["invoice_hash"] == hashlib.sha256("lnbc21test".encode("utf-8")).hexdigest()
    assert receipt["settled"] is True
    assert receipt["verify_url"] == "/agent/verify/job-requester-pubkey"
    assert receipt["attestations_url"] == "/agent/attestations"
    assert receipt["reputation_url"] == "/agent/reputation"
    assert receipt["chain_health_url"] == "/agent/chain/health"
    assert receipt["signing_key"] == receipt["agent_pubkey"]
    _assert_signature_verifies(receipt)


def test_old_minimal_receipt_shape_still_verifies():
    from app.blueprints.agent import get_agent_pubkey_hex, sign_message

    old_receipt = {
        "event_type": "job_receipt",
        "job_id": "old-job",
        "job_type": "ping",
        "request_hash": "a" * 64,
        "payment_hash": "b" * 64,
        "result_hash": "c" * 64,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "agent_pubkey": get_agent_pubkey_hex(),
        "prev_event_hash": None,
        "version": "1.0",
    }
    old_receipt["signature"] = sign_message(canonical_json_bytes(old_receipt))

    _assert_signature_verifies(old_receipt)


def test_receipt_json_download_endpoint_returns_standalone_receipt(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("lnbc21download", "lookup-download"),
    )
    monkeypatch.setattr("app.blueprints.agent.check_invoice_paid", lambda invoice_id: True)

    req = client.post("/agent/request", json={"job_type": "ping", "payload": {"message": "download"}}).get_json()
    job_response = client.get(f"/agent/jobs/{req['job_id']}")
    assert job_response.status_code == 200
    receipt = job_response.get_json()["receipt"]

    verify_response = client.get(f"/agent/verify/{req['job_id']}")
    assert verify_response.status_code == 200
    assert verify_response.get_json()["valid"] is True

    response = client.get(f"/agent/receipts/{req['job_id']}.json")
    body = response.get_json()

    assert response.status_code == 200
    assert response.content_type.startswith("application/json")
    assert response.headers["Content-Disposition"] == f'attachment; filename="hodlxxi-receipt-{req["job_id"]}.json"'
    assert body == receipt
    assert body["schema"] == "hodlxxi.receipt.v1"
    assert body["signature"]
    for secret_marker in ["private", "macaroon", "session", "cookie", "rpc_password", "database_url"]:
        assert secret_marker not in str(body).lower()


def test_receipt_json_download_endpoint_reports_pending_and_missing(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("lnbc21pending", "lookup-pending"),
    )

    req = client.post("/agent/request", json={"job_type": "ping", "payload": {"message": "pending"}}).get_json()

    pending = client.get(f"/agent/receipts/{req['job_id']}.json")
    assert pending.status_code == 409
    assert pending.get_json()["status"] == "no_receipt"
    assert pending.get_json()["reason"] == "receipt_not_issued"

    missing = client.get("/agent/receipts/unknown-job.json")
    assert missing.status_code == 404
    assert missing.get_json()["status"] == "not_found"
