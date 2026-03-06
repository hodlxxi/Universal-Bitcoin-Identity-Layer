import hashlib
import os

os.environ.setdefault("AGENT_PRIVKEY_HEX", "1" * 64)

from app.agent_signer import canonical_json_bytes, verify_message
from app.database import session_scope
from app.models import AgentJob


def _receipt_message(receipt: dict) -> bytes:
    payload = dict(receipt)
    payload.pop("signature", None)
    return canonical_json_bytes(payload)


def test_capabilities_signature_verifies(client):
    res = client.get("/agent/capabilities")
    assert res.status_code == 200
    body = res.get_json()

    signature = body.pop("signature")
    assert verify_message(canonical_json_bytes(body), signature, body["agent_pubkey"])


def test_request_creates_job_and_invoice(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("ln-invoice", "lookup-id-123"),
    )

    res = client.post("/agent/request", json={"job_type": "ping", "payload": {"message": "hello"}})
    assert res.status_code == 201
    body = res.get_json()

    assert body["invoice"] == "ln-invoice"
    assert body["status"] == "invoice_pending"

    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=body["job_id"]).one()
        assert job.status == "invoice_pending"
        assert job.payment_hash == hashlib.sha256("lookup-id-123".encode("utf-8")).hexdigest()


def test_job_receipt_after_marked_paid(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("ln-invoice", "lookup-id-paid"),
    )
    monkeypatch.setattr("app.blueprints.agent.check_invoice_paid", lambda invoice_id: True)

    req = client.post("/agent/request", json={"job_type": "ping", "payload": {"message": "hello"}}).get_json()

    res = client.get(f"/agent/jobs/{req['job_id']}")
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "done"

    receipt = body["receipt"]
    assert receipt["request_hash"] == hashlib.sha256(
        canonical_json_bytes({"job_type": "ping", "payload": {"message": "hello"}})
    ).hexdigest()
    assert verify_message(_receipt_message(receipt), receipt["signature"], receipt["agent_pubkey"])


def test_attestations_returns_receipts(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("ln-invoice", "lookup-id-attest"),
    )
    monkeypatch.setattr("app.blueprints.agent.check_invoice_paid", lambda invoice_id: True)

    req = client.post("/agent/request", json={"job_type": "ping", "payload": {"message": "hello"}}).get_json()
    client.get(f"/agent/jobs/{req['job_id']}")

    res = client.get("/agent/attestations")
    assert res.status_code == 200
    body = res.get_json()
    assert len(body["items"]) >= 1
    assert body["items"][0]["event_type"] == "job_receipt"

def test_request_verify_signature_job_supported(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("ln-invoice", "lookup-id-verify"),
    )

    res = client.post(
        "/agent/request",
        json={
            "job_type": "verify_signature",
            "payload": {
                "message": "hello",
                "signature": "deadbeef",
                "pubkey": "02" + "11" * 32,
            },
        },
    )

    # this is the target behavior we want after implementation
    assert res.status_code == 201
    body = res.get_json()
    assert body["status"] == "invoice_pending"

    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=body["job_id"]).one()
        assert job.job_type == "verify_signature"

def test_verify_signature_job_receipt_contains_verification_result(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("ln-invoice", "lookup-id-verify-paid"),
    )
    monkeypatch.setattr("app.blueprints.agent.check_invoice_paid", lambda invoice_id: True)

    req = client.post(
        "/agent/request",
        json={
            "job_type": "verify_signature",
            "payload": {
                "message": "hello",
                "signature": "deadbeef",
                "pubkey": "02" + "11" * 32,
            },
        },
    ).get_json()

    res = client.get(f"/agent/jobs/{req['job_id']}")
    assert res.status_code == 200

    body = res.get_json()
    assert body["status"] == "done"

    receipt = body["receipt"]
    assert verify_message(_receipt_message(receipt), receipt["signature"], receipt["agent_pubkey"])

    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=req["job_id"]).one()
        assert job.result_json["job_type"] == "verify_signature"
        assert "valid" in job.result_json

def test_verify_signature_job_returns_valid_false_for_bad_signature(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("ln-invoice", "lookup-id-verify-false"),
    )
    monkeypatch.setattr("app.blueprints.agent.check_invoice_paid", lambda invoice_id: True)

    req = client.post(
        "/agent/request",
        json={
            "job_type": "verify_signature",
            "payload": {
                "message": "hello",
                "signature": "deadbeef",
                "pubkey": "02" + "11" * 32,
            },
        },
    ).get_json()

    res = client.get(f"/agent/jobs/{req['job_id']}")
    assert res.status_code == 200

    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=req["job_id"]).one()
        assert job.result_json["job_type"] == "verify_signature"
        assert job.result_json["valid"] is False

def test_capabilities_advertise_verify_signature_job_type(client):
    res = client.get("/agent/capabilities")
    assert res.status_code == 200
    body = res.get_json()

    assert "job_types" in body
    assert "verify_signature" in body["job_types"]

    spec = body["job_types"]["verify_signature"]
    assert spec["price_sats"] == 21
    assert "input_schema" in spec
    assert "output_schema" in spec
    assert spec["input_schema"]["message"] == "string"
    assert spec["input_schema"]["signature"] == "hex"
    assert spec["input_schema"]["pubkey"] == "compressed secp256k1 hex"

def test_verify_endpoint_returns_valid_true_for_existing_receipt(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("ln-invoice", "lookup-id-verify-endpoint"),
    )
    monkeypatch.setattr("app.blueprints.agent.check_invoice_paid", lambda invoice_id: True)

    req = client.post(
        "/agent/request",
        json={
            "job_type": "verify_signature",
            "payload": {
                "message": "hello",
                "signature": "deadbeef",
                "pubkey": "021111111111111111111111111111111111111111111111111111111111111111",
            },
        },
    ).get_json()

    # mint receipt first
    client.get(f"/agent/jobs/{req['job_id']}")

    res = client.get(f"/agent/verify/{req['job_id']}")
    assert res.status_code == 200

    body = res.get_json()
    assert body["job_id"] == req["job_id"]
    assert body["valid"] is True
    assert "agent_pubkey" in body
    assert "event_hash" in body
    assert "receipt" in body

def test_verify_endpoint_returns_404_for_missing_job(client):
    res = client.get("/agent/verify/00000000-0000-0000-0000-000000000000")
    assert res.status_code == 404
    body = res.get_json()
    assert body["error"] == "not_found"

def test_capabilities_advertise_verify_endpoint(client):
    res = client.get("/agent/capabilities")
    assert res.status_code == 200
    body = res.get_json()

    assert "endpoints" in body
    assert "verify" in body["endpoints"]
    assert body["endpoints"]["verify"] == "/agent/verify/<job_id>"

def test_covenant_decode_job_receipt_contains_decoded_result(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("ln-invoice", "lookup-id-covenant"),
    )
    monkeypatch.setattr("app.blueprints.agent.check_invoice_paid", lambda invoice_id: True)

    req = client.post(
        "/agent/request",
        json={
            "job_type": "covenant_decode",
            "payload": {
                "script_hex": "51b1"
            },
        },
    ).get_json()

    res = client.get(f"/agent/jobs/{req['job_id']}")
    assert res.status_code == 200

    body = res.get_json()
    assert body["status"] == "done"

    receipt = body["receipt"]
    assert verify_message(_receipt_message(receipt), receipt["signature"], receipt["agent_pubkey"])

    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=req["job_id"]).one()
        assert job.result_json["job_type"] == "covenant_decode"
        assert job.result_json["script_hex"] == "51b1"
        assert "decoded" in job.result_json
        assert "has_cltv" in job.result_json

def test_capabilities_advertise_covenant_decode_job_type(client):
    res = client.get("/agent/capabilities")
    assert res.status_code == 200
    body = res.get_json()

    assert "job_types" in body
    assert "covenant_decode" in body["job_types"]

    spec = body["job_types"]["covenant_decode"]
    assert spec["price_sats"] == 21
    assert "input_schema" in spec
    assert "output_schema" in spec
    assert spec["input_schema"]["script_hex"] == "hex"
    assert spec["output_schema"]["decoded"] == "string"
    assert spec["output_schema"]["has_cltv"] == "boolean"

def test_reputation_endpoint_returns_basic_agent_stats(client, monkeypatch):
    monkeypatch.setattr(
        "app.blueprints.agent.create_invoice",
        lambda amount_sats, memo, user_pubkey, expiry_seconds=3600: ("ln-invoice", "lookup-id-reputation"),
    )
    monkeypatch.setattr("app.blueprints.agent.check_invoice_paid", lambda invoice_id: True)

    req = client.post(
        "/agent/request",
        json={
            "job_type": "verify_signature",
            "payload": {
                "message": "hello",
                "signature": "deadbeef",
                "pubkey": "021111111111111111111111111111111111111111111111111111111111111111",
            },
        },
    ).get_json()

    client.get(f"/agent/jobs/{req['job_id']}")

    res = client.get("/agent/reputation")
    assert res.status_code == 200

    body = res.get_json()
    assert "agent_pubkey" in body
    assert "total_jobs" in body
    assert "completed_jobs" in body
    assert "job_types" in body
    assert "attestations_count" in body
    assert body["completed_jobs"] >= 1

def test_capabilities_advertise_reputation_endpoint(client):
    res = client.get("/agent/capabilities")
    assert res.status_code == 200
    body = res.get_json()

    assert "endpoints" in body
    assert "reputation" in body["endpoints"]
    assert body["endpoints"]["reputation"] == "/agent/reputation"
