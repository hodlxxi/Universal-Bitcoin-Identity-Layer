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
