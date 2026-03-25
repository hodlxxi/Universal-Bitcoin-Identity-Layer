import hashlib
import os
import uuid

os.environ.setdefault("AGENT_PRIVKEY_HEX", "1" * 64)

from app.agent_signer import canonical_json_bytes, get_agent_pubkey_hex, sign_message, verify_message
from app.database import session_scope
from app.models import AgentJob


def _receipt_message(receipt: dict) -> bytes:
    payload = dict(receipt)
    payload.pop("signature", None)
    return canonical_json_bytes(payload)


def _signed_agent_message(payload: dict, *, msg_type: str = "job_proposal", message_id: str | None = None) -> dict:
    sender = get_agent_pubkey_hex()
    message = {
        "message_id": message_id or str(uuid.uuid4()),
        "conversation_id": "conv-1",
        "thread_id": "thread-1",
        "type": msg_type,
        "from_pubkey": sender,
        "to_pubkey": get_agent_pubkey_hex(),
        "created_at": "2026-01-01T00:00:00Z",
        "payload": payload,
    }
    message["signature"] = sign_message(canonical_json_bytes(message))
    return message


def test_capabilities_signature_verifies(client):
    res = client.get("/agent/capabilities")
    assert res.status_code == 200
    body = res.get_json()

    signature = body.pop("signature")
    assert verify_message(canonical_json_bytes(body), signature, body["agent_pubkey"])
    assert body["capability_schema"]["uri"] == "/agent/capabilities/schema"
    assert body["endpoints"]["skills"] == "/agent/skills"
    assert body["skills"]["count"] >= 1


def test_capabilities_schema_is_machine_readable(client):
    res = client.get("/agent/capabilities/schema")
    assert res.status_code == 200

    body = res.get_json()
    assert body["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert body["title"] == "HODLXXI Agent Capabilities"
    assert "required" in body
    assert "signature" in body["required"]
    assert "skills" in body["properties"]


def test_skills_endpoint_lists_public_skills(client):
    res = client.get("/agent/skills")
    assert res.status_code == 200

    body = res.get_json()
    assert body["count"] >= 1
    assert isinstance(body["items"], list)

    skill = body["items"][0]
    assert skill["skill_id"] == "hodlxxi-bitcoin-identity"
    assert skill["files"]["skill_markdown"].endswith("/SKILL.md")
    assert skill["install"]["raw_url"].startswith("https://raw.githubusercontent.com/")


def test_well_known_agent_document_matches_discovery_surfaces(client):
    res = client.get("/.well-known/agent.json")
    assert res.status_code == 200

    body = res.get_json()
    assert body["agent_pubkey"]
    assert body["capability_schema"]["uri"] == "/agent/capabilities/schema"
    assert body["discovery"]["skills"] == "/agent/skills"
    assert body["endpoints"]["well_known"] == "/.well-known/agent.json"
    assert body["skills"]["count"] >= 1
    assert body["trust_model"]["principle"].startswith("HODLXXI treats agent trust")
    assert body["trust_model"]["identity_model"]["public_key"]["status"] == "verified_runtime_surface"
    assert body["trust_model"]["identity_model"]["operator_binding"]["status"] == "declared_runtime_surface"
    assert body["trust_model"]["identity_model"]["time_locked_capital"]["status"] == "optional_not_verified"
    assert body["trust_model"]["assurance_boundaries"]["on_chain_proof_exposed"] is False


def test_agent_message_executes_job_proposal_and_returns_signed_result(client):
    msg = _signed_agent_message({"job_type": "ping", "payload": {"message": "hello"}})

    res = client.post("/agent/message", json=msg)
    assert res.status_code == 200

    body = res.get_json()
    assert body["type"] == "result"
    assert body["payload"]["job_type"] == "ping"
    assert body["payload"]["result"]["job_type"] == "ping"
    assert body["payload"]["agent_pubkey"] == body["from_pubkey"]
    assert body["payload"]["attestation_ref"]["endpoint"] == "/agent/attestations"

    signature = body.pop("signature")
    assert verify_message(canonical_json_bytes(body), signature, body["from_pubkey"])


def test_agent_message_rejects_bad_signature(client):
    msg = _signed_agent_message({"job_type": "ping", "payload": {"message": "hello"}})
    msg["signature"] = "00"

    res = client.post("/agent/message", json=msg)
    assert res.status_code == 400
    assert res.get_json()["error"] == "invalid_signature"


def test_agent_message_rejects_wrong_recipient(client):
    msg = _signed_agent_message({"job_type": "ping", "payload": {"message": "hello"}})
    msg["to_pubkey"] = "02" + "22" * 32
    msg["signature"] = sign_message(canonical_json_bytes({k: v for k, v in msg.items() if k != "signature"}))

    res = client.post("/agent/message", json=msg)
    assert res.status_code == 400
    assert res.get_json()["error"] == "wrong_recipient"


def test_agent_message_rejects_unsupported_message_type(client):
    msg = _signed_agent_message({"job_type": "ping", "payload": {"message": "hello"}}, msg_type="delegation")

    res = client.post("/agent/message", json=msg)
    assert res.status_code == 400
    assert res.get_json()["error"] == "unsupported_type"


def test_agent_message_rejects_invalid_payload_shape(client):
    msg = _signed_agent_message({"job_type": "ping", "payload": "not-an-object"})

    res = client.post("/agent/message", json=msg)
    assert res.status_code == 400
    assert res.get_json()["error"] == "invalid_payload"


def test_agent_message_duplicate_message_id_returns_cached_result_without_reexecution(client):
    msg = _signed_agent_message({"job_type": "ping", "payload": {"message": "hello"}})

    first = client.post("/agent/message", json=msg)
    assert first.status_code == 200
    first_body = first.get_json()

    second = client.post("/agent/message", json=msg)
    assert second.status_code == 200
    second_body = second.get_json()

    assert second_body == first_body


def test_agent_message_rejects_unsupported_job_type(client):
    msg = _signed_agent_message({"job_type": "does_not_exist", "payload": {}})

    res = client.post("/agent/message", json=msg)
    assert res.status_code == 400
    assert res.get_json()["error"] == "unsupported_job_type"


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
    assert (
        receipt["request_hash"]
        == hashlib.sha256(canonical_json_bytes({"job_type": "ping", "payload": {"message": "hello"}})).hexdigest()
    )
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
            "payload": {"script_hex": "51b1"},
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


def test_marketplace_listing_normalizes_discovery_and_skills(client):
    res = client.get("/agent/marketplace/listing")
    assert res.status_code == 200

    body = res.get_json()
    assert body["listing_version"] == "1.0"
    assert body["discovery"]["capabilities"] == "/agent/capabilities"
    assert body["discovery"]["skills"] == "/agent/skills"
    assert body["capability_schema"]["uri"] == "/agent/capabilities/schema"
    assert body["skills"]["count"] >= 1
    assert body["trust_model"]["identity_model"]["observable_behavior"]["status"] == "verified_runtime_surface"
    assert body["trust_model"]["assurance_boundaries"]["time_locked_capital_proof_exposed"] is False
