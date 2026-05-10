import json
import uuid

from app.agent_signer import canonical_json_bytes, get_agent_pubkey_hex, sign_message
from app.blueprints import agent as agent_module


def _signed_msg(payload: dict) -> dict:
    sender = get_agent_pubkey_hex()
    msg = {
        "message_id": str(uuid.uuid4()),
        "conversation_id": "conv-1",
        "thread_id": "thread-1",
        "type": "job_proposal",
        "from_pubkey": sender,
        "to_pubkey": sender,
        "created_at": "2026-01-01T00:00:00Z",
        "payload": payload,
    }
    msg["signature"] = sign_message(canonical_json_bytes(msg))
    return msg


def test_agent_request_empty_json_structured_error(client):
    res = client.post("/agent/request", json={})
    assert res.status_code == 400
    assert isinstance(res.get_json(), dict)
    assert "error" in res.get_json()


def test_agent_request_malformed_json_structured_error(client):
    res = client.post("/agent/request", data="{", content_type="application/json")
    assert res.status_code == 400
    assert res.get_json()["error"] == "invalid_json"


def test_agent_request_unknown_job_type_structured_error(client):
    res = client.post("/agent/request", json={"job_type": "unknown_job", "payload": {}})
    assert res.status_code == 400
    assert res.get_json()["error"] == "unsupported_job_type"


def test_agent_request_oversized_body_returns_non_500(client):
    oversized = "x" * (agent_module.AGENT_MAX_BODY_BYTES + 1)
    res = client.post("/agent/request", data=oversized, content_type="application/json")
    assert res.status_code in {400, 413}
    assert "error" in res.get_json()


def test_agent_request_oversized_string_field(client):
    res = client.post(
        "/agent/request",
        json={"job_type": "ping", "payload": {"message": "x" * (agent_module.AGENT_MAX_STRING_LENGTH + 1)}},
    )
    assert res.status_code == 400
    assert res.get_json()["error"] == "field_too_large"


def test_agent_request_payload_too_deep(client):
    nested = cur = {}
    for i in range(agent_module.AGENT_MAX_NESTED_DEPTH + 1):
        cur["x"] = {}
        cur = cur["x"]
    res = client.post("/agent/request", json={"job_type": "ping", "payload": nested})
    assert res.status_code == 400
    assert res.get_json()["error"] == "payload_too_deep"


def test_agent_message_malformed_json_structured_error(client):
    res = client.post("/agent/message", data="{", content_type="application/json")
    assert res.status_code == 400
    assert res.get_json()["error"] == "invalid_json"


def test_agent_message_missing_required_fields(client):
    res = client.post("/agent/message", json={"message_id": "a"})
    assert res.status_code == 400
    assert res.get_json()["error"] in {"invalid_envelope", "invalid_payload"}


def test_agent_message_oversized_body(client):
    payload = _signed_msg({"job_type": "ping", "payload": {"message": "ok"}})
    payload["padding"] = "x" * (agent_module.AGENT_MAX_BODY_BYTES + 1)
    res = client.post("/agent/message", data=json.dumps(payload), content_type="application/json")
    assert res.status_code == 413
    assert res.get_json()["error"] == "payload_too_large"


def test_agent_message_oversized_payload_field(client):
    msg = _signed_msg({"job_type": "ping", "payload": {"message": "x" * (agent_module.AGENT_MAX_STRING_LENGTH + 1)}})
    res = client.post("/agent/message", json=msg)
    assert res.status_code == 400
    assert res.get_json()["error"] == "field_too_large"
