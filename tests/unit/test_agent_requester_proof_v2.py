from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from app.auth_api_core import ACTIVE_CHALLENGES, _nostr_event_id, canonical_request_hash, canonical_xonly_pubkey

PUBKEY = "a" * 64
OTHER = "b" * 64


def _body(pubkey=PUBKEY, message="hello", nonce="nonce-1"):
    return {
        "job_type": "ping",
        "payload": {"message": message, "requester_pubkey": pubkey, "demo": "human_proof_v2", "demo_nonce": nonce},
    }


def _event(challenge, pubkey=PUBKEY, sig="c" * 128):
    event = {
        "pubkey": pubkey,
        "created_at": 1_778_350_000,
        "kind": 22242,
        "tags": [["challenge", challenge], ["url", "http://localhost/api/verify"]],
        "content": "HODLXXI agent requester proof",
        "sig": sig,
    }
    event["id"] = _nostr_event_id(event)
    return event


def test_canonical_xonly_pubkey_accepts_xonly_and_compressed():
    assert canonical_xonly_pubkey(PUBKEY) == PUBKEY
    assert canonical_xonly_pubkey("02" + PUBKEY) == PUBKEY
    assert canonical_xonly_pubkey("03" + PUBKEY.upper()) == PUBKEY


def test_proof_challenge_contract_and_login_unchanged(client):
    login = client.post("/api/challenge", json={"pubkey": PUBKEY, "method": "nostr"})
    assert login.status_code == 200
    login_body = login.get_json()
    assert login_body["challenge"].startswith("HODLXXI:login:")
    assert "request_hash" not in login_body

    proof = client.post(
        "/api/challenge",
        json={"pubkey": PUBKEY, "method": "nostr", "purpose": "agent_requester_proof_v1", "request_body": _body()},
    )
    assert proof.status_code == 200
    proof_body = proof.get_json()
    assert proof_body["expires_in"] <= 300
    assert proof_body["request_hash"] == canonical_request_hash(_body())
    assert proof_body["request_hash"] in proof_body["challenge"]
    assert proof_body["challenge"].startswith("HODLXXI:agent-request:")


def test_proof_challenge_rejects_bad_inputs(client):
    cases = [
        ({"pubkey": PUBKEY, "method": "nostr", "purpose": "agent_requester_proof_v1"}, "request_body_required"),
        (
            {"pubkey": PUBKEY, "method": "nostr", "purpose": "agent_requester_proof_v1", "request_body": []},
            "request_body_required",
        ),
        (
            {
                "pubkey": PUBKEY,
                "method": "nostr",
                "purpose": "agent_requester_proof_v1",
                "request_body": {**_body(), "job_type": "other"},
            },
            "unsupported_job_type",
        ),
        (
            {
                "pubkey": PUBKEY,
                "method": "nostr",
                "purpose": "agent_requester_proof_v1",
                "request_body": {"job_type": "ping", "payload": {**_body()["payload"], "demo": "human_proof_v1"}},
            },
            "unsupported_demo_version",
        ),
        (
            {"pubkey": PUBKEY, "method": "nostr", "purpose": "agent_requester_proof_v1", "request_body": _body("bad")},
            "invalid_requester_pubkey",
        ),
        (
            {"pubkey": PUBKEY, "method": "nostr", "purpose": "agent_requester_proof_v1", "request_body": _body(OTHER)},
            "requester_pubkey_mismatch",
        ),
    ]
    for payload, error in cases:
        response = client.post("/api/challenge", json=payload)
        assert response.status_code == 400
        assert response.get_json()["error"] == error


def test_proof_verify_is_proof_only_and_replay_fails(client, monkeypatch):
    import app.auth_api_core as auth_core

    monkeypatch.setattr(auth_core, "verify_nostr_login_event", lambda *a, **k: (True, None))
    response = client.post(
        "/api/challenge",
        json={"pubkey": PUBKEY, "method": "nostr", "purpose": "agent_requester_proof_v1", "request_body": _body()},
    )
    challenge = response.get_json()
    with monkeypatch.context() as m:
        import app.app as legacy

        finish = Mock(side_effect=legacy._finish_login)
        m.setattr(legacy, "_finish_login", finish)
        verified = client.post(
            "/api/verify",
            json={
                "challenge_id": challenge["challenge_id"],
                "pubkey": PUBKEY,
                "nostr_event": _event(challenge["challenge"]),
            },
        )
        assert verified.status_code == 200
        data = verified.get_json()
        assert data["purpose"] == "agent_requester_proof_v1"
        assert "access_token" not in data
        assert finish.call_count == 0
    with client.session_transaction() as sess:
        assert "logged_in_pubkey" not in sess
        assert sess["agent_requester_proof_v1"]["request_hash"] == challenge["request_hash"]
    replay = client.post(
        "/api/verify",
        json={
            "challenge_id": challenge["challenge_id"],
            "pubkey": PUBKEY,
            "nostr_event": _event(challenge["challenge"]),
        },
    )
    assert replay.status_code == 400


def test_agent_request_requires_exact_unexpired_proof_before_invoice(client, monkeypatch):
    create_invoice = Mock(return_value=("lnbc21", "lookup-1"))
    monkeypatch.setattr("app.blueprints.agent.create_invoice", create_invoice)
    body = _body()
    assert client.post("/agent/request", json=body).status_code == 403
    assert create_invoice.call_count == 0

    with client.session_transaction() as sess:
        sess["agent_requester_proof_v1"] = {
            "pubkey": PUBKEY,
            "canonical_pubkey": PUBKEY,
            "request_hash": canonical_request_hash(body),
            "method": "nostr",
            "verified_at": 123,
            "expires_at": int(__import__("time").time()) + 300,
            "purpose": "agent_requester_proof_v1",
        }
    changed = _body(message="changed")
    assert client.post("/agent/request", json=changed).status_code == 403
    assert create_invoice.call_count == 0

    with client.session_transaction() as sess:
        sess["agent_requester_proof_v1"] = {
            "pubkey": PUBKEY,
            "canonical_pubkey": PUBKEY,
            "request_hash": canonical_request_hash(body),
            "method": "nostr",
            "verified_at": 123,
            "expires_at": int(__import__("time").time()) + 300,
            "purpose": "agent_requester_proof_v1",
        }
    ok = client.post("/agent/request", json={**body, "requester_proof": {"level": "signature_verified"}})
    assert ok.status_code == 201
    assert create_invoice.call_count == 1
    with client.session_transaction() as sess:
        assert "agent_requester_proof_v1" not in sess


def test_expired_challenge_fails(client):
    cid = "expired-proof"
    ACTIVE_CHALLENGES[cid] = {
        "pubkey": PUBKEY,
        "canonical_pubkey": PUBKEY,
        "requester_pubkey": PUBKEY,
        "request_hash": canonical_request_hash(_body()),
        "purpose": "agent_requester_proof_v1",
        "challenge": "HODLXXI:agent-request:1:n:" + canonical_request_hash(_body()),
        "created": datetime.now(timezone.utc) - timedelta(minutes=10),
        "expires": datetime.now(timezone.utc) - timedelta(seconds=1),
        "method": "nostr",
    }
    res = client.post("/api/verify", json={"challenge_id": cid, "pubkey": PUBKEY, "nostr_event": _event("x")})
    assert res.status_code == 400
