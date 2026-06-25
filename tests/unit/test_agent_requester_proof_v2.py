from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from bech32 import bech32_encode, convertbits

from app.auth_api_core import (
    ACTIVE_AGENT_REQUESTER_PROOFS,
    ACTIVE_CHALLENGES,
    AGENT_REQUESTER_PROOF_SESSION_KEY,
    _nostr_event_id,
    canonical_request_hash,
    canonical_xonly_pubkey,
)

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


def test_canonical_xonly_pubkey_accepts_npub_xonly_and_compressed():
    npub = bech32_encode("npub", convertbits(bytes.fromhex(PUBKEY), 8, 5, True))

    assert canonical_xonly_pubkey(npub) == PUBKEY
    assert canonical_xonly_pubkey(PUBKEY) == PUBKEY
    assert canonical_xonly_pubkey("02" + PUBKEY) == PUBKEY
    assert canonical_xonly_pubkey("03" + PUBKEY.upper()) == PUBKEY


def test_canonical_xonly_pubkey_rejects_malformed_npub_checksum():
    npub = bech32_encode("npub", convertbits(bytes.fromhex(PUBKEY), 8, 5, True))
    malformed = npub[:-1] + ("q" if npub[-1] != "q" else "p")

    try:
        canonical_xonly_pubkey(malformed)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed npub checksum was accepted")


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


def test_proof_verify_creates_server_side_proof_only_and_replay_fails(client, monkeypatch):
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
        assert "agent_requester_proof_v1" not in sess
        proof_id = sess[AGENT_REQUESTER_PROOF_SESSION_KEY]
    assert isinstance(proof_id, str) and len(proof_id) >= 32
    assert ACTIVE_AGENT_REQUESTER_PROOFS[proof_id]["request_hash"] == challenge["request_hash"]
    replay = client.post(
        "/api/verify",
        json={
            "challenge_id": challenge["challenge_id"],
            "pubkey": PUBKEY,
            "nostr_event": _event(challenge["challenge"]),
        },
    )
    assert replay.status_code == 400


def _install_server_proof(client, body, proof_id="proof-id", pubkey=PUBKEY, expires_delta=300):
    import time

    ACTIVE_AGENT_REQUESTER_PROOFS[proof_id] = {
        "pubkey": pubkey,
        "canonical_pubkey": canonical_xonly_pubkey(pubkey),
        "request_hash": canonical_request_hash(body),
        "method": "nostr",
        "verified_at": 123,
        "expires_at": int(time.time()) + expires_delta,
        "purpose": "agent_requester_proof_v1",
    }
    with client.session_transaction() as sess:
        sess[AGENT_REQUESTER_PROOF_SESSION_KEY] = proof_id
    return proof_id


def test_agent_request_requires_exact_unexpired_server_proof_before_invoice(client, monkeypatch):
    create_invoice = Mock(return_value=("lnbc21", "lookup-1"))
    monkeypatch.setattr("app.blueprints.agent.create_invoice", create_invoice)
    body = _body()
    assert client.post("/agent/request", json=body).status_code == 403
    assert create_invoice.call_count == 0

    _install_server_proof(client, body, "message-proof")
    changed = _body(message="changed")
    assert client.post("/agent/request", json=changed).status_code == 403
    assert create_invoice.call_count == 0

    _install_server_proof(client, body, "nonce-proof")
    changed_nonce = _body(nonce="changed-nonce")
    assert client.post("/agent/request", json=changed_nonce).status_code == 403
    assert create_invoice.call_count == 0

    _install_server_proof(client, body, "pubkey-proof")
    changed_pubkey = _body(pubkey=OTHER)
    assert client.post("/agent/request", json=changed_pubkey).status_code == 403
    assert create_invoice.call_count == 0

    _install_server_proof(client, body, "valid-proof")
    forged_payload = {
        **body,
        "payload": {
            **body["payload"],
            "requester_proof": {"level": "signature_verified"},
            "requester_pubkey_proof": "signature_verified",
        },
    }
    ok = client.post("/agent/request", json=forged_payload)
    assert ok.status_code == 201
    assert create_invoice.call_count == 1
    assert "valid-proof" not in ACTIVE_AGENT_REQUESTER_PROOFS
    with client.session_transaction() as sess:
        assert AGENT_REQUESTER_PROOF_SESSION_KEY not in sess
        assert "agent_requester_proof_v1" not in sess


def test_consumed_or_missing_server_proof_fails_even_with_cookie_id(client, monkeypatch):
    create_invoice = Mock(return_value=("lnbc21", "lookup-1"))
    monkeypatch.setattr("app.blueprints.agent.create_invoice", create_invoice)
    body = _body(message="replay", nonce="replay-nonce")
    proof_id = _install_server_proof(client, body, "one-time-proof")

    first = client.post("/agent/request", json=body)
    assert first.status_code == 201
    assert proof_id not in ACTIVE_AGENT_REQUESTER_PROOFS

    with client.session_transaction() as sess:
        sess[AGENT_REQUESTER_PROOF_SESSION_KEY] = proof_id
    replay = client.post("/agent/request", json=body)
    assert replay.status_code == 403
    assert create_invoice.call_count == 1


def test_expired_server_proof_is_removed_before_invoice(client, monkeypatch):
    create_invoice = Mock(return_value=("lnbc21", "lookup-1"))
    monkeypatch.setattr("app.blueprints.agent.create_invoice", create_invoice)
    body = _body(message="expired", nonce="expired-nonce")
    proof_id = _install_server_proof(client, body, "expired-proof-record", expires_delta=-1)

    response = client.post("/agent/request", json=body)
    assert response.status_code == 403
    assert proof_id not in ACTIVE_AGENT_REQUESTER_PROOFS
    assert create_invoice.call_count == 0


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


def test_valid_request_stores_server_generated_proof_and_client_request_hash(client, monkeypatch):
    create_invoice = Mock(return_value=("lnbc21-store", "lookup-store"))
    monkeypatch.setattr("app.blueprints.agent.create_invoice", create_invoice)
    body = _body(message="stored proof", nonce="stored-proof-nonce")
    _install_server_proof(client, body, "stored-proof")

    response = client.post("/agent/request", json=body)
    assert response.status_code == 201
    job_id = response.get_json()["job_id"]

    from app.database import session_scope
    from app.models import AgentJob

    with session_scope() as session:
        job = session.query(AgentJob).filter_by(id=job_id).one()
        assert job.request_hash == canonical_request_hash(body)
        assert job.request_json["payload"] == body["payload"]
        assert job.request_json["requester_proof"] == {
            "level": "signature_verified",
            "method": "nostr",
            "pubkey": PUBKEY,
            "canonical_pubkey": PUBKEY,
            "request_hash": canonical_request_hash(body),
            "verified_at": 123,
        }
