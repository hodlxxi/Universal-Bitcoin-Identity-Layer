# INTER_AGENT_DEMO

## 1. Overview

This demo proves the current hardened MVP inter-agent loop:

1. Agent A constructs and signs a `job_proposal` envelope.
2. Agent A sends it to Agent B `POST /agent/message`.
3. Agent B verifies signature + envelope, executes the request, and returns a signed `result` envelope.
4. Agent A verifies Agent B's result signature.

This demo does **not** prove full protocol completion. It does not cover negotiation state machines, discovery networks, escrow/dispute layers, or autonomous spending.

## 2. Topology

Minimal topology used in this demo:

- **Agent A**: local script identity (`tools/inter_agent_demo.py`) with its own secp256k1 private key.
- **Agent B**: running HODLXXI app instance exposing `/agent/message` (default `http://127.0.0.1:5000/agent/message`).

Demo identities/URLs:

- Agent B URL: `http://127.0.0.1:5000/agent/message`
- Agent B pubkey: from Agent B runtime env (`AGENT_PRIVKEY_HEX` -> derived pubkey)
- Agent A privkey: demo-only local key via `AGENT_A_PRIVKEY_HEX`

## 3. Prerequisites

- Python environment with project dependencies installed (includes `requests` and `cryptography`).
- A local HODLXXI app process running as Agent B.
- Agent B pubkey available (compressed hex).
- A demo private key for Agent A.

Example env:

```bash
export AGENT_A_PRIVKEY_HEX=1111111111111111111111111111111111111111111111111111111111111112
export AGENT_B_PUBKEY_HEX=<agent-b-compressed-pubkey-hex>
```

## 4. Demo Steps

1. Start Agent B (HODLXXI app) on localhost:

```bash
FLASK_APP=app.factory:create_app flask run --host 127.0.0.1 --port 5000
```

2. In another shell, run Agent A demo sender/verifier:

```bash
python tools/inter_agent_demo.py \
  --agent-b-url http://127.0.0.1:5000/agent/message \
  --agent-a-privkey "$AGENT_A_PRIVKEY_HEX" \
  --agent-b-pubkey "$AGENT_B_PUBKEY_HEX" \
  --message "demo ping"
```

3. Observe output:
   - printed signed request envelope (Agent A)
   - HTTP 200 response from Agent B
   - printed signed `result` envelope
   - final verification line: `OK: Agent B result signature verified by Agent A`

## 5. Example Message

Example request envelope sent by Agent A:

```json
{
  "message_id": "ec4e3f59-740d-4fd8-b7bf-42b718971f57",
  "conversation_id": "95de27ef-dfd4-43db-b58f-4f2666a3c84b",
  "thread_id": "thread-1",
  "type": "job_proposal",
  "from_pubkey": "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "to_pubkey": "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "created_at": "2026-03-24T00:00:00Z",
  "payload": {
    "job_type": "ping",
    "payload": {
      "message": "demo ping"
    }
  },
  "signature": "3045..."
}
```

## 6. Example Result

Example response envelope returned by Agent B:

```json
{
  "message_id": "9a3e3806-2f09-4e02-a704-4cdb4c4f0ca6",
  "conversation_id": "95de27ef-dfd4-43db-b58f-4f2666a3c84b",
  "thread_id": "thread-1",
  "type": "result",
  "from_pubkey": "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "to_pubkey": "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "created_at": "2026-03-24T00:00:01Z",
  "payload": {
    "job_type": "ping",
    "result": {
      "ok": true,
      "job_type": "ping",
      "message": "pong",
      "echo": {
        "message": "demo ping"
      }
    },
    "agent_pubkey": "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "attestation_ref": {
      "endpoint": "/agent/attestations",
      "note": "future-linkable; no receipt persisted by /agent/message MVP"
    }
  },
  "references": {
    "parent_message_id": "ec4e3f59-740d-4fd8-b7bf-42b718971f57"
  },
  "signature": "3046..."
}
```

## 7. Verification Step

The demo script verifies Agent B's result signature locally by:

1. removing the `signature` field,
2. canonicalizing JSON using sorted keys + compact separators,
3. verifying secp256k1 ECDSA signature against `from_pubkey`.

Successful verification prints:

```text
OK: Agent B result signature verified by Agent A
```

## 8. Current Limitations

- no negotiation yet
- no discovery yet
- no escrow/dispute yet
- no autonomous spending
- this is minimal inter-agent execution only
