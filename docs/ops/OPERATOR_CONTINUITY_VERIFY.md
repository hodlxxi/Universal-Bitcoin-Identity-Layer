# Operator Continuity Verification

Use these copy-pasteable commands to review the public HODLXXI operator continuity surfaces.

```bash
BASE="https://hodlxxi.com"
curl -fsS "$BASE/.well-known/hodlxxi-operator.json" | jq .
curl -fsS "$BASE/.well-known/agent.json" | jq .
curl -fsS "$BASE/agent/capabilities" | jq .
curl -fsS "$BASE/agent/discovery" | jq .
curl -fsS "$BASE/api/public/status" | jq .
```

## Expected output

- HTTP 200 for each endpoint.
- `content-type` is `application/json`.
- `operator_pubkey` equals `023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923` in the operator continuity document.
- `agent_pubkey` equals `02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92` across operator continuity, agent.json, capabilities, and discovery where present.
- `covenant.status` is `declared_unfunded`.
- `covenant.verified_on_chain` is `false`.

The packet is a continuity declaration only. It is not proof of locked capital.
