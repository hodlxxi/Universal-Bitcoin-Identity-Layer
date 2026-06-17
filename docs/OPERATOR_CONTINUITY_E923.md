# HODLXXI Operator Continuity: E923

This document records the public continuity packet for the HODLXXI runtime operator identity `E923`.

## Current state

- HODLXXI runtime is live at `https://hodlxxi.com`.
- `E923` is the declared operator identity.
- Operator public key, the stable identity anchor: `023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923`.
- Agent public key, the runtime agent key: `02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92`.
- The operator-agent covenant is declared but currently `declared_unfunded` and not on-chain verified.

## Target state

Public continuity is verified through the runtime endpoint, this repository document, public keys, smoke tests, and later possibly a small funded covenant UTXO after review.

## Explicit non-claims

- This does not prove legal identity.
- This does not prove locked capital yet.
- This does not replace code review, references, or security review.

## Funding policy

Funding a covenant before review would be premature. If the project is considered useful and safe enough to continue, a small public operator-agent covenant UTXO may be funded later.

Future funded proof should publish only public data: `txid`, `vout`, `amount_sats`, `address`, `witness_script_hash`, timelocks, branch roles, and verification commands.

Never publish private keys, seeds, wallet labels, macaroons, xprv, env values, or node secrets. This continuity packet intentionally contains no private keys and no secrets.

## Rotation policy

Normal rotation should be signed by the previous key. Emergency rotation must be explicitly documented as compromised or lost key recovery. Consumers should treat unannounced key changes as a high-risk signal.

## Verification commands

```bash
BASE="https://hodlxxi.com"
curl -fsS "$BASE/.well-known/hodlxxi-operator.json" | jq .
curl -fsS "$BASE/.well-known/agent.json" | jq .
curl -fsS "$BASE/agent/capabilities" | jq .
curl -fsS "$BASE/api/public/status" | jq .
```

Compare `operator_pubkey` and `agent_pubkey` across public surfaces. The local helper script is `scripts/verify_operator_continuity.sh`.
