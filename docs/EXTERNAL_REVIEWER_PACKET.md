# HODLXXI External Reviewer Packet

## Purpose

This packet is a conservative review path for external humans and systems evaluating the current HODLXXI runtime.

It is intended for:

- external developers
- technical reviewers
- agent marketplace reviewers
- grant/investor reviewers
- security-minded operators

It summarizes what can be verified today without asking the reviewer to trust private claims.

## Current short description

HODLXXI is a public-key identity and paid-agent runtime.

External reviewers can verify:

- public agent discovery metadata
- E923 operator continuity declaration
- OAuth/OIDC Sign in with HODLXXI metadata
- public readiness self-scan
- unpaid verifier semantics
- a real paid receipt evidence path
- signed receipt/attestation linkage
- public reputation/chain-health surfaces

These are intentionally narrow runtime claims. They should not be read as legal, financial, custody, certification, or universal compatibility claims.

## Fastest review path

1. Inspect public agent metadata.
2. Run public agent contract smoke.
3. Verify E923 operator continuity.
4. Verify documented paid receipt evidence.
5. Inspect Sign in with HODLXXI metadata.
6. Read non-claims before interpreting evidence.

## Public URLs

```text
https://hodlxxi.com/.well-known/agent.json
https://hodlxxi.com/agent/capabilities
https://hodlxxi.com/agent/discovery
https://hodlxxi.com/.well-known/hodlxxi-operator.json
https://hodlxxi.com/agent/readiness/self-scan
https://hodlxxi.com/.well-known/openid-configuration
https://hodlxxi.com/.well-known/oauth-authorization-server
https://hodlxxi.com/.well-known/oauth-protected-resource
https://hodlxxi.com/oauth/jwks.json
https://hodlxxi.com/agent/reputation
https://hodlxxi.com/agent/attestations
https://hodlxxi.com/agent/chain/health
```

## Copy-paste verification commands

### Public agent contract smoke

```bash
BASE=https://hodlxxi.com bash scripts/smoke_public_agent_contract.sh
```

This checks the public metadata smoke path, an unpaid job lifecycle, `no_receipt` verifier semantics, and missing-job verifier semantics. It requires no secrets.

### Operator continuity

```bash
BASE=https://hodlxxi.com bash scripts/verify_operator_continuity.sh
```

Expected identities:

- operator label: `E923`
- operator pubkey: `023d34633c5c1b72050fede84dcc396b5ea969fa40daa2eabf24cc339959f9e923`
- agent pubkey: `02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92`

### Paid receipt evidence verifier

```bash
BASE=https://hodlxxi.com \
JOB_ID=1013ca86-f09e-40d3-b6ea-862620890b36 \
bash scripts/verify_paid_receipt_evidence.sh
```

Expected result:

```text
PASS: paid receipt evidence verified
```

This verifies an already-completed paid job through public endpoints only. It does not create a job, pay an invoice, require secrets, or print invoice strings.

### Sign in with HODLXXI metadata

```bash
BASE=https://hodlxxi.com

curl -sS "$BASE/.well-known/openid-configuration" | jq '{
  issuer,
  authorization_endpoint,
  token_endpoint,
  jwks_uri,
  response_types_supported,
  grant_types_supported,
  scopes_supported,
  code_challenge_methods_supported
}'

curl -sS "$BASE/.well-known/oauth-authorization-server" | jq '{
  issuer,
  authorization_endpoint,
  token_endpoint,
  jwks_uri,
  grant_types_supported,
  scopes_supported,
  code_challenge_methods_supported
}'

curl -sS "$BASE/.well-known/oauth-protected-resource" | jq '{
  resource,
  authorization_servers,
  jwks_uri,
  bearer_methods_supported,
  scopes_supported
}'

curl -sS "$BASE/oauth/jwks.json" | jq '{
  key_count:(.keys | length),
  keys:[.keys[]? | {kty, use, kid, alg}]
}'
```

## What the evidence currently supports

Current evidence supports:

- the public server responds on the documented agent/OAuth/readiness endpoints;
- HODLXXI publishes machine-readable agent discovery/capabilities metadata;
- HODLXXI publishes E923 operator continuity metadata;
- a real paid `ping` job has a public receipt and matching attestation evidence;
- verifier endpoint returns `verified` and `valid=true` for the documented paid job;
- attestation and chain-health surfaces expose observable history;
- OAuth/OIDC metadata supports a Sign in with HODLXXI integration path using Authorization Code and PKCE S256.

## What this does not prove

This review packet explicitly:

- does not prove legal identity;
- does not prove KYC;
- does not prove custody of funds;
- does not prove locked capital;
- does not prove all future paid jobs will succeed;
- does not prove global consensus or external anchoring;
- does not prove full OIDC certification;
- does not prove universal wallet compatibility;
- does not prove Nostr private DM production readiness;
- does not replace application-specific risk checks;
- does not require or reveal private keys, wallet access tokens, wallet recovery phrases, BOLT11 invoice strings, or secrets.

## Reviewer decision table

| Question                                          | Current review path                                                           |
| ------------------------------------------------- | ----------------------------------------------------------------------------- |
| Is there public agent metadata?                   | `/.well-known/agent.json`, `/agent/capabilities`, public smoke                |
| Is the operator identity declared consistently?   | `/.well-known/hodlxxi-operator.json`, `scripts/verify_operator_continuity.sh` |
| Is there public readiness metadata?               | `/agent/readiness/self-scan`, `docs/READINESS_EVALUATION.md`                  |
| Can paid receipt evidence be checked externally?  | `scripts/verify_paid_receipt_evidence.sh`                                     |
| Can a third-party app integrate login?            | `docs/OIDC_INTEGRATION.md`, OIDC metadata                                     |
| Does this prove legal/KYC/custody/locked capital? | No                                                                            |

## Related documents

- [`docs/READINESS_EVALUATION.md`](READINESS_EVALUATION.md)
- [`docs/OIDC_INTEGRATION.md`](OIDC_INTEGRATION.md)
- [`docs/RECEIPT_VERIFICATION.md`](RECEIPT_VERIFICATION.md)
- [`docs/AGENT_RECEIPT_QUICKSTART.md`](AGENT_RECEIPT_QUICKSTART.md)
- [`docs/AGENT_RECEIPT_V1.md`](AGENT_RECEIPT_V1.md)
- [`docs/OPERATOR_CONTINUITY_E923.md`](OPERATOR_CONTINUITY_E923.md)
- [`docs/ops/PUBLIC_AGENT_CONTRACT_SMOKE.md`](ops/PUBLIC_AGENT_CONTRACT_SMOKE.md)
- [`docs/ops/PAID_EXECUTION_RECEIPT_SMOKE.md`](ops/PAID_EXECUTION_RECEIPT_SMOKE.md)
- [`docs/ops/OPERATOR_CONTINUITY_VERIFY.md`](ops/OPERATOR_CONTINUITY_VERIFY.md)
- [`scripts/smoke_public_agent_contract.sh`](../scripts/smoke_public_agent_contract.sh)
- [`scripts/verify_operator_continuity.sh`](../scripts/verify_operator_continuity.sh)
- [`scripts/verify_paid_receipt_evidence.sh`](../scripts/verify_paid_receipt_evidence.sh)
