# Public Agent Contract Smoke

`scripts/smoke_public_agent_contract.sh` is a public-only production smoke test for the HODLXXI public agent contract. It is designed for safe ops checks against `https://hodlxxi.com` or another explicitly supplied `BASE` URL.

## Run

```bash
BASE=https://hodlxxi.com bash scripts/smoke_public_agent_contract.sh
```

The script defaults to `https://hodlxxi.com` if `BASE` is not set.

## Safety profile

- Public-only and secret-free: it requires only `curl` and `jq`.
- It does not require macaroons, private keys, seed phrases, env files, xprv material, node credentials, or service credentials.
- It creates one unpaid `ping` job through `/agent/request` and does not pay the invoice.
- It redacts invoice-sensitive data by printing only safe summary fields: `job_id`, `status`, whether `payment_hash` is present, and whether `invoice` is present.
- It must not print invoice strings and must not auto-pay invoices.
- It does not restart services and does not modify runtime state beyond creating the single unpaid job request.

## What it checks

The smoke verifies HTTP 200 responses from these public surfaces:

- `/login`
- `/.well-known/agent.json`
- `/agent/capabilities`
- `/agent/discovery`
- `/.well-known/hodlxxi-operator.json`
- `/agent/reputation`
- `/agent/attestations`
- `/agent/chain/health`

It validates the E923 operator continuity declaration, including:

- `schema=hodlxxi.operator_continuity.v1`
- `operator_id=E923`
- the expected E923 `operator_pubkey`
- the expected HODLXXI `agent_pubkey`
- `key_status=active`
- `covenant.status=declared_unfunded`
- `covenant.verified_on_chain=false`
- `covenant.time_locked_capital_proof_exposed=false`

It also checks that operator continuity is advertised from `/.well-known/agent.json`, `/agent/capabilities`, and `/agent/discovery`, then runs `scripts/verify_operator_continuity.sh` with the same `BASE`.

For commerce verifier semantics, it safely creates an unpaid `ping` job and confirms:

- `/agent/jobs/<job_id>` returns HTTP 200 with `status=invoice_pending`, `result=null`, and `receipt=null`.
- `/agent/verify/<job_id>` returns HTTP 409 with `status=no_receipt`, `valid=false`, `verification=unavailable`, `job_status=invoice_pending`, `receipt=null`, and `reason=receipt_not_issued`.
- `/agent/verify/00000000-0000-0000-0000-000000000000` returns HTTP 404 with `error=not_found` and `verification=unavailable`.

## Success meaning

A successful run ends with:

```text
PASS: public agent contract smoke succeeded
```

That means the public agent surfaces, E923 operator continuity advertisements, and unpaid verifier semantics matched the current public contract at the time of the run.

## What this does not prove

This smoke test is intentionally narrow. It does not prove:

- locked capital
- paid job completion
- private key custody beyond public declarations
- legal identity
