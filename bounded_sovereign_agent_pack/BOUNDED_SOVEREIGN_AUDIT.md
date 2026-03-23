# Bounded Sovereign Audit

## Purpose

This audit checks whether a future "bounded sovereign agent" implementation can be honestly layered onto the current repository without overstating runtime reality.

## Current Repo Truth

### Runtime entrypoint reality
- Production WSGI still points at the legacy monolith in `wsgi.py`, which imports `app.app:app` directly.
- A newer factory exists in `app/factory.py`, but it is not the canonical WSGI entrypoint yet.

### Agent routes that already exist
- `app/blueprints/agent.py` exposes discovery, request, job, verification, attestation, reputation, chain-health, marketplace, and one dev-only `mark_paid` endpoint.
- Supported public job types are currently `ping`, `verify_signature`, and `covenant_decode`.

### Signing surfaces that already exist
- `app/agent_signer.py` signs capability payloads and receipts with a single secp256k1 private key loaded from environment or file.
- Receipt verification is exposed by `GET /agent/verify/<job_id>`.

### Lightning payment flow that already exists
- `app/payments/ln.py` creates invoices through `lnd_rest`, `lnd_cli`, or stub mode, and checks settlement state.
- `POST /agent/request` always creates an invoice first and only issues a receipt after settlement is observed.
- OAuth client PAYG top-ups are separate and live in `app/billing_clients.py` and `app/blueprints/billing_agent.py`.

### Receipt, attestation, and history model that already exists
- `AgentJob` stores request JSON, request hash, sats price, invoice data, payment hash, status, and optional result hash.
- `AgentEvent` stores signed receipt JSON, event hash, previous event hash, and timestamp.
- `/agent/attestations`, `/agent/reputation`, and `/agent/chain/health` already expose public history summaries.

### Admin and operator control points that already exist
- The only explicit operator override in the current agent blueprint is the dev-only `POST /agent/jobs/<job_id>/dev/mark_paid` endpoint, guarded by `DEV_AGENT_ADMIN_TOKEN` and disabled in production-like mode.
- Agent signing authority is fully coupled to the operator-managed private key and runtime state.
- No current route delegates root, shell, wallet-send, or unrestricted Bitcoin Core signing authority to the agent.

## Gaps Versus A Bounded Sovereignty Claim

### What is partially present
- Public cryptographic identity.
- Signed job receipts.
- Append-only receipt chaining via `prev_event_hash`.
- Lightning metering before result issuance.
- Public proof surfaces for job history.

### What is missing
- A machine-readable policy manifest that constrains what the agent is allowed to do.
- A spending policy with hard per-action and per-period limits.
- A first-class action log that distinguishes operator actions from agent-requested actions.
- Public proof that autonomy claims match runtime policy.
- Operator-approved execution boundaries for any wallet-touching or admin-touching behavior.

### What must not be claimed yet
- Fully autonomous operation.
- Full decentralization.
- Trustless execution.
- Independence from the operator.
- Unrestricted wallet authority.
- Unrestricted administrative authority.

## Boundaries For This Pack

### Safe claim language
Use: bounded operational sovereignty, policy-bounded authority, limited operational budget, signed action history, and publicly verifiable autonomy claims.

### Unsafe claim language
Do not use overclaiming autonomy language that suggests complete decentralization, no-trust-required execution, or operator separation beyond what the runtime actually enforces.

## Minimal Conclusion

The repo already contains enough identity, billing, signing, and attestation infrastructure to justify a **documentation-first bounded sovereignty design**. It does **not** yet contain runtime policy enforcement for sovereign execution. The right next step is a small, auditable policy-and-history layer added on top of existing agent surfaces, not a broad autonomy rollout.
