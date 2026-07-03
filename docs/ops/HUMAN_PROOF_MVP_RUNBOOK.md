# Human Proof MVP Operator Runbook

## Purpose

This runbook gives a safe launch and validation checklist for the Human Proof MVP. It is documentation only and does not change runtime behavior, payment logic, Lightning logic, invoice creation, payment detection, job execution, receipt signing, receipt schema, requester proof cryptographic logic, requester proof storage behavior, routes, UI behavior, database models, migrations, or production deployment logic.

## Scope

Use this runbook to validate the public Human Proof demo and read-only verification surfaces around the existing Request -> Pay -> Result -> Verify flow:

- `/demo`
- `/agent/verify`
- `/agent/verify/<job_id>`
- `/agent/receipts/<job_id>.json`
- `/agent/attestations`
- `/agent/reputation`
- `/agent/chain/health`

## Non-goals

This runbook does not create jobs, create invoices, pay invoices, mutate database state, rotate secrets, expose credentials, or grant new operational authority. It is not a payment, Lightning, execution, receipt schema, requester proof, database, migration, routing, UI, or deployment change plan.

Human Proof MVP is not a token sale, not an investment, not KYC, not legal identity, not custody, not a promise of profit, not proof of moral trustworthiness, not a guarantee of future performance, not ownership of a network, not global consensus, not consent, and not authority.

## Launch prerequisites

- Confirm the release branch contains only the intended docs/tests changes for this PR.
- Confirm the stacked base includes the launch copy, receipt JSON download, public verifier page, requester proof guard, and runtime context links.
- Confirm the intended service name and host before running any service command.
- Confirm no command in this runbook prints secrets, private keys, cookies, session IDs, macaroons, RPC passwords, database URLs, seed phrases, or raw credentials.

## Single-worker requester proof storage requirement

Requester proof challenges currently live in process-local memory. The MVP launch must run with a single worker and session affinity, or must first replace the process-local memory challenge store with Redis or another shared TTL storage layer.

Do not run a multi-worker launch without session affinity while requester proof challenges remain in process-local memory. A multi-worker deployment can lose pending requester proof challenges when the browser returns to a different worker.

## Preflight checks

Run these read-only checks from the release checkout before staging or production rollout:

```bash
git status --short --branch
git rev-parse --abbrev-ref HEAD
git rev-parse --short HEAD
git diff --name-only
```

Check service state without printing environment files or secrets. Replace `ubid-staging` with the intended unit name only after confirming it:

```bash
systemctl status ubid-staging --no-pager
```

## Staging validation

After the staging checkout and restart, run the consolidated public-surface smoke script:

```bash
BASE_URL=https://staging.hodlxxi.com scripts/smoke_human_proof_public_surfaces.sh
```

The script is read-only. It performs only public `GET` checks, requires no credentials, does not read environment files, and does not create jobs, invoices, payments, or database mutations.

Use staging first. The following commands are safe read-only HTTP checks and do not create jobs, invoices, payments, or database mutations:

```bash
curl -fsS -o /dev/null -w '%{http_code}\n' https://staging.hodlxxi.com/demo
curl -fsS -o /dev/null -w '%{http_code}\n' https://staging.hodlxxi.com/agent/verify
curl -fsS -o /dev/null -w '%{http_code}\n' https://staging.hodlxxi.com/agent/capabilities
curl -fsS -o /dev/null -w '%{http_code}\n' https://staging.hodlxxi.com/agent/attestations
curl -fsS -o /dev/null -w '%{http_code}\n' https://staging.hodlxxi.com/agent/reputation
curl -fsS -o /dev/null -w '%{http_code}\n' https://staging.hodlxxi.com/agent/chain/health
curl -sS -o /tmp/hodlxxi-unknown-verify.json -w '%{http_code}\n' https://staging.hodlxxi.com/agent/verify/unknown-human-proof-mvp-job-id
```

Expected status codes are `200` for `/demo`, `/agent/verify`, `/agent/capabilities`, `/agent/attestations`, `/agent/reputation`, and `/agent/chain/health`. The unknown `/agent/verify/<job_id>` check should return `404` and must not create an invoice.

Pending or no-receipt behavior can be checked only with a previously created non-secret test `job_id`. Do not create a job for this check during read-only validation:

```bash
TEST_JOB_ID='previously-created-non-secret-job-id'
curl -sS -o /tmp/hodlxxi-existing-no-receipt.json -w '%{http_code}\n' "https://staging.hodlxxi.com/agent/verify/${TEST_JOB_ID}"
```

## Production rollout boundary

Production validation should repeat only the read-only checks already proven in staging. Stop before any command that would create jobs, create invoices, pay invoices, mutate state, rotate secrets, or change service configuration.

Confirm the current production ref, intended rollback ref, intended systemd unit, and operator approval before restarting anything. Restart only the intended service if a restart is part of the separately approved deployment procedure.

## Smoke tests

After the production rollout and restart, run the same consolidated public-surface smoke script against production:

```bash
BASE_URL=https://hodlxxi.com scripts/smoke_human_proof_public_surfaces.sh
```

This script is safe for production launch verification because it is read-only, uses only public `GET` requests, requires no credentials, and does not create jobs, invoices, payments, or database mutations.

Production smoke checks are read-only:

```bash
curl -fsS -o /dev/null -w '%{http_code}\n' https://hodlxxi.com/demo
curl -fsS -o /dev/null -w '%{http_code}\n' https://hodlxxi.com/agent/verify
curl -fsS -o /dev/null -w '%{http_code}\n' https://hodlxxi.com/agent/capabilities
curl -fsS -o /dev/null -w '%{http_code}\n' https://hodlxxi.com/agent/attestations
curl -fsS -o /dev/null -w '%{http_code}\n' https://hodlxxi.com/agent/reputation
curl -fsS -o /dev/null -w '%{http_code}\n' https://hodlxxi.com/agent/chain/health
curl -sS -o /tmp/hodlxxi-prod-unknown-verify.json -w '%{http_code}\n' https://hodlxxi.com/agent/verify/unknown-human-proof-mvp-job-id
```

Expected status codes are the same as staging: `200` for public read-only pages and runtime surfaces, `404` for an unknown verifier job.

## Manual browser validation

- Open `https://hodlxxi.com/demo` and confirm the Human Proof launch copy is present.
- Open `https://hodlxxi.com/agent/verify` and confirm the verifier page renders without requiring login or secrets.
- If you have a previously issued public-safe `job_id`, open `https://hodlxxi.com/agent/verify/<job_id>` and confirm the raw JSON verifier response is consistent with the documented receipt state.
- If that job has a receipt, download `https://hodlxxi.com/agent/receipts/<job_id>.json` and confirm it returns the signed receipt JSON.
- Inspect `https://hodlxxi.com/agent/attestations`, `https://hodlxxi.com/agent/reputation`, and `https://hodlxxi.com/agent/chain/health` as factual continuity surfaces only.

## Logs and failure triage

Use logs to diagnose failures without printing secrets. Prefer narrow time windows and the intended service only:

```bash
journalctl -u ubid-staging --since '30 minutes ago' --no-pager
```

Triage order:

1. Confirm the expected git ref is deployed.
2. Confirm the intended service is running.
3. Confirm `/demo` and `/agent/verify` return `200`.
4. Confirm `/agent/verify/<job_id>` returns `404` for an unknown job rather than creating state.
5. Confirm requester proof launch mode is single worker with session affinity, or backed by Redis or another shared TTL storage layer.

## Rollback

Rollback must be staged and explicit:

1. Identify the previous git ref and, if useful, create a rollback branch name before changing anything.
2. Preserve current logs for analysis before restarting or changing refs.
3. Stop before destructive actions and obtain operator confirmation for the exact ref and service.
4. Restore the previous ref only after confirmation.
5. Restart only the intended service, not unrelated units.
6. Verify HTTP smoke checks for `/demo`, `/agent/verify`, `/agent/capabilities`, `/agent/attestations`, `/agent/reputation`, `/agent/chain/health`, and an unknown `/agent/verify/<job_id>` returning `404`.
7. Keep saved logs and the failed ref for post-incident analysis.

Do not run destructive production commands from memory. Do not delete logs, receipts, attestations, databases, invoices, or local continuity state as part of this rollback checklist.

## Post-launch monitoring

- Monitor HTTP status for `/demo`, `/agent/verify`, `/agent/attestations`, `/agent/reputation`, and `/agent/chain/health`.
- Watch no-receipt and not-found verifier responses for unexpected changes.
- Watch logs for requester proof challenge misses that could indicate a missing single worker, missing session affinity, or missing Redis or another shared TTL storage layer.
- Track receipt and attestation continuity as factual runtime counters, not as a human trust score.

## Known limitations

- Requester proof challenge storage is process-local memory unless replaced by Redis or another shared TTL storage layer.
- Single worker and session affinity are launch requirements for the current requester proof store.
- `/agent/reputation` is factual runtime continuity, not a human trust score.
- `/agent/chain/health` is local append-only continuity, not global consensus.
- Receipt verification proves bounded runtime facts and does not independently prove external Lightning settlement without separate evidence.

## Security and claim boundaries

Do not publish secrets, private keys, cookies, session IDs, macaroons, RPC passwords, database URLs, seed phrases, raw credentials, invoice strings from live runs, or sensitive logs.

Human Proof MVP is not a token sale, not an investment, not KYC, not legal identity, not custody, not a promise of profit, not proof of moral trustworthiness, not a guarantee of future performance, not ownership of a network, not global consensus, not consent, and not authority.
