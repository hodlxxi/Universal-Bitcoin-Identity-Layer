# HODLXXI Release Gate: Production Smoke (Manual Only)

This document promotes the existing green **v2.2 production smoke** flow into a release gate safety net.

## Scope and intent

- Keep runtime canonical: **factory-first** `wsgi:app`.
- Preserve existing green production behavior (no runtime changes).
- Keep smoke against live environments as a **manual operation**.
- Never run production smoke automatically from CI.

## Prerequisites

- `bash`, `curl`, and `jq` installed.
- Operator confirms maintenance/release window.
- Optional: VPN / bastion / approved operator host.

## Commands

### Staging manual smoke

```bash
BASE_URL=https://staging.hodlxxi.com bash scripts/hodlxxi_production_smoke_v2_2.sh
```

### Production manual smoke

```bash
BASE_URL=https://hodlxxi.com bash scripts/hodlxxi_production_smoke_v2_2.sh
```

## Safety rules

- Do not export or log secrets while running smoke.
- The script performs request/receipt checks only and does **not** pay invoices.
- Treat any `FAIL>0` as a release blocker.
- Treat `WARN>0` as a review-required signal before release.

## Expected critical surfaces

- `/login`
- `/home`
- `/app`
- `/account`
- `/.well-known/agent.json`
- `/agent/capabilities`
- `/agent/capabilities/schema`
- `/agent/reputation`
- `/agent/attestations`
- `/agent/chain/health`
- `/agent/skills`
- `/agent/request`
- `/agent/jobs/<id>`
- `/agent/verify/<id>`
- `/api/public/status`

## Release-gate decision

- **Pass:** `FAIL=0` and no unexpected regressions.
- **Hold:** any `FAIL>0`, route ownership regressions, or missing critical surface.
- Record PASS/WARN/FAIL summary in release notes with UTC timestamp.
