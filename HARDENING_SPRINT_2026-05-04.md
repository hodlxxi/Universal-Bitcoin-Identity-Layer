# HODLXXI Hardening Sprint Report — 2026-05-04

> **Status:** Historical checkpoint. This document records deployment, cleanup, planning, or protocol state at the time it was written. Do not treat it as the current runbook or current implementation truth unless it is explicitly linked from `docs/DOCUMENTATION_MAP.md` or `docs/READINESS_EVALUATION.md`.


## Production status

- Production health: ready
- Agent public runtime surfaces: healthy
- Agent chain health: chain_ok=true
- Production smoke v2.2: PASS=96 / WARN=0 / FAIL=0
- Production smoke v2.3 runtime: PASS=52 / WARN=0 / FAIL=0
- Runtime route ownership proof: ROUTE_COUNT=94

## Commits

- 695c8a6 Redact rate limiter storage URI in logs
- ba8d4b0 Redact secrets in diagnostics output
- 95d28fe Load DB env safely in backup scripts
- a9e671c Remove rescanblockchain from legacy RPC allowlist
- 3448a29 Use constant-time client secret compare in introspection

## Remediations completed

- Redis credential log redaction.
- Diagnostics secret redaction.
- Safe DB env loading in backup/restore scripts.
- Removed `rescanblockchain` from legacy `/rpc/<cmd>` allowlist.
- Constant-time OAuth introspection client secret comparison.

## Final evidence

- `/health/ready`: ready
- `/agent/reputation`: 200
- `/agent/attestations`: 200
- `/agent/chain/health`: 200
- `/agent/capabilities`: 200
- `/.well-known/agent.json`: 200
- `/.well-known/openid-configuration`: 200
- Smoke v2.2: PASS=96 / WARN=0 / FAIL=0
- Smoke v2.3: PASS=52 / WARN=0 / FAIL=0

## Remaining follow-up items

- Rotate Redis password, FLASK_SECRET_KEY, and Bitcoin RPC password with planned impact.
- Consolidate systemd secrets into a root-only env file.
- Investigate local route ownership proof Redis auth mismatch.
- Add dependency lockfile / hash-pinned install.
- Track Eventlet deprecation as tech debt.
