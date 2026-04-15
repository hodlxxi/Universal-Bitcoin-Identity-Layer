# PRODUCT_OVERVIEW

## One-sentence description

HODLXXI is a Bitcoin-native identity and agent runtime that exposes human login surfaces plus machine-readable, paid agent execution with signed receipts.

## Who it is for

- Developers integrating Bitcoin-oriented identity/auth surfaces.
- Agent builders who need machine-readable capabilities + paid job execution.
- Operators who want verifiable runtime behavior (receipts, attestations, reputation) exposed publicly.

## What makes it different

- It combines web identity surfaces and agent protocol surfaces in one runtime.
- Agent jobs are payment-first (Lightning invoice flow) and receipt-signed.
- It includes covenant-oriented analysis capabilities (`covenant_decode`, `covenant_visualize`) with explicit heuristic boundaries.

## What is live now

- Public discovery + capabilities:
  - `/.well-known/agent.json`
  - `/agent/capabilities`
  - `/agent/capabilities/schema`
  - `/agent/skills`
- Paid job flow:
  - `/agent/request` → `/agent/jobs/<job_id>` → `/agent/verify/<job_id>`
- Public history surfaces:
  - `/agent/attestations`
  - `/agent/reputation`
- Human pages:
  - `/login`, `/home`, `/app`, `/playground`
- PoF surfaces:
  - `/pof`, `/pof/leaderboard`, `/api/pof/stats`

## How to verify it yourself

1. Fetch discovery:
   - `GET /.well-known/agent.json`
   - `GET /agent/capabilities`
2. Submit a small paid job (`ping` or `verify_signature`) to `POST /agent/request`.
3. Pay the returned invoice.
4. Poll `GET /agent/jobs/<job_id>` until `done`.
5. Validate signature status via `GET /agent/verify/<job_id>`.
6. Confirm receipt presence in `GET /agent/attestations`.
7. Check `GET /agent/reputation` for aggregate runtime history fields.

## What is still in transition

- The architecture is moving from monolith-heavy runtime (`app.app`) to blueprint/factory ownership.
- Core browser route ownership has shifted toward blueprints, but not all route logic is fully extracted.
- Some UI paths still delegate into `app.app` for legacy compatibility.
- Staging-confirmed extraction work should not be treated as universal production parity without deployment-specific checks.
