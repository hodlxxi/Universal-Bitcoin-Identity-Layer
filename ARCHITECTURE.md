# HODLXXI Architecture Overview

This file is the short top-level architecture overview.

For the canonical detailed architecture (runtime truth, drift map, and component detail), see:

- **[`docs/SYSTEM_ARCHITECTURE.md`](docs/SYSTEM_ARCHITECTURE.md)**

---

## Canonical documentation decision

- **Canonical detailed architecture doc:** `docs/SYSTEM_ARCHITECTURE.md`
- **Role of this file:** concise overview + navigation pointer

This reduces duplication and avoids conflicting “full architecture” narratives.

---

## Current architecture at a glance

- Runtime entrypoint is currently `wsgi.py` -> `app.app:app` (monolith-first runtime).
- `app/factory.py` is real and test-validated, but not the active WSGI entrypoint in this snapshot.
- Agent UBID paid-job surfaces, signed receipts, attestations, and reputation endpoints are implemented.
- PoF, OAuth/OIDC, LNURL, and covenant/descriptor features are present with mixed maturity (some confirmed, some partial).
- Bounded sovereignty Stage 1 is **partially represented** via paid/signed agent trust surfaces, but dedicated policy/status/actions/executor endpoints are not yet present as first-class routes.

---

## What this overview intentionally does not do

- It does **not** duplicate the full component-level architecture.
- It does **not** claim that planned migrations (full factory migration, complete bounded sovereignty Stage 1 routes, or full Lightning hardening) are complete.
