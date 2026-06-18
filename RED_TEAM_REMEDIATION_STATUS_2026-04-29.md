# Red Team Remediation Status — 2026-04-29

> **Status:** Historical checkpoint. This document records deployment, cleanup, planning, or protocol state at the time it was written. Do not treat it as the current runbook or current implementation truth unless it is explicitly linked from `docs/DOCUMENTATION_MAP.md` or `docs/READINESS_EVALUATION.md`.


## Executive summary

This document tracks remediation work completed after the red-team/security-hardening review.

As of 2026-04-29, the production runtime has been stabilized around the factory-first application boot path. Route ownership has been cleaned up, public documentation/OIDC pages have been restored, `/api/challenge` and `/api/verify` have been moved out of direct `app.app` runtime ownership, chat live rendering has been fixed, and runtime debug noise has been reduced.

Production is currently synced to `main` with PR #173 deployed.

## Current production baseline

- Branch: `main`
- Production synced with `origin/main`
- Runtime boot: factory-first via `wsgi:app`
- Route count: `94`
- Service: `hodlxxi.service`
- Gunicorn/eventlet binding: `127.0.0.1:5000`

Confirmed public/runtime surfaces:

- `/`
- `/login`
- `/logout`
- `/playground`
- `/home`
- `/app`
- `/upgrade`
- `/docs`
- `/oidc`
- `/api/debug/session`
- `/.well-known/agent.json`
- `/agent/capabilities`
- `/agent/reputation`
- `/agent/chain/health`
- `/api/public/status`

## Remediation completed

### PR #165 — Bitcoin route duplicate cleanup

Status: **Resolved**

Summary:

- Removed/cleaned duplicate Bitcoin route registrations.
- Preserved legacy compatibility where needed.
- Reduced route-map ambiguity.

Validation:

- Browser/API smoke passed.
- Route ownership remained stable.

### PR #166 — Restore decode script / QR compatibility

Status: **Resolved**

Summary:

- Restored decode script response compatibility.
- Preserved Bitcoin Core `decodescript` fields at the top level.
- Restored legacy browser QR/metadata fields for the Converter & Decoder panel.

Validation:

- Decode script smoke passed.
- QR output restored.
- `npub_if` and `npub_else` no longer collapse to the same key for mirrored covenant scripts.

### PR #167 — Restore public docs and OIDC pages

Status: **Resolved**

Summary:

- Restored `/docs`.
- Restored `/docs/`.
- Restored `/docs/<slug>`.
- Restored `/oidc`.
- Registered docs routes in factory runtime.

Validation:

- `/docs -> 200`
- `/docs/ -> 200`
- `/docs/principles -> 200`
- `/oidc -> 200`
- `/oauthx/docs -> 200`
- `/.well-known/openid-configuration -> 200`

### PR #168 — Migrate browser links to blueprint endpoints

Status: **Resolved**

Summary:

- Migrated browser runtime links away from bare endpoint assumptions.
- Prepared runtime for removal of transitional aliases.

Validation:

- Browser smoke passed.
- Blueprint endpoint resolution passed.

### PR #169 — Remove browser route endpoint aliases

Status: **Resolved**

Summary:

- Removed transitional factory aliases for:
  - `home`
  - `login`
  - `logout`
  - `playground`
  - `app`
- Canonical endpoints now remain:
  - `ui.home`
  - `auth.login`
  - `auth.logout`
  - `ui.playground`
  - `ui.legacy_chat_route`

Validation:

- Duplicate browser routes removed.
- Route count reduced.
- `/login`, `/logout`, `/home`, `/app`, `/playground` still resolve correctly.

### PR #170 — Move API challenge and verify routes to blueprint

Status: **Resolved / transitional**

Summary:

- Moved factory runtime ownership of:
  - `/api/challenge`
  - `/api/verify`
- New owning blueprint:
  - `api_auth.api_challenge`
  - `api_auth.api_verify`
- Preserved:
  - Nostr login flow
  - Bitcoin signature verification path
  - PSBT Proof-of-Funds compatibility when payload contains `psbt`
  - browser login/session behavior

Validation:

- `/api/challenge -> api_auth.api_challenge`
- `/api/verify -> api_auth.api_verify`
- `/verify_signature -> auth.verify_signature`
- API smoke passed:
  - challenge returns `ok: true`
  - verify missing signature returns `400`
  - invalid PSBT compatibility path returns `400`

Remaining note:

- `api_auth.py` still imports selected legacy helpers from `app.app`.
- This is intentionally deferred to a later monolith-retirement phase.

### PR #171 — Extract API auth core helpers

Status: **Resolved / transitional**

Summary:

Extracted small API auth shared helpers/state into `app/auth_api_core.py`.

Moved:

- `ACTIVE_CHALLENGES`
- `CHALLENGE_TTL_SECONDS`
- `mint_access_token`
- `is_valid_pubkey`
- Nostr login event verification helpers

Kept in `app.app` for now:

- `_finish_login`
- `get_rpc_connection`
- `derive_legacy_address_from_pubkey`
- `get_save_and_check_balances_for_pubkey`

Validation:

- `app.auth_api_core` import test passed.
- `/api/challenge` smoke passed.
- `/api/verify` smoke passed.
- Nostr verification tests passed.
- PSBT compatibility preserved.

Remaining note:

- Heavy login finalization and Bitcoin RPC verification are still deferred.

### PR #172 — Fix chat live rendering

Status: **Resolved**

Summary:

Fixed issue where chat messages were stored and visible after refresh but did not render live.

Changes:

- Added `client_id` to chat messages.
- Backend preserves `client_id`.
- Backend explicitly echoes to sender socket id.
- Backend broadcasts to other sockets using `skip_sid`.
- Frontend optimistic-renders outgoing message.
- Frontend dedupes server echo by `client_id`.
- Frontend listens to both `chat:message` and legacy `message`.

Validation:

- Browser socket connected over websocket.
- Message appears immediately without refresh.
- Server logs confirm message receive/store/emit.
- No duplicate message after server echo.

### PR #173 — Reduce runtime debug noise

Status: **Resolved**

Summary:

- Added factory-owned `/api/debug/session`.
- Stopped frontend `/api/debug/session` calls from producing `404`.
- Lowered verbose `CHAT DEBUG` logs from `info` to `debug`.
- Kept warnings/errors visible.

Validation:

- `/api/debug/session -> 200`
- Safe anonymous/session metadata JSON only.
- No tokens, cookies, secrets, macaroons, or server config exposed.
- Route count now `94`.
- Production smoke passed.

## Current route ownership snapshot

Important factory-owned routes:

```text
/api/debug/session     -> debug_session.api_debug_session
/api/challenge         -> api_auth.api_challenge
/api/verify            -> api_auth.api_verify
/login                 -> auth.login
/logout                -> auth.logout
/home                  -> ui.home
/app                   -> ui.legacy_chat_route
/docs                  -> docs_index
/oidc                  -> ui.oidc_landing
