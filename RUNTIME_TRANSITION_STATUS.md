# RUNTIME_TRANSITION_STATUS

_Last updated: April 14, 2026_

Purpose: map the current monolith-exit / factory-first transition without overstating completion.

## Current architectural truth

- The repository contains **two active runtime centers**:
  1. `app/factory.py` (`create_app`) with blueprint-based registration.
  2. `app/app.py` monolith runtime with extensive routes, guards, aliases, and bootstrap behavior.
- Blueprints are real and live, but the monolith is **not fully removed**.
- Some blueprint routes still call back into `app.app` functions for compatibility.

## What has already been extracted from `app.app`

- Login/logout ownership is implemented in `app/blueprints/auth.py`.
- Core UI entry routes (`/`, `/home`, `/app`, `/playground`) have blueprint ownership in `app/blueprints/ui.py`.
- Dedicated browser shell/login rendering helpers exist in `app/browser_shell_routes.py` and `app/browser_routes.py`.
- Agent protocol surfaces are blueprint-owned in `app/blueprints/agent.py`.

## What still depends on `app.app`

- UI blueprint wrappers for `/account`, `/explorer`, `/onboard`, `/oneword`, and `/upgrade` still import and call handlers from `app.app`.
- Monolith still defines overlapping route aliases and multiple request-gating behaviors.
- Browser route compatibility globals are still wired from `register_browser_routes(...)` in `app.app`.

## Remaining route groups to extract

1. Account and upgrade views from monolith functions into dedicated blueprint-native handlers.
2. Explorer/onboard/oneword aliases into explicit non-monolith route modules.
3. Any residual browser/chat route ownership that depends on monolith registration side effects.

## Bootstrap/runtime side effects still living in legacy code

- Multiple `before_request` guards and compatibility redirects in `app.app` still shape request behavior.
- Browser route handler registration (`register_browser_routes`) is invoked in monolith bootstrap and populates shared route-handler globals.
- Legacy compatibility alias functions in `app.app` remain present for `login/logout/root/playground` callable indirection.

## Transition map

| Area | Current owner | Legacy dependency | Status | Notes |
|---|---|---|---|---|
| login/logout | `app.blueprints.auth` | Monolith still defines alias callables and historical route registration patterns | Extracted, transitional | Blueprint ownership exists; compatibility aliases remain |
| home/app/playground | `app.blueprints.ui` | `/app` behavior can depend on browser handler registration from legacy path | Extracted, transitional | Core routes are blueprint-owned but not fully isolated from legacy globals |
| account/explorer/onboard/oneword/upgrade | `app.blueprints.ui` wrappers | Direct calls into `app.app` functions | Not fully extracted | These are the clearest remaining UI monolith dependencies |
| agent surfaces | `app.blueprints.agent` | None required for primary endpoint definitions | Extracted (live) | Includes discovery, jobs, verify, attestations, reputation, skills |
| bootstrap/runtime initialization | Mixed (`app/factory.py` + `app/app.py`) | Significant monolith bootstrap and guard logic still active | Transitional | Factory runtime exists; monolith still carries substantial runtime behavior |

## Safe next steps

1. Move delegated UI handlers (`account`, `upgrade`, alias redirects) into blueprint-native modules with no `from app.app import ...` calls.
2. Centralize auth gating in one place (factory/blueprint middleware), then remove duplicated monolith `before_request` guards.
3. Replace global browser route-handler state with explicit blueprint/view ownership for `/app` and related browser paths.
4. Keep route-ownership tests and add regression checks for auth semantics to avoid behavior drift during extraction.
5. Once parity is verified, reduce `app.app` to bootstrap-only (then retire).
