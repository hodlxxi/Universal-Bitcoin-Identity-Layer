# Red Team Remediation Status — 2026-04-29

## Summary

Production has been stabilized after the red-team/security-hardening review. Runtime route ownership is cleaner, public docs/OIDC pages are restored, API auth routes were moved into blueprints, chat live rendering was fixed, and runtime debug noise was reduced.

Production is synced with main through PR #173.

## Completed remediation

- PR #165 — Bitcoin route duplicate cleanup: Resolved.
- PR #166 — Restore decode script / QR compatibility: Resolved.
- PR #167 — Restore public docs and OIDC pages: Resolved.
- PR #168 — Migrate browser links to blueprint endpoints: Resolved.
- PR #169 — Remove browser route endpoint aliases: Resolved.
- PR #170 — Move /api/challenge and /api/verify routes to api_auth blueprint: Resolved / transitional.
- PR #171 — Extract API auth core helpers into app/auth_api_core.py: Resolved / transitional.
- PR #172 — Fix chat live rendering without refresh: Resolved.
- PR #173 — Restore /api/debug/session and reduce runtime debug noise: Resolved.

## Current route ownership

/api/debug/session -> debug_session.api_debug_session
/api/challenge     -> api_auth.api_challenge
/api/verify        -> api_auth.api_verify
/login             -> auth.login
/logout            -> auth.logout
/home              -> ui.home
/app               -> ui.legacy_chat_route
/docs              -> docs_index
/oidc              -> ui.oidc_landing

## Remaining risks / deferred work

### Remaining app.app dependencies

Known remaining imports:

- app/blueprints/api_auth.py imports app.app as legacy_auth
- app/blueprints/bitcoin.py imports selected helpers from app.app

Next remediation:

- Extract login finalization/session helpers.
- Extract Bitcoin blueprint compatibility helpers.
- Add tests limiting app.app imports to approved transitional locations.

### Redis authentication/fallback behavior

Runtime logs show Redis initialization can fall back to in-memory storage when authentication fails.

Next remediation:

- Verify production Redis auth configuration.
- Decide whether production should allow fallback.
- Add a config guard or warning escalation if Redis is required.

### Eventlet deprecation

Tests emit Eventlet deprecation warnings.

Next remediation:

- Track migration separately.
- Evaluate ASGI-compatible runtime or Flask-SocketIO alternatives.

### Security audit closeout

Still needed:

- Dependency audit rerun
- GitHub CodeQL / security alert review
- Public endpoint inventory
- Secrets/log leakage review
- Nginx/socket.io proxy review
- Rate-limit verification for auth/API surfaces

## Recommended next PRs

1. e923/extract-login-finalization-core
2. e923/extract-bitcoin-blueprint-core
3. e923/harden-redis-session-config

## Final status

Runtime stabilization is substantially complete. The system is not fully monolith-free yet, but the most fragile runtime route ownership and browser/API compatibility problems have been addressed.
