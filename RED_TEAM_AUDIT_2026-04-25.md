# HODLXXI Red-Team Audit — 2026-04-25

## Baseline

- Production and staging aligned on main after PR #163.
- Production smoke green.
- Staging smoke green.
- Agent public surfaces green.
- BTC/LND status green.
- Production runtime requirements audit: no known vulnerabilities.

## Non-destructive Runtime Findings

### Public/session boundary

Expected public endpoints:

- /
- /login
- /playground
- /.well-known/agent.json
- /agent/capabilities
- /agent/reputation
- /agent/chain/health
- /api/public/status

Expected protected endpoints:

- /home
- /app
- /account
- /upgrade
- /rpc/getblockcount
- /api/rpc/getblockcount

Observed behavior matched expectations.

### Duplicate route registrations

Severity: Medium / technical debt

Observed duplicate route rules:

- /api/decode_raw_script
- /api/rpc/<cmd>
- /app
- /home
- /login
- /logout
- /playground

Impact:

Route shadowing can hide which handler is active. Current route order appears safe, but cleanup should be prioritized before deeper monolith retirement.

Recommended fix branch:

- audit/remove-duplicate-route-registrations

### Security headers

Good:

- HSTS present
- CSP present
- X-Frame-Options present
- X-Content-Type-Options present
- Referrer-Policy present
- Session cookie has Secure, HttpOnly, SameSite=Lax

Hardening items:

- CSP still allows unsafe-inline and unsafe-eval.
- Nginx exposes server version.
- Some duplicate headers appear, including duplicate HSTS / X-Content-Type-Options.

Recommended fix branch:

- audit/nginx-header-hardening

### Agent request validation

Good:

- Missing or invalid job type returns controlled error.
- Oversized payload returns payload_too_large.
- No stack trace observed.
- No accidental free execution observed.

## Static Analysis — Bandit

Command:

bandit -r app -x app/templates,app/static -ll

Summary:

- High: 0
- Medium: 3
- Low: 87

Medium findings:

1. app/app.py:3046 — B108 hardcoded_tmp_directory

Finding:

- Predictable path: /tmp/wallet-backup.dat

Risk:

- Predictable temp paths can allow local race/symlink issues.

Recommended fix:

- Use tempfile.NamedTemporaryFile or a private runtime directory with restrictive permissions.

Recommended fix branch:

- audit/fix-wallet-backup-tempfile

2. app/config.py:155 — B104 hardcoded_bind_all_interfaces

Finding:

- Default APP_HOST=0.0.0.0

Risk:

- Binding all interfaces can expose dev servers if used directly.

Assessment:

- Likely low risk in current production because Gunicorn is bound to 127.0.0.1 behind Nginx.
- Keep as documented config hardening item.

Recommended fix:

- Make production bind explicit and ensure direct Flask dev server is never used in production.

3. app/database.py:345 — B608 hardcoded_sql_expressions

Finding:

- SELECT COUNT(*) FROM {table_name}

Risk:

- Possible SQL injection if table_name is user-controlled.

Recommended fix:

- Allowlist table names before interpolation.

Recommended fix branch:

- audit/fix-sql-table-allowlist

## Dependency Audit — pip-audit

Runtime requirements:

- requirements.txt: no known vulnerabilities found.

Development requirements:

- requirements-dev.txt: 2 known vulnerabilities found.

Findings:

1. pytest 7.4.3
   - CVE-2025-71176
   - Fix version: 9.0.3

2. black 26.1.0
   - CVE-2026-32274
   - Fix version: 26.3.1

Assessment:

- Not a production runtime emergency.
- Fix in a dev-dependency update PR.

Recommended fix branch:

- audit/update-dev-dependencies

## Local Runtime / Config Notes

- Manual imports may show Redis authentication fallback to in-memory session storage if shell environment does not match systemd service environment.
- Staging contains runtime files such as .env, tls.cert, and invoice.macaroon under restricted paths. Permissions should be reviewed and kept out of git.

Recommended fix branch:

- audit/redis-env-consistency
- audit/runtime-secret-permissions

## Priority Fix Plan

P0 / immediate:

- None found.

P1 / next security PRs:

1. audit/fix-sql-table-allowlist
2. audit/fix-wallet-backup-tempfile
3. audit/remove-duplicate-route-registrations

P2 / hardening:

4. audit/update-dev-dependencies
5. audit/nginx-header-hardening
6. audit/redis-env-consistency
7. audit/runtime-secret-permissions

## Summary

The non-destructive red-team pass did not find an emergency production vulnerability.

Main risk areas are transitional architecture and cleanup:

- duplicate route registrations
- remaining app.app compatibility bridges
- one SQL allowlist issue
- one predictable /tmp path
- dev dependency CVEs
- CSP/header hardening
