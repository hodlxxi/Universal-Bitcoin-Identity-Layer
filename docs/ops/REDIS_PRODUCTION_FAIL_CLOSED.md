# Redis Production Fail-Closed Behavior

HODLXXI treats Redis as required production runtime infrastructure for cache/session-adjacent state and rate limiting.

## Contract

- In `FLASK_ENV=production`, startup must fail closed when Redis configuration is missing, invalid, or Redis authentication/connection initialization fails.
- Production must not silently downgrade Redis-backed cache/session or rate-limit storage to in-memory storage.
- Non-production (`development`, test, and local CI-like runs) may use in-memory fallback for developer ergonomics, but each fallback emits a structured `redis.memory_fallback` warning with the affected surface and reason.
- Healthy explicit Redis configuration, such as `REDIS_URL`, keeps the existing Redis initialization path.

## Operator workflow

Before production start or restart, verify that the service environment includes an explicit Redis configuration (`REDIS_URL`, `REDIS_DSN`, or an explicitly managed Redis host configuration) and that Redis is reachable from the application host. Do not print secrets while checking configuration; prefer service health checks and redacted diagnostics.

If production startup fails with a Redis-required error:

1. Leave the service stopped rather than running with degraded in-memory state.
2. Confirm Redis service health and network reachability.
3. Confirm the configured Redis URL/host and authentication material are present in the production environment without printing secret values.
4. Restart HODLXXI after Redis is healthy.

## Rollback

Reverting the fail-closed hardening PR restores the prior Redis fallback behavior. No database schema, Redis data, or production environment value changes are required for rollback.
