# Error Response Documentation

## Status Notes

This document describes **current implemented behavior** in this repository.

It intentionally does **not** describe a unified numeric error catalog because the current runtime does not implement one.

Current state:

- Error responses are **not fully standardized** across all endpoints.
- Most JSON errors use an `error` field, but shape and semantics vary by subsystem.
- OAuth endpoints use OAuth-style `error` and `error_description` fields where implemented.
- Some protected routes redirect to `/login` instead of returning JSON.
- Some routes return HTML error pages or Flask default errors depending on path and handler.

## Current Error Response Patterns

### Pattern A: Generic JSON error object

Common shape in many routes:

```json
{ "error": "..." }
```

Sometimes includes extra fields such as:

- `message`
- `detail`
- `required` / `provided`

Examples are present in Bitcoin routes, LNURL params/check helpers, agent endpoints, and several auth/helper decorators.

### Pattern B: OAuth/OIDC RFC-style error object

`/oauth/authorize` and `/oauth/token` return OAuth-like payloads such as:

```json
{
  "error": "invalid_request",
  "error_description": "Missing required parameters"
}
```

These are used for invalid client, grant, request, and server error cases.

### Pattern C: LNURL callback error object

`/api/lnurl-auth/callback/<session_id>` uses LNURL-style keys:

```json
{
  "status": "ERROR",
  "reason": "..."
}
```

This is distinct from the generic `{ "error": "..." }` pattern.

### Pattern D: Redirect-based auth behavior

Some routes redirect to login instead of returning JSON errors:

- OAuth authorize when user is not authenticated.
- PoF pages protected by `login_required` helper.
- Several UI/account style endpoints.

## Generic JSON Error Responses

The app factory registers global handlers for several status codes:

- `400` → `{ "error": "bad_request", "message": "..." }`
- `401` → `{ "error": "unauthorized", "message": "Authentication required" }`
- `403` → `{ "error": "forbidden", "message": "Access denied" }`
- `404` → `{ "error": "not_found", "message": "Resource not found" }`
- `429` → `{ "error": "rate_limit_exceeded", "message": "..." }`
- `500` → `{ "error": "internal_error", "message": "An unexpected error occurred" }`

Important caveat: many routes return their own payloads directly and do not rely on these handlers.

## OAuth / OIDC Error Responses

Implemented in `app/blueprints/oauth.py`:

### `/oauth/register`

- Validation failures use simple messages in `error`, e.g.:
  - `"client_name is required"`
  - `"redirect_uris must be a non-empty array"`
- Internal failures return `{ "error": "<exception text>" }` with HTTP 500.

### `/oauth/authorize`

Uses OAuth-style JSON for API errors:

- `invalid_request`
- `unsupported_response_type`
- `invalid_client`
- `server_error`

When the user session is missing, this endpoint **redirects to `/login`** (HTTP 302) instead of returning JSON.

### `/oauth/token`

Uses OAuth-style JSON for token exchange errors:

- `unsupported_grant_type`
- `invalid_request`
- `invalid_client`
- `invalid_grant`
- `server_error` (with sanitized description `"Token issuance failed"`)

### `/oauth/introspect`

Does not use OAuth error objects for invalid requests; it returns `{ "active": false }` with HTTP 200 for many invalid-token or invalid-client paths.

## Auth Redirect / Protected Route Behavior

Current behavior is mixed across subsystems:

- Session-protected web routes often redirect to `/login`.
- OAuth token-protected APIs typically return JSON errors (`401`/`403`) instead of redirecting.
- UI routes can return HTML responses (including HTML 401 pages) rather than JSON.

This means clients must not assume one universal auth failure format across all paths.

## Agent Endpoint Error Behavior

Implemented in `app/blueprints/agent.py` with compact string errors, for example:

- `ip_rate_limited` (429)
- `payload_too_large` (400)
- `unsupported_job_type` (400)
- `rate_limited` with message (429)
- `invoice_create_failed` with message (502)
- `not_found` (404)
- `invalid_pagination` (400)
- `missing_signature` (500)

Agent endpoints do **not** use numeric error codes, request IDs, or timestamp fields in error payloads.

## LNURL / PoF / Bitcoin-Related Error Behavior

### LNURL (`app/blueprints/lnurl.py`)

- `/create` and `/params` typically use `{ "error": "..." }` for failures.
- `/callback/<session_id>` uses `{ "status": "ERROR", "reason": "..." }`.
- `/check/<session_id>` not-found case returns `{ "verified": false, "error": "Session not found or expired" }`.

### PoF (`app/pof_routes.py` and `/api/challenge` compatibility route)

- PoF page routes may redirect to login for unauthenticated users.
- `/api/pof/stats` is a data endpoint and currently does not define custom structured error JSON.
- `/api/challenge` returns simple `{ "error": "missing pubkey" }` / `{ "error": "invalid pubkey" }` on validation failures.

### Bitcoin API routes (`app/blueprints/bitcoin.py`)

Common failures are plain JSON with `error`, e.g. command not allowed, unknown command, RPC exception text, missing parameters, challenge mismatch.

## Known Inconsistencies and Gaps

1. **No implemented numeric error code catalog**
   - The runtime does not emit a stable `error_code` integer taxonomy.

2. **No universal envelope**
   - Fields like `ok`, `message`, `detail`, `verified`, `status`, and `reason` appear inconsistently by endpoint.

3. **No universal `request_id` in error responses**
   - Error responses do not consistently include request correlation IDs.

4. **No universal error `timestamp`**
   - Some success payloads include timestamps, but error payloads do not consistently include them.

5. **Redirect vs JSON split**
   - Browser-oriented routes often redirect; API-oriented routes often return JSON; this is not globally normalized.

## Future Error Standardization Notes (Not Yet Active)

The following are reasonable future improvements, but **not current runtime truth**:

- Introduce one canonical JSON error envelope for API routes.
- Add optional request correlation ID to error responses.
- Normalize auth failures (clear separation between browser redirect flows and JSON APIs).
- Keep OAuth RFC errors unchanged where required, while harmonizing non-OAuth API errors.

Until that work is implemented, consumers should integrate per-endpoint based on current behavior.
