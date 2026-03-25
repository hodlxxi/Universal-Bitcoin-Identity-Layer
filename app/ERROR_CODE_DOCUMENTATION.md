# Error Documentation (Current Runtime)

This document reflects **actual error-shape patterns** used across the current runtime.

## Important: no single global error schema

Different subsystems return different envelopes today. Consumers should not assume one canonical `error_code` model for all endpoints.

## Common patterns

### Pattern A: OAuth-style

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid or expired authorization code"
}
```

### Pattern B: Simple service error

```json
{
  "error": "client_name is required"
}
```

### Pattern C: boolean/result style

```json
{
  "verified": false,
  "error": "Session not found or expired"
}
```

## HTTP status usage (practical)

The runtime frequently uses:

- `200`, `201` for success responses.
- `400` for malformed/missing inputs.
- `401` and `403` for authentication/authorization failures.
- `404` for missing resources/session IDs.
- `429` for rate limiting.
- `500`/`503` for server or dependency problems.

## Guidance for integrators

- Prefer endpoint-specific parsing.
- Treat human-readable `error` values as primary identifiers where numeric codes are absent.
- Expect gradual normalization over time rather than assuming normalization is already complete.
