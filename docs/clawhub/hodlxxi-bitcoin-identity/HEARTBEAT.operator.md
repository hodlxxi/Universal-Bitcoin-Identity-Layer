# HODLXXI Operator Heartbeat Checklist

This file is for human operators and repo maintainers.

It is not part of the default ClawHub skill package.

## Manual public-read checks

Use these endpoints for manual smoke testing:

- `/health/ready`
- `/.well-known/openid-configuration`
- `/oauth/jwks.json`
- `/agent/capabilities`
- `/api/public/status`

## Rules

- Do not run recurring heartbeat from an installed skill by default.
- Do not create login sessions automatically.
- Do not submit agent jobs automatically.
- Do not create, check, or pay Lightning invoices automatically.
- Any non-read action requires explicit operator approval.
