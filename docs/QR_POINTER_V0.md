# QR Pointer v0

## Static registry runtime phase

This phase adds only a local, checked-in QR Pointer registry. Each pointer token maps to a JSON record under `app/data/qr_pointers/`. There is no database storage, migration, scan write path, audit event, analytics pipeline, third-party dynamic QR provider, or mutable external redirect trust base in this phase.

## Landing behavior

`GET /qr/<token>` renders a safe HTML interstitial for a valid opaque token. The route is read-only and discovery-only. It does not automatically redirect by default, and it only provides a normal link for an active pointer target.

The page shows:

- the local target path;
- the effective pointer status;
- safe issuer metadata when available;
- the explicit non-claim warning: “This QR Pointer is discovery-only. It does not prove identity, consent, approval, delegation, authorization, payment, receipt validity, reputation, trust, or human presence.”

The page must not load third-party scripts, embed third-party analytics, expose secret-like fields, create jobs, mutate jobs, approve jobs, complete jobs, verify jobs, issue receipts, or change receipt verification semantics.

## Token and target bounds

Tokens are opaque local identifiers. They must not encode PII, job payloads, invoices, request data, delegation secrets, approval tokens, or policy exceptions. Runtime tokens reject slash/path traversal and are constrained to a conservative local pattern.

Targets are local relative paths only. External URLs, protocol-relative URLs, `/agent/request`, delegation surfaces, and policy surfaces are rejected in this phase. Initial allowed targets are limited to:

- `/.well-known/agent.json`
- `/.well-known/hodlxxi-operator.json`
- `/agent/discovery`
- `/agent/capabilities`

Delegation support is intentionally not implemented here. `/qr/<token>` is not a delegation, authorization, consent, approval, payment, receipt, reputation, trust, or human-presence surface.

## Status semantics

- `active`: returns `200` with a safe interstitial and a normal target link.
- `revoked`: returns `410` with a safe non-redirecting page.
- `expired`: returns `410` with a safe non-redirecting page.
- unknown or invalid token: returns `404`.

## Capabilities advertising

This route is not advertised in `/agent/capabilities` during the static registry runtime phase.

## Rollback

1. Remove the QR Pointer blueprint and route registration.
2. Remove static pointer fixtures from `app/data/qr_pointers/`.
3. Remove the landing template.
4. Remove the route contract tests.
5. Revert this document update and any public surface listing update.

No data cleanup is required because there is no DB migration, no storage write path, no analytics, and no job or receipt mutation.
