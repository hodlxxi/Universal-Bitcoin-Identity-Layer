# QR Pointer Registry Contract

The static QR pointer registry backs the public `/qr/<token>` landing surface. It is intentionally small, local, and defensive because printed QR codes can live for years after the runtime changes.

## Discovery-only surface

A QR pointer is discovery-only. Opening `/qr/<token>` renders a bounded landing page so a human can review a local target before choosing what to open. The route must not redirect automatically, mutate jobs, issue receipts, change payment state, change approval state, create delegations, call providers, or treat a scan as consent.

## Registry is not authority

The registry is not an authority source for identity, payment, authorization, approval, delegation, receipt validity, reputation, or human presence. It only maps a static token to a constrained local discovery or verification target.

`/agent/verify/<job_id>` remains the verification authority for receipt checks. A QR pointer may help a human discover that verification URL, but the pointer itself does not verify anything.

## Allowed statuses

Each registry entry must use exactly one of these statuses:

- `active`
- `revoked`
- `expired`

Active pointers may render their allowed target for manual review. Revoked and expired pointers must fail closed with `410 Gone`, even when their stored target is otherwise syntactically allowed.

## Allowed target classes

Targets must be local, bounded, and accepted by `is_allowed_qr_target()`. The intended target classes are:

- static agent discovery surfaces such as `/.well-known/agent.json`, `/agent/capabilities`, and `/agent/discovery`;
- receipt verification surfaces under `/agent/verify/<job_id>`.

Registry targets must not be external URLs, protocol-relative URLs, query strings, fragments, traversal paths, arbitrary local paths, job mutation paths, delegation paths, policy paths, or request paths.

## Token contract

Pointer tokens must be safe URL path tokens:

- non-empty;
- bounded length;
- no slash or backslash;
- no percent-encoded path separator;
- no dot-dot traversal marker;
- only letters, digits, dash, underscore, and dot.

## No secrets or scan tracking

The registry must never contain secrets or sensitive material markers such as private keys, seed phrases, mnemonics, macaroons, RPC passwords, database passwords, session identifiers, cookies, raw credentials, or environment values.

The QR pointer surface must not add analytics, scan events, tracking pixels, provider calls, or other scan tracking. A scan is not an authorization event; it is only a request to view a discovery page.
