# QR Pointer v0

QR Pointer v0 is a contract for discovery pointers to bounded HODLXXI runtime surfaces. It is defensive and fail-closed until a future signed, stored, revocable QR Pointer record exists.

## Current runtime boundary

The current runtime does **not** expose `GET /qr/<token>` and does **not** treat any verifier response field as a canonical signed pointer record. If `/agent/verify/<job_id>` exposes QR-related metadata on a branch, verifiers must treat it only as a discovery-only descriptor that helps reopen `/agent/verify/<job_id>`.

A current verifier QR descriptor is not:

- a signed QR Pointer record;
- a QR image;
- not a bearer token;
- not a route registration;
- identity or human identity;
- consent, approval, delegation, authorization, or execution authority;
- receipt validity by itself;
- payment, trust, reputation, human presence, or operator approval.

Receipt validity remains determined only by the existing receipt verification response and signature checks.

## Target constraints

A QR Pointer target must be local and bounded. External URLs are rejected. `/agent/request` is not a default QR target because request creation is a write surface. Delegation and policy targets remain disallowed until real delegation runtime records, policy, revocation, and verification surfaces exist.

The QR object must not contain secret-like fields such as `token`, `secret`, `password`, `private_key`, `macaroon`, `cookie`, `bearer`, `invoice`, or `preimage`.

## Future canonical records

Future canonical QR Pointer records may be signed, stored, and revocable. That future design must be introduced with explicit schemas, storage, revocation, verification behavior, and route tests before any `/qr/<token>` runtime route is added.
