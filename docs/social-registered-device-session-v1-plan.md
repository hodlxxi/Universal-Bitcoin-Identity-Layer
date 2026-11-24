# Registered-device messaging session V1 (work in progress)

Status: source-only. No new runtime route or session issuance is enabled. Not a
release gate pass. Native Enrollment V2 on paired staging committed an accepted
reservation, active epoch-1 association, native effect/receipt and consumption.
The original issuance expired at its original pairing deadline. This is expected
for enrollment; it is not a sustainable messaging-session contract.

## Separate authority lifetimes

1. Native enrollment is an immutable historical provenance record. Its approval,
   challenge and original OAuth lineage are authenticated at the decision time,
   never extended or revived.
2. A registered device observation rechecks the exact committed native history,
   current active user/client/issuer, binding, association and current Full.
   Subject/device inputs select rows only; this observation is not authentication.
   Initial native associations only in this first slice. Unknown, revoked,
   rotated, expired, Limited or inconsistent evidence must fail closed.
3. A future dedicated registered-device session owner issues a fresh single-use,
   purpose-separated challenge bound to the active association and browser
   context. Social's existing strict Ed25519 verifier authenticates exact
   challenge bytes; UBID authenticates a purpose-specific verification statement
   and consumes the challenge under lock before issuing a new scoped credential.
   The credential must not be a general-purpose OAuth token or a revival of
   Native V2 issuance. Its digest, generation, device and deadline must be
   durable. Revocation, replay, Full loss, binding retirement, association
   rotation, logout and expiry are rechecked at every protected operation.
4. A separate session-binding domain must bind message proofs to the new
   credential generation. Directory/recipient routing and mailbox access must
   use the same current authority; no fallback to a subject-only assertion.
   Desktop enrollment and the paired device's key-only re-login both need a
   user-facing flow. A mobile device must not require a Nostr extension.

## Acceptance before enabling

- Genuine browser native enrollment; expired original issuance, unchanged
  receipt and key; fresh possession proof establishes a new scoped session.
- Wrong device/key, stale or replayed challenge, another browser context, lost
  response, concurrent consume, rotated/revoked binding/association, Limited
  and expired/revoked Full deny. No unbounded challenge storage.
- Logout revokes current session; no credential leakage or plaintext persistence.
- Real Alice and independently admitted Bob send/decrypt both directions;
  reload and inbox read succeed, wrong/limited recipients deny.
- PG16 lock ordering, role/ACL/catalog attestation, exact cross-language vectors,
  both hosted suites and isolated paired browser acceptance must pass.
- Do not change production or close issue #588 on source-only progress.

First slice: `observe_registered_device_v1` is not installed and returns only a
provisional locked observation, not permission. It reuses existing historical
signature/effect verification and current Full verification without reading the
old bearer as live authority. The PG16 paired test covers the expired issuance
case and denial of unknown device/expired current authority. The existing
finalizer catalog profile is used for the historical observation; the final
session-owner role, proof statement, durable challenge/session state, lock
ordering under concurrent mutation, transport integration and UI remain to be
implemented and verified.
