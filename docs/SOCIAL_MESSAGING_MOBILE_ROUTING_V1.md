# Accepted mobile evidence at the recipient-routing boundary

This is a dormant Phase 3 prerequisite. It connects the existing committed
mobile authorization owner to the existing recipient routing verifier port.
It does not complete Phase 3, admit a sender device, issue an inbox grant,
transport or store ciphertext, or activate browser messaging.

## Ownership and authoritative inputs

UBID owns the confidential subject/device/binding mapping and accepted proof.
Social owns the existing opaque recipient capability and eventual independent
ciphertext store. Neither repository imports the other at runtime.

`SqlAlchemyAcceptedMobileBindingEvidenceReader` reads the existing mobile
operation, acceptance receipt, global request owner and exclusive binding owner.
It requires an explicit active PostgreSQL READ COMMITTED session, no pending ORM
writes, and the existing enabled migration guards. It does not begin, flush,
commit, roll back or close the caller's transaction. There is no database or
configuration fallback. The caller must provide a fresh read transaction after
acceptance has committed; the reader cannot certify its own transaction's commit.

The operation must be accepted, its request/digest must match the receipt, the
request owner must be `mobile`, and exactly one binding owner must identify that
same request. Competing Nostr evidence, duplicate receipts/owners, missing rows,
incomplete state and dependency errors fail closed. Queries are bounded to two
rows so ambiguity is rejected. No new table, migration or write is introduced.

`AcceptedMobileBindingAuthorizationVerifier` accepts only the immutable typed
`MobileBindingEvidenceState`, containing exactly one
`AcceptedMobileBindingEvidence`. The injected reader is trusted persistence,
never browser JSON, an OAuth claim, a QR scan or a bare verified signature.
The verifier reuses the existing method parsers and actual cryptographic
verification at the persisted acceptance second. It checks the original
challenge/login context or QR transcript/pairing context, closed accepted result,
request, method digest and canonical binding-record identity. Register, rotate
and adopt must equal the complete current active binding; revoke cannot pass.
The original Nostr verifier is unchanged and is not a mobile fallback.

The binding and authorization window must contain the original acceptance.
Trusted current time must be at or after acceptance and strictly before binding
expiry. Evidence begins at acceptance, including for adoption, so a package
issued before acceptance is ineligible. The short request/QR deadline governs
acceptance, not the lifetime of an already accepted binding. Verification after
that deadline never extends the binding, renews a session or resigns anything.

## Proof identity and compatibility

The mobile proof identifier is exactly:

```
hodlxxi-mobile-binding-authorization-v1-sha256:<method authorizationDigest>
```

The digest is the unchanged SHA-256 of the canonical method envelope. It commits
the method and all signed semantic/context bytes. The distinct prefix identifies
accepted mobile evidence; it does not relabel a Bitcoin signature or QR approval
as `nostr_event_v1`. The identifier alone is neither a credential nor proof.
Existing Nostr proof IDs, binding-record IDs, pairwise HMAC device handles,
recipient package snapshots and Social V1.28E/F.1 envelope digests retain their
original bytes and separate meanings.

The routing gate structurally accepts this additional proof namespace only for
its internal evidence fields. Operational use requires its separate explicit
mobile flag. It still checks Current-Full for both participants, exact complete
current recipient bindings, proof/package interval containment, package digest,
pairwise handles and exact route equality at retention and again at resolution.
It retains the existing request, snapshot and decision schemas and replay rules.
No raw encryption key enters a routing snapshot or decision.

All failures from the new verification/read boundary are the existing generic
`recipient messaging routing unavailable`; submitted values are not logged or
returned. Public keys occur only in the pre-existing signed proof, binding,
transient exact comparison and outward encryption package. No private key,
exported CryptoKey, message plaintext, content key or private label is accepted.

## Default-off source gates

Each requires a literal boolean; absent means false:

- `SqlAlchemyAcceptedMobileBindingEvidenceReader(..., enabled=False)`;
- `AcceptedMobileBindingAuthorizationVerifier(..., enabled=False)`;
- `SocialMessagingRecipientRoutingGateV1(..., mobile_authorization_enabled=False)`.

Disabled readers/verifiers access no evidence. There is no environment flag,
factory import, HTTP route or deployment configuration for these additions.
The existing recipient package runtime is unchanged; its OAuth-only current
binding lookup is not upgraded into authorization by this source.

## Cross-repository verification and remaining work

The identical fixture `tests/fixtures/social_messaging_phase3_routing_v1.json`
contains one actual existing UBID package-producer output, a synthetic
ciphertext-only Social envelope, its exact digest and the existing canonical
UBID routing request. Each repository checks its real producer/consumer
independently. Ciphertext bytes are deterministic byte patterns, not encrypted
private text; the package uses the existing public mobile binding vector.
No participant private key or content-encryption key is in the fixture.

The existing guarded disposable PostgreSQL test proves committed acceptance
and reader recreation for both methods; a pending operation has no evidence.
Pure tests additionally cover all lifecycle vectors, method/receipt substitution,
proof expiry, exact binding changes, package identity, both Current-Full checks,
revocation/rotation and replay conflict. Synthetic routing repositories are test
substitutes only; they are never a production persistence fallback.

Before Phase 4, Phase 3 still needs:

1. Transactional production dispatch over Nostr/mobile evidence and current Full/
   binding readers, with documented lock order and admission linearization.
2. Exact authenticated sender-device and recipient-self request admission. A
   participant approving a public key does not prove request possession of its
   private CryptoKey. OAuth alone or an arbitrary device selector is insufficient.
3. Authorized package issuance tied to Social's fresh capability, including
   atomic confidential snapshot retention before the package is released.
4. Additive UBID routing-registry/decision-ledger migration, durable adapter,
   collision/idempotency/concurrency tests and namespace rotation policy.
5. Reviewed recipient-self retrieval authorization and a minimized opaque
   outward routing/storage contract; internal decisions contain UBID identities
   and cannot simply be copied into Social's ciphertext store.
6. Social authenticated, CSRF-protected, bounded ciphertext-only submission and
   persistent ciphertext store, exact retry/replay coordination with UBID, and
   honest commit/response-loss recovery.
7. Bounded inbox/read pagination and cursor binding, current-device revocation/
   rotation rechecks, retention/quotas, opaque sender attribution, and an explicit
   sender-device copy/history decision compatible with the frozen envelope.
8. Default-off runtime/client/route composition and the complete offline
   transport/storage/inbox lifecycle rehearsal. Activation and a real two-user
   rehearsal require separate operational authorization.

The browser encryption/reception/local-decryption UI belongs to Phase 4. No
source test or routing decision is a claim of delivery or messaging completion.
