# Social messaging recipient routing V1

Status: dormant, source-only contract. This phase adds no HTTP route, database
table, migration, adapter, configuration, factory wiring, deployment, or
runtime activation. It changes no Social source or ciphertext format.

## Privacy and authority boundary

The outward recipient package remains privacy-minimized. It contains a
viewer-pairwise recipient alias and viewer-pairwise device handles, plus the
X25519 public material needed by the browser to wrap a message key. It does not
contain the canonical recipient subject, device ID, or binding ID.

The device handle is intentionally non-reversible:

    d_ || base64url_no_padding(
      HMAC-SHA256(
        alias_secret,
        "HODLXXI_RECIPIENT_DEVICE_HANDLE_V1" || 0x00 ||
        "1" || 0x00 || alias_version || 0x00 ||
        viewer_subject || 0x00 || recipient_subject || 0x00 || binding_id
      )[0:16]
    )

It is stable only for the same secret namespace, alias version, viewer,
recipient, and exact binding ID. It separates viewers and alias versions. The
HMAC is not an encoded identifier and cannot itself recover its inputs.
Consequently, authoritative delivery requires UBID to retain the exact mapping
when the recipient package is issued. Reconstructing identity later from a
public key, binding version, array position, or snapshot time is forbidden.

The immutable confidential snapshot binds the viewer subject, recipient
subject, alias namespace version, exact outward package snapshot ID and
deadline, and the complete sorted set of handle/device/binding/version routes.
Each route also retains the stable identifier and bounded interval of its
independently verified binding-authorization evidence. Public keys are used
only transiently to compare the authoritative binding and outward package and
are discarded before the snapshot or decision is constructed. Alias, private
label, keys or seeds, credentials, plaintext, ciphertext, and message keys are
not routing metadata.

The immutable decision binds the message ID and envelope digest to the same
authenticated viewer for whom the pairwise handles were created, the exact
recipient, the exact package snapshot, its expiry, and all routes. It is an
internal UBID result. It is not an outward package or ciphertext envelope.

## Independent authorization prerequisite

OAuth or session possession authenticates a request context; it does not prove
that a participant authorized an exact X25519 binding. The existing
SocialMessagingDeviceBinding registration path is therefore insufficient on
its own. V1 requires an injected verifier to return a strict immutable result
for exact equality of:

- subject, device ID, binding ID, and binding version;
- X25519 public key;
- binding valid-from and expiry;
- a bounded evidence interval and stable proof identifier.

A boolean, mapping, OAuth bearer, session, service token, key equality, version,
ordering, or timing is never accepted as evidence. Missing, malformed,
expired, duplicate, or mismatched evidence fails closed. The dormant
identity-signature producer and verifier contract is now defined in
`SOCIAL_MESSAGING_DEVICE_BINDING_AUTHORIZATION_V1.md`; no provider,
persistence, application composition, or runtime path is implemented or wired.
That identity authorization does not itself prove browser possession of the
X25519 private key. A future runtime adapter must source the public key from an
already proven browser-device setup or add an explicit possession challenge.

Current exact bindings and current Full entitlement for both viewer and
recipient are separately injected authority ports. They are checked when a
snapshot is retained and again when a request is resolved. Snapshot expiry
must be no more than 300,000 milliseconds after issue and no later than every
binding, binding-authorization proof, and Full-entitlement proof. Rotation or
revocation makes the retained exact route set differ from current authority,
so the old snapshot fails before a decision is accepted.

Replacement devices receive only packages and wraps created for their new
binding. There is no historical-wrap delivery. Revocation prevents future
acceptance but cannot promise retroactive erasure of ciphertext already copied
or delivered.

The Current-Full result uses the canonical
`hodlxxi-full-entitlement-v1-sha256:<64 lowercase hex>` producer defined in
`CURRENT_ENTITLEMENT_EVIDENCE_V1.md`. The routing consumer accepts that exact
typed output and still independently requires an exact subject match, current
validity, and coverage of the complete package or snapshot interval. Regex
validity alone never grants authority: the digest is a content identity, not a
signature, credential, or caller-supplied proof.

## Closed request

The only accepted request is canonical ASCII JSON: duplicate-member rejecting,
compact, and sorted by key. Its maximum encoded size is 2,048 bytes.

    {
      "envelopeDigest":"hodlxxi-social-message-envelope-v1-sha256:<64 lowercase hex>",
      "messageId":"m_<43 canonical unpadded base64url characters>",
      "recipientDeviceHandles":["d_<22 canonical unpadded base64url characters>"],
      "recipientPackageSnapshotId":"sha256:<64 lowercase hex>",
      "schema":"hodlxxi.social_messaging_recipient_routing_request.v1",
      "version":1
    }

The handle array contains 1 through 16 strictly increasing unique values and
must equal the snapshot's complete handle set. Unknown members, Unicode,
noncanonical encodings, missing, extra, subset, or duplicate handles, and all
identity, key, alias, and credential fields are rejected.

Internal snapshots and decisions also use compact sorted-key ASCII
serialization for deterministic comparison, capped at 16,384 and 8,192 bytes
respectively. Subjects, device IDs, and binding IDs are canonical lowercase
64-hex strings. Binding versions are integers from 1 through 1,024. Timestamps
are nonnegative JavaScript-safe UTC epoch milliseconds; authority evidence
uses whole-second UTC datetimes at its injected boundary.

## Atomic repository contract and failure behavior

This phase defines only a Protocol for a future atomic confidential repository.
It provides exact snapshot retention, unambiguous snapshot lookup, and an
atomic message-ID decision ledger. It must enforce:

- one handle has one viewer/recipient/device/binding owner at a time;
- exact snapshot registration is idempotent, including renewal for the same
  tuple, while conflicting ownership fails;
- duplicate device IDs, binding IDs, proof IDs, or handle mappings fail;
- one message ID plus the same digest is an idempotent retry;
- one message ID plus a different digest is a conflict;
- duplicate rows or any other repository ambiguity fail rather than selecting
  a record.

Every failure exposed by this boundary is the same generic message:

    recipient messaging routing unavailable

No partial route, count, target-existence detail, or dependency error crosses
the boundary.

An eventual implementation needs a new additive UBID routing-registry
migration because no current table authoritatively retains the
deviceHandle-to-viewer/recipient/device/binding relationship or the message-ID
decision ledger. That migration is explicitly deferred. Social will later need
its own independent ciphertext/message store; neither store is introduced in
this phase.
