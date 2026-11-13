# Native Social Enrollment V2 challenge producer V1

This source creates the original first-enrollment challenge on the existing
native V2 issuance graph. It grants no association, admission, bearer or messaging
authority. It is default off, with no route, factory installation, operational
key, migration, grants or runtime activation.

## Trusted construction and phone binding

`EnrollmentChallengeConfig` is immutable server configuration: UBID issuer,
OAuth client, backend, service principal, exact Social audience and a bounded
integer lifetime from 1 through 60,000 milliseconds. No request parameter selects
these fields. Both construction and default enable flags require literal
booleans. `build_enrollment_v2_challenge_composition()` returns `None` without
loading infrastructure when disabled.

The enabled composition receives the existing exact
`SqlAlchemyOAuthSessionLifecycle`; its already explicit fresh Session factory
and canonical bearer verifier are reused. Client and issuer must agree with
that lifecycle. The lower-level `NativeV2EnrollmentChallengeOwner` requires an
already active, clean PostgreSQL READ COMMITTED root with no savepoint. It never
begins, commits, closes or replaces its caller transaction.

The only operation selectors are the original native issuance ID and the
phone's existing canonical viewer bearer. The real lifecycle verifies the
bearer and its stored digest; its exact JTI and subject must match the real
locked `NativeV2AuthorityReader` facts. A desktop bearer or unrelated valid
token cannot select another phone issuance. Genuine BIP340 approval, original
acceptance, Current-Full, parent OAuth/browser/session, child token, client,
issuer and X25519 binding are read through the existing native reader. Their
original closed identities, revocation rules and deadlines remain in force.

## One persisted original

Native graph locks precede a fixed `SHARE ROW EXCLUSIVE` lock on the existing
challenge table. The lock serializes absent-row creation against INSERT writers;
it does not rely on a new advisory-lock convention. A bound query selects at
most two rows for the existing canonical `sessionBinding`, which already commits
the exact native issuance, child, parent, subject, device, binding and client.
There is no new hash domain or mutable latest-row selector.

- No matching row: create a fresh challenge ID and attempt ID with server
  cryptographic randomness, using the existing canonical Enrollment V2 and
  VerificationContext V1 serializers.
- One matching row: lock and parse the existing parent and its immutable native
  revision. Reconstruct and compare the original exact canonical bytes against
  the same approved native facts. Return that original, without randomness,
  re-signing, new IDs or a refreshed timer.
- More than one matching row, invalid state, damaged bytes, missing native
  revision or expiry: deny. No replacement, repair or latest-row choice occurs.

The parent INSERT uses the existing store. Only the existing AFTER INSERT
trigger creates revision 1 in the same transaction. The producer never writes
the companion, backfills old rows or defaults a missing revision to 1.

The timer starts at the server observation after lock waits. Exclusive expiry
is capped by the configured maximum and the existing native reader's earliest
deadline, including phone, approver, browser, Full, binding, pairing, semantic
proposal and pre-enrollment. The revision read can also wait, so its earlier
observation is followed by another fresh clock sample. An expired original
cannot acquire another interval through retries or lost responses.

All approval-bound subject, device, Ed25519 public key and X25519 facts come
from the locked native record. The existing session/approver preimages and
association ID constructor are reused. The context's initial association
version/epoch describes the proposed operation; it is not an assertion that
association history is currently absent. Only reservation/finalization perform
their original fresh association-history checks. The producer creates no
association and cannot replace those checks.

## Caller publication and database roles

`NativeV2EnrollmentChallengeOwner.create(issuance_id, viewer_bearer=...)` returns
only a provisional immutable result. `check_before_commit(result)` accepts only
that owner's exact result in the original active root. It revalidates the
phone, native facts, unique original challenge and real revision; copies,
completed savepoints, connection swaps, changed facts and late expiry deny.

`EnrollmentV2ChallengeComposition.challenge(...)` uses the existing
[caller transaction boundary](SOCIAL_ENROLLMENT_V2_RUNTIME_COMPOSITION_V1.md)
to flush, recheck, commit, close and sample time again before publishing the
distinct committed wrapper. Uncertain commit never returns a transient success
or automatically repeats creation. An exact retry returns the original while
valid; expiry after a successful commit retains history and still denies renewal.

This writer uses a separate explicit native issuance lifecycle/factory, with
challenge INSERT in addition to its existing native reader/producer permissions.
It must not reuse or broaden the finalization principal: that principal's closed
catalog profile forbids challenge INSERT. Default single-role catalog behavior
remains unchanged. The finalization caller can explicitly select the closed
[challenge-writer peer profile](SOCIAL_ENROLLMENT_V2_RUNTIME_COMPOSITION_V1.md#explicit-challenge-writer-role)
so both restricted principals can coexist; that configuration grants no SQL rights.
Disposable PostgreSQL verification covers effective permissions, native trigger
rollback, concurrent creation and a genuine clock after completed lock waits.
Operational grants and installation remain separate target-specific work.

The result contains only the original context, enrollment, approval-event wire,
issuedAt, exclusive expiresAt and native revision 1. Its committed/provisional
status describes publication, with `final_admission="denied"` and
`bearer_authority="none"`. It is not a portable authority capability. The separate
[confidential ingress](SOCIAL_ENROLLMENT_V2_INGRESS_V1.md) authenticates the Social
backend and matching phone before exposing participant-specific bytes.

## Verification boundary and remaining work

Standard-library tests cover the disabled construction contract and bounded,
immutable configuration. Additional tests use the real native reader, bearer
verification, canonical serializers and reservation consumer with explicit
in-memory SQLite catalog/lock/trigger doubles. A fixed public challenge reproduces
the existing real Ed25519 signature without any participant private key. This
proves that producer bytes can cross the real next source consumer; it does not
make UBID an Ed25519 verifier or replace the real Social verification statement.

The native rehearsal uses the actual restricted PostgreSQL writer and revision
trigger. A cross-repository rehearsal obtains this producer's original bytes
through Social's real default Node HTTP client, a temporary Unix listener and
the confidential Flask ingress before reservation and atomic finalization.
The temporary listener, child process and cluster are torn down afterward.
Its trusted synthetic Social statement and shape-only phone proof do not prove
new Social Ed25519 execution or a deployed browser flow.

[Confidential HTTP ingress](SOCIAL_ENROLLMENT_V2_INGRESS_V1.md) now has a
separate default-off source adapter. Social producer runtime installation, key/trust provisioning,
operational role setup, live migrations, staging activation and DM transport
remain separate. No HTTP or browser registration flow is enabled by this source.

Canonical prerequisites:
[native V2](SOCIAL_SESSION_ISSUANCE_V2_PROVENANCE_V1.md),
[native issued revision](SOCIAL_DEVICE_CHALLENGE_REVISION_V1.md),
[handoff](SOCIAL_PREACCEPTANCE_ED25519_HANDOFF_V2.md),
[reservation](SOCIAL_ENROLLMENT_V2_RESERVATION_V1.md), and
[finalization](SOCIAL_ENROLLMENT_V2_FINALIZATION_V1.md).
