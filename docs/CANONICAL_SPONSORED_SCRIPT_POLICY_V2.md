# Canonical Sponsored Script Policy V2 — Evidence Only

**Status:** proposed, read-only, not deployed, not an admission or a current-entitlement policy.

**Schema:** hodlxxi.canonical_sponsored_script_evidence.v2

**Policy:** hodlxxi.canonical_sponsored_script_policy.v2

**Implementation:** app/services/canonical_sponsored_script_policy_v2.py

## Why V2 exists

CanonicalAdmissionEdgeV1 fixes the early CLTV branch to the child.
That is **not** the unilateral script arrangement in the already-funded
Alice/Bob demonstration. A Canon V1 record must not be silently rewritten,
mis-tagged or reinterpreted as V2. V2 evidence is a distinct type/schema,
and V1 canonical checks and previous historical records are untouched.

The V2 script-policy layer recognizes the actual mirror orientation:

| Leg | Earlier unilateral receiver branch | Later unilateral sender/fallback branch |
| --- | --- | --- |
| Leg A, early | **Sponsor** at early(d) | Child at middle(d) |
| Leg B, late | **Child** at middle(d) | Sponsor at late(d) |

The terms "receiver" and "sender" above are the parsed legacy script
field names and **not** a statement about who funded the UTXO, who controls
another participant's keys, or whether a cooperative spend exists.
This policy accepts **CLTV-only legacy_777** scripts; it does not extend
operator-agent current_144, multisig, Taproot or any wallet permission.

For every child depth d >= 1:

    middle(d) = 1,777,777 - 777 * (d - 1)
    early(d)  = middle(d) - 777
    late(d)   = middle(d) + 777

| Relationship | Child depth | Early | Middle | Late |
| --- | ---: | ---: | ---: | ---: |
| Alice (E923) → Bob | 1 | 1,777,000 | 1,777,777 | 1,778,554 |
| Bob → Charlie | 2 | 1,776,223 | 1,777,000 | 1,777,777 |
| Charlie → Dave | 3 | 1,775,446 | 1,776,223 | 1,777,000 |

The finite absolute-block-height range has a positive-window maximum
child depth of 2,288. There is no arbitrary-depth guarantee from this
particular fixed-height schedule.

## Fixed validation

The function validate_canonical_sponsored_scripts_v2 takes two exact witness
scripts in either input order and an **explicit** sponsor compressed key
and sponsor depth. It relies on the existing authoritative script/pair
parser to enforce:

- Two distinct actual Script bytes, exact mirrored unilateral keys and
  Bitcoin-valid compressed secp256k1 public keys.
- Exact Bitcoin mainnet legacy_777 CLTV-only covenant template.
- One common middle height, two 777-block deltas, and the child-depth
  schedule specified above.
- The V2 direction: sponsor early on leg A and late on leg B, child at
  the shared middle on both legs.
- Alice/E923 as the unique permitted **depth-zero** anchor, while a
  child at depth 1, 2, and so forth may later become a sponsor under
  independently validated, currently Full lineage evidence.
- Deterministically ordered earlier/later raw scripts and their hashes,
  parent/child public keys, pair hash, protocol identity and policy
  version, and a canonical serialized evidence digest.

Every immutable output revalidates the complete raw pair. Forged
fields, role swaps, wrong depth, noncanonical keys, script substitutions,
hash substitutions and wrong schema/version fail closed.

## Explicit non-claims / hard boundary

CanonicalSponsoredScriptEvidenceV2.grants_full is **always false**.
This is a typed **script proof**, not a persisted admission edge, a
trusted funded relation, an authorization, a source of current Full,
or a child's signature/consent. Depth is caller-supplied and is **not**
validated against a persisted sponsor lineage by this policy.

The prior exact-UTXO sponsored_admission_funding_preflight can check
two explicit, distinct outputs through Bitcoin Core, but it remains
read-only and its observation may become stale. A successful pair
scan is insufficient to accept or authorize a new member. Existing
confirmed-UTXO observation with gettxout(..., False) excludes the
mempool: fresh admission-time spend/mempool policy is required.

No GitHub CI run can grant a subject Full, change Social authority,
create a database row, or deploy to the VPS.

## Source-bound V2 admission proposal (implemented, proposed only)

The new app/services/canonical_admission_proposal_v2.py adds a separate,
immutable hodlxxi.canonical_sponsored_admission_proposal.v2 record.
It builds on V2 script evidence, TrustedCovenantRegistration and
CanonicalCovenantFundingSet **without changing their V1 storage contracts**.

The proposal validates:
- The exact child-subject trusted registration of the two real scripts.
- An effective recognized funding set consisting of exactly the two
  matching distinct registration anchors, of equal positive satoshi value.
- A recent two-outpoint observation (120-second maximum) bound to exact
  P2WSH scriptPubKey hashes, confirmations and unspent states.
- An active genesis evaluation for Alice at depth 0 or the exact
  digest and identity of a preceding V2 proposal at greater depth.
- Three distinct supplied SHA-256 references to import provenance,
  sponsor-key evidence and child acceptance **without treating those
  references as validated signatures or independently trusted proof**.
- Deterministic canonical serialization/digest of the complete proposal.

Important: this is an immutable **proposal**, not an effective admission
record. A parent proposal is only a structural lineage predecessor; it
does not prove that Bob is currently Full or authorized to sponsor
Charlie. Supplying an arbitrary reference digest does not establish
child consent. The observation source may be caller-controlled and is
not, in isolation, independent proof that Bitcoin Core was queried;
the trusted observation adapter is the intended source. A successful
proposal never becomes Full through the pure evaluator.
Both grants_full and is_effective always return False.

The proposed record must not be written into current_entitlement_evidence,
Social roles, or an existing V1 admission edge table as though it were
approved. Durable source capture, signature verification, transactional
uniqueness/conflict handling, reorg/mempool spend checks, and genuine
current Full sponsor evaluation remain separate prerequisites.

## Dual consent proof for sponsor and child (read-only, no grant)

An independent proof module now exists at
app/services/canonical_admission_consent_v2.py. Its issuance function
constructs a **fresh 256-bit nonce** and a bounded 5-minute challenge
over the canonical SHA-256 digest of the *complete* V2 proposal.
Separate domain-separated ASCII signmessage texts bind the protocol,
Bitcoin network, proposal, exact sponsor and child compressed keys,
role (sponsor or child), nonce and expiration.

The verification function requires **two separate legacy Bitcoin
Signed Message compact signatures** (standard base64, 65 bytes).
For each distinct signature it derives the corresponding compressed-key
Bitcoin P2PKH address and calls the existing Bitcoin Core
verifymessage RPC using the exact role-specific ASCII text. This is
intended to interoperate with the existing legacy UBID login signing
scheme, not Bitcoin transaction signing or a newly invented key format.

The returned immutable verification receipt stores hashes of the two
signed messages, two compact signatures, challenge, and proposal.
Both grants_full and replay_protected are **always false**. Every
read-only proof result needs independent server trust before it can
ever be used for admission. A caller can construct a challenge or a
receipt object; neither object proves that UBID ever issued it or that
the nonce was reserved or consumed. The module does not persist a
nonce, verify active signer sessions, verify Full sponsor lineage,
check revocation, or register an admission.

Security prerequisites for any live entitlement transition remain:
a transactionally unique issued-challenge row, strict issuance
ownership, challenge consumption exactly once, two verified signers,
fresh independent UTXO observation with mempool/reorg policy,
effective ancestor Full, idempotent canonical V2 registration and
entitlement publication. None of these state-changing operations
can be inferred from a successful cryptographic signature check alone.

## Separate V2 admission implementation required next

1. Promote the independent **proposed-only V2 source-bound domain** into
   a separately versioned durable admission registry with verified
   lifecycle and migration. Preserve V1 records verbatim. Validate
   actual current Full sponsor/ancestor authority, not the fact that a
   parent proposal happens to exist.
2. Capture authenticated, sponsor-scoped, idempotent import provenance,
   exact distinct on-chain UTXO registration and positive equal sats,
   both parties' public-key/key-possession and acceptance signals.
3. Under a controlled transaction, enforce one parent per child,
   sponsor current Full and active lineage, no cycle or competing
   registrations, fresh Bitcoin snapshot and mempool-spend policy,
   revocation/stale-snapshot safeguards, and crash-safe replay.
4. Add a general per-subject current-entitlement evaluator and refresh,
   with independently verifiable Full for Bob and each successor.
   Do not reuse the E923-only root refresh or copy another user's
   role. Social must consume the authoritative UBID result.
5. Verify existing Alice/Bob outputs and Bob→Charlie sponsor
   permissions in staging, then encrypted two-user messaging, before
   any production authorization or deployment change.

CI exercises the real Alice/Bob witness-script bytes, generic Bob/Charlie
and Charlie/Dave depth transitions, deliberately reversed V1-only
pairs, malformed inputs and forged immutable evidence. The V1
preflight classification intentionally remains
reverse_branch_roles_requires_policy_review; V2 is a separate
policy rather than a silent change to V1.
