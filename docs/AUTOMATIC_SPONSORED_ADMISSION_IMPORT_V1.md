# Automatic Sponsored Admission — implementation boundary (V1)

## Objective

When an existing canonical Full participant (sponsor) imports a new
counterparty's public mirrored covenant descriptors through UBID, the
application should detect the candidate and complete verified canonical
registration automatically, once **both** exact scripts and qualifying UTXOs
are available. A previously imported pair must be recoverable without
importing or funding again.

Every eligible Full participant must be able to sponsor their own successor
(Bob -> Charlie), without a privileged Alice/E923-only UI shortcut.

## Cascading sponsors and fixed 777-block schedule

The admission depth belongs to the **child**, not to the number of keys a
sponsor has or the number of contacts imported. Each independent sponsor-child
pair receives its own two exact mirrored UTXOs. The sponsor must itself be
currently canonical Full and its unique parent lineage must be valid.

For child depth `d >= 1`:

```text
middle(d) = 1,777,777 - 777 * (d - 1)
early(d)  = middle(d) - 777
late(d)   = middle(d) + 777

Alice -> Bob      d=1   1,777,000 / 1,777,777 / 1,778,554
Bob -> Charlie    d=2   1,776,223 / 1,777,000 / 1,777,777
Charlie -> Dave   d=3   1,775,446 / 1,776,223 / 1,777,000
```

A Full participant may sponsor multiple distinct children and may simultaneously
be a child in one parent relationship and sponsor in other child relationships.
There is no special E923 operator exemption for depth >0 sponsorship. Do not
derive Full from a sponsor's identity alone or copy the parent entitlement
without separately observing each child's UTXOs.

`canonical_sponsor_lineage.py` has a pure fail-closed evaluator for finite
ancestry snapshots; it does not itself persist an admission or activate Full.
The fixed V1 positive-block-height schedule and evaluator have an explicit
maximum child depth of 2288; do not claim an unbounded absolute CLTV ladder.

## Current finding

The legacy `POST /import_descriptor` route in `app/app.py` calls Bitcoin
Core `importdescriptors` and optionally imports an address label. It does
not durably associate the imported witness script with an authenticated
sponsor/child relation and does not write TrustedCovenantRegistration,
CanonicalAdmissionEdge, Full membership or current-entitlement evidence.

A wallet-global watch-only descriptor is **not** a grant of identity,
participant consent, UTXO ownership, or Canonical Full.

## Real demonstrator incompatibility

Existing Alice (`...59f9e923`) and Bob (`...320f80a3`) scripts parse as an
exact mirrored `cltv_only`, `legacy_777` pair with these unilateral branches:

- earlier leg: Alice at 1,777,000; Bob at 1,777,777;
- later leg: Bob at 1,777,777; Alice at 1,778,554.

The current depth-1 `CanonicalAdmissionEdgeV1` contract instead binds
sponsor Alice -> child Bob as Bob early / Alice middle, and
Alice middle / Bob late. Those are distinct role assignments even
though all three absolute heights match.

The read-only `sponsored_admission_import_preflight` classifies these
exact vectors as `reverse_branch_roles_requires_policy_review`.
**This classification cannot grant Full.** Do not relabel sender/receiver,
edit historical on-chain Scripts, change Canon's fixed semantics silently,
or invent a `TrustedCovenantRegistration` simply to satisfy tests.

## Versioned Canon V2 script-role policy (implemented, read-only)

The proposed `canonical_sponsored_script_policy_v2.py` is a **separate**
`hodlxxi.canonical_sponsored_script_evidence.v2` type. It validates
the actual sponsored CLTV-only order (sponsor early, child at the shared
middle, sponsor late) against the fixed 777-block schedule and
supports Alice→Bob at depth 1, Bob→Charlie at depth 2 and successor
sponsorship at subsequent valid depths. The witness script input
order is normalized, metadata and hashes are revalidated, and the
evidence has a canonical digest. **It is not CanonicalAdmissionEdgeV2
registration or authority.** It does not change the historical Canon V1
record validation or the existing V1 preflight classification and
always has `grants_full == False`.

See `docs/CANONICAL_SPONSORED_SCRIPT_POLICY_V2.md` for the exact
V2 policy boundary, witness ordering and admission prerequisites.

## Exact-UTXO funding snapshot preflight (implemented, read-only)

`app/services/sponsored_admission_funding_preflight.py` adds a second,
independent check over **two explicit** `CandidateOutpoint(txid, vout,
amount_sats)` values. It does not discover outpoints from wallet balances,
address labels, or `listdescriptors`. The caller is responsible for
authenticated sponsor-bound provenance; this preflight does not supply it.

The implementation:

- requires the same fail-closed mirror shape as the import preflight, preserving
  the `reverse_branch_roles_requires_policy_review` classification for the
  real Alice/Bob pair;
- derives the earlier and later witness-script SHA-256 from the authoritative
  parser and then derives the exact native-P2WSH `scriptPubKey` hashes;
- binds those hashes to explicitly selected distinct `txid:vout` outputs;
- uses the existing `TrustedBitcoinCovenantObservationAdapter` to observe
  Bitcoin Core `gettxout` and a consistent before/after best-block snapshot;
- checks both outputs, positive equal exact integer satoshi amounts,
  scriptPubKey equality, unspent state and at least one confirmation;
- returns `two_exact_utxos_observed_no_admission` for a successful snapshot.
  **All results have `grants_full == False`.**

The adapter's current `gettxout(txid, vout, False)` observes the confirmed
UTXO set with mempool excluded. A pending mempool spend therefore requires
a separate admission-time policy/check. A successful observation is neither
durable proof nor authorization, and can become stale immediately. Do not
store it as a canonical admission record or use it to refresh Full without
a separately approved transactional protocol and fresh re-observation.

The dedicated GitHub Actions workflow runs both import and funding preflight
unit tests. It has no permission or path to mutate a VPS, wallet or database.

## Canon V2 admission proposal (implemented, read-only)

A separate proposed-only domain layer now exists in
`app/services/canonical_admission_proposal_v2.py`. It binds the V2
sponsor-early script evidence to an ACTIVE exact two-outpoint
`TrustedCovenantRegistration`, an EFFECTIVE exact two-anchor
`CanonicalCovenantFundingSet`, and a recent (at most 120 seconds)
two-outpoint chain observation with positive/equal sats, exact P2WSH
scriptPubKeys, confirmations and unspent status. V2 records reference
a live genesis-evaluation anchor for depth 1 or an exact previous
**V2 proposal** at depth 2+. Bob→Charlie ancestry may be structurally
represented, but a parent proposal is not proof Bob is currently Full.

Import provenance, sponsor-key evidence and child acceptance are
recorded as distinct SHA-256 **references**, not as cryptographically
verified signatures. Bitcoin observations must originate from the
trusted adapter; a caller-supplied observation alone is not independent
on-chain proof. This code creates no DB row, automatically verified
membership, current-entitlement evidence or Social role. Both
`grants_full` and `is_effective` remain unconditionally false.

The sponsor-relative pair hash from the V2 script evidence differs
from the child-relative pair hash in a trusted registration. Exact
scripts, participant keys and on-chain outpoint bindings are therefore
compared, not falsely equated between these two perspectives.

## Two independently signed admissions (read-only preflight)

The new `app/services/canonical_admission_consent_v2.py` implements
role-separated Bitcoin Signed Message verification through the same
`verifymessage` RPC style used by the current UBID browser login.
For each proposed Canon V2 admission it creates a random 256-bit
challenge and constructs two separate messages (sponsor and child),
binding protocol domain, Bitcoin network, full proposal digest,
signer key, counterparty key, role, nonce and expiry (maximum 5 minutes).

Verification requires distinct canonical compact Bitcoin message
signatures from **both** sponsor and child; each is verified by Bitcoin
Core against the P2PKH address derived from its actual compressed key.
The implementation explicitly fails closed if RIPEMD160 support is
missing, rather than using the legacy utility's fallback. The
verification receipt contains message/signature hashes, never grants
Full, and is not itself a trusted signed authority.

**Not yet implemented:** server-side ownership of issuance,
transactionally unique issued/consumed nonce, authenticated sessions,
durable signed consent storage, current sponsor Full lineage,
funding/reorg/mempool observation transaction boundary, or any
entitlement/Social publication. A caller may construct a challenge
and fake an already-verified receipt if the admission path were to
trust these data objects; it must not. Future admission must consume
only freshly verified outputs of the trusted server authority
and must enforce replay prevention atomically.

## Required continuation (not implemented by this preflight PR)

1. **Ingest after confirmed import.** A successful, exact scoped descriptor
   import emits an idempotent, authenticated sponsor-bound event. Make the
   event durable in staging; avoid deriving sponsor authority from a
   wallet-global `listdescriptors` scan. A failed Bitcoin Core import
   creates no admission event.
2. **Match two exact scripts.** Parse with the existing
   `parse_covenant_leg` and `validate_mirrored_covenant_pair` validator.
   Enforce same two pubkeys, reversed unilateral roles, equal 777-block
   deltas, valid common middle height, exact CLTV-only profile, and distinct
   script hashes. One-leg arrival remains `pending`.
3. **Bind exact UTXOs.** The read-only two-UTXO snapshot preflight exists;
   authenticated provenance, admission-time mempool policy, durable binding
   and atomic re-observation are **not yet implemented**. Verify Bitcoin Core `gettxout` against the
   SHA-256 witness Script to P2WSH scriptPubKey mapping, both exact txid:vout
   identities, sufficient confirmations, positive/equal satoshi amounts,
   current unspent state, and fresh observation. Reject wallet balances,
   merely imported address labels, and unrelated outputs.
4. **Prove sponsor and child.** Use the canonical current-entitlement
   resolver, not legacy Flask `session['access_level']`, for Full sponsor
   verification. Establish the child's canonical persisted user and
   authenticated public-key possession. Require an explicit approved
   consent/acceptance protocol if required by the current Canon; a public
   descriptor is not child consent. Reject circular or competing sponsors.
5. **Complete Canon V2 admission from the versioned script policy.**
   The independent V2 script-role policy now validates the actual
   demonstrator arrangement, including sponsors at depth >0. A distinct
   effective Canon V2 admission record, durable registry, lineage-aware evaluator,
   lifecycle and explicitly approved entitlement policy are **still
   required**. Fail closed until these are implemented and approved;
   do not reinterpret or mutate V1 records.
6. **Atomic canonical persistence.** Within one controlled, locked,
   idempotent transaction append the authorized Trusted Registration,
   funding set, Admission Edge and relevant observation/provenance;
   latest negative/revoked state must not be overwritten by a stale retry.
   Use existing repositories, not a new role flag or hidden operator key.
7. **Refresh for ordinary participants.** The existing root refresh timer
   targets Alice specifically. A generic member/lineage evidence refresh
   must maintain Bob's short-lived `current_entitlement_evidence`
   without running a root-only policy under Bob's identity. Social
   continues reading `/agent/authority/current/<subject>.json`.
8. **Historical recovery.** Provide a guarded, staging-only replay for
   previously imported descriptors and both currently unspent exact
   outputs. Require explicit sponsor ownership binding and provenance;
   do not equate an arbitrary wallet-global descriptor with Alice's import.

## Acceptance tests

- Alice and Bob's literal on-chain scripts: pair recognized but admission
  blocked under unamended Canon V1; never grant Full from the preflight.
- Canon-aligned synthetic depth-1 pair: structural candidate only.
- Any one-leg, duplicate, nonmatching, spent/unconfirmed or unequal UTXO,
  ambiguous provenance, key mismatch, stale sponsor, revoked evidence, or
  conflicting registration: fail closed without Full writes.
- After separately approved policy and durable ingress implementation:
  Alice imports both scripts; Bob accepts/verifies; staging UBID and
  Social independently report `full`; Full Directory and device
  admission function; repeat import makes no duplicate evidence.
- Bob can sponsor Charlie under the same exact published rules.
- Production unchanged until all tests and staging E2E pass.

This PR contains **read-only V1 structural and exact-UTXO snapshot preflights,
a V2 script-role evidence validator, a source-bound proposed-only V2
admission object, regression tests and CI**.
No `/import_descriptor` route changes, database migrations, automatic
grants, cron/timer changes, production writes, or deployments.
