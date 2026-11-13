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
3. **Bind exact UTXOs.** Verify Bitcoin Core `gettxout` against the
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
5. **Resolve Canon policy incompatibility explicitly.** Review the
   reversed first-leg roles using a versioned policy/protocol amendment
   compatible with the shipped real Scripts and with sponsors at depth >0.
   Require audited membership semantics and propagation of sponsor
   lineage. Fail closed until approval; never silently downgrade checks.
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

This PR contains **only the pure read-only structural preflight and its
regression tests**. No `/import_descriptor` route changes, database migrations,
automatic grants, cron/timer changes, production writes, or deployments.
