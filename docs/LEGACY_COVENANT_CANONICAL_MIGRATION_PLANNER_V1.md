# Legacy Covenant Canonical Migration Planner V1

Status: **IMPLEMENTED SOURCE-ONLY / OPERATOR DRY-RUN / NOT PRODUCTION-ACTIVATED**

This component produces a deterministic, minimized plan describing legacy
covenant observations and relationships that can be proved as possible
bootstrap candidates under the current Canon. It does not decide who is Full,
bootstrap records, or change runtime authority.

## Authority boundary

Sponsor proposes. Bitcoin proves. UBID verifies. Canon determines Full. Login
only activates access. Social only displays the result. Explorer observation is
Bitcoin evidence; it is never canonical membership authority.

A Bitcoin Core wallet is an observation/indexing container. Two watch-only
wallets can contain the same descriptor and the same UTXO. Wallet occurrence is
therefore not covenant identity. The planner deduplicates witness scripts by
exact bytes (and their exact SHA-256), outpoints by exact `txid:vout`,
participants by canonical x-only public-key identity in memory, and
relationships by the unordered participant pair. Wallet provenance is reduced
to an opaque count and cannot affect a decision.

The current human admission profile remains `legacy_777`. The planner reuses
the existing Bitcoin Script opcode parser and mirrored-pair validator from
`mirrored_covenant_pair`, and the existing cascade heights, confirmation
threshold, lifecycle representations, and read-validated canonical records
from `canonical_admission_edge` and `trusted_covenant_registration`. It does not
create a second Canon. A candidate that cannot be proved with those contracts
fails closed.

Observed `current_144`, delta 164, same-window, nested, cooperative, ambiguous,
or malformed structures remain classified inventory. They are not silently
promoted. A future change from 777 to 144 requires a separate review.

## Planning pipeline

1. An operator supplies immutable observations from every approved observation
   wallet and a read-only snapshot built from validated canonical records.
2. `raw(...)` witness scripts are extracted, exact-byte deduplicated, and parsed
   with the existing opcode-aware parser. No regex searches raw script hex for
   public keys.
3. Parsed scripts are grouped by the exact unordered normalized participant
   pair. Unsupported scripts remain opaque diagnostics.
4. UTXOs are globally deduplicated by exact transaction ID and output index.
   Conflicting facts about one outpoint fail the whole plan closed.
5. A UTXO is associated with a witness script only when its scriptPubKey is
   exactly `00 20 SHA256(witness_script)` (native P2WSH).
6. Exact scripts are compared with current relationships selected through an
   EFFECTIVE root binding or EFFECTIVE ordinary admission edge. An exact
   current relation is `already_canonical`; registration activity alone is not.
7. Genesis comes from the injected current canonical snapshot. Reachability and
   depth start only with effective canonical edges. An observed relationship
   can extend candidate reachability only after exact current-profile structure,
   cascade orientation, funding, amount, and confirmation checks pass.
8. Deterministic JSON is sorted and hashed. Exact source values never enter the
   public serializer.

The pure planner has no SQLAlchemy session, RPC client, or mutation method. The
operator CLI can consume an explicitly prepared JSON observation/snapshot
export. Its explicit `--live` mode reads all loaded Bitcoin Core wallets using
only `listwallets`, `listdescriptors`, and `listunspent`; it loads existing
Genesis, root-registration bindings, admission-edge, and trusted-registration
records through their read APIs. Root-bound registrations are included even
when no ordinary admission edge refers to them, but only through the
authoritative `resolve_effective` seam. Historical proposed, disputed,
superseded, or revoked root bindings never contribute current canonical state.
Root resolution and snapshot construction use one common evaluation timestamp;
ambiguous, malformed, digest-mismatched, wrong-Genesis, or inactive-registration
sources fail closed.

Trusted registration != current admission. A trusted registration proves the
registration layer only; it does not independently make an ordinary human
relationship current in Canon. Current relationship authority has exactly two
seams:

- root: the active registration selected by the source-validated EFFECTIVE
  canonical root binding;
- ordinary child: the exact active registration referenced by a
  source-validated EFFECTIVE canonical admission edge.

Registrations referenced only by proposed, disputed, superseded, or revoked
admission edges remain historical facts. They cannot produce
`already_canonical`, cannot extend canonical reachability, and conservatively
produce `canonical_conflict` with
`historical_admission_edge_not_current_authority`. When the registration itself
is still active, the additional reason is
`active_registration_without_effective_admission`. The planner does not decide
whether a future bootstrap should reuse, transition, revoke, or replace it.
PostgreSQL connections set `default_transaction_read_only=on`. This keeps live
access out of tests while providing an operator-only production rehearsal path.
Any collection/configuration failure is reported generically so credentials are
not echoed.

## Relationship classes

- `role_swapped_contiguous_triple`: roles swap across two legs with one shared
  middle height and equal adjacent deltas.
- `role_swapped_same_window`: roles swap but both scripts use the same window;
  this is not current human Canon.
- `single_script_only`: the reciprocal leg is absent.
- `multiple_scripts_other`: multiple scripts do not prove one supported pair.
- `nested_or_cooperative`: the parsed family is not the current simple CLTV
  admission family.
- `unsupported_delta`: the reciprocal structure uses an unrecognized delta.
- `ambiguous_multiple_profiles`: one pair contains incompatible profiles.

## Decisions and reasons

- `already_canonical`: exact scripts have current authority through an
  EFFECTIVE validated root binding or EFFECTIVE validated admission edge;
  `canonical_record_already_exists`.
- `eligible_for_bootstrap`: and only this status means all current `legacy_777`
  structure, exact native-P2WSH funding, confirmations, cascade depth and
  canonical sponsor-lineage facts were proved. It is still only a plan.
- `incomplete_relation`: `only_one_script`.
- `incomplete_funding`: `only_one_funded_leg` or
  `required_leg_amounts_do_not_match`.
- `unconfirmed_funding`: `minimum_confirmations_not_met`.
- `unsupported_profile`: explicit reasons distinguish 144, 164, same-window,
  and nested/cooperative observations.
- `ambiguous`: conflicting scripts, profiles, sponsor orientation, or multiple
  currently unspent outpoints for one required leg.
- `unreachable_from_genesis`: `sponsor_not_canonical`.
- `canonical_conflict`: current authority conflicts, or historical registration
  state exists without current admission authority. Historical reasons include
  `historical_admission_edge_not_current_authority`,
  `active_registration_without_effective_admission`, and
  `registration_without_current_admission_authority`.
- `invalid`: for example `candidate_heights_do_not_match_depth`.

Browser `users` existence is optional diagnostics only. It neither creates nor
rejects a participant or candidate. The planner never calls legacy balance
ratio code. `wpkh`/XPUB descriptors are counted only as non-raw descriptors;
XPUB remains Checking-only private metadata and never supplies identity or
eligibility.

## Output privacy

Default human and JSON reports contain only domain-separated opaque diagnostic
references. They do not contain raw/compressed/x-only public keys, descriptors,
witness scripts, transaction IDs, addresses, XPUBs, wallet names, private keys,
RPC or database credentials, cookies, or tokens. Opaque refs are diagnostic and
are not canonical IDs. Exact material exists only in the in-process input and
validation objects.

Example:

```console
python scripts/legacy_covenant_canonical_migration_plan.py \
  --input /operator/read-only-observation.json --pretty
```

For a separately authorized runtime dry run, `--live` requires explicit
`DATABASE_URL`, `RPC_USER`, `RPC_PASSWORD`, `RPC_HOST`, and `RPC_PORT`
configuration. It queries every wallet returned by `listwallets`; wallet names
remain opaque in output.

The command is visibly labelled `READ-ONLY DRY RUN`. It provides no `--apply`,
`--write`, `--bootstrap`, or `--activate` option. `--output` can write only the
minimized report selected by the operator; it cannot write PostgreSQL or a
Bitcoin wallet.

## Explicit non-claims

This planner does not determine Full or Verified, grant access, create a browser
user, create canonical participants/admissions/registrations/funding sets or
entitlement evidence, write PostgreSQL, mutate a wallet, import descriptors,
derive Checking authority, activate Full Directory, expose an HTTP/MCP/Social
surface, or replace legacy login authority. Observed graph connectivity is not
canonical lineage. Funding is not membership. A User row is not participant
proof.

The next intended step is a separately reviewed, controlled bootstrap design.
No bootstrap or production action is authorized by this source-only planner.
