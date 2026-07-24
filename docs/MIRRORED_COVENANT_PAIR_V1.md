# Canonical Mirrored Covenant Pair Validator V1

This pure-domain validator parses authorization-grade raw Bitcoin Script hex. One leg is
not one mirrored pair: in a directed leg the receiver has the earlier unilateral CLTV
path, the sender has the later fallback, and direction is sender → receiver.

The leg schema is `hodlxxi.mirrored_covenant_leg.v1`; the pair schema is
`hodlxxi.mirrored_covenant_pair.v1`; the validator version is
`hodlxxi.mirrored_covenant_pair_validator.v1`; and the network is exactly `bitcoin`.

## Exact mirror contract

For legs A then B, A.receiver equals B.sender, A.sender equals B.receiver,
A.sender_height equals B.receiver_height (the single shared middle height), and both
deltas are equal. Input order does not matter. Both legs must contain the same exact two
compressed secp256k1 pubkeys. Therefore **Alice incoming + Bob outgoing is not FULL**:
unrelated counterparties cannot make an exact reciprocal pair.

Supported families are `cltv_only` (two exact unilateral CLTV branches) and
`cooperative_2_of_2_cltv` (an exact cooperative 2-of-2 branch plus those two fallback
branches). Mixed families, extra paths, alternative thresholds, repeated or third
participants, non-minimal encodings, and trailing bytes fail closed.

Lock heights 1–16 use `OP_1`–`OP_16`; larger heights use minimally encoded positive
ScriptNum direct pushes; zero and negative ScriptNums are invalid lock heights.

`current_144` means 144 blocks and `legacy_777` means 777 blocks. A caller supplies an
immutable allow-list; legacy is never accepted implicitly and arbitrary deltas are never
classified.

Exact compressed keys are authoritative for mirroring. X-only identities are exposed
for downstream use, but two distinct compressed keys with one x coordinate are rejected
because an exact-pair downstream layer could not distinguish them.

Raw Script hex is the authoritative source of every parsed leg field. Semantic fields
cannot be supplied independently: direct leg and pair dataclass construction is
revalidated against the raw Scripts, and canonical pair bytes are produced only after
full pair revalidation.

## Boundaries and explicit non-claims

The one declared, unfunded operator-agent script is one leg, not a pair. An unfunded
declaration is not funding; put exactly: **unfunded declaration is not funding**.
Script validation is not UTXO observation, and **pair validation is not entitlement**.
In particular this validator does not:

- inspect blockchain state, Bitcoin Core, explorers, wallets, descriptors, balances,
  outpoints, confirmations, funding, unspent status, browser or Flask sessions;
- establish KYC or legal identity, key possession, private-key ownership, descriptor
  ownership, or transaction ownership;
- create, sign, fund, or broadcast a transaction;
- write entitlement evidence or grant FULL access;
- expose a route, CLI command, scheduled job, or MCP surface;
- deploy, migrate, restart services, or alter production declarations.

Trusted registration and outpoint binding belong to future PR6.8. That later boundary
may connect exact declarations to trusted observations; this validator deliberately
makes no claim about funding, UTXOs, balances, or entitlement.
