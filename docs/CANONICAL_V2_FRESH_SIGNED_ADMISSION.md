# Issue #588 — signed N+M candidate, newer server Bitcoin Core scan (PR #591)

**State:** source-only, RUNTIME_ENABLED=False on existing services. Never
activate or migrate live databases from this PR. This is a genuine
*composition of proposed-candidate intake* with the server Core adapter,
not EFFECTIVE admission or Full authority.

## Fixed authorization/provenance boundary

Before this change `validate_canonical_multi_outpoint_admission_proposal_v2_sources`
required `proposal.snapshot == current_snapshot`. Because a real sponsor
and child sign across independent interactions, an initially signed
snapshot (with an exact timestamp/hash) cannot equal a later
mempool-inclusive Bitcoin observation. Requiring literal equality made
a practical, fresh observation path impossible.

New `validate_canonical_multi_outpoint_admission_fresh_sources_v2` retains
the **original signed proposal SHA and every exact UTXO commitment** but
compares it to a fresh observation. It rejects any changed txid/vout,
direction, value, P2WSH script, child/sponsor key, parent basis, aggregate
mirror balance, or trust ceiling. Both mirrored sides must be confirmed
and unspent. Observation is required within 30 seconds of finalizing,
at or after signing and at an equal or greater block height; finalization
must be within the existing 300-second nonce TTL relative to the
original proposed_at. The durable nonce ledger separately enforces its
real issuance time, one-use consumption, and role-separated BTC signatures.

The original strict validator remains unchanged for existing callers.

## Server + transaction composition

`SqlAlchemyCanonicalMultiLegCandidateRegistryV2.reserve_candidate_from_server_in_transaction`
now reads **server-configured Bitcoin Core** (network, tip, IBD and mempool
sequence checks) and uses its server-only RPC for signature verification.
The caller's already-open PostgreSQL transaction locks and verifies the
sponsor's Current Full, consumes both signatures' issued challenge,
and atomically stores an immutable PROPOSED candidate with the **new**
observation digest/height/time and all live UTXO reservations. Failure
rolls back the nonce, header and all outputs. This removes one missing
realistic step between #590 and authoritative intake.

## Security limitations — stop before any Full/production activation

- The method still accepts `authenticated_sponsor_pubkey` and
  `authenticated_child_pubkey` parameters from its **caller**. There is
  not yet a server-authenticated, separate sponsor/child session ingress,
  so *even a successful proposed candidate is not trusted admission*.
- A depth >0 sponsor currently checks a parent *candidate*, not an
  independently verified EFFECTIVE ancestor. The final registration must
  require the latter and current sponsor Full.
- The source-only server Core adapter cannot independently attest
  operator control of the local bitcoind. Restrict DB/RPC process and
  permissions, validate staging service identity and use a non-owner
  PostgreSQL writer role.
- **Do not** write `canonical_multileg_effective_edges_v2` or
  `current_entitlement_evidence` from this method. Those must be bound
  to the trusted session and fresh Core proof in one separately reviewed,
  lock-guarded transaction, with expiry/spend/reorg handling and the
  exact child-identity uniqueness policy across strict-two and multileg.
- Current `Current Full` authority must fail closed on invalidated
  collateral, revocation, timeout or network outage. Do not assume a
  materialized Full row is permanently valid.
- No Social changes; no messaging changes; no stage/prod runtime flags.

## Verification

Focused CI runs the existing atomic multileg PostgreSQL 16 tests plus
additional in-transaction fresh Core tests, with a **synthetic** fake RPC,
and pure unit cases for 3+2 outputs, delayed signatures, malformed/missing
UTXOs, changed scripts/amounts, stale snapshots, incorrect parent and
rollback. A fake local Core in tests is NEVER proof of Bitcoin funding.

**Next required implementation:** independent authenticated two-session
challenge + stored signed proposal, server Core final verification
within an authoritative EFFECTIVE/Current Full transaction, and full
Alice→Bob→Charlie staging probes. Production remains untouched.
