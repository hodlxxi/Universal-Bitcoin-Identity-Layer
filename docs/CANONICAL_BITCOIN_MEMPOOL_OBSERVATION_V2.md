# Canon V2 mempool-inclusive N+M source preflight (dormant)

**Stacked on #586 → #585 → #584 and predecessors. This code is not an EFFECTIVE admission.**

## Why this gate exists

The old `TrustedBitcoinCovenantObservationAdapter` calls
`gettxout(txid, vout, false)`. Bitcoin Core's `include_mempool=false`
ignores mempool spends. Thus an output still in the chain UTXO set but
already spent by a mempool transaction can appear available.

The new `observe_multileg_with_mempool_v2` is an independent, deliberately
unwired read-only helper. It sends **`gettxout(..., true)` for every N+M
outpoint**, retaining the existing strict amount, P2WSH `scriptPubKey`
hash, confirmations and sorted-outpoint validation. It requires an exact
nonempty earlier side, later side, min(total earlier, total later), and
up to 256 signed outpoints through the existing immutable mirror types.

It also brackets the scan with:

- `getblockcount` and `getbestblockhash`, refusing a changed chain tip;
- `getrawmempool(false, true)`, requiring a valid integer mempool sequence
  and refusing any intervening mempool sequence change.

The mempool TXID list is not copied into the receipt or persisted.

The operation fails closed if an output is already spent in the node's
mempool, unconfirmed, mismatched, missing, or if the tip or mempool
sequence changes. An unavailable/nonconformant RPC or non-second-precision
clock is also rejected.

## What it **does not** establish

1. **No trusted caller.** The RPC interface is injected for source-only
   testing; a fake, compromised, remote, or caller-controlled RPC can lie.
   A future active service must construct the Bitcoin Core RPC instance from
   server-owned authenticated configuration, not a request field.
2. **No permanent snapshot.** A successful observation is true only for
   that node during that check. It cannot prevent a future mempool spend,
   double spend by unseen peers, or blockchain reorganization. Re-observe
   immediately before any eventual EFFECTIVE transition, capture the chain
   source, and define reorg and revoke/downgrade semantics independently.
3. **No proof of participant control.** Output existence and script identity
   are different from proof of keys and fresh consent, and cannot replace
   current Full sponsor authority, replay protection or a validated complete
   effective ancestor chain.
4. **No membership update.** `RUNTIME_ENABLED=False`, no route, service,
   scheduler, database migration, Full publication, or Social status changes.
   `source_is_authoritative`, `is_effective`, and `grants_full` remain
   false on the returned typed evidence.
5. **No guarantee of network-wide mempool state.** Only the queried Bitcoin
   Core instance and its observed mempool/chain state are covered. The
   double-sequence check closes drift *during this scan*, not after it.

## Verification

Isolated unit tests use controlled fake Bitcoin RPC responses and model
a realistic 3+2 collateral distribution, unequal aggregate sides, unconfirmed
outputs, mempool spends, a changing chain tip, mempool sequence drift,
malformed RPC output, unavailable RPC and script mismatches. They assert
that every call carries `include_mempool=true`.

All test signatures, chain responses and participant authority are synthetic.
A later disposable PostgreSQL acceptance test must bind this source to the
one-transaction global collateral ledger, fresh authenticated signer proof
and independently verified current sponsor Full.

No merge, production migration, runtime restart or live activation is
authorized by this source-only change.

Bitcoin Core RPC documentation:
- https://bitcoincore.org/en/doc/30.0.0/rpc/blockchain/gettxout/
- https://bitcoincore.org/en/doc/30.0.0/rpc/blockchain/getrawmempool/
