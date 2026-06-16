<!-- HODLXXI_RUNTIME_PRODUCT_POSITIONING_V1 -->
# HODLXXI Runtime Product Positioning

HODLXXI is a Bitcoin-native trust runtime for public-key agents and services.

Short framing:

`Trust infrastructure for public keys.`

This document fixes the current product direction so the project does not become publicly too broad.

## 1. Core product

The core product is the runtime layer:

- public-key identity
- machine-readable capabilities
- Lightning-priced agent jobs
- signed receipts
- attestations
- reputation surfaces
- runtime health
- Nostr-compatible messaging policy

The core loop is:

`public key -> capability -> paid job -> result -> receipt -> attestation -> reputation`

## 2. Best current wedge

The strongest current wedge is:

`Receipt/attestation API + paid agent runtime`

This means an external app can discover HODLXXI, request a paid job, verify the signed receipt, and use attestations or reputation as a trust signal.

## 3. First external developer path

The first developer path is documented in:

- `docs/AGENT_RECEIPT_QUICKSTART.md`

That path is:

1. discover the runtime
2. inspect capabilities
3. request a paid job
4. poll the job
5. verify the receipt
6. inspect attestations and reputation

## 4. What HODLXXI is not

HODLXXI should not be introduced first as:

- a generic marketplace
- a P2P exchange
- a custodial trading system
- a wallet
- a social network
- a covenant-only demo
- a broad civilization protocol

Those may be downstream applications or long-term research directions, but they are not the first public product framing.

## 5. Role of KeyMarket

KeyMarket is a demo consumer app built on top of the runtime idea.

It demonstrates how a marketplace-like application can use public keys, offers, message envelopes, deposits, receipts, attestation exports, and runtime probes.

KeyMarket is not the core product. HODLXXI is the reusable runtime layer.

## 6. Role of readiness scanning

Agent Readiness Report is a good onboarding product and lead magnet.

It should be treated as an entry use case:

- scan a target service
- inspect public machine-readable endpoints
- check capabilities
- check Nostr policy
- check runtime and Lightning health
- produce JSON and human-readable report
- issue receipt or attestation

Readiness scanning supports the runtime story, but the runtime itself remains the core product.

## 7. Product priorities

Near-term priorities:

1. Make the receipt/attestation path easy for external developers.
2. Keep the paid agent job lifecycle deterministic and documented.
3. Make public discovery surfaces stable and machine-readable.
4. Keep test coverage around agent, receipt, trust, and public surfaces strong.
5. Avoid adding high-compliance-risk exchange behavior before legal review.

## 8. Public one-liner

Use this as the main external framing:

`HODLXXI is a Bitcoin-native trust runtime for public-key agents and services.`

Use this as the short framing:

`Trust infrastructure for public keys.`

<!-- END_HODLXXI_RUNTIME_PRODUCT_POSITIONING_V1 -->
