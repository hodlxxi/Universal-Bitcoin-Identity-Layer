# HODLXXI Nostr DVM Compatibility

HODLXXI exposes a template-only Nostr/DVM announcement surface:

- `GET /agent/nostr/announcement`

This endpoint helps Nostr DVM, NIP-89, and NIP-90 builders understand how to advertise or call the existing HODLXXI paid agent runtime.

## Runtime flow

discover -> inspect -> request -> invoice -> pay -> result -> receipt -> trust event

## Non-goals

This endpoint does not:

- publish to Nostr relays
- sign Nostr events with a Nostr private key
- manage NIP-47 / Nostr Wallet Connect spending
- trigger auto-payments
- custody user funds

## Intended use

External DVM builders can fetch this endpoint, inspect the template, and adapt it for their own Nostr tooling.


## NIP-90 examples

See `docs/AGENT_NIP90_COMPATIBILITY.md` and `examples/nostr/` for request, feedback, and result examples.
