# Agent receipt v1 fixtures

These fixtures are deterministic examples for HODLXXI receipt v1 canonicalization, hash, and verifier-state tests.

They cover:

- recomputing `request_hash` from `request_payload.json`,
- recomputing `result_hash` from `result_payload.json`,
- canonicalizing an unsigned receipt before signature verification,
- canonicalizing a signed receipt for `event_hash`, and
- normalized verifier JSON for HTTP 409 `no_receipt` and HTTP 404 `not_found` states.

The `receipt_signed.json` signature is an illustrative placeholder. It is not a valid production signature unless a test explicitly proves it against the included `agent_pubkey`; the current fixture tests do not make that claim. Live signatures must be verified against the receipt `agent_pubkey` from live receipts. The fixture `agent_pubkey` is a deterministic fixture public key, not a production HODLXXI operator or agent identity.

For the fixed placeholder signed receipt, `event_hash = sha256(canonical_json_bytes(receipt_signed)).hexdigest()` is:

```text
f32c21837c6810091a3934d5e5c553dfa16190c6f2b62f326f8922569ff91f77
```
