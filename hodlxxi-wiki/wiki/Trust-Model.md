# Trust Model (Repository-Grounded)

## Framing
Repository trust narrative emphasizes cryptographic identity, signed outputs, and observable operation history, while explicitly avoiding overclaiming unproven on-chain backing.

## Verified/runtime-exposed trust anchors
- Public-key identity and signed capability surfaces are exposed through `/.well-known/agent.json` and `/agent/capabilities`.
- Attestation and reputation endpoints exist for observable job history (`/agent/attestations`, `/agent/reputation`, `/agent/chain/health`).
- Tests verify language boundaries such as `unfunded_declared` and wording that avoids proving uptime/capital from declaration alone.

## Declared but bounded anchors
- Operator identity binding is runtime-declared metadata.
- Covenant/time-locked-capital motifs are present in docs/trust payloads, but repository surfaces explicitly flag these as optional or not verified by default.

## Discipline for future updates
When updating trust language:
1. Keep cryptographic and economic claims tied to concrete runtime surfaces.
2. Distinguish declared metadata from verifiable enforcement.
3. Preserve `optional_not_verified` style semantics unless new proof endpoints are implemented, tested, and runtime-evidenced.

## See also
- [Covenant Model](./Covenant-Model.md)
- [Reputation Surface](./Reputation-Surface.md)
