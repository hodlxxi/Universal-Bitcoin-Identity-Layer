# Risk and Honesty Notes

## Centralization risks
- The system is operated from a hosted service model and currently depends on an operator-controlled runtime, keys, database state, and infrastructure.
- Public-key identity and signed receipts improve accountability, but they do not remove operator centralization.

## Survivability gaps
- The agent trust model itself says the system does not prove future uptime, long-term persistence, or censorship resistance.
- There is no verified runtime proof in this checkout that the service can survive operator disappearance or infrastructure loss.

## Protocol clarity gaps
- The repository contains a mix of mature runtime code, legacy monolith paths, and forward-looking docs.
- Grant reviewers should be told plainly that protocol surfaces exist today, but some narratives around them are ahead of the implementation.

## Interoperability gaps
- OAuth/OIDC and public JSON surfaces are present, but outside-developer packaging and integration examples still need work.
- Local self-hosting and contributor onboarding are improving but not yet fully smooth.

## Covenant/runtime gap
- Covenant-related tooling exists today as descriptor inspection, script decoding, and participant matching.
- That is not the same as a currently exposed proof surface for long-horizon covenant backing, reserves, or service survivability.
- This is the most important area where applications must avoid overclaiming.

## Market and adoption uncertainty
- There is no basis in this repository to claim broad adoption.
- The public-good thesis is credible, but ecosystem demand for a Bitcoin-native identity layer still has to be proven through actual use.

## How to phrase these honestly without killing the application
Use language like this:
- "The project already exposes working Bitcoin-native identity, OAuth/OIDC, Lightning payment, and verifiable receipt surfaces."
- "It is not yet fully mature, decentralized, or backed by runtime-exposed covenant proofs."
- "Funding would harden and clarify an implemented open-source stack rather than fund a purely speculative concept."
- "The project's strongest present value is reusable infrastructure and verification surfaces, not claims of complete trustlessness."
- "Covenants remain an important design direction, but current grant requests should center on the functionality that is verifiable in code today."
