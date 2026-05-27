# NIP-17 Runtime Plan (Phase 0 Contract Layer)

## Scope
This document defines a **Phase 0 runtime contract** for introducing NIP-17 messaging support in HODLXXI using documentation and contract tests only.

Phase 0 is intentionally non-invasive:
- no runtime behavior changes
- no route removals
- no schema migrations
- no Socket.IO flow changes
- no plaintext messaging rewrites yet

## Current State
HODLXXI currently provides:
- Factory-created Flask runtime from `wsgi:app`.
- Existing browser and agent surfaces for login, app access, discovery, and messaging endpoints.
- Working real-time messaging/signaling paths already in production contract scope.

At this phase, no NIP-17-specific runtime feature flag behavior is required.

## Target State
Target architecture is a staged evolution to Nostr-native messaging contracts where:
- Runtime can publish and consume NIP-17-compatible envelopes.
- Ciphertext transport is the default and eventually mandatory mode.
- Agent capabilities can advertise supported messaging metadata without breaking existing clients.

The end-state is not implemented in Phase 0; this document establishes compatibility and safety constraints.

## Plaintext Risk
Plaintext chat payload paths create long-term risks:
- relay/operator visibility of message contents
- accidental logging leakage of sensitive content
- weaker privacy guarantees versus modern Nostr DM expectations

Phase 0 explicitly acknowledges this risk while preserving existing runtime behavior.

## Ciphertext-Only Future Model
Future phases should converge on a ciphertext-only model:
- NIP-44 encrypted content as the payload baseline
- NIP-17 envelope semantics for DM routing and client interoperability
- clear policy that plaintext transport is deprecated and then disabled by staged rollout gates

## NIP Overview (NIP-17, NIP-44, NIP-59)
- **NIP-17**: higher-level private direct messaging conventions for interoperable DM flows.
- **NIP-44**: encryption format expectations for modern private message content.
- **NIP-59**: gift-wrap style event packaging patterns used to transport encrypted payload artifacts.

Together, these define a migration path from ad-hoc plaintext/runtime-local messaging toward interoperable encrypted Nostr messaging.

## Kind Goals
### Kind 14 / Kind 15 Goals
Phase goals for message kinds:
- preserve route contracts that may carry message ingress/egress responsibilities
- reserve capability declaration space for kind 14/15 handling metadata
- avoid hard enforcement until encrypted-path rollout phases begin

### Kind 10050 Relay Discovery Goals
Discovery goals:
- prepare capability and discovery surfaces for relay hint publication
- support future policy where messaging clients can discover preferred relays
- keep Phase 0 additive: no mandatory runtime dependency on kind 10050 yet

## Custody and Key Ownership Invariant
**HODLXXI must never require custody of user private keys.**

All NIP-17 evolution must preserve user-controlled key material and non-custodial login/messaging assumptions.

## Migration Phases
1. **Phase 0 (this phase): Contract layer only**
   - docs + tests
   - no behavior change
2. **Phase 1: Capability surfacing**
   - optional metadata exposure for planned NIP-17/NIP-44 support
3. **Phase 2: Dual-path messaging**
   - plaintext legacy path + encrypted path coexistence behind explicit policy gates
4. **Phase 3: Encrypted default**
   - ciphertext path becomes default
5. **Phase 4: Ciphertext-only enforcement**
   - plaintext path removed/deactivated after compatibility and telemetry criteria are met

## Rollback Strategy
At every phase boundary:
- keep prior route contracts intact until next phase is proven
- gate new policy with reversible config flags
- maintain last-known-good runtime artifact for immediate deploy rollback
- avoid schema-coupled rollouts during messaging contract transition

## Staging-First Rollout Strategy
Rollout order:
1. Validate contract tests in local and CI.
2. Deploy to staging with observability checks and compatibility verification.
3. Exercise legacy clients and candidate NIP clients against discovery + messaging surfaces.
4. Promote to production only after staging pass criteria are met.

No phase should promote directly to production without staging validation.
