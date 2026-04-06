# Experimental / Partial / In-Progress

This page tracks items that are incomplete, transitional, or aspirational. Entries here are not "working now" claims.

## Partial implementation surfaces
1. **LNURL-auth cryptographic verification depth**
   - Callback code includes placeholder commentary; treat cryptographic verification posture as partial.

2. **PoF semantics and UX hardening**
   - PoF routes are present, but privacy/aggregation semantics and product polish should be treated as evolving implementation details.

3. **Covenant trust lane progression**
   - Covenant declarations exist, but funded/on-chain enforcement exposure is intentionally limited in runtime trust claims.

## Refactor in progress
1. **Monolith-to-factory transition**
   - Repository contains both legacy monolith and factory/blueprint paths, indicating ongoing migration.

2. **Route/path duality and compatibility layers**
   - `/api/*` and `/api/bitcoin/*` coexist in different modules; legacy proxies/compat blueprints remain active.

## Planned / aspirational (explicitly documented)
- Factory-first architecture completion beyond current mixed state.
- Additional refactor/modularization goals noted in docs roadmap sections.
- Broader Lightning/payment stabilization themes described in docs.

## See also
- [Roadmap](./Roadmap.md)
- [Architecture](./Architecture.md)
