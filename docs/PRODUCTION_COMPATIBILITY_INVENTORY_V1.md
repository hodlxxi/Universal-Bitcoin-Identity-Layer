# Production Compatibility Inventory V1

Status: **REPOSITORY AUDIT — NOT DEPLOYMENT APPROVAL**

This deterministic inventory covers production/main `6873e8fb73cbea8fda43fe3609bbdbb2817d8299` through staging `0f5688692f70029d53589f7d03df54a6abae5d1b`. The merge base is the production SHA. Staging is 64 commits ahead and zero behind: 64 commits, 30 merges, 167 changed files, 31,453 additions, 162 deletions and seven migrations. The [strict JSON inventory](data/production_compatibility_inventory_v1.json) is the detailed machine contract.

## Evidence and terminology

The complete full and first-parent histories, merge subjects/PR numbers, exact file diff, factory/blueprint wiring, OAuth/OIDC/JWT/session/bearer paths, action gateway, models/storage, every migration, PR6.8–PR6.20, MCP/systemd/release material, tests, required status documents and Compass were inspected. Repository evidence cannot establish host, schema, data, ledger, service or RPC truth.

**Active** means registered/configured and reachable at startup or on a request. **Dormant** means checked in but not runtime wired. **Deployed** requires host evidence; **not deployed at pinned main** means absent from the production basis, not a live-host finding. Imported is not invoked, registered is not called, source-only is not deployed, and reference proof is not current proof.

## Component and startup analysis

The JSON classifies material file families into `SECURITY_AUTH_FOUNDATION`, `SCHEMA_MIGRATION`, `ACTIVE_RUNTIME_COMPATIBILITY`, `DORMANT_CRT_DOMAIN`, `READ_ONLY_PROOF_SURFACE`, `LIVE_SOURCE_LOOKUP`, `BITCOIN_OBSERVATION_WIRING`, `SHADOW_ENTITLEMENT`, `ENFORCEMENT`, `DEPLOYMENT_TOOLING`, `FEDERATION_REPLICATION`, and `DOCUMENTATION_TEST_ONLY`, with status, dependencies, effect, risk, train, rollback and non-claims.

- `app.factory.create_app` configures the local session secret, loads existing RS256 signing material, initializes infrastructure, and calls `register_blueprints`. `app.factory.register_blueprints` imports and registers `app.oidc.oidc_bp`, `app.blueprints.oauth.oauth_bp`, and `app.blueprints.crt_authorization_proof.crt_authorization_proof_bp`.
- OAuth/OIDC/JWT is startup-imported and request-active. `app.blueprints.oauth` hardens registration, redirects, PKCE, scopes, token issue/introspection and invokes `validate_canonical_access_token`. `app.oauth_utils.token_required` invokes strict bearer parsing, `validate_canonical_access_token`, then `resolve_current_entitlement`. The active resolver reads existing active-user state and returns LIMITED; it does not compute canonical CRT FULL. JWT/session state remains local.
- PR6.15 is an active registered read-only route surface. `crt_authorization_proof_discovery`, `crt_authorization_proof_catalog`, `crt_authorization_proof_artifact`, and `crt_authorization_proof_verify` use `canonical_crt_authorization_proof_publication` and pinned static artifacts. They require neither database nor RPC. References are not fresh live proof; verification grants no entitlement.
- Models may be imported, but factory startup never applies SQL. Storage is invoked only if a caller constructs its repository. `InternalActionGateway`, action authorization, step-up, operations, receipts and handlers are dormant: no gateway instance, route, handler registry, scheduler or startup service exists. `EvidenceBackedCurrentEntitlementResolver` is not constructed.
- PR6.17 source planning, PR6.18 Bitcoin observation snapshot, and PR6.19 composition are caller-injected dormant adapters/contracts. No factory service calls Bitcoin RPC; no live lookup, current-proof writer or shadow comparator is wired.
- The exact range's MCP change is a `tools/__init__.py` packaging fix. Existing MCP release/systemd files are checked-in tooling, not proof of installation or deployment. Flask does not start the MCP sidecar.

## CRT PR6.8–PR6.20

Staging contains the complete local pure-domain path: PR6.8 trusted registration; PR6.9 canonical E923 genesis; PR6.10 admission edge; PR6.11 sponsor lineage; PR6.12 membership; PR6.13 FULL/LIMITED policy; PR6.14 proof artifact; PR6.15 reference publication/verification; PR6.16 explicit-snapshot proof resolver; PR6.17 trusted source plan; PR6.18 globally anchored Bitcoin snapshot; PR6.19 HODLXXI V1 local snapshot-to-proof composition; and PR6.20 Project Compass.

PR6.8–PR6.14 and PR6.16–PR6.19 are dormant/source-only; storage adapters require unapplied-status-unknown schema and PR6.18 requires caller-supplied observation wiring. PR6.15 alone is runtime-wired as read-only reference routes. PR6.20 is documentation/test-only. None is deployed merely because it is in staging. There is no live canonical entitlement or enforcement.

## Schema compatibility

The exact seven migrations, purposes and assumptions appear once in JSON. They add action operations, step-up challenges and FK/unique binding, entitlement evidence, trusted registrations/outpoints, admission edges, and E923 genesis records. They are additive in intent, but constraints/indexes may conflict or lock; `IF NOT EXISTS` cannot prove shape. No complete rollback SQL or rehearsal evidence exists. Old-code/new-schema and new-code/old-schema require sanitized rehearsal. Production schema/ledger truth, uniqueness/FK conflicts, data shape, PostgreSQL lock duration, backup/restore and compatibility remain blockers.

## Ordered release trains

The JSON defines scope, entry gates, migration requirements, staging validation, telemetry, rollback, exit gates, dependencies and exclusions for:

0. inventory and prerequisites;
1. security/auth compatibility foundation;
2. additive schema and migration foundation;
3. dormant CRT domain contracts;
4. read-only proof and verification surfaces;
5. live canonical source lookup and read-only Bitcoin observation;
6. durable current-proof storage and freshness;
7. shadow comparison and canonical entitlement;
8. bounded enforcement;
9. production cutover and legacy balance-to-FULL retirement;
10. signed portable bundles, lifecycle authority and replication.

Auth, schema, read-only routes, RPC, entitlement and enforcement require separate rollback boundaries. Trains 5–10 must not be collapsed because they add external truth, durability, authority and operational risk. This inventory is not approval to deploy any train.

## Blockers and decisions

Blockers are marked only `VERIFIED_FROM_REPOSITORY`, `REQUIRES_READ_ONLY_HOST_AUDIT`, `REQUIRES_READ_ONLY_DATABASE_METADATA_AUDIT`, `REQUIRES_SANITIZED_REHEARSAL`, `OPERATOR_DECISION_REQUIRED`, or `DEFERRED`. JSON records exact statuses for unknown schema/ledger truth; absent rehearsal/rollback SQL; old/new compatibility; uniqueness/FK/lock risk; backup/restore; unproven staging runtime; OAuth/OIDC/JWT and startup compatibility; controls; absent shadow comparison, canonical entitlement and Bitcoin-RPC orchestration; still-active legacy balance-to-FULL; and deferred signed authority/federation.

Operators must decide first-train contents, first-deployment read-only CRT routes, migration window, rollback tolerance, proof freshness, shadow duration, mismatch threshold, bounded population, legacy retirement gate, revocation authority, descendant behavior, re-sponsorship, and signing/portability timing.

## Project Compass alignment

- **HC-03 Bitcoin Objective Layer:** Bitcoin facts do not confer social authority.
- **HC-07 Exact Relationship, Not Wallet-Wide Aggregation:** use exact registered `txid:vout`, scripts and relationships, never wallet totals.
- **HC-08 Membership and Authorization Separation:** CRT, FULL/LIMITED, bearer/session/JWT, admin and action authority remain distinct.
- **HC-09 Fail-Closed Authorization:** stale, contradictory or unavailable canonical evidence cannot become FULL.
- **HC-14 Preserve Useful Legacy Infrastructure:** retain observation, authentication and history.
- **HC-15 Shadow Before Cutover:** shadow Train 7 precedes enforcement/cutover.
- **HC-16 Release-Train Discipline:** auth, schema, domain, read-only, lookup, shadow, enforcement and replication remain bounded.

PR6.21 changes no production behavior, introduces no central server dependency, changes no canonical semantics, deletes no historical evidence, and retires no legacy path.

## Exact non-claims

There is no deployment approval; no migration application; no migration rehearsal claim; no production database inspection; no production schema truth claim; no production data read; no secret inspection; no service restart; no runtime configuration change; no route or blueprint change by PR6.21; no authentication behavior change by PR6.21; no authorization behavior change by PR6.21; no Bitcoin RPC call; no LND call; no wallet operation; no session or JWT mutation; no entitlement write; no action authorization; no legacy cutover; no proof signing; no portable authority claim; no federation or replication claim; no rollback proof beyond repository evidence; and no production readiness claim from tests alone. These 24 statements are exact in JSON.

## Exact PR6.22 read-only boundary

PR6.22 may read only sanitized host/process and PostgreSQL metadata: deployed commit/artifact identity, unit/route registration, health/restart counters, variable names only, server/schema version, table/column/index/constraint existence, migration identifiers, estimated sizes/counts, lock/timeout settings and backup metadata. It must not read environment values, credentials, secrets, private/wallet/macaroon material, application rows, personal data, proof payloads, Bitcoin RPC/LND, or mutate, restart, deploy or migrate anything.
