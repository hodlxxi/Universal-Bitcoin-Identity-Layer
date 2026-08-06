# Production Host and Database Metadata Audit V1

Status: **SANITIZED READ-ONLY EVIDENCE — NOT DEPLOYMENT APPROVAL**

This repository-owned report is derived solely from the completed immutable audit report whose SHA-256 is `1b30768d3a00ccf188e15bf75dc5ce1007065b093c502ab1187e95a41ca8984f`. The repository basis is `b458470b409ed5a5f66844eddaf4a892bd335e12`; production was `6873e8fb73cbea8fda43fe3609bbdbb2817d8299` and protected staging was `fe333cdb5068a73b4dc57b875e1b0223b01855f7`. The audit transaction was read-only, both protected checkouts remained clean and unchanged, and no deployment, migration, restart, or database write occurred. The strict [JSON artifact](data/production_host_database_metadata_audit_v1.json) is normative for exact records.

## Deployment truth

Remote staging code at the repository basis, production checkout code, and the protected local staging checkout are three different code states. Active service metadata is a fourth kind of evidence. Repository presence does not prove deployed presence; deployed presence does not prove a component is active; an active unit does not prove every route is healthy.

Production contains `app/factory.py` and `app/blueprints/oauth.py`. It does not contain the checked paths `app/blueprints/crt_authorization_proof.py`, `app/services/current_entitlement.py`, `app/services/hodlxxi_v1_snapshot_proof_composition.py`, and `docs/PRODUCTION_COMPATIBILITY_INVENTORY_V1.md`. Those four checks do not prove that all CRT code is absent.

## Sanitized host runtime metadata

The active/running, enabled units observed were `hodlxxi-mcp.service`, `hodlxxi.service`, `lnd.service`, and `nginx.service`, each with restart count zero. The PostgreSQL meta-unit was active/exited and enabled, restart count zero. `hodlxxi-molt-agent-report.service` was inactive/dead and static; `hodlxxi-molt-agent.service`, `ubid-agent-watcher.service`, `ubid-lnurl-staging.service`, and `ubid-staging.service` were inactive/dead and disabled; `hodlxxi-molt-promo.service` was masked and inactive/dead. All reported restart counts were zero; the template PostgreSQL unit's structure was unknown. Safe process identities were Python/MCP, Python/Gunicorn, LND, and nginx. Working-directory identity was reduced to categories in JSON. The protected staging unit was inactive, so the audit did not prove a protected staging application process running.

Normalized listeners were: UDP `UNKNOWN:3478` (TURN), `LOOPBACK:3478` (TURN), and `LOOPBACK:53` (resolver); TCP `WILDCARD:22` (SSH), `WILDCARD:80` and `WILDCARD:443` (nginx), `WILDCARD:9735` (LND), `UNKNOWN:3478` (TURN), and loopback ports `53`, `3478`, `5000`, `5432`, `6379`, `8080`, `8332`, `8765`, `8766`, and `10009`. No address literal is retained.

Nginx configuration contained wildcard listeners on ports 80 and 443, a loopback listener on 8766, a named application upstream, and a loopback MCP upstream on 8765. Configured locations covered root, health, ACME, Socket.IO, MCP/agent MCP, public and internal API prefixes, LNURL, OAuth/token, play/playground, and a development dashboard. Configuration presence does not establish deployed application route presence, reachability, response correctness, or health.

## PostgreSQL metadata

The client and server were PostgreSQL `16.14 (Ubuntu 16.14-0ubuntu0.24.04.1)`. Default transaction read-only was on and the audit transaction was read-only. Statement timeout was 10 seconds, lock timeout 1 second, idle-in-transaction-session timeout 0, maximum connections 100, and WAL level `replica`. Installed extension inventory contained `plpgsql` 1.0. The point-in-time lock summary contained one granted relation `AccessShareLock` and one granted virtual-transaction `ExclusiveLock`; it does not establish migration lock duration.

Exactly one application database candidate was identified only as `cd098bd0f85e4f7b5767fdc94daa08d4f9d08bbda0c60ebb6065bbc754ce0106`, with four signature tables: `oauth_clients`, `oauth_codes`, `oauth_tokens`, and `users`. Catalog metadata recorded their columns, eight constraints, twenty indexes, estimated row counts of 85, 0, -1, and -1 respectively, and estimated total sizes of 188416, 114688, 131072, and 81920 bytes. Negative estimates are PostgreSQL estimates, not exact row counts. No application rows were read.

The named tables `alembic_version`, `migrations`, and `schema_migrations` were absent. This means those tables were absent, not that every possible migration ledger was absent. Alternate ledger presence is unknown. Migration identifiers were not present in the source report, and migration application is not proven. The four application tables are present with catalog-observed structure; the seven PR6.21 target structures are absent; structures outside the query are unknown.

## Seven-migration readiness matrix

| Migration | Target structures | Production structure / constraint-index | Status | Consumed now | Rehearsal and rollback |
|---|---|---|---|---|---|
| `2026-07-20_action_operations.sql` | action operations | absent / absent | `ABSENT` | no | Sanitized rehearsal required; no rollback SQL and dropping loses history. |
| `2026-07-20_action_step_up_challenges.sql` | step-up challenges | absent / absent | `ABSENT` | no | Sanitized rehearsal required; no rollback SQL and dropping loses audit state. |
| `2026-07-21_action_step_up_operation_binding.sql` | unique and foreign-key binding | absent / absent | `ABSENT` | no | Sanitized rehearsal required; no rollback SQL and addition may lock or fail. |
| `2026-07-22_current_entitlement_evidence.sql` | entitlement evidence | absent / absent | `ABSENT` | no | Sanitized rehearsal required; no rollback SQL and dropping loses history. |
| `2026-07-25_trusted_covenant_registration.sql` | registrations and registered outpoints | absent / absent | `ABSENT` | no | Sanitized rehearsal required; no rollback SQL and cascade/drop loses evidence. |
| `2026-07-26_canonical_admission_edge_registry_v1.sql` | admission edges | absent / absent | `ABSENT` | no | Sanitized rehearsal required; no rollback SQL and dropping loses history. |
| `2026-07-26_canonical_e923_genesis_record_v1.sql` | genesis records | absent / absent | `ABSENT` | no | Sanitized rehearsal required; no rollback SQL and dropping loses history. |

Absence avoids no migration risk by itself: compatibility, data conflicts, lock duration, and rollback remain unrehearsed. No `PRESENT_COMPATIBLE_NOT_PROVEN` conclusion is made.

## Backup and rollback readiness

`pg_dump` and `pg_restore` were present; pgBackRest and WAL-G were absent. Metadata showed `dpkg-db-backup.timer` and its service. Tooling or timer presence does not prove an application database backup exists. Restore readiness is not proven, and no restore rehearsal occurred.

## PR6.21 blocker disposition

| Blocker | Disposition | Evidence |
|---|---|---|
| `PRODUCTION_SCHEMA_TRUTH_UNKNOWN` | `PARTIALLY_RESOLVED` | Four relevant tables are catalog-observed; complete compatibility is not. |
| `MIGRATION_LEDGER_TRUTH_UNKNOWN` | `PARTIALLY_RESOLVED` | Three named ledgers are absent; alternatives are unknown and migration application is not proven. |
| `MIGRATION_REHEARSAL_ABSENT` | `STILL_BLOCKED` | No rehearsal. |
| `ROLLBACK_SQL_ABSENT_OR_INCOMPLETE` | `OPERATOR_DECISION_REQUIRED` | Repository limitation remains. |
| `OLD_CODE_NEW_SCHEMA_COMPATIBILITY` | `STILL_BLOCKED` | Rehearsal required. |
| `NEW_CODE_OLD_SCHEMA_COMPATIBILITY` | `STILL_BLOCKED` | Rehearsal required. |
| `UNIQUENESS_FK_CONFLICT_RISK` | `PARTIALLY_RESOLVED` | Targets are absent; application behavior remains unrehearsed. |
| `POSTGRESQL_LOCK_DURATION_RISK` | `STILL_BLOCKED` | Point-in-time locks cannot prove duration. |
| `BACKUP_RESTORE_REHEARSAL` | `STILL_BLOCKED` | Neither backup nor restore is proven. |
| `STAGING_RUNTIME_NOT_PROVEN_BY_REPOSITORY` | `RESOLVED_BY_HOST_METADATA` | Protected staging unit observed inactive; running process not proven. |
| `OAUTH_OIDC_JWT_COMPATIBILITY` | `STILL_BLOCKED` | Metadata does not test behavior. |
| `APPLICATION_STARTUP_IMPORT_COMPATIBILITY` | `STILL_BLOCKED` | No production-like startup rehearsal. |
| `FEATURE_FLAG_AND_ROLLBACK_CONTROLS` | `OPERATOR_DECISION_REQUIRED` | Control selection remains operational. |
| `SHADOW_COMPARISON_NOT_IMPLEMENTED` | `DEFERRED` | Shadow comparison remains deferred. |
| `CANONICAL_ENTITLEMENT_NOT_IMPLEMENTED` | `DEFERRED` | Canonical entitlement remains deferred. |
| `PRODUCTION_BITCOIN_RPC_ORCHESTRATION_NOT_IMPLEMENTED` | `DEFERRED` | Production orchestration remains deferred. |
| `LEGACY_BALANCE_TO_FULL_ACTIVE` | `PARTIALLY_RESOLVED` | Repository evidence says it remains active; metadata does not validate behavior. |
| `SIGNED_PORTABLE_AUTHORITY_AND_FEDERATION_DEFERRED` | `DEFERRED` | Signing, authority, federation, and replication remain deferred. |

## Release decision and Compass alignment

Production deployment is not approved. Train 0 repository and metadata inventory is complete. Train 1 is not release-approved and requires a sanitized production-like startup/auth compatibility rehearsal. Train 2 is not release-approved and requires migration plus backup/restore rehearsal. Trains 3–10 remain dependent on their PR6.21 gates. The exact next technical task is PR6.23: a sanitized rehearsal plan and non-production harness, not production deployment.

This audit aligns with HC-03 by treating database and host facts as objective metadata, not social authority; HC-07 by granting no wallet-wide relationship inference; HC-08 by separating membership, authorization, and runtime identity; HC-09 by making unknown compatibility fail closed; HC-14 by preserving useful legacy infrastructure and evidence; HC-15 by retaining shadow-before-cutover; and HC-16 by preserving release-train gates. Host/database metadata does not itself grant membership, authorization, administrator authority, or FULL status.

## Explicit non-claims

The exact 27 machine-enforced non-claims are: no deployment approval; no deployment performed; no migration applied; no migration rehearsal; no database write; no application-row inspection; no production data export; no environment value inspection; no secret inspection; no credential inspection; no service restart; no runtime configuration change; no route change; no authentication behavior change; no authorization behavior change; no Bitcoin RPC call; no LND call; no wallet operation; no backup proof from tooling presence; no restore proof; no startup compatibility proof; no OAuth/OIDC/JWT compatibility proof; no production readiness claim; no legacy cutover; no proof signing; no portable authority; and no federation or replication.
