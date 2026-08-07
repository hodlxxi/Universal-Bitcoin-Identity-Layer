# Production Compatibility Rehearsal Plan V1

Status: **REPOSITORY-SUPPORTED DISPOSABLE HARNESS — EXECUTION NOT RUN — NO RELEASE AUTHORITY**

PR6.23 created the plan and execute-mode engine. PR6.24 makes the disposable engine repository-supported and tested, but does not execute PostgreSQL. A real run still requires separate explicit authorization for one marker-owned non-production laboratory. On a production host, that authorization covers only the disposable laboratory and never any production resource.

The production source basis is `6873e8fb73cbea8fda43fe3609bbdbb2817d8299`. The staging source basis is `872485fedce951365a3325e3bfd0ad766112c272`. The PR6.22 source audit report SHA-256 is `1b30768d3a00ccf188e15bf75dc5ce1007065b093c502ab1187e95a41ca8984f`, and the sanitized application-database identifier is `cd098bd0f85e4f7b5767fdc94daa08d4f9d08bbda0c60ebb6065bbc754ce0106`. The real database name is neither included nor derived.

The strict [JSON plan](data/production_compatibility_rehearsal_plan_v1.json) is normative. Plan mode, future execution evidence, and release approval are three distinct things:

1. This committed plan describes work whose phase states are all `NOT_RUN`.
2. A future sanitized result may report `PASS`, `FAIL`, or `BLOCKED` evidence from an approved laboratory.
3. Only a later, explicit operator decision may change a release gate. Neither this plan nor a result artifact is release authority.

## Why existing evidence is insufficient

Ordinary SQLite CI is valuable for application behavior, but it cannot prove PostgreSQL compatibility. SQLite does not reproduce PostgreSQL catalog identity, `JSON` behavior, time-zone-aware types, regular-expression checks, partial indexes, sequence behavior, PostgreSQL DDL locking, PostgreSQL constraint creation, custom-format archives, or restore semantics. SQLite table creation from SQLAlchemy also differs from the production-like old schema and can conceal new-code/old-schema failures. SQLite success must therefore never be treated as PostgreSQL migration or startup proof.

PR6.22 is sanitized read-only metadata, not behavioral evidence. It establishes that four relevant tables and their observed columns, eight constraints, and twenty indexes existed; the seven PR6.21 target structures were absent; and specific backup tools were present. It did not call `create_app`, exercise OAuth/OIDC/JWT behavior, apply a migration, measure DDL behavior, create a backup, or restore an archive. Catalog presence does not prove startup compatibility, migration compatibility, backup availability, or recovery readiness.

## Disposable laboratory and fail-closed boundary

The `execute` command requires the exact acknowledgement `DISPOSABLE-NONPRODUCTION-REHEARSAL-V1`, explicit repository and workspace paths, the two exact source SHAs, an explicit approved temporary root, an explicit Python binary, an explicit Git binary, and an explicit PostgreSQL binary directory. It reads no application configuration file. It rejects inherited runtime/database configuration by variable name without retaining any value.

Execution as UID 0 is rejected because root would expand the damage boundary of path mistakes, cluster control, archive creation, and cleanup. The laboratory needs no privileged port, system service, system cluster, or protected checkout access. A non-root account makes operating-system ownership part of the containment contract.

No existing PostgreSQL cluster and no operator-supplied DSN are accepted. An existing cluster carries unknown databases, roles, extensions, configuration, sockets, and cleanup authority. An external DSN could silently reach a system or production cluster. The harness instead creates its own cluster under a previously nonexistent workspace, writes an ownership marker with exclusive creation, configures `listen_addresses = ''`, and passes only its private Unix-socket directory to clients. TCP, non-loopback/network targets, password-bearing DSNs, arbitrary targets, and the reserved targets `postgres`, `template0`, and `template1` are refused. Execute-time target identities are generated only after preflight and must match `^hodlxxi_rehearsal_[a-z0-9_]+$`; no generated target identity is written to a sanitized result.

The workspace must be a direct child of the explicitly approved temporary root and must not exist at invocation. Existing empty directories are rejected because the harness did not create them. After creating the directory, the harness creates and repeatedly verifies its ownership marker. A missing, changed, or symlinked marker removes cleanup authority and leaves the path in place for operator review.

## Immutable source isolation

The repository must be clean. Git verifies that both exact commit objects exist locally. The harness never clones, fetches, pulls, switches, resets, cleans, or writes an existing checkout. It uses local `git archive` output, traversal-safe extraction inside the marker-owned workspace, and read-only extracted trees for:

- production: `6873e8fb73cbea8fda43fe3609bbdbb2817d8299`;
- staging: `872485fedce951365a3325e3bfd0ad766112c272`.

The application probes run in separate Python processes with `PYTHONDONTWRITEBYTECODE` and an explicit `PYTHONPATH`, so imports cannot mix the two snapshots. Ephemeral RS256 signing material is created only inside the owned workspace. It is synthetic laboratory material, not copied key material.

## Exact fourteen phases

All committed phase states are `NOT_RUN`. No phase is pre-classified as successful.

1. `REHEARSAL_00_PREFLIGHT` — validate acknowledgement, non-root execution, paths, exact local source objects, repository cleanliness, binaries, workspace absence, ownership marker, Unix-socket architecture, and absence of inherited production configuration.
2. `REHEARSAL_01_EPHEMERAL_CLUSTER` — create a private temporary PostgreSQL cluster, with Unix sockets only and TCP disabled.
3. `REHEARSAL_02_SYNTHETIC_OLD_SCHEMA` — create an execute-time generated target and load the sanitized four-table schema-only baseline.
4. `REHEARSAL_03_NEW_CODE_OLD_SCHEMA_STARTUP` — probe staging `create_app`, required blueprint registration, connection, and four-table queryability against the old schema.
5. `REHEARSAL_04_NEW_CODE_OLD_SCHEMA_AUTH` — exercise the supported synthetic OAuth/OIDC matrix with staging code and the old schema.
6. `REHEARSAL_05_APPLY_SEVEN_MIGRATIONS` — apply exactly the seven migrations below, stopping at the first failure.
7. `REHEARSAL_06_VERIFY_MIGRATED_CATALOG` — verify migration-declared tables, columns, table-qualified named constraints, exact primary/unique/foreign-key column relationships, inline check counts, and explicit indexes.
8. `REHEARSAL_07_OLD_CODE_NEW_SCHEMA_STARTUP` — probe production-basis application startup against the migrated additive schema.
9. `REHEARSAL_08_NEW_CODE_NEW_SCHEMA_STARTUP_AUTH` — probe staging startup and repeat the supported synthetic authentication matrix against the migrated schema.
10. `REHEARSAL_09_BACKUP` — create a custom-format archive of only the disposable target, inspect its contents, and calculate SHA-256.
11. `REHEARSAL_10_RESTORE` — verify the checksum and restore only into a second execute-time generated target in the same disposable cluster.
12. `REHEARSAL_11_COMPARE` — compare normalized schema, relation ownership categories, table/sequence/index counts, per-table synthetic row counts, and queryability of every restored application table.
13. `REHEARSAL_12_CLEANUP` — stop only the harness-created cluster and remove only marker-owned temporary artifacts.
14. `REHEARSAL_13_RESULT` — emit a sanitized result object with no release authority.

Substantive phases run only after every prerequisite has `PASS`. A `FAIL` or `BLOCKED` phase marks later substantive phases `BLOCKED`; only cleanup and sanitized result emission may still run. Cleanup is a safety action, not silent continuation.

## Exact seven-migration order

No downgrade SQL is generated, applied, or modified.

1. `migrations/2026-07-20_action_operations.sql`
2. `migrations/2026-07-20_action_step_up_challenges.sql`
3. `migrations/2026-07-21_action_step_up_operation_binding.sql`
4. `migrations/2026-07-22_current_entitlement_evidence.sql`
5. `migrations/2026-07-25_trusted_covenant_registration.sql`
6. `migrations/2026-07-26_canonical_admission_edge_registry_v1.sql`
7. `migrations/2026-07-26_canonical_e923_genesis_record_v1.sql`

The migrated-catalog check derives required relations, columns, table-qualified named constraints, inline check counts, and explicit indexes from these immutable files. It separately verifies the exact table, ordered local columns, referenced table and columns, and delete action for every primary-key, unique, and foreign-key constraint, including unnamed inline constraints. `IF NOT EXISTS` is not treated as shape proof.

## Synthetic old-schema baseline

`tests/fixtures/production_catalog_baseline_v1.sql` is schema-only. It contains no `INSERT`, production row, sequence value, owner identity, user identifier, public key, token, client material, production timestamp, network address, or database name.

It reconstructs only:

- `oauth_clients`, including the thirteen catalog-observed columns, its primary key, and four observed indexes;
- `oauth_codes`, including the ten observed columns, its primary key, two observed foreign keys, and five observed indexes;
- `oauth_tokens`, including the twelve observed columns, its primary key, two observed foreign keys, and seven observed indexes;
- `users`, including the six observed columns, its primary key, and four observed indexes.

Types are conservative repository-ORM-compatible choices needed for the rehearsal. PR6.22 did not publish a full schema dump. This catalog reconstruction is not a complete production schema clone and must not be represented as one. Synthetic application rows are created only by the future probe inside the disposable target and never copied from production.

## Startup probe definition

The mechanics follow existing fixtures: construct `create_app` with an explicit testing configuration, use an ephemeral JWKS directory, create a Flask test client, inspect `url_map`, and exercise storage through the application. For PostgreSQL, the child receives an internally constructed Unix-socket connection string for the execute-time target. The parent passes a fresh allowlisted environment mapping; it never copies `os.environ`.

The allowlist supplies only the application version, synthetic Flask material, testing mode, RS256 issuer and JWKS path, disabled HTTPS/rate limiting, the isolated source path, workspace-local home/temp paths, and the internally constructed Unix-socket database connection. The probe installs guards before importing the factory: internet-family socket connects, HTTP clients, email clients, Bitcoin RPC construction, and external callbacks fail closed. Redis `ping` is replaced with a deterministic connection failure so `create_app` exercises its reviewed non-production memory fallback without opening a Redis connection. Full Redis integration is `BLOCKED`: no separately created disposable Redis service is part of V1.

The startup check requires application construction, OAuth/OIDC route registration, a simple database query, and queryability of all four baseline tables. Production-basis phase 7 is startup-only; it does not claim old-code authentication compatibility.

## Synthetic OAuth/OIDC matrix

Where supported by staging contracts, phases 4 and 8 cover:

- application startup and OAuth/OIDC blueprint registration;
- safe dynamic client registration plus managed-metadata rejection;
- exact redirect URI acceptance and unsafe/mismatched redirect rejection;
- mandatory PKCE S256 plus missing, plain, and incorrect-verifier rejection;
- finite allowed scopes plus unknown/reserved scope rejection;
- authorization-code issue, atomic one-time consumption, and reuse rejection;
- RS256 access-token and ID-token issue using ephemeral signing material;
- strict Bearer parsing and ambiguous-header rejection;
- signature, issuer, audience, persisted-digest, scope, user, and client binding validation;
- active and inactive introspection;
- revoked or expiration-mismatched token rejection;
- inactive-user rejection;
- exact active-user `LIMITED` entitlement with `current_full_relation_satisfied = false`;
- proof that rehearsal metadata does not grant CRT `FULL`.

If a required import or dependency cannot be isolated, the probe returns `BLOCKED` with a fixed evidence code. A blocked or unsupported probe cannot be converted to `PASS`. Raw exceptions and command output never enter the result.

## Backup and restore verification

The backup phase reuses the safety meaning of `docs/ops/POSTGRES_BACKUP_RESTORE.md`, `scripts/postgres_backup_verified.sh`, and `scripts/postgres_verify_backup.sh` without modifying or invoking those production-oriented scripts. It operates only against the harness-created cluster.

Evidence requires all of the following: custom-format archive creation, SHA-256 verification, readable archive contents, successful restore into a second disposable target, normalized schema equality after removing only `\restrict` and `\unrestrict` marker lines, relation ownership-category equality, equal table/sequence/index counts, equal per-table synthetic row counts, and a successful query against every restored application table. `pg_dump` exit zero or `pg_restore --list` alone is insufficient.

This proves neither that a production backup exists nor that production recovery is ready. Production recovery still requires separate outage, recovery-point, write-shutdown, ownership, privilege, health, rollback, and incident procedures.

## Result schema and sanitization

Every phase result has exactly:

- `phase`;
- `status`: `NOT_RUN`, `PASS`, `FAIL`, or `BLOCKED`;
- `evidence_code`;
- `duration_ms`;
- `sanitized_detail`;
- `artifact_sha256`;
- `cleanup_status`.

Results contain no raw stdout/stderr, credentials, DSNs, runtime database identities, IP-address literals, or environment values. Evidence details come from a fixed vocabulary. The result repeats the two source SHAs, has `release_authority = NONE`, and has `release_gate_effect = NONE`.

## Failure handling and cleanup authority

Every external command is an argument vector through an injectable runner; `shell=True` is never used. Repository tests use only fake runners, including a complete successful 14-phase command simulation; they do not execute PostgreSQL. A command failure discards raw output and produces a fixed `FAIL` evidence code. A missing safe dependency or safety-gate rejection produces `BLOCKED`. No failed prerequisite is bypassed.

The harness records cluster-start intent before invoking `pg_ctl`. If startup reports failure, cleanup still attempts to stop the owned data directory; it does not assume no server started. An outer `finally` also attempts cleanup for orchestration-level interruptions. If stop cannot be proven, the workspace remains. Cleanup does not call `dropdb` and never targets a system cluster. It verifies the marker immediately before removal and deletes only the one marker-owned workspace. Missing or changed ownership evidence causes cleanup refusal, not best-effort deletion.

## Release-gate effects

This plan changes no release gate:

- `TRAIN_0`: `COMPLETE`;
- `TRAIN_1`: `NOT_RELEASE_APPROVED`;
- `TRAIN_2`: `NOT_RELEASE_APPROVED`;
- `TRAINS_3_THROUGH_10`: `DEPENDENT_ON_PR6_21_GATES`.

Even a future all-`PASS` result would be evidence for review, not automatic approval. Train 1 still needs an explicit release decision after startup/auth evidence. Train 2 still needs an explicit release decision after migration and backup/restore evidence.

## Separately authorized invocation boundary

PR6.24 does not run this command. After separate authorization, the invocation must use a clean non-protected checkout, a non-root account, an already approved temporary root, a nonexistent direct-child workspace, a new output path outside that workspace, no inherited runtime configuration, and the explicit binaries. The command shape is:

```bash
env -i PATH=/usr/bin:/bin \
  /absolute/path/to/python /absolute/clean/non-protected/checkout/tools/production_compatibility_rehearsal_v1.py execute \
  --ack DISPOSABLE-NONPRODUCTION-REHEARSAL-V1 \
  --repository /absolute/clean/non-protected/checkout \
  --temporary-root /tmp/operator-approved-root \
  --workspace /tmp/operator-approved-root/new-direct-child \
  --production-sha 6873e8fb73cbea8fda43fe3609bbdbb2817d8299 \
  --staging-sha 872485fedce951365a3325e3bfd0ad766112c272 \
  --git-binary /usr/bin/git \
  --python-binary /absolute/path/to/python \
  --postgresql-binary-directory /usr/lib/postgresql/16/bin \
  --output /tmp/new-sanitized-result.json
```

Before any such execution, operators must decide exactly:

1. the approved host, non-root account, and temporary root; use of a production host requires separate explicit authorization for the disposable laboratory only;
2. the exact Python, Git, and PostgreSQL binary paths and versions;
3. whether both immutable snapshots can use the approved isolated dependency environment;
4. how laboratory egress denial and Unix-socket-only controls are independently verified;
5. acceptable phase duration and migration-lock thresholds;
6. the explicit sanitized-result output path and failed-artifact retention policy;
7. how any exact `BLOCKED` probe affects further review;
8. who reviews evidence and makes the separate Train 1 and Train 2 release decisions.

## Exact PR6.24 boundary

PR6.24 may:

- provision an isolated disposable laboratory;
- run the PR6.23 harness;
- use synthetic data only;
- emit a sanitized result artifact;
- classify phases `PASS`, `FAIL`, or `BLOCKED`;
- propose release-gate changes based on evidence.

PR6.24 may not:

- contact or modify production resources outside the disposable laboratory;
- use the production PostgreSQL cluster;
- use production rows;
- use production credentials;
- use production database names;
- deploy staging;
- apply production migrations;
- restart production services;
- call production Bitcoin RPC or LND;
- change entitlement or enforcement;
- merge release trains;
- declare production readiness automatically.

## Project Compass alignment

- **HC-03 Bitcoin Objective Layer:** laboratory database facts remain technical evidence and confer no social authority.
- **HC-07 Exact Relationship:** synthetic authentication and schema metadata cannot establish wallet-wide or participant relationships.
- **HC-08 Membership and Authorization Separation:** startup, authentication, membership, entitlement, administrator authority, and release authority remain separate.
- **HC-09 Fail-Closed Authorization:** unknown, unsupported, stale, or inconsistent evidence becomes `BLOCKED` or `FAIL`, never automatic `FULL`.
- **HC-14 Preserve Useful Legacy Infrastructure:** production-basis startup is tested against additive schema without modifying or deleting legacy infrastructure.
- **HC-15 Shadow Before Cutover:** this isolated rehearsal precedes any shadow entitlement, enforcement, or cutover work.
- **HC-16 Release-Train Discipline:** Train 1 compatibility and Train 2 schema/restore evidence stay bounded and do not collapse later trains.

Rehearsal evidence does not grant membership, authorization, administrator authority, or `FULL` status.

## Exact non-claims

The exact ordered 38 non-claims are:

1. no deployment approval;
2. no deployment performed;
3. no production migration;
4. no migration rehearsal executed;
5. no database created;
6. no database contacted;
7. no database write;
8. no application-row inspection;
9. no production data copied;
10. no production database name;
11. no environment-value inspection;
12. no secret inspection;
13. no credential inspection;
14. no service restart;
15. no runtime configuration change;
16. no route change;
17. no authentication behavior change;
18. no authorization behavior change;
19. no Bitcoin RPC call;
20. no LND call;
21. no wallet operation;
22. no network request;
23. no PostgreSQL subprocess executed;
24. no backup created;
25. no restore executed;
26. no startup compatibility proof;
27. no OAuth/OIDC/JWT compatibility proof;
28. no migration compatibility proof;
29. no backup availability proof;
30. no restore readiness proof;
31. no production readiness claim;
32. no Train 1 approval;
33. no Train 2 approval;
34. no legacy cutover;
35. no CRT FULL grant;
36. no proof signing;
37. no portable authority;
38. no federation or replication.
