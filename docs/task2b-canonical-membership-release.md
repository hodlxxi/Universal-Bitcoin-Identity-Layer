# Task 2B Canonical Full Membership release

The proposed PR targets `main`. The integration branch starts at
`ca15cb0fbb752aba0b4e29ae111491cacc17c6eb` and carries forward the
implementation rehearsed against the deployed release source export.

`main` already carries anonymous Login RPC isolation, single-flight Nostr
Login, and daemon cleanup. This integration retains those changes and carries
over the deployed Logout response headers, origin and CSRF checks, and
missing-generation handling. The migration manifest includes eight signed
admission migrations already present on `main`. Apply only the steps missing
from the database migration ledger.

## Authority and runtime contracts

A verified Legacy or Nostr identity remains Limited until UBID resolves
unambiguous Current Full Evidence. Login consumes the browser challenge. Later
requests reevaluate authority, including live browser-generation validity when
the service configures the OAuth lifecycle. The public authority endpoint and
Social consume the same evidence decision.

The authenticated Full browser sponsor submits a mirrored covenant import. The
web role persists the intent before calling Core and journals the confirmed
descriptor import. The response reports pending UTXO verification. The separate
publisher recovers eligible journals and validates the two confirmed funded
legs, the 777-block depth rules, and all active ancestors. It commits the
effective edge, unique global claims, per-participant observations and Full
evidence atomically. Bob uses the same route as Alice to sponsor Charlie. A
member with expired or revoked authority cannot sponsor or obtain Full access.
Admission history stays available for audit.

## Ownership and privileges

| Principal | Canonical rights | Operational scope |
| --- | --- | --- |
| DBA | Provisions roles, installs and audits DDL, and authorizes emergency maintenance | Run migrations in a separate DBA session |
| `hodlxxi_canonical_owner` | Owns the protected canonical tables, view and routines. Off-request authority to record a supported canonical revocation | NOLOGIN. No web or publisher membership. DBA may assume it for controlled maintenance |
| `hodlxxi` | Reads authority and registration, appends authenticated intents, and journals confirmed scripts and pairs | Existing web login, including ordinary user and OAuth DML. No canonical evidence, effective-edge, observation, claim, or revocation insert |
| `hodlxxi_canonical_publisher` | Reads authority and trusted registrations/outpoints, recovers the import journal, appends evidence, effective edges, outpoints and observations, and rewrites only the refresh cursor | NOLOGIN. Grant inheritance to the dedicated refresh login and provision that identity independently of web |
| Existing Social finalizer and challenge writer | Existing SELECT and row-lock privileges on evidence, plus SELECT on the five lineage relations | Preserve their pinned ACL profiles and evidence-trigger/function attestation |
| PUBLIC | No direct access to protected canonical relations or routines | Existing unrelated service grants follow their own profiles |

PostgreSQL uses UPDATE privilege for row locks. The shared evidence table keeps
its table-level lock privilege for the four trusted service roles. Its
unconditional immutable trigger rejects every row UPDATE and DELETE. The
publisher can lock immutable intent and effective rows via restricted column
grants. It can touch only the legacy `users.last_login` column through its
direct grant. DELETE, TRUNCATE, trigger control and ownership are denied for
canonical history. The DBA-owned `sql_drop` event trigger blocks runtime
cascades that would drop a protected canonical dependency through a legacy
identity/OAuth owner. Existing identity/OAuth ownership still gives the web
role responsibility for those services and their availability.

The installation assigns 21 distinct SECURITY DEFINER functions to the
NOLOGIN owner. Their relations are explicitly qualified. The fixed search path
is `pg_catalog, pg_temp`, with temporary objects searched last. Direct
EXECUTE is owner-only, including the proposed-candidate expiry function.
The web journals authenticated sponsorship and must be trusted to verify the
browser signature and intent. The dedicated publisher must be trusted to
observe Core and publish accurate evidence. Access to either service identity
is part of the application security boundary.

## Staged rollout

1. On a disposable PostgreSQL 16 cluster, restore a schema-only snapshot with
   owners and service ACLs intact. Run the rehearsal below and compare the
   attested catalog and historical row fingerprints. Inspect PostgreSQL role
   membership, effective schema and database grants, DEFAULT PRIVILEGES, and
   unexpected owners before requesting Production DDL approval.
2. After separate approval, provision the two NOLOGIN principals with
   NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION and NOBYPASSRLS.
   Provision a dedicated publisher login with those attributes and only
   inherited `hodlxxi_canonical_publisher` membership. Fence the web login
   from the owner and publisher roles. The database and public schema must
   be administered independently of the web and publisher logins. If the
   effective CREATE check fails, resolve the inherited grant or transfer
   database/schema administration through an approved DBA change.
3. Apply the files in
   [the release manifest](data/task2b-canonical-migration-order.txt) from top
   to bottom in one DBA transaction with `ON_ERROR_STOP`. Keep the automatic
   import and publisher disabled while installing. The manifest contains the
   original 11 dependency-ordered migration files and the ownership migration.
   For a previously migrated environment, first verify the exact migration
   ledger and object definitions, then rehearse applying only the missing
   privilege migration and the subsequent publisher registration-read migration. Capture the pre-change schema, ACLs, role memberships
   and lock budget so the operator can identify drift and abort cleanly.
4. Deploy the reviewed code through the approved release procedure. Test
   anonymous Login, authenticated Legacy and Nostr Login, logout confirmation
   and replay denial, and the Social authority consumer against staging.
   Configure the existing root evidence publisher and the automatic refresh
   worker to use their dedicated publisher identity. Validate preview TLS and
   each service's access to its own dependencies.
5. Enable the staged watch-only descriptor import and worker only after
   approval. Pin the chain and the named descriptors-enabled, private-keys-
   disabled wallet. Schedule non-overlapping refreshes and verify that the
   slowest full population traversal, including RPC retries, remains safely
   within the 120-second automatic evidence validity. Check Limited fallback
   after a revoked or unspendable ancestor and freshness under repeated cycles.

Run the isolated release gate from the repository root with an existing test
interpreter, a schema-only dump, and optionally the paired Social checkout.

```bash
./scripts/test_task2b_pg16.sh TEST_ENV/bin/python PRODUCTION_SCHEMA_ONLY.dump SOCIAL_CHECKOUT
```

The runner uses a fresh PostgreSQL data directory and a private network
namespace. The HTTPS check uses test DNS and CA fixtures in the private mount
namespace. `TASK2B_TEST_FILTER` can narrow a diagnostic run. The test runner
starts no Bitcoin process. Native Bitcoin Core checks separately require an
approved isolated regtest node to exercise descriptor imports, signing,
confirmations, spend and reorg behavior. A future Production readiness check
also needs an approved read-only check of chain selection, actual wallet
metadata and RPC compatibility. It does not require creating funding
transactions.

Run the browser, authorization and wallet regression from the repository root.

```bash
TEST_ENV/bin/python -m pytest -q tests/test_auth_flows.py \
  tests/unit/test_{canonical_login_persistence,balance_based_full_access_contract,anonymous_login_privacy,auth_signature_fail_closed,monolith_auth_security,nostr_auth_verify_helper,real_login_clears_guest_label_contract,oauth_bearer_legacy_compatibility,oauth_bearer_validation,current_entitlement_evidence,current_entitlement_resolver,automatic_sponsored_import_v1,covenant_wallet_routes,browser_route_ownership}.py \
  tests/unit/test_{oauth_stale_browser_logout,nostr_login_single_flight,request_pipeline_rpc_isolation,canonical_v2_server_bitcoin_collateral,canonical_v2_browser_admission,canonical_v2_issuer_generation_binding,canonical_v2_tx_browser_authority,social_session_issuance_v2_storage}.py
```

## Rollback and release gates

- A migration failure rolls back the containing transaction. Confirm that the
  original owners, grants, constraints and table fingerprints remain intact
  before retrying. Leave role provisioning separate from the schema transaction
  so unused roles can be handled through the DBA change record.
- After commit, first disable automatic import and stop new publisher runs.
  Keep canonical authority reads, immutability and current evidence checks.
  Automatic Full expires within its signed-off validity window. An authorized
  operator can record an immediate revocation where policy allows.
- Keep the protected ledger after admissions have committed. Use a reviewed
  forward repair, or rehearse restoring an authorized backup into a disposable
  cluster before proposing a data recovery. Any schema rollback must include
  an inventory of existing ownership and row dependencies. Returning owner
  privileges to the web login or restoring balance-based access would weaken
  the security policy.
- Review requires clean Git commits, a green isolated Auth and PostgreSQL
  release gate, the production-schema role matrix and paired Social results.
  Merge requires explicit approval. Release additionally requires the
  approved DBA change, current Production role and schema preflight, a
  successful isolated Core rehearsal, the refresh cadence check, and
  deployment approval. Production deployment is unauthorized for this task.

## Verification

| Gate | Passed | Failed |
| --- | ---: | ---: |
| Browser authentication, wallet routes, evidence resolution and upstream security regressions | 463 | 0 |
| PostgreSQL 16 and paired Social HTTPS | 72 | 0 |
| Existing signed admission and global outpoint PostgreSQL suites | 11 | 0 |
| Social reader, OAuth BFF and authority composition | 3 | 0 |
| Ordered migrations on the restored Production schema | 12 | 0 |

The PostgreSQL gate verified the separate web and publisher logins, recursive
Alice → Bob → Charlie sponsorship, conflicting outpoints, concurrent retries,
revocation, Social catalog attestation and the inherited-DDL rollback guard.
The Auth process exited normally with the daemon cleanup inherited from
`main`. The signed effective-admission fixture uses a current clock for the
seven-day candidate window. Bitcoin RPC was synthetic. The prior full-data
rehearsal covered the original 11 migrations. This run verified the ownership
stage on the restored schema with disposable evidence fixtures and confirmed
that the seeded evidence fingerprint was unchanged.

Review is ready. Merge requires explicit approval. Core regtest and the
publisher cadence still require verification for Production release. The task
changed no Production checkout, database, service, wallet or runtime setting.
