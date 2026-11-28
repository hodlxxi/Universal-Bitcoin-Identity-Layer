# HODLXXI — paired preview → main → staging → production

**Release gate: OPEN.** This document is an operating contract, not permission
to deploy to production. All currently running production services and wallets
remain untouched without separately granted production authorization.

## What must work for a person

1. Alice signs in on laptop. Canonical Full is derived from current funded
   mirrored Bitcoin contracts, not from login method or a manually chosen role.
2. Once on a new phone, Alice opens a private pairing link/QR. Phone creates
   nonextractable X25519 and Ed25519 keys. Laptop Alice compares the short code
   and approves. No Nostr extension or signer is required on the phone.
3. After the original five-minute *enrollment* window expires, the same phone
   starts a *new* short-lived messaging session by signing a fresh server
   challenge with its **existing** Ed25519 key; Full and device revocation are
   checked again. The phone must not be enrolled again, and old native V2
   issuance/parent OAuth/session must not be revived.
4. Bob enters from an independent clean browser/profile and imports the two
   existing, fully funded and confirmed reciprocal descriptors. Publisher
   detects canonical mirrored relationship; both UBID and Social show Bob Full
   automatically, without a second membership signature or manual database edit.
   An imported unconfirmed/spent/reorged pair may not elevate Bob.
5. Alice and Bob send and decrypt messages in both directions. Server stores
   ciphertext only. Reload restores inbox and authorized device keys. Bob may
   sponsor Charlie; limited and revoked participants may not send.
6. Device key rotation/revocation, logout, expiry and Full demotion must deny
   both old sessions and pending/replayed messages. No silently repeated
   signature after an ambiguous request.

## Environment parity means controlled equivalence, not one shared system

- Candidate preview, staging and production must run the **same immutable
  reviewed code SHA** and all relevant migrations/feature contract versions for
  the promoted release. Compare source SHA *and running process configuration*,
  not branch names. Do not cherry-pick or copy uncommitted staging code.
- Preview and staging use **distinct databases, Redis, service tokens, issuer
  keys, cookie domains, TLS, ports and working trees**, with their own runtime
  roles. Never copy the production database or private server keys into preview.
- Bitcoin network must match mainnet for real collateral evidence. Use isolated
  watch-only descriptors/read-only chain RPC. Never copy a production spending
  wallet, seed, private key or wallet unlock context.
- Feature flags and role permission behavior must match intended production
  defaults **after** acceptance; never enable unsafe write paths by matching an
  old production environment blindly. Runtime health, TLS, database ACL and
  subject/alias isolation are separate checks.
- For real phone testing, preview must be reachable via a **phone-accessible
  HTTPS origin with a trusted certificate**, not just Mac-local `127.0.0.1`
  SSH forwards and `.test` hostnames. Do not disable TLS verification or
  expose native `/internal` routes publicly.

## Single final acceptance (avoid dozens of destructive browser loops)

A. **Automated** (no browser): all hosted checks on exact PR HEAD, paired
   PG16 tests, source/runtime parity audit, migration order, status/ACL,
   publisher Full readback, session replay/expiry/revocation, ciphertext tests.

B. **One laptop + one phone**: Alice signs in; pairing QR/link, comparison,
   approval, registered receipt; wait until initial enrollment issuance expires;
   phone recovers by possession without Nostr or re-enrollment; send and
   decrypt a message. Preserve IndexedDB and cookies unless a single test
   explicitly tests revocation.

C. **One independent browser profile**: Bob Full after canonical sponsor
   import, Alice → Bob, Bob → Alice, reload, denial for Limited and stale
   credentials. Bob → Charlie admission checked via canonical cascade.

D. **Promotion**:
   1. Merge only ready UBID #597 and Social #73 after exact-hosted gate and
      complete preview acceptance. Close #588 only after full acceptance.
   2. Deploy exact merged main SHAs to isolated *existing staging*, apply
      migrations in declared order, compare running SHAs and role/flag
      parity, repeat one smoke test (not another full registration).
   3. Request separate explicit permission for production deployment.
      Prepare backup, DB migration safety check, rollback release and
      session/compatibility plan; deploy exact tested SHAs atomically by
      service, restart and verify health/authority/messaging. Full rollback
      criteria agreed before any production change.

## Read-only preview audit

From a checkout that contains the script:

```bash
python3 scripts/audit_paired_preview_read_only.py \
  --root /srv/hxxi-paired-app-3c2b954 \
  --ubid-head <40-character-PR-597-commit> \
  --social-head <40-character-Social-73-commit>
```

It reports FAIL if a preview checkout is still on the previous test candidate
or if any isolated service/PG16 identity/HTTPS endpoint is unavailable. It
does **not** deploy, authorize, restart, reveal keys or modify production. A
PASS is only an infrastructure prerequisite, **not** proof of E2EE delivery.
