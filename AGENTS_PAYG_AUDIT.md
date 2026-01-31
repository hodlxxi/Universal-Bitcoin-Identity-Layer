# AGENTS_PAYG_AUDIT.md

## Executive summary (5 bullets)
- PAYG billing exists only as **invoice creation/check + balance crediting**; **no endpoint actually enforces payment** (no 402/paywall middleware) so agents can use APIs without paying once they have auth where required.【F:app/dev_routes.py†L255-L466】
- The **current billable identity is Bitcoin pubkey in the session** (payments.user_pubkey, ubid_users.pubkey), not OAuth client_id; OAuth usage is counted but not billed or enforced.【F:app/dev_routes.py†L69-L451】【F:app/blueprints/account_api_compat.py†L91-L152】
- **Invoice handling is stubbed by default** (LN_BACKEND=stub) and payment confirmation can be faked via TEST_INVOICE_PAID; no automatic LND webhook/settlement pipeline is wired to usage enforcement.【F:app/payments/ln.py†L48-L81】
- OAuth and LNURL flows are implemented, but **OAuth/JWT access is not tied to PAYG balance**, so payment is optional and not required for access today.【F:app/blueprints/oauth.py†L87-L351】【F:app/app.py†L9649-L9699】
- There are **duplicate OAuth/LNURL/demo route stacks** (blueprints vs app.py monolith), increasing risk of inconsistent auth/billing behavior; enforcement will need to be added in one place and reconciled across stacks.【F:app/factory.py†L96-L171】【F:app/app.py†L572-L10419】

---

## Payment flow map

```
Agent (browser/session)
   │
   │ POST /api/billing/create-invoice (compat) or /dev/billing/create-invoice
   ▼
create_invoice_route() → payments.ln.create_invoice() → LND REST or stub
   │
   │ INSERT payments (status=pending, amount_sats, invoice_id, user_pubkey)
   │ INSERT/UPDATE ubid_users (pubkey, plan, sats_balance)
   ▼
Agent pays Lightning invoice (out of band)
   │
   │ POST /api/billing/check-invoice (compat) or /dev/billing/check-invoice
   ▼
check_invoice_route() → payments.ln.check_invoice_paid()
   │
   │ UPDATE payments status=paid, metadata.credited=true
   │ UPDATE ubid_users.sats_balance += amount_sats; payg_enabled true
   ▼
Balance credited (but **no API paywall uses it**) → API access unchanged
```

**Where invoice is created**
- Endpoint: `POST /dev/billing/create-invoice` (compat alias `POST /api/billing/create-invoice`).【F:app/dev_routes.py†L255-L351】【F:app/blueprints/billing_api_compat.py†L1-L31】
- Function: `create_invoice_route` calls `app.payments.ln.create_invoice`.【F:app/dev_routes.py†L255-L298】【F:app/payments/ln.py†L48-L60】

**How invoice status is checked**
- Endpoint: `POST /dev/billing/check-invoice` (compat alias `POST /api/billing/check-invoice`).【F:app/dev_routes.py†L356-L466】【F:app/blueprints/billing_api_compat.py†L24-L31】
- Function: `check_invoice_route` calls `app.payments.ln.check_invoice_paid`.【F:app/dev_routes.py†L356-L416】【F:app/payments/ln.py†L66-L80】

**Where credits/balance are stored and updated**
- Postgres tables: `payments` and `ubid_users` are updated directly in `dev_routes.py` (raw SQL).【F:app/dev_routes.py†L311-L451】
- Account UI reads `ubid_users.sats_balance` and recent `payments` rows via `/api/account/summary`.【F:app/blueprints/account_api_compat.py†L91-L152】

**What counts as “usage”**
- Only **usage statistics** are counted: `oauth_tokens` and `oauth_codes` are counted per client for dashboards; there is no per-request metering or billing deduction in code today.【F:app/dev_routes.py†L192-L213】

**Where paywall triggers / response**
- **MISSING**: No 402 or balance check is wired into API routes. The only enforcement is session-level gating for invoice creation (limited accounts only).【F:app/dev_routes.py†L46-L103】【F:app/blueprints/demo.py†L31-L46】

---

## Billable identity (key decision)

### What the code bills today
- **Billable entity = Bitcoin pubkey** stored in session (`session["logged_in_pubkey"]`), persisted as `payments.user_pubkey` and `ubid_users.pubkey`.【F:app/dev_routes.py†L46-L451】
- `account_api_compat` also keys on `session.logged_in_pubkey` and reads `ubid_users` and `payments` by pubkey.【F:app/blueprints/account_api_compat.py†L91-L152】
- OAuth clients are stored in `oauth_clients`, but **billing logic does not use client_id**; usage stats are read by client_id only for reporting.【F:app/dev_routes.py†L192-L237】

### Recommendation for agents-first billing
- **Default billable identity should be OAuth `client_id`** (agent/app identity). This aligns billing to the entity that makes API calls and scales across user accounts.
- **Optional: user-based billing** can remain a secondary mode for user-specific actions (e.g., PoF verification tied to a user’s pubkey), but agent PAYG should primarily debit per client_id.

---

## Route protection matrix (protected endpoints)

> Legend: **Auth** = session or OAuth required; **Paywall** = 402/balance check; **Rate limit** = limiter-only.

| Endpoint | Auth required? | Paywall? | Notes |
| --- | --- | --- | --- |
| `POST /dev/billing/create-invoice` | Session (limited, non-guest) | No | Only allows limited accounts; no balance check for other APIs.【F:app/dev_routes.py†L46-L351】 |
| `POST /dev/billing/check-invoice` | Session (limited, non-guest) | No | Credits balance if paid; no access enforcement elsewhere.【F:app/dev_routes.py†L356-L466】 |
| `POST /api/billing/create-invoice` | Session (proxy to /dev) | No | Compat route to `/dev/billing/create-invoice`.【F:app/blueprints/billing_api_compat.py†L1-L31】 |
| `POST /api/billing/check-invoice` | Session (proxy to /dev) | No | Compat route to `/dev/billing/check-invoice`.【F:app/blueprints/billing_api_compat.py†L24-L31】 |
| `GET /api/account/summary` | Session | No | Reads balance + payments; no enforcement for other endpoints.【F:app/blueprints/account_api_compat.py†L91-L152】 |
| `POST /api/account/set-payg` | Session (limited only) | No | Enables PAYG flag for pubkey; no metering attached to API calls.【F:app/blueprints/account_api_compat.py†L157-L187】 |
| `GET /dev/dashboard` | Session (full only) | No | Admin-only dev dashboard; blocked by before_request too.【F:app/dev_routes.py†L210-L252】【F:app/app.py†L681-L690】 |
| `GET /api/demo/protected` | OAuth token (read_limited) | No | OAuth token required; still no billing enforcement.【F:app/app.py†L9649-L9699】 |
| `GET /api/demo/pro` and `/api/demo/protected` (blueprint) | Session | No | Demo auth uses session only (no billing).【F:app/blueprints/demo.py†L23-L46】 |
| `GET /oauth/clients*` (app.py) | Session | No | Login required; not billed.【F:app/app.py†L10067-L10419】 |

**Free-access leaks (paid resources reachable without payment)**
- **All API endpoints** are effectively free unless they already require login/OAuth; **none require PAYG balance or invoice settlement**. There is no 402/insufficient-balance response in code.【F:app/dev_routes.py†L46-L466】【F:app/blueprints/demo.py†L13-L46】
- **Bitcoin RPC read endpoints** are public (rate-limited only), exposing potentially costly RPC calls without payment enforcement.【F:app/blueprints/bitcoin.py†L28-L117】

---

## Can an agent register and get a persistent ID?

Yes, but it depends on which “identity” you mean:
- **OAuth client_id** (agent/app identity): `/oauth/register` creates a persistent `client_id` and `client_secret` in `oauth_clients`. This is not currently tied to billing enforcement.【F:app/blueprints/oauth.py†L51-L151】【F:app/app.py†L9055-L9107】
- **User identity** (human/pubkey): `/api/challenge` + `/api/verify` (or `/verify_signature`) sets `session["logged_in_pubkey"]` and `session["access_level"]`. This is used for billing today and persisted in `ubid_users` when invoices are created.【F:app/app.py†L7561-L7717】【F:app/dev_routes.py†L311-L351】

**Billable identity used in code today**: Bitcoin pubkey in session (payments.user_pubkey).【F:app/dev_routes.py†L69-L451】

---

## Can an agent use the service end-to-end today?

**Yes, for OAuth + demo-protected routes, but payment is not required.**
- **OAuth register → authorize → token**: Implemented in both `app/blueprints/oauth.py` and `app/app.py` (monolith). The monolith is used by `wsgi.py`.【F:wsgi.py†L1-L9】【F:app/app.py†L9055-L9175】【F:app/blueprints/oauth.py†L87-L351】
- **Token use**: `/api/demo/protected` requires an OAuth token with `read_limited` and validates against the stored token in DB storage; no billing check is present.【F:app/app.py†L9649-L9699】
- **Usage counting**: only counts token/code issuance for dashboards; not billed or enforced.【F:app/dev_routes.py†L192-L213】

---

## Will an agent actually be forced to pay?

**No.** There is **no paywall or balance check** in request handling. Payment endpoints exist to top up a balance, but **no API route checks that balance** or returns a 402. Evidence:
- Payment creation/check are isolated in `dev_routes.py`; no middleware uses `ubid_users.sats_balance` or `payments` to gate endpoints.【F:app/dev_routes.py†L255-L466】
- The UI claims a 402 behavior, but no corresponding server-side logic exists.【F:app/blueprints/ui.py†L1771-L1782】

---

## Exact commands to reproduce locally (payment enforcement)

> These commands show the **current behavior** (payment is not enforced). Replace placeholders with real values.

### 1) Register an OAuth client (agent identity)
```bash
curl -sS -X POST http://localhost:5000/oauth/register \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"agent-demo","redirect_uris":["http://localhost:7000/callback"]}'
```
(Endpoint exists in both monolith and blueprint; monolith is used by wsgi.)【F:wsgi.py†L1-L9】【F:app/app.py†L9055-L9107】

### 2) Get a session (limited access) using challenge/verify
```bash
# Get challenge
curl -sS -c cookies.txt -X POST http://localhost:5000/api/challenge \
  -H 'Content-Type: application/json' \
  -d '{"pubkey":"<COMPRESSED_PUBKEY_HEX>"}'

# Verify signature (replace <SIG> with a real signature of the challenge)
curl -sS -b cookies.txt -c cookies.txt -X POST http://localhost:5000/api/verify \
  -H 'Content-Type: application/json' \
  -d '{"challenge_id":"<CHALLENGE_ID>","pubkey":"<COMPRESSED_PUBKEY_HEX>","signature":"<SIG>"}'
```
(These set `session.logged_in_pubkey` and `access_level`.)【F:app/app.py†L7561-L7717】

### 3) Create an invoice (PAYG top-up)
```bash
curl -sS -b cookies.txt -X POST http://localhost:5000/api/billing/create-invoice \
  -H 'Content-Type: application/json' \
  -d '{"amount_sats": 1000, "billing_mode": "payg"}'
```
(Proxy to `/dev/billing/create-invoice`.)【F:app/blueprints/billing_api_compat.py†L1-L31】【F:app/dev_routes.py†L255-L351】

### 4) Simulate payment confirmation (stub mode)
When running the server locally, export:
```bash
export LN_BACKEND=stub
export TEST_INVOICE_PAID=true
```
Then check the invoice:
```bash
curl -sS -b cookies.txt -X POST http://localhost:5000/api/billing/check-invoice \
  -H 'Content-Type: application/json' \
  -d '{"invoice_id":"<INVOICE_ID>"}'
```
(Stubbed `check_invoice_paid` returns true with TEST_INVOICE_PAID.)【F:app/payments/ln.py†L66-L80】【F:app/dev_routes.py†L356-L466】

### 5) Confirm balance change (no enforcement yet)
```bash
curl -sS -b cookies.txt http://localhost:5000/api/account/summary
```
(Shows updated `sats_balance` and recent payments.)【F:app/blueprints/account_api_compat.py†L91-L152】

### 6) Call a “paid” endpoint until limit triggers
**There is no limit/paywall today**, so this will not 402. For example:
```bash
# Requires OAuth token with read_limited, but does not check payment
curl -sS -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:5000/api/demo/protected
```
(No billing enforcement or 402 response exists.)【F:app/app.py†L9649-L9699】

---

## Code pointers (hyper-specific)

### OAuth register/auth/token endpoints
- **Monolith (used by wsgi)**: `app/app.py`
  - `/oauth/register` → `oauth_register`【F:app/app.py†L9055-L9107】
  - `/oauth/authorize` → `oauth_authorize`【F:app/app.py†L9126-L9146】
  - `/oauth/token` → `oauth_token`【F:app/app.py†L9147-L9175】
- **Blueprint stack**: `app/blueprints/oauth.py`
  - `/oauth/register` → `register_client`【F:app/blueprints/oauth.py†L64-L151】
  - `/oauth/authorize` → `authorize`【F:app/blueprints/oauth.py†L154-L239】
  - `/oauth/token` → `token`【F:app/blueprints/oauth.py†L246-L351】

**Storage**: `oauth_clients`, `oauth_codes`, `oauth_tokens` via `app/db_storage.py` and `app/models.py`.【F:app/db_storage.py†L89-L219】【F:app/models.py†L60-L170】

### JWT issuance and JWKS
- JWT issuance: `issue_rs256_jwt` in `app/tokens.py`.【F:app/tokens.py†L25-L59】
- JWKS endpoint: `/.well-known/openid-configuration` and `/oauth/jwks.json` in `app/oidc.py`.【F:app/oidc.py†L18-L54】

### LNURL-auth endpoints
- Blueprint: `app/blueprints/lnurl.py` (`/api/lnurl-auth/create|params|callback|check`).【F:app/blueprints/lnurl.py†L30-L214】
- Monolith duplicates: `app/app.py` (`/api/lnurl-auth/*`).【F:app/app.py†L9548-L9634】
- Storage table: `lnurl_challenges` via `app/db_storage.py` and `app/models.py`.【F:app/db_storage.py†L528-L574】【F:app/models.py†L189-L220】

### PAYG invoice creation/check
- Endpoints: `POST /dev/billing/create-invoice`, `POST /dev/billing/check-invoice`.【F:app/dev_routes.py†L255-L466】
- Compatibility endpoints: `/api/billing/create-invoice`, `/api/billing/check-invoice`.【F:app/blueprints/billing_api_compat.py†L1-L31】
- Lightning integration: `app/payments/ln.py` (`create_invoice`, `check_invoice_paid`).【F:app/payments/ln.py†L27-L80】
- Storage tables: `payments`, `ubid_users` (raw SQL in `dev_routes.py`).【F:app/dev_routes.py†L311-L451】

### Metering / quota logic
- Usage stats per client: `get_usage_stats` counts `oauth_tokens` + `oauth_codes` (no billing).【F:app/dev_routes.py†L192-L213】
- Rate limiting: `app/security.py` sets global limiter; individual routes use `@limiter.limit`.【F:app/security.py†L64-L157】【F:app/blueprints/oauth.py†L51-L351】

### Middleware / decorators enforcing billing
- `require_billing_limited` (only protects invoice endpoints).【F:app/dev_routes.py†L46-L103】
- **MISSING**: no global paywall middleware or balance check on API endpoints.

### Rate limiting configuration
- Global limiter + per-route decorators in `app/security.py`, `app/blueprints/oauth.py`, `app/blueprints/lnurl.py`, `app/blueprints/bitcoin.py`, etc.【F:app/security.py†L64-L157】【F:app/blueprints/oauth.py†L51-L351】【F:app/blueprints/lnurl.py†L30-L214】【F:app/blueprints/bitcoin.py†L22-L117】

---

## Findings (with severity)

### Critical
1) **No payment enforcement anywhere.** There is no 402 or balance check on API routes; payment only updates balance and does not gate access.【F:app/dev_routes.py†L255-L466】【F:app/blueprints/demo.py†L13-L46】
2) **Billable identity mismatch.** Billing tracks pubkey, while API usage is tied to OAuth `client_id`/tokens; there’s no binding between these, so agents can use API without paying on their client_id.【F:app/dev_routes.py†L192-L451】【F:app/blueprints/oauth.py†L64-L351】

### High
3) **Invoice flow is stubbed by default.** In production, failure to set LN_BACKEND means invoices are fake and can be marked paid via TEST_INVOICE_PAID, undermining real payment enforcement.【F:app/payments/ln.py†L48-L80】
4) **Duplicate OAuth/LNURL stacks** increase risk of bypassing future paywall middleware (blueprints vs monolith).【F:app/factory.py†L96-L171】【F:app/app.py†L572-L10419】

### Medium
5) **Public Bitcoin RPC endpoints** are rate-limited only; no auth or payment gating could lead to resource abuse/cost exposure.【F:app/blueprints/bitcoin.py†L22-L117】

### Low
6) **UI claims 402 paywall**, but server does not implement it (docs drift).【F:app/blueprints/ui.py†L1771-L1782】

---

## Minimal patch plan (1–3 days)

1) **Attach billing checks at token issuance *and* per-request (defense in depth)**
   - Add middleware/decorator on API routes to verify **client_id → billing account** and **sats_balance ≥ cost** before fulfilling request.
   - Enforce at `/oauth/token` to prevent issuing access tokens when balance is insufficient (optional, but helps prevent free-token hoarding).【F:app/blueprints/oauth.py†L246-L351】【F:app/app.py†L9147-L9175】

2) **Define a single billable identity: client_id**
   - Add a `billing_account_id` or `owner_pubkey` binding on `oauth_clients` and require it for payg deductions.
   - Migrate invoice creation to target client_id (not just session pubkey).

3) **Implement paywall response format**
   - Standardize `402 Payment Required` JSON:
     ```json
     {"error":"payment_required","invoice_id":"...","payment_request":"bolt11","sats_needed":123}
     ```
   - Add idempotency key to invoice creation (prevent invoice spam per client_id).

4) **Invoice settlement plumbing**
   - Add LND webhook or polling worker to mark payments as paid and credit balance atomically (avoid manual check endpoint for production).
   - Ensure `payments.metadata.credited` stays idempotent (already partly done).【F:app/dev_routes.py†L418-L451】

5) **Anti-abuse controls**
   - Prevent client_id farming: require authenticated owner_pubkey for `/oauth/register` in production.
   - Add per-client rate limits *and* min balance per request to block free-tier abuse.

---

## Route table (all discovered Flask routes)

> Notes: The runtime entrypoint (`wsgi.py`) uses `app/app.py`, which also defines many routes directly. The factory/blueprint stack exists in parallel. Duplicates are noted.

### app/app.py routes
- `/` GET; `/app` GET; `/home` GET; `/login` GET; `/logout` GET; `/playground` GET; `/playground/` GET (alias); `/upgrade` GET/POST; `/account` GET; `/accounts` (via compat blueprint)【F:app/app.py†L1673-L10772】
- API auth: `/api/challenge` POST; `/api/verify` POST; `/verify_signature` POST; `/guest_login` POST; `/api/whoami` GET; `/api/debug/session` GET【F:app/app.py†L5011-L10353】
- OAuth: `/oauth/register` POST; `/oauth/authorize` GET; `/oauth/token` POST; `/oauth/introspect` POST; `/oauth/clients` GET; `/oauth/clients/<id>` GET; `/oauth/clients/<id>/rotate-secret` POST; `/oauthx/status` GET; `/oauthx/docs` GET; `/.well-known/openid-configuration` (via oidc_bp)【F:app/app.py†L9055-L10419】【F:app/oidc.py†L18-L54】
- LNURL-auth: `/api/lnurl-auth/create` GET/POST; `/api/lnurl-auth/params` GET; `/api/lnurl-auth/callback/<session_id>` GET; `/api/lnurl-auth/check/<session_id>` GET【F:app/app.py†L9548-L9634】
- PoF: `/pof` (blueprint); `/api/pof/verify_psbt` POST; `/api/playground/pof/challenge` POST; `/api/playground/pof/verify` POST【F:app/pof_routes.py†L24-L281】【F:app/app.py†L7606-L10359】
- Demo: `/api/demo/free` GET; `/api/demo/protected` GET【F:app/app.py†L8455-L9699】
- Ops: `/health` GET; `/metrics` GET; `/metrics/prometheus` GET; `/turn_credentials` GET; `/screensaver` GET; `/api/public/status` GET【F:app/app.py†L599-L9176】
- Bitcoin/RPC: `/rpc/<cmd>` GET; `/decode_raw_script` POST; `/import_descriptor` POST; `/set_labels_from_zpub` POST; `/export_descriptors` GET; `/export_wallet` GET; `/convert_wif` POST; `/verify_pubkey_and_list` GET【F:app/app.py†L6920-L7397】

### Blueprint routes (factory stack)
- `app/blueprints/auth.py`: `/login`, `/verify_signature`, `/guest_login`, `/logout` (session-based).【F:app/blueprints/auth.py†L31-L208】
- `app/blueprints/oauth.py`: `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/introspect` (duplicate of monolith).【F:app/blueprints/oauth.py†L64-L351】
- `app/blueprints/lnurl.py`: `/api/lnurl-auth/create|params|callback|check` (duplicate of monolith).【F:app/blueprints/lnurl.py†L30-L214】
- `app/blueprints/bitcoin.py`: `/api/rpc/<cmd>`, `/api/verify`, `/api/decode_raw_script`, `/api/descriptors`, `/api/challenge` (overlaps monolith).【F:app/blueprints/bitcoin.py†L28-L209】
- `app/blueprints/demo.py`: `/api/demo/free`, `/api/demo/pro`, `/api/demo/protected` (overlaps monolith).【F:app/blueprints/demo.py†L13-L46】
- `app/blueprints/admin.py`: `/health`, `/health/live`, `/health/ready`, `/metrics`, `/metrics/prometheus`, `/turn_credentials`.【F:app/blueprints/admin.py†L23-L149】
- `app/blueprints/account_api_compat.py`: `/api/account/summary`, `/api/account/set-payg` (DB-backed account info).【F:app/blueprints/account_api_compat.py†L91-L187】
- `app/blueprints/billing_api_compat.py`: `/api/billing/create-invoice`, `/api/billing/check-invoice` (proxies).【F:app/blueprints/billing_api_compat.py†L1-L31】
- `app/playground_routes.py`: `/playground`, `/pof`, `/pof/verify`, `/api/playground/stats`, `/api/playground/activity` (not registered in monolith by default).【F:app/playground_routes.py†L1-L55】
- `app/stats_routes.py`: `/stats/`, `/stats/api` (not registered in monolith).【F:app/stats_routes.py†L99-L118】
- `app/docs_routes.py`: `/docs/<slug>` (registered in monolith via `register_docs_routes`).【F:app/docs_routes.py†L1-L27】【F:app/app.py†L594-L606】

---

## What’s missing to guarantee payment (exact changes)

1) **Add billing middleware to paid endpoints**
   - Create `require_payg_balance(cost, client_id)` that checks `ubid_users.sats_balance` (or new client balance table) and **returns 402 + invoice** when insufficient.
   - Attach to any endpoint that should be paid (e.g., PoF verification, covenant read/write, RPC-heavy endpoints). 

2) **Tie OAuth tokens to a billable client**
   - Include `client_id` in JWT or token store and **debit per request** using that client_id.
   - Store usage in a `usage_stats` or `usage_events` table so billing can be audited and disputes resolved.

3) **Enforce invoice settlement before token issuance**
   - Optional but strong: when `sats_balance < cost`, block `/oauth/token` and return 402 with invoice.

4) **Wire LND settlement to balances**
   - Replace manual `/billing/check-invoice` with webhook/poller that updates `payments.status` and `ubid_users.sats_balance` atomically.

5) **Anti-abuse controls**
   - Require authenticated pubkey for `/oauth/register` in production.
   - Add per-client rate limits and IP throttles for registration and token issuance.

