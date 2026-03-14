# Security & Architecture Audit – Universal Bitcoin Identity Layer

Date: 2026-03-14
Scope: `app/*`, `tests/*`, lint/CI config.

## 1) Repo risk map

Highest-risk areas identified:

- `app/app.py` (~12.4k lines): multiple auth gates, duplicate OAuth logic, legacy/compat code, and mixed session+token behavior.
- `app/blueprints/oauth.py` + `app/oidc.py`: OAuth/OIDC/PKCE/token issuance and introspection.
- `app/tokens.py`: JWT algorithm/key behavior.
- `app/security.py` + `app/config.py`: prod/dev security defaults and middleware enforcement.
- `app/agent_invoice_api.py` + `app/payments/ln.py`: subprocess and infrastructure boundary assumptions.
- Test coverage: `tests/test_oauth_flows.py`, `tests/test_auth_flows.py` (strong happy-path coverage, weak adversarial coverage).

---

## 2) Findings table

| # | Title | Severity | Affected file(s) | Area |
|---|---|---|---|---|
| 1 | PKCE can be bypassed via reversed parameter validation path | **Critical** | `app/blueprints/oauth.py`, `app/oidc.py` | `/oauth/token`, `validate_pkce()` |
| 2 | OAuth introspection accepts unsigned/forged JWTs as active | **Critical** | `app/blueprints/oauth.py` | `/oauth/introspect` |
| 3 | `/api/verify` trusts `nostr` and `lightning` methods without cryptographic proof | **Critical** | `app/app.py` | `api_verify()` |
| 4 | Auth cookies are set with `secure=False` and access token cookie not `HttpOnly` | **High** | `app/app.py` | `_finish_login()` |
| 5 | Weak/unsafe secret fallback behavior in runtime paths | **High** | `app/app.py`, `app/config.py` | startup secret handling |
| 6 | Token algorithm/issuer architecture drift (HS256 config vs always-RS256 issuance) | **High** | `app/tokens.py`, `app/config.py`, `app/app.py` | JWT issuance/verification |
| 7 | Multiple `before_request` auth gates with conflicting allowlists | **Medium** | `app/app.py` | auth guard stack |
| 8 | Placeholder token format (`sub.random`) coexists with JWT/OAuth flow | **Medium** | `app/app.py` | `mint_access_token()` and callers |
| 9 | Error responses leak internal exception details in auth/OAuth paths | **Low** | `app/blueprints/oauth.py`, `app/blueprints/auth.py` | error handlers |
| 10 | Lint/format tooling excludes highest-risk file (`app/app.py`) | **Low** | `pyproject.toml`, `.flake8` | static quality gates |

---

## 3) Detailed findings

### 1. PKCE can be bypassed via reversed parameter validation path
- **Severity:** Critical
- **Affected files:** `app/blueprints/oauth.py`, `app/oidc.py`
- **Code area:** `token()` calls `validate_pkce(code_verifier, stored_challenge, ...)` while helper expects `(code_challenge, code_verifier)` and also has a “swapped order” fallback.
- **Why this is a problem:** PKCE correctness depends on strict verifier→challenge validation. Current logic intentionally accepts swapped semantics, enabling non-standard acceptance conditions.
- **Exploit/failure scenario:** Attacker with an intercepted authorization code and observed `code_challenge` can submit crafted `code_verifier` values that satisfy reversed checks and obtain tokens.
- **Minimal fix:**
  1. Change callsite to `validate_pkce(code_data["code_challenge"], code_verifier, ...)`.
  2. Remove swapped-order fallback from `validate_pkce()`.
  3. Add explicit tests for swapped-argument rejection.
- **Current test coverage:** Partial. Existing tests cover happy path and random wrong verifier, but not adversarial crafted verifier for reversed validation.

### 2. OAuth introspection accepts unsigned/forged JWTs as active
- **Severity:** Critical
- **Affected file:** `app/blueprints/oauth.py`
- **Code area:** `introspect()` uses `jwt.decode(..., options={"verify_signature": False, ...})`.
- **Why this is a problem:** RFC 7662 introspection must not mark attacker-crafted tokens as active. Disabling signature verification allows arbitrary claims.
- **Exploit/failure scenario:** Any party with valid client credentials can submit a forged JWT with future `exp` and get `{ "active": true }`; relying resource servers may accept fake identities/scopes.
- **Minimal fix:**
  1. Verify signature against current JWKS/public key.
  2. Validate `iss`, `aud`, and expiration.
  3. Prefer DB-backed opaque token introspection if access tokens are DB-issued.
- **Current test coverage:** Weak. Tests only assert valid token becomes active and random invalid token becomes inactive; no forged-but-well-formed token test.

### 3. `/api/verify` trusts `nostr` and `lightning` methods without cryptographic proof
- **Severity:** Critical
- **Affected file:** `app/app.py`
- **Code area:** `api_verify()` sets `ok = True` for `method == "nostr"` and `method == "lightning"`.
- **Why this is a problem:** This is direct auth bypass in a login endpoint.
- **Exploit/failure scenario:** Attacker requests `/api/challenge` with method `nostr`/`lightning`, then calls `/api/verify` with any non-empty signature and gets authenticated session + tokens without proving key ownership.
- **Minimal fix:**
  1. Remove unconditional `ok = True` branches.
  2. Implement real signature verification for those methods, or reject as `501 Not Implemented`.
  3. Add negative tests that fake signatures cannot authenticate.
- **Current test coverage:** Missing for this exact bypass path.

### 4. Auth cookies are set with `secure=False` and access token cookie not `HttpOnly`
- **Severity:** High
- **Affected file:** `app/app.py`
- **Code area:** `_finish_login()`.
- **Why this is a problem:** Cookies carrying auth material are sent over HTTP if misrouted and access token is script-readable.
- **Exploit/failure scenario:** XSS or mixed-content/HTTP downgrade situations can steal bearer-like cookie data.
- **Minimal fix:**
  1. Set `secure=True` in production (config-gated).
  2. Set `httponly=True` for access token cookie if browser JS does not strictly require it.
  3. Consider `SameSite=Strict` where possible.
- **Current test coverage:** None around cookie flags.

### 5. Weak/unsafe secret fallback behavior in runtime paths
- **Severity:** High
- **Affected files:** `app/app.py`, `app/config.py`
- **Code area:** startup secret resolution + config defaults.
- **Why this is a problem:** If `FLASK_SECRET_KEY` is absent, runtime silently generates ephemeral secret; `JWT_SECRET` defaults to known dev value in config.
- **Exploit/failure scenario:** Misconfigured prod deployment can boot with weak/default secrets or rotating session secrets on restart, causing session invalidation and potential token predictability if HS256 path is used.
- **Minimal fix:**
  1. Fail fast in production when secrets are absent/default.
  2. Remove insecure defaults (`change-me`, `dev-secret-*`) from runtime code paths.
  3. Enforce config validation on startup.
- **Current test coverage:** Unit tests validate `validate_config()`, but monolith startup path does not enforce it.

### 6. Token algorithm/issuer architecture drift (HS256 config vs always-RS256 issuance)
- **Severity:** High
- **Affected files:** `app/tokens.py`, `app/config.py`, `app/app.py`
- **Code area:** `issue_rs256_jwt()` contains unconditional `if True:` RS256 branch; config default says `JWT_ALGORITHM=HS256`; monolith has separate decode config.
- **Why this is a problem:** Issuance/verification mismatch causes brittle auth behavior and can produce “works accidentally” failures depending on which endpoint validates token.
- **Exploit/failure scenario:** Tokens issued in one flow fail verification in another, leading to accidental bypasses (fallback checks), unexpected 401s, or inconsistent trust boundaries.
- **Minimal fix:**
  1. Remove dead `if True` branch and honor one canonical algorithm policy.
  2. Unify token issuance/validation through one module.
  3. Add integration tests crossing all token-consuming endpoints.
- **Current test coverage:** Partial and flow-local only.

### 7. Multiple `before_request` auth gates with conflicting allowlists
- **Severity:** Medium
- **Affected file:** `app/app.py`
- **Code area:** several guards (`_oauth_public_allowlist`, `check_auth`, `_public_guard_for_lnurl`, and additional late guards).
- **Why this is a problem:** Security behavior depends on declaration/import order and duplicated path checks. This causes accidental exposure or accidental lockout when adding routes.
- **Exploit/failure scenario:** New sensitive endpoint may be unintentionally public due to one allowlist while another assumes it is protected; regressions are hard to detect.
- **Minimal fix:**
  1. Replace with one centralized auth middleware.
  2. Define route-level auth policy declaratively.
  3. Add exhaustive tests for public/protected matrix.
- **Current test coverage:** Not comprehensive for route policy matrix.

### 8. Placeholder token format (`sub.random`) coexists with JWT/OAuth flow
- **Severity:** Medium
- **Affected file:** `app/app.py`
- **Code area:** `mint_access_token()` and usage in `api_verify()` / `_finish_login()`.
- **Why this is a problem:** Non-standard opaque-like token string is mixed with JWT/OAuth semantics, increasing chance of accidental acceptance/rejection and auth confusion.
- **Exploit/failure scenario:** Clients treat placeholder token as bearer JWT, hit endpoints with incompatible validators, and code later adds naive parsing assumptions.
- **Minimal fix:**
  1. Stop issuing placeholder tokens from login flows.
  2. Use one canonical token service (JWT or opaque DB token).
  3. Mark legacy flows as deprecated with hard cutoff.
- **Current test coverage:** No tests that enforce token type consistency across flows.

### 9. Error responses leak internal exception details in auth/OAuth paths
- **Severity:** Low
- **Affected files:** `app/blueprints/oauth.py`, `app/blueprints/auth.py`
- **Code area:** returns `str(e)` in HTTP responses.
- **Why this is a problem:** Leaks backend internals and implementation details to clients.
- **Exploit/failure scenario:** Attackers gain insight into DB schema, validation branches, or infrastructure dependencies.
- **Minimal fix:** Return generic messages to clients; keep detailed stack traces in logs only.
- **Current test coverage:** None for information disclosure behavior.

### 10. Lint/format tooling excludes highest-risk file (`app/app.py`)
- **Severity:** Low
- **Affected files:** `pyproject.toml`, `.flake8`
- **Code area:** Black/isort/flake8 exclusions.
- **Why this is a problem:** Most security-sensitive file bypasses routine static hygiene, allowing complexity and defects to accumulate.
- **Exploit/failure scenario:** Security bugs persist because the largest file is systematically outside quality gates.
- **Minimal fix:** Gradually re-enable linting/formatting for `app/app.py` (start with focused rules), block new violations.
- **Current test coverage:** N/A (process/tooling).

---

## 4) Top 10 fixes in order

1. Fix PKCE verification contract and remove swapped fallback.
2. Replace `/oauth/introspect` no-verify decode with real signature+claim validation.
3. Remove `ok=True` bypass in `/api/verify` (`nostr`, `lightning`) until real verification exists.
4. Harden auth cookies (`Secure`, `HttpOnly`, strict SameSite policy as possible).
5. Enforce startup fail-fast for missing/weak secrets in production.
6. Unify token architecture (single issuer/validator; remove placeholder token path).
7. Collapse all `before_request` auth logic into one policy engine.
8. Eliminate duplicate OAuth implementations between monolith and blueprint; keep one source of truth.
9. Remove exception detail leakage from public error responses.
10. Bring `app/app.py` back under lint/static analysis with staged cleanup.

---

## 5) Cheap wins

- Delete swapped-order PKCE compatibility code (small patch, large security gain).
- Replace `verify_signature=False` introspection decode with DB lookup path already present in monolith.
- Flip cookie flags in `_finish_login()` based on existing env/config (`FORCE_HTTPS`, `SECURE_COOKIES`).
- Add one regression test each for:
  - forged introspection token rejected,
  - `nostr/lightning` fake verify rejected,
  - PKCE reversed exploit rejected.
- Replace `return jsonify({"error": str(e)})` with generic error constants.

---

## 6) Dangerous unknowns (needs runtime/manual verification)

- Which app entrypoint is authoritative in production over time (`wsgi.py -> app.app` now, but factory exists and may be used later).
- Whether any reverse proxy path permits direct Gunicorn exposure, invalidating “localhost/internal” assumptions.
- Whether frontend depends on non-HttpOnly access cookie (`at`) for JS (affects migration plan).
- Whether third-party resource servers trust `/oauth/introspect` output directly (amplifies forged-token risk).
- Actual OAuth client storage/rotation policy and secret lifecycle in production DB.

---

## 7) Suggested tests to add immediately

1. **PKCE exploit regression test:** assert token exchange fails when `code_verifier = b64url(sha256(code_challenge))` under current reversed call shape.
2. **Introspection forged token test:** submit attacker-crafted JWT with future `exp`; must return `active=false` unless signature/issuer/audience valid.
3. **`/api/verify` bypass test:** create challenge with `method="nostr"` and random signature; must fail.
4. **Cookie security test:** in production config, assert `Set-Cookie` has `Secure` and `HttpOnly` for auth cookies.
5. **Auth policy matrix test:** enumerate public/protected routes and assert expected status (200/302/401).
6. **Token consistency test:** all issued access tokens should be one canonical type and accepted by all protected APIs using shared verifier logic.
