# What Works Now (Strict Repository Evidence)

This page is limited to code-backed and/or test-backed items. Live production claims are excluded unless explicit runtime evidence artifacts are captured and referenced. If support is only conceptual or doc-level, the claim belongs in `Experimental.md`, `Roadmap.md`, or topical conceptual pages.

## Verified by code + tests
1. **Health and metrics endpoint contracts**
   - `/health` route contract is test-covered for healthy status and version presence.
   - `/metrics` route existence and JSON response shape are test-covered.

2. **OIDC discovery + JWKS publication contracts**
   - `/.well-known/openid-configuration` and `/oauth/jwks.json` are implemented and asserted in tests.

3. **OAuth2 authorization-code core path (test context)**
   - Client registration route exists and is exercised in tests.
   - Authorization and token routes have validation/redirect behavior covered in tests.

4. **Bitcoin signature authentication path (test context)**
   - `/verify_signature` challenge checks, input validation, and success/failure branches are covered by tests.

5. **Guest login path (test context)**
   - `/guest_login` PIN and anonymous flows are covered by tests.

6. **LNURL-auth session lifecycle route behavior (test context)**
   - Create/check/callback/params routes are implemented; create/check response patterns are test-covered.

7. **PoF route surface presence (repo-defined)**
   - `/pof/`, `/pof/leaderboard`, `/pof/verify`, `/pof/certificate/<id>`, `/api/pof/stats` are present in route modules.

8. **Agent discovery + signed capability surfaces (test context)**
   - `/.well-known/agent.json`, `/agent/capabilities`, `/agent/capabilities/schema`, `/agent/skills`, `/agent/marketplace/listing` exist.
   - Tests assert signature verification and schema/discovery structure.

9. **Agent paid job lifecycle under mocked settlement (test context)**
   - `/agent/request` + `/agent/jobs/<id>` + `/agent/attestations` flows are tested with mocked invoice settlement.
   - Signed receipt generation and verification behavior is asserted in tests.

10. **Conservative trust/report wording controls (test context)**
   - Tests assert `unfunded_declared` wording and anti-overclaim language on trust/report pages.

## Explicitly excluded pending stronger evidence
- Live production uptime/performance claims.
- Live funded covenant proof claims.
- Real external Lightning settlement reliability.

## See also
- [Runtime State](./Runtime-State.md)
