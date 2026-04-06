# Runtime State (Repo-Based)

> Live runtime access is not used by default in this wiki pass. This file tracks repository-defined and test-indicated truth, with explicit confidence labels.

## Confidence Levels
- **Repo-defined:** route/module exists in repository code.
- **Test-verified:** behavior is asserted in repository tests.
- **Runtime-verified:** behavior is backed by captured runtime artifact files under `hodlxxi-wiki/raw/runtime/`.
- **Not verified live:** no direct runtime artifact was reviewed in this pass.

## Repo-defined surfaces
- **Health/ops (repo-defined):** `/health`, `/metrics`, `/metrics/prometheus`.
- **Auth (repo-defined):** `/verify_signature`, `/guest_login`, `/logout`, `/api/lnurl-auth/*`.
- **OAuth/OIDC (repo-defined):** `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`, `/oauth/jwks.json`, `/.well-known/openid-configuration`.
- **Agent (repo-defined):** `/.well-known/agent.json`, `/agent/capabilities`, `/agent/skills`, `/agent/request`, `/agent/jobs/<id>`, `/agent/attestations`, `/agent/reputation`, `/agent/chain/health`, trust/report pages.
- **PoF (repo-defined):** `/pof/`, `/pof/leaderboard`, `/pof/verify`, `/pof/certificate/<id>`, `/api/pof/stats`.
- **Bitcoin utility (repo-defined):** APIs are present across `/api/*` and `/api/bitcoin/*` depending on module/compatibility path.

## Test-verified observations
- **Health behavior (test-verified):** tests assert `status=healthy` and version metadata.
- **OIDC/JWKS behavior (test-verified):** tests assert required discovery and key fields.
- **LNURL session behavior (test-verified):** tests cover create/check response patterns.
- **OAuth behavior (test-verified):** tests cover client registration, required parameter validation, and auth redirects.
- **Agent behavior (test-verified):** tests cover signed capabilities/skills discovery and trust/report wording boundaries.

## Runtime-verified observations
- No runtime snapshot artifacts were added in this hardening pass.
- Current runtime-verified set for this page: **none recorded**.

## Not verified live in this pass
- Actual hosted uptime and availability.
- Current production data shape or counts.
- External RPC/LND behavior in the deployed environment.

## Evidence workflow
For future runtime-verified updates, store timestamped evidence files in:
- `hodlxxi-wiki/raw/runtime/*.json`
- `hodlxxi-wiki/raw/runtime/*.txt`

Then cite those files in relevant wiki pages before promoting claims to runtime-verified.

## See also
- [What Works Now](./What-Works-Now.md)
- [Experimental](./Experimental.md)
- [Agent Capabilities](./Agent-Capabilities.md)
- [Auth Surfaces](./Auth-Surfaces.md)
