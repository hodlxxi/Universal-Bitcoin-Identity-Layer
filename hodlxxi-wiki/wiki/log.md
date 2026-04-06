# HODLXXI Wiki Log

[2026-04-06]

Event: bootstrap

Details:
- Created `hodlxxi-wiki/` structure with `raw/` and `wiki/` layers.
- Initialized canonical wiki pages:
  - `index.md`, `Overview.md`, `Trust-Model.md`, `Runtime-State.md`,
  - `Agent-Capabilities.md`, `Auth-Surfaces.md`, `Lightning-Payments.md`,
  - `Covenant-Model.md`, `Reputation-Surface.md`, `Architecture.md`,
  - `What-Works-Now.md`, `Experimental.md`, `Roadmap.md`, `log.md`.
- Added local wiki maintenance script: `scripts/wiki_lint.py`.

Sources reviewed:
- `README.md`
- `ARCHITECTURE.md`
- `TRUST_MODEL.md`
- `AGENT_PROTOCOL.md`
- `docs/AGENT_SURFACES.md`
- `docs/SYSTEM_ARCHITECTURE.md`
- `docs/API_REFERENCE.md`
- `docs/README.md`
- `docs/COVENANT_SYSTEM.md`
- `BLUEPRINT_ARCHITECTURE.md`
- `app/factory.py`
- `app/blueprints/{agent,auth,oauth,lnurl,bitcoin,ui}.py`
- `app/pof_routes.py`
- `tests/integration/{test_api_endpoints,test_agent_trust_surface,test_agent_ubid}.py`
- `tests/{test_auth_flows,test_oauth_flows,test_bitcoin_flows}.py`
- `skills/public/hodlxxi-bitcoin-identity/SKILL.md`

[2026-04-06]

Event: review-hardening

Details:
- Hardened `hodlxxi-wiki/AGENTS.md` with strict hard constraints and critical-error language.
- Normalized `wiki/log.md` into append-only event format.
- Tightened evidence/confidence framing in runtime-oriented wiki pages.
- Added explicit raw-evidence workflow docs in all `raw/*` subdirectories.
- Improved cross-linking across core wiki pages with short `See also` sections.
- Extended `scripts/wiki_lint.py` checks for raw subdirectories, raw scaffolding presence, and top-level headings.
- Kept README changes minimal with a wording-only refinement.

Sources reviewed:
- `hodlxxi-wiki/AGENTS.md`
- `hodlxxi-wiki/wiki/{Overview,Trust-Model,Runtime-State,Architecture,What-Works-Now,Experimental,log}.md`
- `scripts/wiki_lint.py`
- `README.md`
