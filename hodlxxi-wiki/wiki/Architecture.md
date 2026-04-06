# Architecture (Current Repository Reality)

## Runtime shape
- Flask runtime includes both a legacy monolith (`app/app.py`) and a factory/blueprint architecture (`app/factory.py`, `app/blueprints/*`).
- Factory registers modular blueprints while preserving legacy route compatibility overrides for `/login` and `/playground`.

## Monolith vs factory transition
- Repository and docs describe a transitional state: monolith-first with partial modularization.
- `wsgi.py` uses factory creation path, while legacy code paths remain in use for selected handlers.

## Route compatibility layer
- Compatibility blueprints and endpoint aliases exist (`account_api_compat`, `billing_api_compat`, `home` aliasing, legacy proxy functions).
- This indicates active refactor with backward-compatibility preservation.

## Agent/public surfaces
- Agent discovery and execution routes are blueprint-managed (`app/blueprints/agent.py`).
- Public docs and trust endpoints are available without requiring user login in tested paths.

## Docs/runtime separation
- Core architecture/trust docs live under repository root and `docs/`.
- Runtime behavior lives in `app/` and is partially validated by unit/integration tests under `tests/`.
- This wiki layer (`hodlxxi-wiki/`) is synthesis, not source-of-truth runtime state.

## See also
- [Runtime State](./Runtime-State.md)
- [Experimental](./Experimental.md)
