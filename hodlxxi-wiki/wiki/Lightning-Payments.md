# Lightning Payments Surface

## Implemented repository surfaces
- Agent billing endpoints exist: `/api/billing/agent/create-invoice`, `/api/billing/agent/check-invoice`.
- Agent job flow uses invoice creation + payment lookup before marking jobs complete.
- Agent pricing constants are present (e.g., `PING_SATS`, attestation costs).
- OAuth-paid client gating is used for selected Bitcoin RPC endpoints via billing decorators.

## Tests indicating behavior
- Integration tests patch invoice creation/check functions and validate invoice-pending -> done job transition.
- Tests assert receipt issuance after marked-paid conditions.

## Caveats
- This wiki pass does not verify live LND/backend payment settlement.
- LNURL-auth is an authentication flow, not direct proof of paid invoice settlement in agent job processing.
