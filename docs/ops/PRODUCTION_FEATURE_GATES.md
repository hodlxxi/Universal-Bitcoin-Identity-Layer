# Production Feature Gates

HODLXXI defaults defensive, developer-only, public diagnostic, and unsafe legacy
surfaces to closed in production. Boolean flags are enabled only by explicit true
values: `1`, `true`, `yes`, or `on`. Unset values and all other strings are
treated as disabled.

Production defaults:

| Flag | Default | Surface |
| --- | --- | --- |
| `ENABLE_DEBUG_ROUTES` | `false` | Debug session inspection routes such as `/api/debug/session`. |
| `ENABLE_DEV_ROUTES` | `false` | Developer routes such as `/dev/*` and agent dev payment simulation. |
| `ENABLE_PUBLIC_METRICS` | `false` | Public `/metrics` and `/metrics/prometheus`. |
| `ENABLE_PUBLIC_TURN_CREDENTIALS` | `false` | Public `/turn_credentials`. |
| `ENABLE_LEGACY_WALLET_ROUTES` | `false` | Unsafe legacy wallet/API routes such as `/api/rpc/<cmd>` and `/api/descriptors`. Do not use this flag as the production fix for the covenant wallet UI. |
| `ENABLE_OAUTH_DEV_ROUTES` | `false` | OAuth developer helper routes. |

Health/readiness, OIDC discovery, JWKS, public status, LNURL auth, core OAuth,
agent public surfaces, billing agent, NIP17, POF, and UI routes remain registered
without these flags.

Authenticated covenant wallet actions are product routes, not public legacy
surfaces. The browser covenant workflow keeps these routes available only after
session authorization proves both `logged_in_pubkey` and `access_level == "full"`:

- `POST /import_descriptor`
- `POST /set_labels_from_zpub`
- `GET /export_descriptors`
- `GET /rpc/<cmd>` for the strict full-user browser allowlist only

Anonymous, guest, and limited sessions must not receive `200` responses from
these wallet routes. `ENABLE_LEGACY_WALLET_ROUTES=true` must not be enabled in
production merely to restore the wallet UI because it also reopens broader legacy
surfaces that are intentionally closed by default.


`GET /export_wallet` is intentionally not restored by this recovery PR. The
current browser shell still contains an Export Wallet control that targets that
legacy endpoint, but wallet-file export needs a separate owner-only export
design with explicit approval, receipts, and operator runbook coverage before it
can be safely exposed. This PR does not add `dumpwallet`, `dumpprivkey`,
`walletpassphrase`, `importprivkey`, `send*`, `stop`, or arbitrary RPC passthrough
to any browser allowlist.
