# Production Feature Gates

HODLXXI defaults defensive and developer-only surfaces to closed in production.
Boolean flags are enabled only by explicit true values: `1`, `true`, `yes`, or `on`.
Unset values and all other strings are treated as disabled.

Production defaults:

| Flag | Default | Surface |
| --- | --- | --- |
| `ENABLE_DEBUG_ROUTES` | `false` | Debug session inspection routes such as `/api/debug/session`. |
| `ENABLE_DEV_ROUTES` | `false` | Developer routes such as `/dev/*` and agent dev payment simulation. |
| `ENABLE_PUBLIC_METRICS` | `false` | Public `/metrics` and `/metrics/prometheus`. |
| `ENABLE_PUBLIC_TURN_CREDENTIALS` | `false` | Public `/turn_credentials`. |
| `ENABLE_LEGACY_WALLET_ROUTES` | `false` | Legacy wallet/RPC routes such as `/rpc/<cmd>`, `/api/rpc/<cmd>`, descriptor import/export, and zpub labeling. |
| `ENABLE_OAUTH_DEV_ROUTES` | `false` | OAuth developer helper routes. |

Health/readiness, OIDC discovery, JWKS, public status, LNURL auth, core OAuth,
agent public surfaces, billing agent, NIP17, POF, and UI routes remain registered
without these flags.
