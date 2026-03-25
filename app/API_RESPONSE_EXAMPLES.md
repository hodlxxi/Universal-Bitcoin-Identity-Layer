# API Response Examples (Current Runtime-Oriented)

These examples are representative of current runtime patterns. They are examples, not a formal compatibility guarantee.

## Health

### `GET /health`

```json
{
  "status": "ok"
}
```

## OAuth client registration

### `POST /oauth/register` success

```json
{
  "client_id": "client_xxx",
  "client_secret": "...",
  "client_name": "Example App",
  "redirect_uris": ["https://example.com/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "client_id_issued_at": 1730000000
}
```

### `POST /oauth/register` validation error

```json
{
  "error": "client_name is required"
}
```

## OAuth token exchange

### `POST /oauth/token` success (shape may vary by config)

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### `POST /oauth/token` invalid grant

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid or expired authorization code"
}
```

## LNURL-auth

### `POST /api/lnurl-auth/create` success

```json
{
  "session_id": "...",
  "challenge": "...",
  "lnurl": "https://<host>/api/lnurl-auth/callback/<session_id>",
  "qr_code": "https://<host>/api/lnurl-auth/callback/<session_id>",
  "k1": "...",
  "tag": "login"
}
```

### `GET /api/lnurl-auth/check/<session_id>` not found

```json
{
  "verified": false,
  "error": "Session not found or expired"
}
```

## PoF stats

### `GET /api/pof/stats` success

```json
{
  "verified_users": 12,
  "total_btc": 3.75,
  "addresses_verified": 47
}
```

## Error-format reality check

Current runtime uses multiple response patterns. Integrators should parse per-endpoint contracts rather than assuming one universal envelope.
