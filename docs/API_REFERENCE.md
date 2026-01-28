# HODLXXI API Reference

Complete reference for all 55+ API endpoints.

## Table of Contents

1. [Authentication](#authentication)
2. [OAuth2/OIDC](#oauth2oidc)
3. [Proof-of-Funds](#proof-of-funds)
4. [Bitcoin/Covenant](#bitcoincovenant)
5. [Chat/Real-time](#chatreal-time)
6. [Admin/Developer](#admindeveloper)
7. [Playground](#playground)

---

## Authentication

### POST /verify_signature
Verify Bitcoin message signature.

**Request:**
```json
{
  "message": "challenge_string",
  "signature": "base64_sig",
  "address": "bc1q..."
}
```

**Response:**
```json
{
  "verified": true,
  "pubkey": "02abc...",
  "access_level": "full"
}
```

### POST /guest_login
Anonymous guest access.

**Request:**
```json
{
  "pin": "optional_pin_code"
}
```

**Response:**
```json
{
  "ok": true,
  "label": "Guest-abc123"
}
```

### POST /special_login
Admin login with whitelisted pubkey.

**Request:**
```json
{
  "signature": "base64_sig"
}
```

**Response:**
```json
{
  "verified": true,
  "pubkey": "023d34...",
  "access_level": "special"
}
```

### GET /logout
End session.

---

## OAuth2/OIDC

### POST /oauth/register
Register new OAuth2 client.

**Request:**
```json
{
  "client_name": "MyApp",
  "redirect_uris": ["https://myapp.com/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"]
}
```

**Response:**
```json
{
  "client_id": "client_abc123",
  "client_secret": "secret_xyz789",
  "created_at": "2025-12-12T17:00:00Z"
}
```

### GET /oauth/authorize
OAuth2 authorization endpoint.

**Parameters:**
- `client_id` - Client identifier
- `redirect_uri` - Callback URL
- `response_type` - "code"
- `scope` - Requested scopes
- `state` - CSRF protection

### POST /oauth/token
Exchange authorization code for tokens.

**Request:**
```json
{
  "grant_type": "authorization_code",
  "code": "auth_code_here",
  "redirect_uri": "https://myapp.com/callback",
  "client_id": "client_abc123",
  "client_secret": "secret_xyz789"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_xyz",
  "scope": "profile:read"
}
```

### POST /oauth/introspect
Validate access token.

### POST /oauth/revoke
Revoke token.

### GET /oauth/clients
List client's OAuth applications.

---

## Proof-of-Funds

### POST /pof/api/generate-challenge
Generate PoF challenge.

**Request:**
```json
{
  "addresses": ["bc1q...", "bc1p..."]
}
```

**Response:**
```json
{
  "challenge": "hex_challenge",
  "message": "HODLXXI Proof of Funds\nChallenge: ...",
  "addresses": ["bc1q..."]
}
```

### POST /pof/api/verify-signatures
Verify signed addresses and calculate balance.

**Request:**
```json
{
  "signatures": [
    {"address": "bc1q...", "signature": "base64_sig"}
  ],
  "privacy_level": "threshold"
}
```

**Response:**
```json
{
  "verified_addresses": [
    {"address": "bc1q...", "balance": 0.5}
  ],
  "total_balance": 0.5,
  "tier": "whale",
  "certificate_id": "cert_abc123"
}
```

---

## Bitcoin/Covenant

### GET /verify_pubkey_and_list
List all descriptors for a pubkey.

**Parameters:**
- `pubkey` - Compressed hex pubkey

**Response:**
```json
{
  "descriptors": [
    {
      "desc": "raw(6382...)#checksum",
      "saving_balance_usd": "1234.56",
      "checking_balance_usd": "789.01",
      "op_if_pub": "02abc...",
      "op_else_pub": "03def..."
    }
  ]
}
```

### POST /decode_raw_script
Decode Bitcoin script hex.

**Request:**
```json
{
  "script_hex": "6382012088ac..."
}
```

**Response:**
```json
{
  "asm": "OP_IF OP_1 <pubkey> OP_CHECKSIG OP_ELSE ...",
  "type": "nonstandard",
  "reqSigs": 1
}
```

### POST /import_descriptor
Import descriptor to wallet.

**Request:**
```json
{
  "descriptor": "raw(...)#checksum",
  "label": "MyContract",
  "rescan": false
}
```

### GET /export_descriptors
Export all wallet descriptors.

### GET /export_wallet
Download complete wallet backup.

### GET /rpc/<cmd>
Execute Bitcoin RPC command (admin only).

---

## Chat/Real-time

### Socket.IO Events

**Connection:**
```javascript
const socket = io('https://hodlxxi.com');
```

**Events:**
- `connect` - Connection established
- `user:logged_in` - User joined
- `user:left` - User disconnected
- `message` - New chat message
- `online:list` - Online users list

---

## Admin/Developer

### GET /dev-dashboard
Developer dashboard (requires auth).

### GET /metrics
Application metrics.

### GET /metrics/prometheus
Prometheus-format metrics.

### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-12-12T17:00:00Z",
  "services": {
    "database": "healthy",
    "redis": "healthy",
    "bitcoin_rpc": "healthy"
  }
}
```

---

## Playground

### GET /playground
Interactive API testing interface.

### POST /api/playground/pof/challenge
Playground PoF challenge.

### POST /api/playground/pof/verify
Playground PoF verification.

### POST /api/playground/lightning/init
Initialize Lightning authentication flow.

### GET /api/playground/lightning/callback
Lightning auth callback.

### POST /api/playground/nostr/auth
Nostr key authentication.

### GET /api/playground/stats
Playground usage statistics.

### GET /playground-globals
Global playground configuration.

---

## LNURL-auth

### POST /api/lnurl-auth/create
Create LNURL-auth session.

### GET /api/lnurl-auth/params
Get LNURL-auth parameters.

### GET /api/lnurl-auth/callback/<session_id>
LNURL-auth callback handler.

### GET /api/lnurl-auth/check/<session_id>
Check auth status.

---

## Rate Limits

**General:** 10 requests/second  
**Auth endpoints:** 5 requests/minute  
**Socket.IO:** 1000 burst allowed

## Authentication

Most endpoints require authentication via:
1. Session cookie (after login)
2. OAuth2 Bearer token
3. API key (future)

## Error Responses
```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": {}
}
```

**Common HTTP status codes:**
- `200` - Success
- `400` - Bad request
- `401` - Unauthorized
- `403` - Forbidden
- `429` - Rate limited
- `500` - Server error

---

**Last updated:** December 12, 2025
