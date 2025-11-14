# API Response Examples

Complete documentation of all API endpoints with request/response examples.

## Table of Contents
- [Authentication Endpoints](#authentication-endpoints)
- [OAuth2/OIDC Endpoints](#oauth2oidc-endpoints)
- [LNURL-Auth Endpoints](#lnurl-auth-endpoints)
- [Chat & Messaging Endpoints](#chat--messaging-endpoints)
- [Bitcoin Wallet Endpoints](#bitcoin-wallet-endpoints)
- [Proof of Funds (PoF) Endpoints](#proof-of-funds-pof-endpoints)
- [Monitoring Endpoints](#monitoring-endpoints)

---

## Authentication Endpoints

### Health Check
**Endpoint:** `GET /health`

**Description:** Health check endpoint for monitoring system status

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1698765432.123,
  "active_sockets": 42,
  "online_users": 15,
  "chat_history_size": 1250,
  "rpc": "connected"
}
```

**Error Response:**
```json
{
  "status": "unhealthy",
  "timestamp": 1698765432.123,
  "rpc": "error",
  "rpc_error": "Connection refused"
}
```

---

### Challenge Issuance
**Endpoint:** `POST /api/challenge`

**Description:** Create a short-lived login challenge that the wallet must sign.

**Request Body:**
```json
{
  "pubkey": "02a1b2c3d4e5f6..."
}
```

**Success Response (200):**
```json
{
  "challenge_id": "0f7e09b4-6382-47f8-9cf5-0e3cc0a34c51",
  "challenge": "HODLXXI:login:1698765432:9b7c2d10",
  "expires_in": 300
}
```

**Error Response (400):**
```json
{
  "error": "Missing or invalid pubkey"
}
```

---

### Verify Challenge Signature
**Endpoint:** `POST /api/verify`

**Description:** Validate the signed challenge and mint an access token.

**Request Body:**
```json
{
  "challenge_id": "0f7e09b4-6382-47f8-9cf5-0e3cc0a34c51",
  "pubkey": "02a1b2c3d4e5f6...",
  "signature": "304502210..."
}
```

**Success Response (200):**
```json
{
  "verified": true,
  "token_type": "Bearer",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": null,
  "expires_in": 900,
  "pubkey": "02a1b2c3d4e5f6...",
  "access_level": "limited"
}
```

**Error Responses:**
```json
// Missing parameters
{
  "error": "Missing required parameters"
}

// Expired or missing challenge
{
  "error": "Invalid or expired challenge"
}

// Signature verification failure
{
  "error": "Invalid signature"
}
```

---

## OAuth2/OIDC Endpoints

### OpenID Configuration Discovery
**Endpoint:** `GET /.well-known/openid-configuration`

**Description:** OpenID Connect discovery endpoint

**Response (200):**
```json
{
  "issuer": "https://yourdomain.com",
  "authorization_endpoint": "https://yourdomain.com/oauth/authorize",
  "token_endpoint": "https://yourdomain.com/oauth/token",
  "jwks_uri": "https://yourdomain.com/oauth/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "claims_supported": ["sub", "name", "email", "picture"]
}
```

---

### Client Registration
**Endpoint:** `POST /oauth/register`

**Description:** Register a new OAuth2 client application

**Request Body:**
```json
{
  "client_name": "My Bitcoin App",
  "redirect_uris": [
    "https://myapp.com/callback"
  ],
  "pubkey": "02a1b2c3d4e5f6...",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_post"
}
```

**Success Response (201):**
```json
{
  "ok": true,
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "s3cr3t_v4lu3_g3n3r4t3d",
  "client_name": "My Bitcoin App",
  "redirect_uris": [
    "https://myapp.com/callback"
  ],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "created_at": 1698765432
}
```

**Error Responses:**
```json
// Missing required fields
{
  "ok": false,
  "error": "client_name and redirect_uris required"
}

// Invalid redirect URI
{
  "ok": false,
  "error": "Invalid redirect_uri format"
}
```

---

### Authorization Request
**Endpoint:** `GET /oauth/authorize`

**Description:** Initiate OAuth2 authorization flow

**Query Parameters:**
- `response_type`: code (required)
- `client_id`: Client ID (required)
- `redirect_uri`: Callback URL (required)
- `scope`: openid profile email (optional)
- `state`: Anti-CSRF token (recommended)
- `nonce`: Replay protection (recommended)

**Example Request:**
```
GET /oauth/authorize?
  response_type=code&
  client_id=550e8400-e29b-41d4-a716-446655440000&
  redirect_uri=https://myapp.com/callback&
  scope=openid+profile+email&
  state=xyz123&
  nonce=abc789
```

**Success Response (302 Redirect):**
```
Location: https://myapp.com/callback?
  code=AUTH_CODE_HERE&
  state=xyz123
```

**Error Response (302 Redirect):**
```
Location: https://myapp.com/callback?
  error=invalid_request&
  error_description=Invalid+client_id&
  state=xyz123
```

---

### Token Exchange
**Endpoint:** `POST /oauth/token`

**Description:** Exchange authorization code for access token

**Request Body (Authorization Code Grant):**
```json
{
  "grant_type": "authorization_code",
  "code": "AUTH_CODE_HERE",
  "redirect_uri": "https://myapp.com/callback",
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "s3cr3t_v4lu3_g3n3r4t3d"
}
```

**Success Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_value_here",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email"
}
```

**Request Body (Refresh Token Grant):**
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "refresh_token_value_here",
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "s3cr3t_v4lu3_g3n3r4t3d"
}
```

**Error Responses:**
```json
// Invalid authorization code
{
  "error": "invalid_grant",
  "error_description": "Invalid or expired authorization code"
}

// Invalid client credentials
{
  "error": "invalid_client",
  "error_description": "Invalid client_id or client_secret"
}

// Missing parameters
{
  "error": "invalid_request",
  "error_description": "Missing required parameter: grant_type"
}
```

---

## LNURL-Auth Endpoints

### Create LNURL-Auth Session
**Endpoint:** `POST /api/lnurl-auth/create`

**Description:** Create a new LNURL-auth session for Lightning wallet login

**Request Body:**
```json
{
  "client_id": "my-app-client-id"
}
```

**Success Response (200):**
```json
{
  "ok": true,
  "session_id": "lnauth_abc123def456",
  "lnurl": "LNURL1DP68GURN8GHJ7MRWW4EXCTNXD9SHG6NPVCHXXMMD9AKXUATJDSKHQCTE8AEK2UMND9HKU0F4XSUNJWPHXUCRJDE3VDJNZV33XQENJWPS8YMRWDFHVCUNJVE3VY6KYWF5XVMNJD3JXS6NQVE38Q6NSD3SVSUK2DFHVCCRJV338Q6KGVP5XF6KZWFEX5UNJ0F4XYEN2VFEXA",
  "k1": "challenge_string_here",
  "expires_in": 300
}
```

**Error Response (500):**
```json
{
  "ok": false,
  "error": "Failed to create session"
}
```

---

### Check LNURL-Auth Status
**Endpoint:** `GET /api/lnurl-auth/check/<session_id>`

**Description:** Check if LNURL-auth has been completed

**Success Response (200) - Pending:**
```json
{
  "ok": true,
  "status": "pending"
}
```

**Success Response (200) - Authenticated:**
```json
{
  "ok": true,
  "status": "authenticated",
  "pubkey": "02a1b2c3d4e5f6...",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600
}
```

**Error Response (404):**
```json
{
  "ok": false,
  "error": "Session not found or expired"
}
```

---

## Chat & Messaging Endpoints

### Realtime Messaging
**Channel:** Socket.IO `message` event

**Description:** Chat is delivered exclusively over the Socket.IO connection. Authenticated clients emit `message` events and receive broadcast messages in the same channel.

**Client Emit Payload:**
```json
"Hello, everyone!"
```

**Server Broadcast Payload:**
```json
{
  "pubkey": "02a1b2c3d4e5f6...",
  "text": "Hello, everyone!",
  "ts": 1698765432.123
}
```

**Notes:**
- Requests made without an authenticated session are ignored by the server.
- There is no REST endpoint for sending messages or fetching chat history; clients should persist their own local history from the realtime stream.

---

## Bitcoin Wallet Endpoints

### Get Wallet Balance
**Endpoint:** `GET /api/wallet/balance`

**Description:** Get wallet balance (requires authentication)

**Success Response (200):**
```json
{
  "ok": true,
  "balance": {
    "confirmed": 1.50000000,
    "unconfirmed": 0.05000000,
    "total": 1.55000000
  },
  "balance_sat": {
    "confirmed": 150000000,
    "unconfirmed": 5000000,
    "total": 155000000
  }
}
```

---

### Generate Receive Address
**Endpoint:** `POST /api/wallet/new-address`

**Description:** Generate a new receiving address

**Request Body:**
```json
{
  "address_type": "bech32"
}
```

**Success Response (200):**
```json
{
  "ok": true,
  "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
  "address_type": "bech32",
  "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
}
```

---

### Send Bitcoin Transaction
**Endpoint:** `POST /api/wallet/send`

**Description:** Create and broadcast a Bitcoin transaction

**Request Body:**
```json
{
  "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
  "amount": 0.01,
  "fee_rate": 10,
  "subtract_fee": false
}
```

**Success Response (200):**
```json
{
  "ok": true,
  "txid": "a1b2c3d4e5f6...",
  "amount_sent": 0.01,
  "fee_paid": 0.00001500,
  "confirmations": 0,
  "broadcast": true
}
```

**Error Responses:**
```json
// Insufficient funds
{
  "ok": false,
  "error": "Insufficient funds. Required: 0.01001500 BTC, Available: 0.005 BTC"
}

// Invalid address
{
  "ok": false,
  "error": "Invalid Bitcoin address"
}
```

---

## Proof of Funds (PoF) Endpoints

### Create PoF Challenge
**Endpoint:** `POST /api/pof/challenge`

**Description:** Create a Proof of Funds challenge

**Request Body:**
```json
{
  "pubkey": "02a1b2c3d4e5f6...",
  "covenant_id": "covenant_abc123"
}
```

**Success Response (200):**
```json
{
  "ok": true,
  "challenge_id": "chal_abc123",
  "challenge": "HODLXXI-PoF:abc123:1698765432",
  "expires_in": 900
}
```

**Error Responses:**
```json
// Not a member
{
  "ok": false,
  "error": "membership required"
}

// Missing pubkey
{
  "ok": false,
  "error": "pubkey required"
}
```

---

### Verify PSBT for PoF
**Endpoint:** `POST /api/pof/verify_psbt`

**Description:** Verify a Partially Signed Bitcoin Transaction for Proof of Funds

**Request Body:**
```json
{
  "challenge_id": "chal_abc123",
  "psbt": "cHNidP8BAH0CAAAAAe...",
  "privacy_level": "aggregate",
  "min_sat": 100000
}
```

**Privacy Levels:**
- `aggregate`: Show total amount
- `threshold`: Show only if minimum is met
- `boolean`: Show only true/false for threshold

**Success Response (200) - Aggregate:**
```json
{
  "ok": true,
  "pubkey": "02a1b2c3d4e5f6...",
  "total_sat": 150000000,
  "expires_in": 172800
}
```

**Success Response (200) - Threshold:**
```json
{
  "ok": true,
  "pubkey": "02a1b2c3d4e5f6...",
  "meets_min_sat": true,
  "expires_in": 172800
}
```

**Success Response (200) - Boolean:**
```json
{
  "ok": true,
  "pubkey": "02a1b2c3d4e5f6...",
  "has_threshold": true,
  "expires_in": 172800
}
```

**Error Responses:**
```json
// Invalid challenge
{
  "ok": false,
  "error": "invalid or expired challenge"
}

// No OP_RETURN challenge
{
  "ok": false,
  "error": "OP_RETURN challenge missing"
}

// No live inputs
{
  "ok": false,
  "error": "no live inputs"
}

// PSBT too large
{
  "ok": false,
  "error": "PSBT too large"
}
```

---

### Get PoF Status
**Endpoint:** `GET /api/pof/status/<pubkey>`

**Description:** Get current Proof of Funds attestation status

**Query Parameters:**
- `covenant_id`: Optional covenant identifier

**Example Request:**
```
GET /api/pof/status/02a1b2c3d4e5f6...?covenant_id=covenant_abc123
```

**Success Response (200) - Has Attestation:**
```json
{
  "ok": true,
  "status": {
    "pubkey": "02a1b2c3d4e5f6...",
    "covenant_id": "covenant_abc123",
    "total_sat": 150000000,
    "method": "psbt",
    "privacy_level": "aggregate",
    "proof_hash": "a1b2c3d4e5f6...",
    "expires_at": 1698937232,
    "created_at": 1698765432
  }
}
```

**Success Response (200) - No Attestation:**
```json
{
  "ok": true,
  "status": null
}
```

---

## Monitoring Endpoints

### OAuth Status
**Endpoint:** `GET /oauthx/status`

**Description:** Get OAuth system status and statistics

**Success Response (200):**
```json
{
  "status": "operational",
  "timestamp": 1698765432,
  "statistics": {
    "total_clients": 42,
    "active_sessions": 128,
    "tokens_issued_today": 1543,
    "authorization_codes_active": 23
  },
  "uptime_seconds": 3456789
}
```

---

### System Metrics
**Endpoint:** `GET /api/metrics`

**Description:** Get system metrics (requires admin authentication)

**Success Response (200):**
```json
{
  "ok": true,
  "metrics": {
    "active_websocket_connections": 42,
    "online_users": 15,
    "chat_messages_total": 12543,
    "authentication_requests_total": 5432,
    "failed_authentication_attempts": 23,
    "rpc_connection_status": "healthy",
    "memory_usage_mb": 256.5,
    "uptime_seconds": 3456789
  }
}
```

---

## WebSocket Events

### Connection
**Event:** `connect`

**Description:** Sent automatically when the Socket.IO client establishes a connection. Authentication relies on the existing Flask session cookie; there is no separate `authenticate` event.

---

### Chat Message
**Event:** `message`

**Description:** Broadcast whenever an authenticated user submits a chat message. The same event name is used for client emits and server broadcasts.

**Client emit example:**
```json
"Hello, everyone!"
```

**Server broadcast example:**
```json
{
  "pubkey": "02a1b2c3d4e5f6...",
  "text": "Hello, everyone!",
  "ts": 1698765432.123
}
```

---

### WebRTC Offer
**Event:** `rtc:offer`

**Description:** Relay a WebRTC offer to another participant.

**Payload shape:**
```json
{
  "to": "02a1b2c3d4e5f6...",
  "from": "03b2c3d4e5f6...",
  "sdp": "v=0..."
}
```

---

### WebRTC Answer
**Event:** `rtc:answer`

**Description:** Relay a WebRTC answer to the original offerer.

**Payload shape:**
```json
{
  "to": "02a1b2c3d4e5f6...",
  "from": "03b2c3d4e5f6...",
  "sdp": "v=0..."
}
```

---

### WebRTC ICE Candidate
**Event:** `rtc:ice`

**Description:** Exchange ICE candidates between peers.

**Payload shape:**
```json
{
  "to": "02a1b2c3d4e5f6...",
  "from": "03b2c3d4e5f6...",
  "candidate": {
    "candidate": "candidate:842163049 1 udp 1677729535 ...",
    "sdpMid": "0",
    "sdpMLineIndex": 0
  }
}
```

---

### WebRTC Hangup
**Event:** `rtc:hangup`

**Description:** Notify the remote peer that a call has ended.

**Payload shape:**
```json
{
  "to": "02a1b2c3d4e5f6...",
  "from": "03b2c3d4e5f6..."
}
```

---

### PoF Updated
**Event:** `pof:updated`

**Description:** Broadcast after a Proof of Funds attestation is recorded.

**Server emits:**
```json
{
  "pubkey": "02a1b2c3d4e5f6...",
  "covenant_id": "covenant_abc123",
  "total_sat": 150000000,
  "privacy_level": "aggregate",
  "expires_at": 1698937232,
  "method": "psbt"
}
```

---


## Rate Limiting

All API endpoints are subject to rate limiting:

**Default Limits:**
- Authentication endpoints: 10 requests/minute per IP
- General API endpoints: 60 requests/minute per authenticated user
- WebSocket messages: 30 messages/minute per connection

**Rate Limit Headers:**
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1698765492
```

**Rate Limit Exceeded Response (429):**
```json
{
  "ok": false,
  "error": "Rate limit exceeded",
  "retry_after": 30,
  "limit": 60,
  "window": "1 minute"
}
```

---

## Pagination

Endpoints that return lists support pagination:

**Query Parameters:**
- `limit`: Number of items per page (default: 50, max: 100)
- `offset`: Number of items to skip
- `before`: Cursor for time-based pagination (Unix timestamp)
- `after`: Cursor for time-based pagination (Unix timestamp)

**Paginated Response:**
```json
{
  "ok": true,
  "data": [...],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 1250,
    "has_more": true,
    "next_offset": 50,
    "prev_offset": null
  }
}
```
