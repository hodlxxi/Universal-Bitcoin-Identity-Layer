# OAuth2/OIDC and LNURL-Auth Complete Specification

Complete technical specification for OAuth2, OpenID Connect, and LNURL-Auth implementations in the HODLXXI API.

## Table of Contents
- [OAuth 2.0 Implementation](#oauth-20-implementation)
- [OpenID Connect (OIDC)](#openid-connect-oidc)
- [Grant Types and Flows](#grant-types-and-flows)
- [Scope Definitions](#scope-definitions)
- [Client Registration](#client-registration)
- [LNURL-Auth Specification](#lnurl-auth-specification)
- [Endpoint Reference](#endpoint-reference)
- [Integration Examples](#integration-examples)

---

## OAuth 2.0 Implementation

### Standards Compliance

The HODLXXI API implements:
- **RFC 6749** - The OAuth 2.0 Authorization Framework
- **RFC 6750** - Bearer Token Usage
- **RFC 7636** - Proof Key for Code Exchange (PKCE)
- **RFC 7662** - Token Introspection
- **OpenID Connect Core 1.0**

### Supported Grant Types

| Grant Type | Use Case | Client Type |
|-----------|----------|-------------|
| `authorization_code` | Web/mobile apps with backend | Confidential |
| `refresh_token` | Token refresh | All |
| `client_credentials` | Service-to-service | Confidential |

### Token Types

| Token | Format | Lifetime | Usage |
|-------|--------|----------|-------|
| Access Token | JWT | 1 hour | API authentication |
| Refresh Token | JWT | 30 days | Token renewal |
| ID Token | JWT | 1 hour | User identity (OIDC) |
| Authorization Code | Opaque | 10 minutes | Code exchange |

---

## OpenID Connect (OIDC)

### Discovery Endpoint

**URL:** `GET /.well-known/openid-configuration`

**Response:**
```json
{
  "issuer": "https://api.yourdomain.com",
  "authorization_endpoint": "https://api.yourdomain.com/oauth/authorize",
  "token_endpoint": "https://api.yourdomain.com/oauth/token",
  "userinfo_endpoint": "https://api.yourdomain.com/oauth/userinfo",
  "jwks_uri": "https://api.yourdomain.com/oauth/jwks.json",
  "registration_endpoint": "https://api.yourdomain.com/oauth/register",
  "revocation_endpoint": "https://api.yourdomain.com/oauth/revoke",
  "introspection_endpoint": "https://api.yourdomain.com/oauth/introspect",
  
  "response_types_supported": [
    "code"
  ],
  "response_modes_supported": [
    "query",
    "fragment"
  ],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "client_credentials"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256",
    "HS256"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_post",
    "client_secret_basic",
    "none"
  ],
  "scopes_supported": [
    "openid",
    "profile",
    "email",
    "wallet:read",
    "wallet:write",
    "chat:read",
    "chat:write",
    "pof:read",
    "pof:write"
  ],
  "claims_supported": [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "name",
    "email",
    "picture",
    "pubkey"
  ],
  "code_challenge_methods_supported": [
    "S256",
    "plain"
  ]
}
```

### JWKS Endpoint

**URL:** `GET /oauth/jwks.json`

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2024-10-29",
      "alg": "RS256",
      "n": "base64_encoded_modulus",
      "e": "AQAB"
    }
  ]
}
```

---

## Grant Types and Flows

### 1. Authorization Code Flow

**Overview:** Most secure flow for web and mobile applications.

**Flow Diagram:**
```
┌────────┐                                           ┌───────────┐
│        │                                           │           │
│ Client │                                           │   Auth    │
│  App   │                                           │  Server   │
│        │                                           │           │
└───┬────┘                                           └─────┬─────┘
    │                                                      │
    │  1. Authorization Request                           │
    │  GET /oauth/authorize?                              │
    │    response_type=code&                              │
    │    client_id=CLIENT_ID&                             │
    │    redirect_uri=CALLBACK_URL&                       │
    │    scope=openid+profile+wallet:read&                │
    │    state=RANDOM_STATE                               │
    │ ────────────────────────────────────────────────────▶
    │                                                      │
    │  2. User Authentication                             │
    │     (LNURL-auth or signature-based)                 │
    │                                                      │
    │  3. Authorization Code Response                     │
    │  Redirect to:                                       │
    │  CALLBACK_URL?code=AUTH_CODE&state=RANDOM_STATE     │
    │ ◀────────────────────────────────────────────────────
    │                                                      │
    │  4. Token Request                                   │
    │  POST /oauth/token                                  │
    │  {                                                  │
    │    grant_type: "authorization_code",                │
    │    code: "AUTH_CODE",                               │
    │    redirect_uri: "CALLBACK_URL",                    │
    │    client_id: "CLIENT_ID",                          │
    │    client_secret: "CLIENT_SECRET"                   │
    │  }                                                  │
    │ ────────────────────────────────────────────────────▶
    │                                                      │
    │  5. Token Response                                  │
    │  {                                                  │
    │    access_token: "ACCESS_TOKEN",                    │
    │    token_type: "Bearer",                            │
    │    expires_in: 3600,                                │
    │    refresh_token: "REFRESH_TOKEN",                  │
    │    id_token: "ID_TOKEN",                            │
    │    scope: "openid profile wallet:read"              │
    │  }                                                  │
    │ ◀────────────────────────────────────────────────────
    │                                                      │
```

**Step-by-Step Implementation:**

#### Step 1: Authorization Request

**Endpoint:** `GET /oauth/authorize`

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `response_type` | Yes | Must be `code` |
| `client_id` | Yes | Client identifier |
| `redirect_uri` | Yes | Callback URL (must be registered) |
| `scope` | Yes | Space-separated scope list |
| `state` | Recommended | CSRF protection token |
| `nonce` | Recommended | Replay protection (OIDC) |
| `code_challenge` | Optional | PKCE code challenge |
| `code_challenge_method` | Optional | `S256` or `plain` |

**Example Request:**
```http
GET /oauth/authorize?response_type=code&client_id=550e8400-e29b-41d4-a716-446655440000&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid+profile+wallet%3Aread&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj HTTP/1.1
Host: api.yourdomain.com
```

**Response (Success):**
```http
HTTP/1.1 302 Found
Location: https://app.example.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=af0ifjsldkj
```

**Response (Error):**
```http
HTTP/1.1 302 Found
Location: https://app.example.com/callback?error=invalid_request&error_description=Missing+client_id&state=af0ifjsldkj
```

#### Step 2: Token Exchange

**Endpoint:** `POST /oauth/token`

**Request Headers:**
```http
Content-Type: application/json
Authorization: Basic base64(client_id:client_secret)
```

**Request Body:**
```json
{
  "grant_type": "authorization_code",
  "code": "SplxlOBeZQQYbYS6WxSbIA",
  "redirect_uri": "https://app.example.com/callback",
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "client_secret_here"
}
```

**Alternative with PKCE:**
```json
{
  "grant_type": "authorization_code",
  "code": "SplxlOBeZQQYbYS6WxSbIA",
  "redirect_uri": "https://app.example.com/callback",
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
}
```

**Success Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMmExYjJjM2Q0ZTVmNi4uLiIsImlhdCI6MTY5ODc2NTQzMiwiZXhwIjoxNjk4NzY5MDMyLCJqdGkiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJpc3MiOiJob2RseHhpLWFwaSIsImF1ZCI6ImhvZGx4eGktY2xpZW50cyIsInR5cGUiOiJhY2Nlc3NfdG9rZW4iLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIHdhbGxldDpyZWFkIn0.signature",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMmExYjJjM2Q0ZTVmNi4uLiIsImlhdCI6MTY5ODc2NTQzMiwiZXhwIjoxNzAxMzU3NDMyLCJqdGkiOiI2NjBmOTUxMS1mM2FjLTUyZTUtLi4uIiwiaXNzIjoiaG9kbHh4aS1hcGkiLCJ0eXBlIjoicmVmcmVzaF90b2tlbiIsImZhbWlseSI6InJmX2ZhbWlseV9hYmMxMjMifQ.signature",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMmExYjJjM2Q0ZTVmNi4uLiIsImlzcyI6ImhvZGx4eGktYXBpIiwiYXVkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiZXhwIjoxNjk4NzY5MDMyLCJpYXQiOjE2OTg3NjU0MzIsIm5hbWUiOiJBbGljZSIsInB1YmtleSI6IjAyYTFiMmMzZDRlNWY2Li4uIiwibm9uY2UiOiJuLTBTNl9XekEyTWoifQ.signature",
  "scope": "openid profile wallet:read"
}
```

**Error Response:**
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code has expired",
  "error_uri": "https://api.yourdomain.com/docs/errors#invalid_grant"
}
```

---

### 2. Refresh Token Flow

**Overview:** Obtain new access token using refresh token.

**Endpoint:** `POST /oauth/token`

**Request:**
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "client_secret_here",
  "scope": "openid profile wallet:read"
}
```

**Note:** The `scope` parameter is optional. If provided, it must not include any scope not originally granted.

**Success Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile wallet:read"
}
```

**Important:** The old refresh token is invalidated (token rotation). Always use the new refresh token for subsequent refreshes.

---

### 3. Client Credentials Flow

**Overview:** Machine-to-machine authentication without user context.

**Endpoint:** `POST /oauth/token`

**Request:**
```json
{
  "grant_type": "client_credentials",
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "client_secret_here",
  "scope": "wallet:read pof:read"
}
```

**Success Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "wallet:read pof:read"
}
```

**Note:** No refresh token is issued. No ID token is issued (no user context).

---

## Scope Definitions

### Standard OIDC Scopes

#### `openid` (Required for OIDC)
- **Description:** Indicates OIDC request, triggers ID token issuance
- **Claims:** `sub`, `iss`, `aud`, `exp`, `iat`
- **Required:** Yes (for OIDC flows)

#### `profile`
- **Description:** Access to user profile information
- **Claims:** `name`, `pubkey`, `picture`
- **Permissions:** Read user profile data
- **Example Use:** Display user information in UI

#### `email`
- **Description:** Access to user email (if available)
- **Claims:** `email`, `email_verified`
- **Permissions:** Read user email address
- **Note:** May be null for Bitcoin-only authentication

---

### Custom API Scopes

#### `wallet:read`
- **Description:** Read-only access to wallet data
- **Permissions:**
  - View wallet balance
  - View transaction history
  - View receiving addresses
  - View UTXO set
- **Endpoints:**
  - `GET /api/wallet/balance`
  - `GET /api/wallet/transactions`
  - `GET /api/wallet/addresses`
  - `GET /api/wallet/utxos`
- **Example Use:** Portfolio tracking apps

#### `wallet:write`
- **Description:** Full wallet access including sending
- **Permissions:**
  - All `wallet:read` permissions
  - Generate new addresses
  - Create transactions
  - Sign and broadcast transactions
  - Export wallet data
- **Endpoints:**
  - `POST /api/wallet/new-address`
  - `POST /api/wallet/send`
  - `POST /api/wallet/sign-psbt`
- **Security:** Requires additional authentication for sensitive operations
- **Example Use:** Wallet management applications

#### `chat:read`
- **Description:** Read-only access to chat messages
- **Permissions:**
  - View chat history
  - View online users
  - Listen to WebSocket chat events
- **Endpoints:**
  - Socket.IO: subscribe to `message` events
  - (UI pages render current participants; there is no standalone REST API yet.)
- **Example Use:** Chat monitoring tools

#### `chat:write`
- **Description:** Send chat messages
- **Permissions:**
  - All `chat:read` permissions
  - Send messages
  - React to messages
  - Report messages
- **Endpoints:**
  - Socket.IO: emit `message` events
- **Example Use:** Chat applications

#### `pof:read`
- **Description:** Read Proof of Funds attestations
- **Permissions:**
  - View own PoF status
  - View public PoF attestations (if privacy allows)
- **Endpoints:**
  - `GET /api/pof/status/:pubkey`
- **Example Use:** Covenant membership verification

#### `pof:write`
- **Description:** Create Proof of Funds attestations
- **Permissions:**
  - All `pof:read` permissions
  - Create PoF challenges
  - Submit PSBT for verification
- **Endpoints:**
  - `POST /api/pof/challenge`
  - `POST /api/pof/verify_psbt`
- **Example Use:** Proving bitcoin holdings

#### `admin` (Reserved)
- **Description:** Administrative access
- **Permissions:** All system operations
- **Grant:** Only via manual approval
- **Use:** System administration only

---

### Scope Combinations

**Recommended Combinations:**

| Use Case | Scopes |
|----------|--------|
| Simple login | `openid profile` |
| View-only wallet | `openid profile wallet:read` |
| Full wallet access | `openid profile wallet:read wallet:write` |
| Chat application | `openid profile chat:read chat:write` |
| Covenant member | `openid profile wallet:read pof:read pof:write` |
| Portfolio tracker | `openid profile wallet:read` |
| Service account | `wallet:read pof:read` (no openid) |

---

## Client Registration

### Dynamic Client Registration

**Endpoint:** `POST /oauth/register`

**Request Headers:**
```http
Content-Type: application/json
```

**Request Body (Required Fields):**
```json
{
  "client_name": "My Bitcoin App",
  "redirect_uris": [
    "https://myapp.com/callback"
  ],
  "pubkey": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
}
```

**Request Body (All Fields):**
```json
{
  "client_name": "My Bitcoin App",
  "client_uri": "https://myapp.com",
  "logo_uri": "https://myapp.com/logo.png",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/auth/callback"
  ],
  "pubkey": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "grant_types": [
    "authorization_code",
    "refresh_token"
  ],
  "response_types": [
    "code"
  ],
  "token_endpoint_auth_method": "client_secret_post",
  "scope": "openid profile wallet:read wallet:write",
  "contacts": [
    "admin@myapp.com"
  ],
  "tos_uri": "https://myapp.com/tos",
  "policy_uri": "https://myapp.com/privacy"
}
```

**Field Descriptions:**

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `client_name` | Yes | String | Human-readable application name |
| `redirect_uris` | Yes | Array | List of valid redirect URIs |
| `pubkey` | Yes | String | Bitcoin public key of client owner |
| `client_uri` | No | URL | Application homepage |
| `logo_uri` | No | URL | Application logo |
| `grant_types` | No | Array | Allowed grant types (default: `["authorization_code"]`) |
| `response_types` | No | Array | Allowed response types (default: `["code"]`) |
| `token_endpoint_auth_method` | No | String | Token endpoint auth method |
| `scope` | No | String | Requested default scope |
| `contacts` | No | Array | Contact email addresses |
| `tos_uri` | No | URL | Terms of Service URL |
| `policy_uri` | No | URL | Privacy Policy URL |

**Success Response (201 Created):**
```json
{
  "ok": true,
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "cGFzc3dvcmQ",
  "client_id_issued_at": 1698765432,
  "client_secret_expires_at": 0,
  "client_name": "My Bitcoin App",
  "client_uri": "https://myapp.com",
  "logo_uri": "https://myapp.com/logo.png",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/auth/callback"
  ],
  "grant_types": [
    "authorization_code",
    "refresh_token"
  ],
  "response_types": [
    "code"
  ],
  "token_endpoint_auth_method": "client_secret_post",
  "scope": "openid profile wallet:read wallet:write",
  "pubkey": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "contacts": [
    "admin@myapp.com"
  ],
  "tos_uri": "https://myapp.com/tos",
  "policy_uri": "https://myapp.com/privacy"
}
```

**Error Response (400 Bad Request):**
```json
{
  "ok": false,
  "error": "invalid_client_metadata",
  "error_description": "redirect_uris must be HTTPS URLs"
}
```

**Validation Rules:**

1. **redirect_uris:**
   - Must be HTTPS (except localhost for development)
   - Must not contain fragments (#)
   - Must be exact match (no wildcards)

2. **client_name:**
   - Required
   - 3-100 characters
   - No special characters except space, hyphen, underscore

3. **pubkey:**
   - Required
   - Valid Bitcoin public key (compressed format)
   - 66 hex characters
   - Must start with 02 or 03

4. **URLs (client_uri, logo_uri, tos_uri, policy_uri):**
   - Must be valid HTTPS URLs
   - Must be publicly accessible

---

### Client Management

#### Get Client Information

**Endpoint:** `GET /oauth/client/:client_id`

**Authentication:** Required (Bearer token of client owner)

**Response:**
```json
{
  "ok": true,
  "client": {
    "client_id": "550e8400-e29b-41d4-a716-446655440000",
    "client_name": "My Bitcoin App",
    "redirect_uris": ["https://myapp.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "created_at": 1698765432,
    "last_used": 1698850000
  }
}
```

#### Update Client

**Endpoint:** `PUT /oauth/client/:client_id`

**Authentication:** Required (Bearer token of client owner)

**Request:**
```json
{
  "client_name": "Updated App Name",
  "redirect_uris": [
    "https://myapp.com/callback",
    "https://myapp.com/auth/callback",
    "https://myapp.com/new-callback"
  ]
}
```

#### Delete Client

**Endpoint:** `DELETE /oauth/client/:client_id`

**Authentication:** Required (Bearer token of client owner)

**Response:**
```json
{
  "ok": true,
  "message": "Client deleted successfully"
}
```

---

## LNURL-Auth Specification

### Overview

LNURL-auth enables authentication using Lightning Network wallets without requiring custodial services.

**Standards:**
- LUD-04: LNURL-auth
- Compatible with: Zeus, Breez, BlueWallet, Phoenix

---

### Authentication Flow

```
┌──────────┐                                    ┌─────────────┐
│          │                                    │             │
│ Client   │                                    │   Server    │
│   App    │                                    │             │
│          │                                    │             │
└────┬─────┘                                    └──────┬──────┘
     │                                                 │
     │  1. Request LNURL-auth session                 │
     │  POST /api/lnurl-auth/create                   │
     │ ───────────────────────────────────────────────▶
     │                                                 │
     │  2. Session created with LNURL and k1          │
     │  {                                              │
     │    session_id: "lnauth_abc123",                │
     │    lnurl: "LNURL1...",                          │
     │    k1: "challenge_hex",                         │
     │    expires_in: 300                              │
     │  }                                              │
     │ ◀───────────────────────────────────────────────
     │                                                 │
     │  3. Display LNURL as QR code                   │
     │                                                 │
     │  4. User scans with Lightning wallet           │
     │     ┌──────────┐                                │
     │     │ Lightning│                                │
     │     │  Wallet  │                                │
     │     └────┬─────┘                                │
     │          │  5. Wallet decodes LNURL             │
     │          │  GET callback URL with              │
     │          │    k1, sig, key                      │
     │          │ ─────────────────────────────────────▶
     │          │                                      │
     │          │  6. Server verifies signature       │
     │          │                                      │
     │          │  7. Authentication response         │
     │          │  { status: "OK" }                   │
     │          │ ◀─────────────────────────────────────
     │          │                                      │
     │  8. Poll for authentication status             │
     │  GET /api/lnurl-auth/check/lnauth_abc123       │
     │ ───────────────────────────────────────────────▶
     │                                                 │
     │  9. Authentication confirmed                   │
     │  {                                              │
     │    status: "authenticated",                    │
     │    pubkey: "02...",                            │
     │    access_token: "eyJh...",                    │
     │    expires_in: 3600                            │
     │  }                                              │
     │ ◀───────────────────────────────────────────────
     │                                                 │
```

---

### LNURL-Auth Endpoints

#### 1. Create LNURL-Auth Session

**Endpoint:** `POST /api/lnurl-auth/create`

**Description:** Create a new LNURL-auth session for wallet authentication

**Request Body (Optional):**
```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "scope": "openid profile wallet:read",
  "state": "csrf_protection_token"
}
```

**Success Response (200):**
```json
{
  "ok": true,
  "session_id": "lnauth_dF8h2Kp9mN3qR5sT7wX",
  "lnurl": "LNURL1DP68GURN8GHJ7MRWW4EXCTNXD9SHG6NPVCHXXMMD9AKXUATJDSKHQCTE8AEK2UMND9HKU0F4XSUNJWPHXUCRJDE3VDJNZV33XQENJWPS8YMRWDFHVCUNJVE38Q6NQVE3VY6KYWF5XVMNJD3JXS6NQVE38Q6KGVP5XF6KZWFEX5UNJ0F4XYEN2VFEXA",
  "k1": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "callback_url": "https://api.yourdomain.com/lnurl-auth/verify?session=lnauth_dF8h2Kp9mN3qR5sT7wX&k1=a1b2c3...&tag=login",
  "expires_in": 300,
  "expires_at": 1698765732
}
```

**QR Code Generation:**
```javascript
// Client should display LNURL as QR code
import QRCode from 'qrcode';

QRCode.toDataURL(lnurl, {
  width: 300,
  margin: 2,
  color: {
    dark: '#000000',
    light: '#FFFFFF'
  }
}, (err, url) => {
  // Display QR code to user
  document.getElementById('qr-code').src = url;
});
```

---

#### 2. LNURL-Auth Callback (Lightning Wallet)

**Endpoint:** `GET /lnurl-auth/verify`

**Description:** Called by Lightning wallet to authenticate (not by client app)

**Query Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `session` | Yes | Session ID from create response |
| `k1` | Yes | Challenge from create response |
| `sig` | Yes | Signature over k1 by wallet's key |
| `key` | Yes | Wallet's public key (hex) |

**Example Request:**
```
GET /lnurl-auth/verify?session=lnauth_dF8h2Kp9mN3qR5sT7wX&k1=a1b2c3d4e5f6...&sig=304502210...&key=02a1b2c3d4e5f6... HTTP/1.1
Host: api.yourdomain.com
```

**Success Response (200):**
```json
{
  "status": "OK",
  "event": "LOGGED_IN"
}
```

**Error Response (400):**
```json
{
  "status": "ERROR",
  "reason": "Invalid signature"
}
```

---

#### 3. Check Authentication Status

**Endpoint:** `GET /api/lnurl-auth/check/:session_id`

**Description:** Poll this endpoint to check if authentication completed

**Example Request:**
```
GET /api/lnurl-auth/check/lnauth_dF8h2Kp9mN3qR5sT7wX HTTP/1.1
Host: api.yourdomain.com
```

**Response (Pending):**
```json
{
  "ok": true,
  "status": "pending",
  "expires_in": 245
}
```

**Response (Authenticated):**
```json
{
  "ok": true,
  "status": "authenticated",
  "pubkey": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile wallet:read"
}
```

**Response (Expired):**
```json
{
  "ok": false,
  "error": "session_expired",
  "error_description": "LNURL-auth session has expired"
}
```

**Polling Strategy:**
```javascript
async function pollAuthStatus(sessionId) {
  const maxAttempts = 60; // 5 minutes (5s intervals)
  
  for (let i = 0; i < maxAttempts; i++) {
    const response = await fetch(`/api/lnurl-auth/check/${sessionId}`);
    const data = await response.json();
    
    if (data.status === 'authenticated') {
      // Success! Store tokens
      storeTokens(data.access_token, data.refresh_token);
      return data;
    }
    
    if (!data.ok || data.status === 'expired') {
      throw new Error('Authentication failed or expired');
    }
    
    // Wait 5 seconds before next poll
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  
  throw new Error('Authentication timeout');
}
```

---

### LNURL-auth Integration with OAuth

**Combine LNURL-auth with OAuth flow:**

```javascript
// 1. Start OAuth flow
const authUrl = new URL('/oauth/authorize', API_BASE);
authUrl.searchParams.append('response_type', 'code');
authUrl.searchParams.append('client_id', CLIENT_ID);
authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
authUrl.searchParams.append('scope', 'openid profile wallet:read');
authUrl.searchParams.append('state', csrfToken);

// 2. User clicks "Login with Lightning"
// 3. Server generates LNURL-auth session
// 4. After successful LNURL-auth, server creates authorization code
// 5. Server redirects to: REDIRECT_URI?code=AUTH_CODE&state=csrf_token
// 6. Client exchanges code for tokens
```

---

## Endpoint Reference

### Complete Endpoint List

#### OpenID Connect Discovery
```
GET /.well-known/openid-configuration
```

#### JWKS
```
GET /oauth/jwks.json
```

#### Client Registration
```
POST   /oauth/register          - Register new client
GET    /oauth/client/:id        - Get client info
PUT    /oauth/client/:id        - Update client
DELETE /oauth/client/:id        - Delete client
```

#### Authorization
```
GET  /oauth/authorize           - Start OAuth flow
POST /oauth/authorize           - User consent
```

#### Token Management
```
POST   /oauth/token             - Exchange code / refresh token
POST   /oauth/revoke            - Revoke token
POST   /oauth/introspect        - Introspect token
```

#### User Info
```
GET /oauth/userinfo             - Get user information (OIDC)
```

#### LNURL-Auth
```
POST /api/lnurl-auth/create     - Create LNURL session
GET  /lnurl-auth/verify         - Verify signature (wallet callback)
GET  /api/lnurl-auth/check/:id  - Check auth status
```

#### OAuth Status
```
GET /oauthx/status              - OAuth system status
GET /oauthx/docs                - OAuth documentation
```

---

## Integration Examples

### Example 1: Web Application (React)

```javascript
// oauthService.js
class OAuthService {
  constructor(config) {
    this.clientId = config.clientId;
    this.redirectUri = config.redirectUri;
    this.baseUrl = config.baseUrl;
    this.scope = config.scope || 'openid profile wallet:read';
  }
  
  // Generate PKCE challenge
  async generatePKCE() {
    const verifier = this.generateRandomString(128);
    const challenge = await this.sha256(verifier);
    
    return {
      verifier,
      challenge: this.base64URLEncode(challenge)
    };
  }
  
  generateRandomString(length) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let random = '';
    const randomValues = crypto.getRandomValues(new Uint8Array(length));
    
    for (let i = 0; i < length; i++) {
      random += charset[randomValues[i] % charset.length];
    }
    
    return random;
  }
  
  async sha256(plain) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return await crypto.subtle.digest('SHA-256', data);
  }
  
  base64URLEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    
    for (let byte of bytes) {
      str += String.fromCharCode(byte);
    }
    
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  // Start OAuth flow
  async login() {
    const state = this.generateRandomString(32);
    const nonce = this.generateRandomString(32);
    const pkce = await this.generatePKCE();
    
    // Store for later verification
    sessionStorage.setItem('oauth_state', state);
    sessionStorage.setItem('oauth_nonce', nonce);
    sessionStorage.setItem('pkce_verifier', pkce.verifier);
    
    // Build authorization URL
    const authUrl = new URL(`${this.baseUrl}/oauth/authorize`);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('client_id', this.clientId);
    authUrl.searchParams.append('redirect_uri', this.redirectUri);
    authUrl.searchParams.append('scope', this.scope);
    authUrl.searchParams.append('state', state);
    authUrl.searchParams.append('nonce', nonce);
    authUrl.searchParams.append('code_challenge', pkce.challenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');
    
    // Redirect to authorization page
    window.location.href = authUrl.toString();
  }
  
  // Handle callback
  async handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');
    
    // Check for errors
    if (error) {
      throw new Error(`OAuth error: ${error} - ${params.get('error_description')}`);
    }
    
    // Verify state
    const storedState = sessionStorage.getItem('oauth_state');
    if (state !== storedState) {
      throw new Error('Invalid state parameter');
    }
    
    // Exchange code for tokens
    const verifier = sessionStorage.getItem('pkce_verifier');
    const tokens = await this.exchangeCode(code, verifier);
    
    // Clean up session storage
    sessionStorage.removeItem('oauth_state');
    sessionStorage.removeItem('oauth_nonce');
    sessionStorage.removeItem('pkce_verifier');
    
    return tokens;
  }
  
  // Exchange authorization code for tokens
  async exchangeCode(code, codeVerifier) {
    const response = await fetch(`${this.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: this.redirectUri,
        client_id: this.clientId,
        code_verifier: codeVerifier
      })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Token exchange failed: ${error.error_description}`);
    }
    
    return await response.json();
  }
}

// Usage in React component
import { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  
  const oauth = new OAuthService({
    clientId: process.env.REACT_APP_CLIENT_ID,
    redirectUri: `${window.location.origin}/callback`,
    baseUrl: process.env.REACT_APP_API_BASE,
    scope: 'openid profile wallet:read wallet:write'
  });
  
  const handleLogin = () => {
    oauth.login();
  };
  
  return (
    <div>
      <button onClick={handleLogin}>
        Login with Bitcoin
      </button>
    </div>
  );
}

function Callback() {
  const navigate = useNavigate();
  const oauth = new OAuthService({...});
  
  useEffect(() => {
    oauth.handleCallback()
      .then(tokens => {
        // Store tokens
        localStorage.setItem('access_token', tokens.access_token);
        localStorage.setItem('refresh_token', tokens.refresh_token);
        
        // Navigate to home
        navigate('/');
      })
      .catch(error => {
        console.error('Authentication failed:', error);
        navigate('/login');
      });
  }, []);
  
  return <div>Authenticating...</div>;
}
```

---

### Example 2: LNURL-Auth (React)

```javascript
// LNURLAuth.jsx
import React, { useState, useEffect } from 'react';
import QRCode from 'qrcode.react';

function LNURLAuth() {
  const [session, setSession] = useState(null);
  const [status, setStatus] = useState('idle'); // idle, loading, polling, authenticated, error
  const [error, setError] = useState(null);
  
  // Create LNURL session
  const createSession = async () => {
    setStatus('loading');
    setError(null);
    
    try {
      const response = await fetch('/api/lnurl-auth/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      
      if (!response.ok) {
        throw new Error('Failed to create session');
      }
      
      const data = await response.json();
      setSession(data);
      setStatus('polling');
      
      // Start polling
      pollAuthStatus(data.session_id);
      
    } catch (err) {
      setError(err.message);
      setStatus('error');
    }
  };
  
  // Poll authentication status
  const pollAuthStatus = async (sessionId) => {
    const maxAttempts = 60; // 5 minutes
    
    for (let i = 0; i < maxAttempts; i++) {
      try {
        const response = await fetch(`/api/lnurl-auth/check/${sessionId}`);
        const data = await response.json();
        
        if (data.status === 'authenticated') {
          // Success!
          localStorage.setItem('access_token', data.access_token);
          localStorage.setItem('refresh_token', data.refresh_token);
          setStatus('authenticated');
          
          // Redirect to home
          window.location.href = '/';
          return;
        }
        
        if (!data.ok) {
          throw new Error(data.error_description || 'Authentication failed');
        }
        
        // Wait 5 seconds before next poll
        await new Promise(resolve => setTimeout(resolve, 5000));
        
      } catch (err) {
        setError(err.message);
        setStatus('error');
        return;
      }
    }
    
    // Timeout
    setError('Authentication timeout. Please try again.');
    setStatus('error');
  };
  
  return (
    <div className="lnurl-auth">
      <h2>Login with Lightning</h2>
      
      {status === 'idle' && (
        <button onClick={createSession}>
          Generate QR Code
        </button>
      )}
      
      {status === 'loading' && (
        <div>Creating session...</div>
      )}
      
      {status === 'polling' && session && (
        <div>
          <p>Scan this QR code with your Lightning wallet</p>
          <QRCode
            value={session.lnurl}
            size={300}
            level="M"
          />
          <p>Session expires in {session.expires_in} seconds</p>
          <p className="text-muted">
            Or paste this LNURL: <code>{session.lnurl}</code>
          </p>
        </div>
      )}
      
      {status === 'authenticated' && (
        <div>
          <p>✓ Authentication successful!</p>
          <p>Redirecting...</p>
        </div>
      )}
      
      {status === 'error' && (
        <div className="error">
          <p>❌ Error: {error}</p>
          <button onClick={createSession}>
            Try Again
          </button>
        </div>
      )}
    </div>
  );
}

export default LNURLAuth;
```

---

### Example 3: Service-to-Service (Python)

```python
# oauth_client.py
import requests
from typing import Optional, Dict
import time

class OAuthClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token: Optional[str] = None
        self.token_expiry: Optional[int] = None
    
    def authenticate(self, scope: str = "wallet:read pof:read") -> Dict:
        """Authenticate using client credentials"""
        response = requests.post(
            f"{self.base_url}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": scope
            }
        )
        
        response.raise_for_status()
        data = response.json()
        
        self.access_token = data["access_token"]
        self.token_expiry = int(time.time()) + data["expires_in"]
        
        return data
    
    def ensure_authenticated(self):
        """Ensure we have a valid access token"""
        if not self.access_token or time.time() >= self.token_expiry - 60:
            self.authenticate()
    
    def api_request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make authenticated API request"""
        self.ensure_authenticated()
        
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.access_token}"
        
        response = requests.request(
            method,
            f"{self.base_url}{endpoint}",
            headers=headers,
            **kwargs
        )
        
        response.raise_for_status()
        return response.json()
    
    def get_wallet_balance(self) -> Dict:
        """Example: Get wallet balance"""
        return self.api_request("GET", "/api/wallet/balance")
    
    def get_pof_status(self, pubkey: str, covenant_id: str = "") -> Dict:
        """Example: Get Proof of Funds status"""
        params = {"covenant_id": covenant_id} if covenant_id else {}
        return self.api_request("GET", f"/api/pof/status/{pubkey}", params=params)

# Usage
if __name__ == "__main__":
    client = OAuthClient(
        base_url="https://api.yourdomain.com",
        client_id="550e8400-e29b-41d4-a716-446655440000",
        client_secret="your_client_secret"
    )
    
    # Get wallet balance
    balance = client.get_wallet_balance()
    print(f"Balance: {balance['balance']['total']} BTC")
    
    # Get PoF status
    pof = client.get_pof_status("02a1b2c3d4e5f6...")
    print(f"PoF Status: {pof}")
```

---

## Security Best Practices

### 1. Always Use PKCE

PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks.

**Generate code verifier and challenge:**
```javascript
// Verifier: 43-128 character random string
const verifier = generateRandomString(128);

// Challenge: SHA256 hash of verifier, base64url encoded
const challenge = base64url(sha256(verifier));
```

### 2. Validate State Parameter

Always validate the state parameter to prevent CSRF attacks.

### 3. Use HTTPS Only

Never use OAuth over HTTP in production.

### 4. Validate Redirect URIs

Server must validate redirect_uri exactly matches registered URI.

### 5. Short-Lived Authorization Codes

Authorization codes expire after 10 minutes and are single-use.

### 6. Token Storage

- **Access tokens:** Memory (not localStorage)
- **Refresh tokens:** HTTP-only secure cookie or secure storage
- **Never:** Store tokens in URL or localStorage without encryption

### 7. Scope Validation

Always request minimum necessary scopes.

---

## Troubleshooting

### Common Issues

**Issue: invalid_redirect_uri**
- Solution: Ensure redirect_uri exactly matches registered URI (including trailing slash)

**Issue: invalid_grant - authorization code expired**
- Solution: Exchange code within 10 minutes

**Issue: invalid_grant - code already used**
- Solution: Don't reuse authorization codes

**Issue: LNURL-auth session expired**
- Solution: Sessions expire after 5 minutes, create new session

**Issue: Token refresh returns invalid_grant**
- Solution: Refresh token may have been revoked or expired (30 days)

---

**Document Version:** 1.0.0  
**Last Updated:** October 29, 2024  
**Specification Compliance:** OAuth 2.0 (RFC 6749), OIDC Core 1.0, LNURL-auth (LUD-04)
