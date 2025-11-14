# System Architecture

> Comprehensive architecture documentation for the HODLXXI Universal Bitcoin Identity Layer

## Table of Contents

- [Overview](#overview)
- [High-Level Architecture](#high-level-architecture)
- [Component Architecture](#component-architecture)
- [Authentication Flow](#authentication-flow)
- [Data Architecture](#data-architecture)
- [Security Architecture](#security-architecture)
- [Network Architecture](#network-architecture)
- [Deployment Architecture](#deployment-architecture)
- [Technology Stack](#technology-stack)

---

## Overview

HODLXXI is a production-ready Bitcoin identity and authentication layer that combines traditional OAuth2/OIDC with Lightning Network authentication (LNURL-Auth) to provide a universal identity system bridging Web2 and Web3.

### Design Principles

1. **Security First**: Defense-in-depth approach with multiple security layers
2. **Non-Custodial**: Never store or control user private keys
3. **Interoperable**: Support both traditional OAuth2 and Lightning Network auth
4. **Scalable**: Designed for horizontal scaling
5. **Privacy-Focused**: Minimal data collection, cryptographic verification
6. **Standards-Compliant**: Full OAuth2, OIDC, and LNURL spec compliance

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Client Applications                          │
│                                                                       │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌──────────────┐    │
│  │  Web App  │  │  Mobile   │  │  Desktop  │  │  Lightning   │    │
│  │  (OAuth2) │  │   App     │  │    App    │  │    Wallet    │    │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └──────┬───────┘    │
│        │              │              │               │              │
└────────┼──────────────┼──────────────┼───────────────┼──────────────┘
         │              │              │               │
         │              └──────────────┴───────────────┘
         │                             │
         │ HTTPS                       │ LNURL-Auth/WebSocket
         │                             │
┌────────┴─────────────────────────────┴───────────────────────────────┐
│                          API Gateway / Load Balancer                  │
│                          (Nginx / Traefik)                           │
│                     - TLS Termination                                │
│                     - Rate Limiting                                  │
│                     - DDoS Protection                                │
└────────┬─────────────────────────────┬───────────────────────────────┘
         │                             │
┌────────┴─────────────────────────────┴───────────────────────────────┐
│                      HODLXXI Application Layer                        │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Flask Application                         │   │
│  │                    (Python 3.8+)                            │   │
│  │                                                              │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │   │
│  │  │  OAuth2  │  │  LNURL   │  │  Wallet  │  │   Chat   │  │   │
│  │  │  Module  │  │  Module  │  │  Module  │  │  Module  │  │   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │   │
│  │       │             │             │             │         │   │
│  │  ┌────┴─────────────┴─────────────┴─────────────┴─────┐  │   │
│  │  │         Core Services Layer                        │  │   │
│  │  │                                                      │  │   │
│  │  │  • Authentication Service                          │  │   │
│  │  │  • Authorization Service                           │  │   │
│  │  │  • Session Management                              │  │   │
│  │  │  • Token Management (JWT)                          │  │   │
│  │  │  • Signature Verification                          │  │   │
│  │  │  • Rate Limiter                                    │  │   │
│  │  │  • WebSocket Manager                               │  │   │
│  │  └──────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└────────┬──────────────────────────────────┬────────────────────────┘
         │                                  │
         │ PostgreSQL Protocol              │ Bitcoin RPC
         │                                  │
┌────────┴──────────────┐          ┌────────┴──────────────────────────┐
│   Database Layer      │          │     Bitcoin Infrastructure         │
│                       │          │                                    │
│  ┌─────────────────┐ │          │  ┌──────────────────────────────┐ │
│  │   PostgreSQL    │ │          │  │      Bitcoin Core Node       │ │
│  │                 │ │          │  │                              │ │
│  │  • Users        │ │          │  │  • Full Node                │ │
│  │  • Sessions     │ │          │  │  • Wallet RPC               │ │
│  │  • OAuth Tokens │ │          │  │  • Transaction Index        │ │
│  │  • Clients      │ │          │  │  • Mempool                  │ │
│  │  • Messages     │ │          │  └──────────────────────────────┘ │
│  │  • Audit Logs   │ │          │                                    │
│  └─────────────────┘ │          │  ┌──────────────────────────────┐ │
│                       │          │  │   Lightning Network Node     │ │
│  ┌─────────────────┐ │          │  │   (Optional)                │ │
│  │     Redis       │ │          │  │                              │ │
│  │  (Cache/Queue)  │ │          │  │  • LNURL-Auth               │ │
│  └─────────────────┘ │          │  │  • Payment Integration      │ │
│                       │          │  └──────────────────────────────┘ │
└───────────────────────┘          └────────────────────────────────────┘

         │                                  │
         │                                  │
┌────────┴──────────────────────────────────┴────────────────────────────┐
│                    Monitoring & Observability                          │
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ Prometheus  │  │   Grafana   │  │ ELK Stack   │  │   Sentry    │ │
│  │  (Metrics)  │  │ (Dashboard) │  │   (Logs)    │  │   (Errors)  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. OAuth2/OIDC Provider Module

```
┌──────────────────────────────────────────────────────────────┐
│                    OAuth2/OIDC Module                         │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Authorization Endpoints                             │    │
│  │  • /oauth/authorize                                  │    │
│  │  • /oauth/token                                      │    │
│  │  • /oauth/introspect                                 │    │
│  │  • /oauth/revoke                                     │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Discovery Endpoints                                 │    │
│  │  • /.well-known/openid-configuration                │    │
│  │  • /.well-known/jwks.json                           │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Token Management                                    │    │
│  │  • Authorization Code Generation                     │    │
│  │  • Access Token Issuance (JWT)                      │    │
│  │  • Refresh Token Handling                           │    │
│  │  • Token Validation & Verification                  │    │
│  │  • Token Revocation                                 │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Client Management                                   │    │
│  │  • Client Registration                               │    │
│  │  • Client Authentication                             │    │
│  │  • Redirect URI Validation                          │    │
│  │  • Scope Validation                                 │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### 2. LNURL-Auth Module

```
┌──────────────────────────────────────────────────────────────┐
│                    LNURL-Auth Module                          │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  LNURL Endpoints                                     │    │
│  │  • /api/lnurl-auth/login                            │    │
│  │  • /api/lnurl-auth/verify                           │    │
│  │  • /api/lnurl-auth/callback                         │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Challenge-Response System                           │    │
│  │  • K1 Challenge Generation                          │    │
│  │  • Signature Verification (secp256k1)               │    │
│  │  • Public Key Derivation                            │    │
│  │  • Session Binding                                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Lightning Wallet Integration                        │    │
│  │  • LUD-04 Protocol Compliance                       │    │
│  │  • QR Code Generation                               │    │
│  │  • Wallet Detection                                 │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### 3. Bitcoin Wallet Module

```
┌──────────────────────────────────────────────────────────────┐
│                   Bitcoin Wallet Module                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Wallet Operations                                   │    │
│  │  • Create Wallet                                    │    │
│  │  • Load Wallet                                      │    │
│  │  • Backup/Restore                                   │    │
│  │  • Encryption/Decryption                            │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Transaction Management                              │    │
│  │  • UTXO Management                                  │    │
│  │  • Address Generation                               │    │
│  │  • Transaction History                              │    │
│  │  • Balance Queries                                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Bitcoin Core RPC Client                            │    │
│  │  • Connection Pool                                  │    │
│  │  • Request Signing                                  │    │
│  │  • Error Handling                                   │    │
│  │  • Retry Logic                                      │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### 4. Proof of Funds (PoF) Module

```
┌──────────────────────────────────────────────────────────────┐
│               Proof of Funds (PoF) Module                     │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  PSBT Verification Engine                           │    │
│  │  • PSBT Parsing                                     │    │
│  │  • UTXO Verification                                │    │
│  │  • Signature Validation                             │    │
│  │  • Ownership Proof                                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Privacy Levels                                      │    │
│  │  • Boolean (Yes/No - has funds)                     │    │
│  │  • Threshold (Above/Below amount)                   │    │
│  │  • Aggregate (Exact total)                          │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Challenge System                                    │    │
│  │  • Challenge Generation                             │    │
│  │  • Challenge Expiry (5 min)                         │    │
│  │  • Proof Caching (1 hour)                           │    │
│  │  • Challenge Replay Prevention                      │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### 5. Real-time Chat Module

```
┌──────────────────────────────────────────────────────────────┐
│                    Chat Module                                │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  WebSocket Manager                                   │    │
│  │  • Connection Pool                                  │    │
│  │  • Heartbeat/Ping-Pong                              │    │
│  │  • Automatic Reconnection                           │    │
│  │  • Connection Authentication                         │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Message Routing                                     │    │
│  │  • Direct Messages (User-to-User)                   │    │
│  │  • Channel Messages (Broadcast)                     │    │
│  │  • Room Management                                  │    │
│  │  • Presence System                                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Message Storage                                     │    │
│  │  • In-Memory Buffer (Redis)                         │    │
│  │  • Message History (Optional DB)                    │    │
│  │  • Message Encryption                               │    │
│  │  • Retention Policies                               │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

---

## Authentication Flow

### OAuth2 Authorization Code Flow

```
┌──────────┐                                           ┌──────────┐
│          │                                           │          │
│  Client  │                                           │  HODLXXI │
│   App    │                                           │   API    │
│          │                                           │          │
└────┬─────┘                                           └────┬─────┘
     │                                                      │
     │ 1. Authorization Request                            │
     │ GET /oauth/authorize?                               │
     │     response_type=code&                             │
     │     client_id=CLIENT_ID&                            │
     │     redirect_uri=CALLBACK_URL&                      │
     │     scope=openid+profile                            │
     │────────────────────────────────────────────────────>│
     │                                                      │
     │                                                      │ 2. User
     │                                                      │ Authentication
     │                                                      │ (Bitcoin Sig
     │                                                      │  or LNURL)
     │                                                      │
     │ 3. Authorization Code                               │
     │ Redirect: CALLBACK_URL?code=AUTH_CODE               │
     │<────────────────────────────────────────────────────│
     │                                                      │
     │ 4. Token Exchange                                   │
     │ POST /oauth/token                                   │
     │ {                                                    │
     │   "grant_type": "authorization_code",               │
     │   "code": "AUTH_CODE",                              │
     │   "client_id": "CLIENT_ID",                         │
     │   "client_secret": "CLIENT_SECRET",                 │
     │   "redirect_uri": "CALLBACK_URL"                    │
     │ }                                                    │
     │────────────────────────────────────────────────────>│
     │                                                      │
     │                                                      │ 5. Validate
     │                                                      │ Code & Client
     │                                                      │
     │ 6. Access + Refresh Tokens                          │
     │ {                                                    │
     │   "access_token": "eyJhbG...",                      │
     │   "token_type": "Bearer",                           │
     │   "expires_in": 3600,                               │
     │   "refresh_token": "tGzv3J...",                     │
     │   "scope": "openid profile"                         │
     │ }                                                    │
     │<────────────────────────────────────────────────────│
     │                                                      │
     │ 7. API Request with Access Token                    │
     │ GET /api/users/profile                              │
     │ Authorization: Bearer eyJhbG...                      │
     │────────────────────────────────────────────────────>│
     │                                                      │
     │                                                      │ 8. Validate
     │                                                      │ Token (JWT)
     │                                                      │
     │ 9. Protected Resource                               │
     │ { "user_id": "...", "bitcoin_pubkey": "..." }      │
     │<────────────────────────────────────────────────────│
     │                                                      │
```

### LNURL-Auth Flow

```
┌───────────┐                                    ┌──────────┐
│ Lightning │                                    │  HODLXXI │
│  Wallet   │                                    │   API    │
└─────┬─────┘                                    └────┬─────┘
      │                                               │
      │ 1. Request LNURL Login                        │
      │ GET /api/lnurl-auth/login                     │
      │──────────────────────────────────────────────>│
      │                                               │
      │                                               │ 2. Generate
      │                                               │ K1 Challenge
      │                                               │
      │ 3. LNURL-Auth Response                        │
      │ {                                             │
      │   "tag": "login",                             │
      │   "k1": "random_challenge_hex",               │
      │   "callback": "https://.../lnurl-auth/verify" │
      │ }                                             │
      │<──────────────────────────────────────────────│
      │                                               │
      │ 4. Display QR Code                            │
      │ (lnurl-auth://domain?tag=login&k1=...)        │
      │                                               │
      │ 5. User Scans QR                              │
      │                                               │
      │ 6. Wallet Signs K1 Challenge                  │
      │ (secp256k1 signature with wallet key)         │
      │                                               │
      │ 7. Callback with Signature                    │
      │ GET /api/lnurl-auth/verify?                   │
      │     k1=challenge&                             │
      │     sig=signature&                            │
      │     key=pubkey                                │
      │──────────────────────────────────────────────>│
      │                                               │
      │                                               │ 8. Verify
      │                                               │ Signature
      │                                               │
      │                                               │ 9. Create
      │                                               │ Session
      │                                               │
      │ 10. Success Response                          │
      │ {                                             │
      │   "status": "OK",                             │
      │   "session_token": "...",                     │
      │   "expires_at": "2025-10-31T12:00:00Z"        │
      │ }                                             │
      │<──────────────────────────────────────────────│
      │                                               │
```

### Proof of Funds Verification Flow

```
┌──────────┐                                    ┌──────────┐
│  Client  │                                    │  HODLXXI │
│          │                                    │   API    │
└────┬─────┘                                    └────┬─────┘
     │                                               │
     │ 1. Request PoF Challenge                      │
     │ POST /api/pof/challenge                       │
     │ {                                             │
     │   "privacy_level": "threshold",               │
     │   "threshold_amount": 1000000                 │
     │ }                                             │
     │──────────────────────────────────────────────>│
     │                                               │
     │                                               │ 2. Generate
     │                                               │ Challenge
     │                                               │
     │ 3. Challenge Response                         │
     │ {                                             │
     │   "challenge_id": "uuid",                     │
     │   "message": "Prove funds for HODLXXI...",    │
     │   "expires_at": "2025-10-31T12:05:00Z"        │
     │ }                                             │
     │<──────────────────────────────────────────────│
     │                                               │
     │ 4. User Creates PSBT                          │
     │ (in their wallet software)                    │
     │ - Includes UTXOs                              │
     │ - Signs with private keys                     │
     │ - Does NOT broadcast                          │
     │                                               │
     │ 5. Submit Signed PSBT                         │
     │ POST /api/pof/verify                          │
     │ {                                             │
     │   "challenge_id": "uuid",                     │
     │   "psbt": "cHNidP8BA...",                     │
     │   "signature": "MEUCIQDxN..."                 │
     │ }                                             │
     │──────────────────────────────────────────────>│
     │                                               │
     │                                               │ 6. Verify PSBT
     │                                               │ - Parse PSBT
     │                                               │ - Verify UTXOs
     │                                               │ - Check sigs
     │                                               │ - Calculate
     │                                               │   balance
     │                                               │
     │ 7. Verification Result                        │
     │ {                                             │
     │   "verified": true,                           │
     │   "meets_threshold": true,                    │
     │   "proof_id": "uuid",                         │
     │   "valid_until": "2025-10-31T13:00:00Z"       │
     │ }                                             │
     │<──────────────────────────────────────────────│
     │                                               │
     │ 8. Use Proof ID for Access                    │
     │ (Proof cached for 1 hour)                     │
     │                                               │
```

---

## Data Architecture

### Database Schema

```sql
-- Users Table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    bitcoin_pubkey VARCHAR(66) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE,
    email VARCHAR(255),
    profile_data JSONB,
    is_special_user BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- OAuth Clients Table
CREATE TABLE oauth_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    allowed_scopes TEXT[] DEFAULT ARRAY['openid', 'profile'],
    is_confidential BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    owner_user_id INTEGER REFERENCES users(id)
);

-- OAuth Authorization Codes Table
CREATE TABLE oauth_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) REFERENCES oauth_clients(client_id),
    user_id INTEGER REFERENCES users(id),
    scope TEXT[],
    redirect_uri VARCHAR(512),
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- OAuth Tokens Table
CREATE TABLE oauth_tokens (
    id SERIAL PRIMARY KEY,
    access_token VARCHAR(512) UNIQUE NOT NULL,
    refresh_token VARCHAR(512) UNIQUE,
    client_id VARCHAR(255) REFERENCES oauth_clients(client_id),
    user_id INTEGER REFERENCES users(id),
    scope TEXT[],
    expires_at TIMESTAMP NOT NULL,
    refresh_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP
);

-- Sessions Table
CREATE TABLE sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    session_data JSONB,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    user_agent TEXT
);

-- LNURL Auth Challenges Table
CREATE TABLE lnurl_challenges (
    k1 VARCHAR(64) PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    public_key VARCHAR(66),
    verified BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Proof of Funds Challenges Table
CREATE TABLE pof_challenges (
    challenge_id UUID PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    challenge_message TEXT NOT NULL,
    privacy_level VARCHAR(20) NOT NULL,
    threshold_amount BIGINT,
    verified BOOLEAN DEFAULT FALSE,
    verified_amount BIGINT,
    proof_valid_until TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Chat Messages Table (Optional - can use Redis)
CREATE TABLE chat_messages (
    id SERIAL PRIMARY KEY,
    room_id VARCHAR(255),
    sender_id INTEGER REFERENCES users(id),
    recipient_id INTEGER REFERENCES users(id),
    message_text TEXT,
    encrypted_payload TEXT,
    message_type VARCHAR(20) DEFAULT 'text',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP
);

-- Audit Logs Table
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Rate Limit Tracking Table
CREATE TABLE rate_limits (
    id SERIAL PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    request_count INTEGER DEFAULT 1,
    window_start TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(identifier, endpoint, window_start)
);

-- Bitcoin Wallets Table
CREATE TABLE bitcoin_wallets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    wallet_name VARCHAR(255) NOT NULL,
    encrypted_descriptor TEXT,
    is_watch_only BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_sync TIMESTAMP
);

-- Indexes for Performance
CREATE INDEX idx_users_bitcoin_pubkey ON users(bitcoin_pubkey);
CREATE INDEX idx_oauth_codes_expires_at ON oauth_codes(expires_at);
CREATE INDEX idx_oauth_tokens_access_token ON oauth_tokens(access_token);
CREATE INDEX idx_oauth_tokens_refresh_token ON oauth_tokens(refresh_token);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_chat_messages_room_id ON chat_messages(room_id);
CREATE INDEX idx_chat_messages_created_at ON chat_messages(created_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
```

### Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Data Flow                                 │
│                                                                   │
│  ┌──────────┐       ┌───────────┐       ┌──────────────────┐   │
│  │  Client  │──────>│    API    │──────>│   PostgreSQL     │   │
│  │  Request │   1   │  Gateway  │   2   │   (Persistent)   │   │
│  └──────────┘       └─────┬─────┘       └──────────────────┘   │
│                            │                                     │
│                            │ 3                                   │
│                            ↓                                     │
│                      ┌───────────┐                              │
│                      │   Redis   │                              │
│                      │  (Cache)  │                              │
│                      └─────┬─────┘                              │
│                            │                                     │
│                            │ 4                                   │
│                            ↓                                     │
│                      ┌───────────┐       ┌──────────────────┐   │
│                      │  Bitcoin  │──────>│   Blockchain     │   │
│                      │    Core   │   5   │    Network       │   │
│                      └───────────┘       └──────────────────┘   │
│                                                                   │
│  Flow:                                                           │
│  1. Client request arrives at API Gateway                       │
│  2. API writes/reads from PostgreSQL (persistent data)          │
│  3. API checks/updates Redis cache (sessions, rate limits)      │
│  4. API queries Bitcoin Core for wallet/blockchain operations   │
│  5. Bitcoin Core syncs with blockchain network                  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

See [SECURITY_REQUIREMENTS.md](app/SECURITY_REQUIREMENTS.md) for complete details. Key layers:

1. **Network Layer**: Firewall, DDoS protection, TLS 1.3
2. **Application Layer**: Rate limiting, CORS, CSRF protection
3. **Authentication Layer**: Multi-factor, signature verification
4. **Authorization Layer**: RBAC, scope-based access
5. **Data Layer**: Encryption at rest, secure key management

---

## Network Architecture

### Production Deployment

```
                     Internet
                        │
                        │
                        ↓
┌───────────────────────────────────────────────────┐
│          Cloudflare / CDN                          │
│          - DDoS Protection                         │
│          - Rate Limiting (Layer 7)                │
│          - SSL/TLS Termination                    │
└──────────────────┬────────────────────────────────┘
                   │
                   ↓
┌───────────────────────────────────────────────────┐
│          Load Balancer (Nginx/HAProxy)            │
│          - Layer 7 Load Balancing                 │
│          - Health Checks                          │
│          - SSL Re-encryption                      │
└──────────────────┬────────────────────────────────┘
                   │
         ┌─────────┴──────────┐
         │                    │
         ↓                    ↓
┌──────────────┐      ┌──────────────┐
│  App Server  │      │  App Server  │
│   Instance 1 │      │  Instance 2  │
│              │      │              │
│ - Flask App  │      │ - Flask App  │
│ - WebSocket  │      │ - WebSocket  │
│ - Redis      │      │ - Redis      │
└──────┬───────┘      └──────┬───────┘
       │                     │
       └──────────┬──────────┘
                  │
         ┌────────┴────────┐
         │                 │
         ↓                 ↓
┌──────────────┐   ┌──────────────┐
│ PostgreSQL   │   │  Bitcoin     │
│ Primary      │   │  Core Node   │
│              │   │              │
└──────┬───────┘   └──────────────┘
       │
       ↓
┌──────────────┐
│ PostgreSQL   │
│ Replica      │
│ (Read-only)  │
└──────────────┘
```

### Port Configuration

| Service | Port | Protocol | Access |
|---------|------|----------|--------|
| HTTPS | 443 | TCP | Public |
| HTTP (redirect) | 80 | TCP | Public |
| Flask App | 5000 | TCP | Internal |
| PostgreSQL | 5432 | TCP | Internal |
| Redis | 6379 | TCP | Internal |
| Bitcoin RPC | 8332 | TCP | Internal |
| Bitcoin P2P | 8333 | TCP | Public (Bitcoin node) |
| Prometheus | 9090 | TCP | Internal/VPN |
| WebSocket | 443 | TCP/WS | Public |

---

## Deployment Architecture

### Docker Compose Stack

```yaml
services:
  app:
    build: .
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://...
      - BITCOIN_RPC_URL=http://bitcoin:8332
    depends_on:
      - db
      - redis
      - bitcoin

  db:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7
    volumes:
      - redis_data:/data

  bitcoin:
    image: bitcoin/bitcoin:latest
    volumes:
      - bitcoin_data:/bitcoin/.bitcoin

  nginx:
    image: nginx:latest
    ports:
      - "443:443"
      - "80:80"
    depends_on:
      - app

volumes:
  postgres_data:
  redis_data:
  bitcoin_data:
```

### Kubernetes Architecture (Optional)

For larger deployments, Kubernetes can provide:
- Auto-scaling based on metrics
- Self-healing (automatic pod restarts)
- Rolling updates with zero downtime
- Service mesh for internal communication

---

## Technology Stack

### Backend
- **Language**: Python 3.8+
- **Framework**: Flask 2.0+
- **WSGI Server**: Gunicorn
- **Async**: Gevent / asyncio

### Database
- **Primary**: PostgreSQL 15+
- **Cache/Queue**: Redis 7+
- **ORM**: SQLAlchemy

### Bitcoin Integration
- **Bitcoin Core**: 24.0+
- **RPC Client**: Custom Python-bitcoinrpc
- **PSBT**: Bitcoin-python

### Authentication
- **JWT**: PyJWT
- **OAuth2**: Authlib
- **Cryptography**: secp256k1, ecdsa

### WebSocket
- **Library**: Flask-SocketIO
- **Protocol**: WebSocket (RFC 6455)

### Monitoring
- **Metrics**: Prometheus
- **Logs**: ELK Stack / Loki
- **APM**: Sentry
- **Dashboard**: Grafana

### Infrastructure
- **Container**: Docker
- **Orchestration**: Docker Compose / Kubernetes
- **Reverse Proxy**: Nginx / Traefik
- **SSL**: Let's Encrypt / Certbot

---

## Scalability Considerations

### Horizontal Scaling

The application is designed to scale horizontally:

1. **Stateless Application**: All state in Redis/PostgreSQL
2. **Load Balancer**: Distribute traffic across multiple instances
3. **Database Replication**: Read replicas for query distribution
4. **Redis Cluster**: Distributed caching and session storage
5. **WebSocket Sticky Sessions**: Load balancer session affinity

### Performance Optimization

- **Connection Pooling**: PostgreSQL and Bitcoin RPC
- **Caching Strategy**: Redis for sessions, rate limits, hot data
- **Database Indexing**: Optimized queries with proper indexes
- **Async Operations**: Non-blocking I/O for Bitcoin RPC calls
- **CDN**: Static assets and API responses where appropriate

### Future Enhancements

- GraphQL endpoint for flexible queries
- gRPC for service-to-service communication
- Message queue (RabbitMQ/Kafka) for async tasks
- Multi-region deployment with data replication
- Lightning Network node integration

---

## Diagrams Source

All diagrams in this document are created using ASCII art for maximum compatibility. For visual diagrams:

1. Use [Mermaid](https://mermaid.js.org/) for flow diagrams
2. Use [Draw.io](https://draw.io/) for architecture diagrams
3. Use [PlantUML](https://plantuml.com/) for sequence diagrams

---

## Additional Resources

- [API Documentation](app/API_RESPONSE_EXAMPLES.md)
- [Security Requirements](app/SECURITY_REQUIREMENTS.md)
- [Production Deployment](app/PRODUCTION_DEPLOYMENT.md)
- [OAuth/LNURL Specification](app/OAUTH_LNURL_SPECIFICATION.md)
- [Error Code Documentation](app/ERROR_CODE_DOCUMENTATION.md)

---

**Last Updated**: October 31, 2025  
**Version**: 1.0.0  
**Maintainer**: HODLXXI Team
