# HODLXXI System Architecture

**Version:** 1.0 (Stabilized December 2025)  
**Status:** Production, preparing for event-based refactor

---

## Executive Summary

HODLXXI is a Bitcoin-native identity and authorization platform that bridges Web2 applications with Bitcoin's cryptographic identity model. It combines:

- **Bitcoin signature authentication** (BIP-322, ECDSA)
- **OAuth2/OIDC provider** (Auth0-like service)
- **Proof-of-Funds verification** (PSBT-based)
- **21-year covenant contracts** (descriptor wallets)
- **Lightning Network integration** (LNURL-auth, payments - in progress)
- **Real-time chat/video** (Socket.IO + WebRTC)

---

## High-Level Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                         HODLXXI Platform                         │
│                      https://hodlxxi.com                         │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         ┌─────────┐    ┌──────────┐   ┌──────────┐
         │  Nginx  │    │  Flask   │   │ Socket.IO│
         │ (Proxy) │───▶│  (WSGI)  │◀──│(Real-time)│
         └─────────┘    └──────────┘   └──────────┘
              │               │               │
              │         ┌─────┴─────┐        │
              │         ▼           ▼        │
              │    ┌─────────┐ ┌────────┐   │
              │    │Postgres │ │ Redis  │   │
              │    │  (DB)   │ │(Cache) │   │
              │    └─────────┘ └────────┘   │
              │         │                    │
              └─────────┼────────────────────┘
                        ▼
                  ┌──────────────┐
                  │ Bitcoin Core │ (via SSH tunnel)
                  │  Full Node   │
                  └──────────────┘
```

---

## Core Components

### 1. Web Server Layer

**Nginx** (Port 443)
- TLS termination (Let's Encrypt)
- Rate limiting (10 req/s general, 5 req/min auth)
- WebSocket proxy for Socket.IO
- Static file serving

**Gunicorn** (Port 5000, internal)
- WSGI server with eventlet worker
- Single worker (for Socket.IO compatibility)
- Handles HTTP and WebSocket connections

### 2. Application Layer

**Flask Monolith** (`app/app.py` - 12,805 lines)
- Main application logic
- 55+ HTTP routes
- Socket.IO event handlers
- Bitcoin RPC integration
- OAuth2/OIDC provider

**Blueprints** (Partial modularization)
- `pof_bp` - Proof-of-Funds routes
- `oidc_bp` - OpenID Connect
- `pof_api_bp` - PoF API
- `oauth_bp` - OAuth2 endpoints

### 3. Data Layer

**PostgreSQL** (17 tables)
- Identity: `users`, `ubid_users`
- Sessions: `sessions`, `rate_limits`
- OAuth: `oauth_clients`, `oauth_codes`, `oauth_tokens`
- PoF: `proof_of_funds`, `pof_challenges`
- Payments: `payments`, `subscriptions`
- Chat: `chat_messages`
- Admin: `audit_logs`, `usage_stats`

**Redis**
- Session storage
- Real-time presence tracking
- Rate limit counters
- Challenge/nonce caching

### 4. Bitcoin Integration

**Bitcoin Core** (Remote via SSH)
- Wallet: `hodlandwatch`
- Descriptor-based covenant storage
- UTXO scanning for PoF
- Message signature verification
- Script validation

**Connection:**
```bash
ssh -L 8332:localhost:8332 user@remote-node
```

**RPC Methods Used:**
- `verifymessage()` - Auth
- `scantxoutset()` - PoF balance
- `listdescriptors()` - Covenant management
- `getbalance()`, `getblockcount()` - Stats

---

## Authentication Flows

### Flow 1: Bitcoin Signature Login
```
1. User visits /login
2. Server generates challenge (UUID)
3. User signs challenge with Bitcoin key
4. POST /verify_signature with (message, signature, address)
5. Server verifies via Bitcoin Core RPC
6. Session created with pubkey as identity
7. Access level determined (limited/full/special)
```

### Flow 2: Guest Login
```
1. POST /guest_login (optionally with PIN)
2. Server generates guest identity: "guest-random-{uuid}"
3. Session created with limited access
4. No Bitcoin signature required
```

### Flow 3: Special/Admin Login
```
1. User signs challenge with whitelisted pubkey
2. POST /special_login
3. Server checks against SPECIAL_USERS env var
4. If match: access_level = "special" (admin)
```

### Flow 4: OAuth2 for Web2 Apps
```
Client App                 HODLXXI                  User
    │                         │                       │
    │─── GET /oauth/authorize ────────────────────────▶
    │                         │                       │
    │                         │◀──── Login (BTC) ─────│
    │                         │                       │
    │◀──── Redirect + code ───│                       │
    │                         │                       │
    │─── POST /oauth/token ───▶                       │
    │    (code + secret)      │                       │
    │                         │                       │
    │◀──── access_token ──────│                       │
    │                         │                       │
    │─── API calls + token ───▶                       │
```

---

## Key Features

### 1. Proof-of-Funds (PoF)

**Two implementations:**
- **Simple:** Message signature per address
- **Enhanced:** PSBT-based (in `pof_routes.py`)

**Privacy Levels:**
- `boolean` - Just proves ownership (no amount)
- `threshold` - Proves balance > X (no exact amount)
- `full` - Full disclosure

**Flow:**
```
1. Generate challenge: POST /pof/api/generate-challenge
2. Sign message with each address
3. Submit signatures: POST /pof/api/verify-signatures
4. Server queries UTXO set via scantxoutset
5. Returns total balance + certificate
```

### 2. Covenant System (Core Feature)

**Purpose:** 21-year Bitcoin contracts (expires 2042)

**Implementation:**
- Descriptor-based: `raw(script_hex)#checksum`
- Two account types: SAVE (P2WSH) and CHECK (P2WPKH)
- Explorer UI at `/home` (lines 5488-5860)

**Script Structure:**
```
OP_IF
  <pubkey_A> OP_CHECKSIG        # Path 1: Immediate spend
OP_ELSE
  <2042-01-01> OP_CLTV OP_DROP  # Path 2: Time-locked
  <pubkey_B> OP_CHECKSIG
OP_ENDIF
```

**API:**
- List: `GET /verify_pubkey_and_list?pubkey=...`
- Import: `POST /import_descriptor`
- Export: `GET /export_wallet`
- Decode: `POST /decode_raw_script`

### 3. Real-Time Chat

**Technology:** Socket.IO over WebSocket

**Events:**
- `connect` / `disconnect`
- `message` - Chat messages
- `user:logged_in` / `user:left`
- `online:list` - Active users

**Status:** Infrastructure ready, 0 messages in production

### 4. Playground

**Location:** `/playground`

**Purpose:** Interactive API testing environment

**Features:**
- Test all auth methods
- PoF demos
- Lightning simulation
- Nostr key auth
- Live code execution

---

## Membership Tiers

**Plans:**
- **Free** - Basic access, rate-limited
- **Builder** - 1000 sats/month, increased limits
- **Pro** - 5000 sats/month, full API access

**Payment:** Lightning Network invoices (LND integration pending)

---

## Security Model

### Authentication
- No passwords, only cryptographic signatures
- Session-based (secure cookies)
- OAuth2 Bearer tokens for API access
- Rate limiting on all endpoints

### Authorization
Access levels:
- `guest` - Limited, read-only
- `limited` - Standard user
- `full` - Verified Bitcoin identity
- `special` - Admin (whitelisted pubkeys)

### Bitcoin Integration
- Non-custodial (no private keys stored)
- All balances verified on-chain
- Message signatures verified via Bitcoin Core
- Descriptors only (no seed phrases)

### Data Privacy
- No email required
- Pseudonymous pubkey identities
- Optional PoF privacy modes
- Covenant scripts hashed (P2WSH/Taproot)

---

## Deployment Architecture

**Server:** Ubuntu 24.04 (1 vCPU, 1GB RAM)

**Services:**
```
systemd:
├─ hodlxxi.service   (Flask + Gunicorn + Socket.IO)
├─ nginx.service     (Reverse proxy)
├─ postgresql.service (Database)
└─ redis-server.service (Cache)
```

**External Dependencies:**
- Bitcoin Core (via SSH tunnel)
- Let's Encrypt (TLS certificates)
- DNS: hodlxxi.com

**File Structure:**
```
/srv/ubid/
├── app/
│   ├── app.py              (12,805 lines - main monolith)
│   ├── blueprints/         (Modular routes)
│   ├── templates/          (Jinja2 HTML)
│   └── static/             (CSS, JS, images)
├── backups/                (Database dumps)
├── docs/                   (This documentation)
├── venv/                   (Python 3.12 virtualenv)
├── .env                    (Environment config)
└── wsgi.py                 (Gunicorn entrypoint)
```

---

## Performance Metrics

**Current Load:**
- Memory: ~90MB (Flask + Gunicorn)
- CPU: Minimal (<5% avg)
- Uptime: Days without restart
- Response time: <100ms (auth endpoints)

**Capacity:**
- Current: 2 users, 0 OAuth clients (after cleanup)
- Rate limits: 10 req/s general, 5 req/min auth
- Database: <1MB (after test data removal)

---

## Migration Path: Event-Based Architecture

**Goal:** Transition from monolithic to event-sourced identity system

**Target Architecture:**
```
Identity Events (signed)
    ↓
Relay Network (distributed)
    ↓
App Queries Events (verify signatures)
```

**Phase 1: Design** (Current)
- [x] Document current architecture
- [x] Clean up monolith
- [ ] Design identity_events table
- [ ] Spec relay API

**Phase 2: Build** (Next 2-3 weeks)
- [ ] Create `hodlxxi/bitcoin.py` module
- [ ] Implement identity_events model
- [ ] Build relay API
- [ ] Migrate existing data

**Phase 3: Deploy** (Following month)
- [ ] Run dual systems (legacy + events)
- [ ] Gradual cutover
- [ ] Deprecate old tables
- [ ] Federation testing

---

## Known Limitations

1. **No Lightning Node:** LNURL-auth routes exist but non-functional
2. **Monolithic codebase:** 12k+ lines in single file
3. **Dual user tables:** `users` and `ubid_users` (redundant)
4. **Manual payments:** No automated Lightning invoice processing
5. **Covenant storage:** Descriptors in Bitcoin Core, not database

---

## Next Steps

**Immediate (Week 1):**
- [ ] Install LND
- [ ] Implement LNURL-auth
- [ ] Test all authentication flows

**Short-term (Month 1):**
- [ ] Refactor Bitcoin integration into module
- [ ] Design identity_events schema
- [ ] Build relay API prototype

**Long-term (Quarter 1):**
- [ ] Event-based identity migration
- [ ] Federation/relay network
- [ ] Mobile apps (React Native)
- [ ] Hardware wallet support

---

**Document Version:** 1.0  
**Last Updated:** December 12, 2025  
**Maintained By:** alnostru  
**Repository:** (Add when public)
