# System Architecture

HODLXXI's technical architecture integrates Bitcoin primitives into a coordination framework.

This document describes the system design without philosophical interpretation.

---

## High-Level Overview

```
┌─────────────────────────────────────────┐
│         User Applications               │
│  (Web UI, Mobile, CLI, Third-party)    │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│         HODLXXI Core Services           │
│  - Authentication                       │
│  - Covenant Management                  │
│  - Reputation Tracking                  │
│  - Identity Resolution                  │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│         Bitcoin Layer                   │
│  - Time-locked Transactions             │
│  - PSBTs                                │
│  - Message Signing                      │
└─────────────────────────────────────────┘
```

---

## Core Components

### 1. Identity Layer

**Bitcoin Keys as Identity**

Every participant has:
- Extended public key (xpub) as persistent identity
- Private keys for signing and unlocking
- Deterministic address derivation

**No accounts or passwords.**

Authentication flow:
1. Client generates signature challenge
2. User signs with private key
3. Server verifies signature against xpub
4. Session token issued

### 2. Covenant Layer

**Time-Locked Commitments**

Participants create Bitcoin transactions with:
- `OP_CHECKLOCKTIMEVERIFY` for time locks
- Multi-signature schemes for partnerships
- Taproot for complex conditions

Covenants are stored on-chain.  
No off-chain database required.

### 3. Reputation Layer

**Observable History**

Reputation is derived from:
- On-chain covenant history (time-locks created/honored)
- Signed messages and attestations
- Nostr events (optional interoperability)

No centralized reputation database.  
Each client computes reputation locally from public data.

### 4. Communication Layer

**Nostr Integration (Optional)**

For off-chain coordination:
- Direct messages via Nostr relays
- Attestations and reviews
- Event announcements

Nostr is optional. Core functions work without it.

---

## Data Flow

### Creating a Covenant

```
1. User selects commitment parameters (amount, duration)
2. Client generates PSBT with time-lock script
3. User reviews and signs PSBT with hardware wallet
4. Client broadcasts transaction to Bitcoin network
5. Covenant is now live and verifiable by anyone
```

### Verifying a Covenant

```
1. Observer queries Bitcoin blockchain for address
2. Observer finds time-locked UTXO
3. Observer extracts unlock conditions from script
4. Observer verifies signature matches claimed identity
5. Observer updates reputation assessment locally
```

---

## Technical Stack

### Backend

**Language:** Python 3.11+  
**Framework:** Flask 3.0  
**Database:** PostgreSQL 14+ (for application state, not covenants)  
**Cache:** Redis 7+ (sessions, temporary data)

### Bitcoin Integration

**Full Node:** Bitcoin Core 24.0+  
**RPC Interface:** bitcoinrpc-python  
**Wallet:** Descriptor-based wallets (BIP-380)  
**PSBTs:** BIP-174 for transaction construction

### Frontend

**Web:** Standard HTML/CSS/JS (no heavy frameworks)  
**Mobile:** Progressive Web App (PWA) or native apps (future)

### Infrastructure

**Hosting:** Self-hosted VPS (Ubuntu 24 LTS)  
**No cloud dependencies** (AWS, Google, etc.)  
**No third-party analytics or tracking**

---

## Security Model

### Threat Model

**What HODLXXI protects against:**
- Centralized censorship (no single point of failure)
- Unauthorized spending (only key holder can unlock)
- Reputation manipulation (history is immutable)

**What HODLXXI does NOT protect against:**
- Lost private keys (no recovery mechanism)
- Compromised devices (malware can steal keys)
- Social engineering (users can be tricked)
- Legal coercion (government can prosecute)

### Authentication

**No passwords.**

Authentication uses cryptographic signatures:
- Client generates random challenge
- User signs challenge with Bitcoin private key
- Server verifies signature
- Session token issued (short-lived, JWT)

### Key Management

**Users must:**
- Store private keys securely (hardware wallet recommended)
- Back up seed phrases
- Never share private keys

**Server never:**
- Sees user private keys
- Stores user passwords
- Custodies user funds

---

## API Design

### REST Endpoints

```
POST   /auth/challenge         # Get signing challenge
POST   /auth/verify            # Verify signature, get token

GET    /identity/:xpub         # Get identity info
GET    /covenants/:xpub        # List covenants for identity

POST   /covenant/create        # Create new covenant (returns PSBT)
POST   /covenant/broadcast     # Broadcast signed PSBT

GET    /reputation/:xpub       # Get reputation metrics
GET    /history/:xpub          # Get action history
```

### WebSocket Events (Optional)

```
covenant.created     # New covenant broadcast
covenant.unlocked    # Covenant reached unlock time
identity.updated     # Identity metadata changed
```

---

## Database Schema

### Application Database (PostgreSQL)

**Note:** Covenants are NOT stored in database. They are on-chain only.

Database stores:
- Session tokens (temporary)
- Cached blockchain data (for performance)
- User preferences (optional)
- API rate limits

Key tables:
```sql
-- Sessions (temporary, auto-expire)
CREATE TABLE sessions (
  token UUID PRIMARY KEY,
  xpub VARCHAR(128) NOT NULL,
  expires_at TIMESTAMP NOT NULL
);

-- Cached covenant metadata (derived from blockchain)
CREATE TABLE covenant_cache (
  txid VARCHAR(64) PRIMARY KEY,
  xpub VARCHAR(128) NOT NULL,
  unlock_height INTEGER NOT NULL,
  amount_sats BIGINT NOT NULL,
  created_at TIMESTAMP NOT NULL
);
```

### On-Chain Data (Bitcoin Blockchain)

The source of truth is always the blockchain.

Database is:
- Read-only cache
- Performance optimization
- Not authoritative

---

## Scalability

### Current Limits

- Bitcoin block time: ~10 minutes
- Bitcoin transaction throughput: ~7 TPS globally
- HODLXXI does not change these limits

### Scaling Strategies

**Layer 2 Integration (Future):**
- Lightning Network for micropayments
- Real-time chat and coordination
- Frequent updates off-chain

**Batching:**
- Multiple covenant creations in one transaction
- Reduces on-chain footprint

**Client-Side Computation:**
- Reputation calculated locally
- No centralized reputation server needed

---

## Deployment

### Production Setup

```bash
# Bitcoin full node (required)
bitcoind -daemon -txindex=1

# PostgreSQL database
createdb hodlxxi

# Redis cache
redis-server

# HODLXXI backend
cd /srv/ubid/app
pip install -r requirements.txt
flask run --host=0.0.0.0 --port=5000

# Nginx reverse proxy
nginx -c /etc/nginx/nginx.conf
```

### Environment Variables

```bash
BITCOIN_RPC_USER=...
BITCOIN_RPC_PASSWORD=...
BITCOIN_RPC_HOST=localhost
BITCOIN_RPC_PORT=8332

DATABASE_URL=postgresql://user:pass@localhost/hodlxxi
REDIS_URL=redis://localhost:6379

SECRET_KEY=...  # For session tokens
```

---

## Monitoring

### Health Checks

```
GET /health          # Application status
GET /bitcoin/health  # Bitcoin node sync status
```

### Metrics

- Covenant creation rate
- Transaction confirmation times
- API response times
- Bitcoin node sync status

### Logging

- Structured JSON logs
- No PII (personally identifiable information)
- Blockchain addresses logged (public anyway)

---

## Future Enhancements

### Planned Features

- Lightning Network integration (micropayments, chat)
- Nostr relay hosting (optional)
- Mobile apps (iOS, Android)
- Hardware wallet support (Ledger, Trezor, ColdCard)

### Research Directions

- Covenant opcodes (OP_CTV, OP_CAT)
- Zero-knowledge proofs for privacy
- Cross-chain bridges (other UTXO chains)

---

## Limitations

### What This Architecture Cannot Do

- Instant finality (Bitcoin confirmations take time)
- High throughput (limited by Bitcoin block size)
- Strong privacy (transactions are public)
- Turing-complete contracts (Bitcoin Script is limited)

### What This Architecture Can Do

- Censorship-resistant commitments
- Verifiable history without trusted parties
- Self-custodial identity and funds
- Exit without permission

---

## Next Steps

**Understand time-locks:** [Time-Locked Covenants](covenants)

**See the theory:** [CRT Theory](crt_theory)

**Read about incentives:** [Reputation & Incentives](reputation)

---

*Architecture defines what is possible.*  
*Incentives define what actually happens.*
