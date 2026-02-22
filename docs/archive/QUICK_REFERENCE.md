# HODLXXI Quick Reference

## 🎯 Main User Flows

### Login
```
https://hodlxxi.com/login
  → POST /verify_signature (Bitcoin sig)
  → POST /special_login (Admin)
  → POST /guest_login (Anonymous)
```

### Playground
```
https://hodlxxi.com/playground
  → 5 React tabs (Legacy, API, LNURL, OAuth, PoF)
```

### Proof-of-Funds
```
https://hodlxxi.com/pof/
  → /pof/verify (Create PoF)
  → /pof/leaderboard (View rankings)
  → /pof/certificate/<id> (Share proof)
```

### Developer
```
https://hodlxxi.com/dev-dashboard
  → View stats, OAuth clients
  → /upgrade (Manage membership)
```

## 🔌 Key API Endpoints

### Auth
- `POST /verify_signature` - Bitcoin signature verification
- `POST /api/challenge` - Get challenge for signing
- `POST /api/verify` - Verify signature against challenge

### OAuth2
- `POST /oauth/register` - Register OAuth client
- `GET /oauth/authorize` - Authorization page
- `POST /oauth/token` - Get access token

### Proof-of-Funds
- `POST /api/playground/pof/challenge` - Generate PoF challenge
- `POST /api/playground/pof/verify` - Verify PSBT proof

### LNURL
- `POST /api/lnurl-auth/create` - Create Lightning auth session
- `GET /api/lnurl-auth/check/<id>` - Poll auth status

## 📊 Database Tables
```
users, ubid_users           - Identity
oauth_clients/codes/tokens  - OAuth2 state
proof_of_funds              - PoF attestations
chat_messages               - Real-time chat
payments, subscriptions     - Billing
sessions, rate_limits       - Access control
```

## 🎨 Templates
```
playground.html      - Main interactive UI (React)
dashboard.html       - User dashboard
dev_dashboard.html   - Developer console
pof/landing.html     - PoF homepage
pof/verify.html      - Create PoF
pof/leaderboard.html - Whale rankings
pof/certificate.html - Shareable proof
```

