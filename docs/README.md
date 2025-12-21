# HODLXXI Documentation

**Last Updated:** December 12, 2025  
**Status:** Production-ready, documented, stabilized

---

## 📚 Documentation Index

### Core Documentation
1. **[SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md)** - Complete system overview
   - High-level architecture diagram
   - Component descriptions
   - Authentication flows
   - Deployment details
   - Migration roadmap

2. **[API_REFERENCE.md](API_REFERENCE.md)** - API endpoint documentation
   - All 55+ routes documented
   - Request/response examples
   - Authentication requirements
   - Rate limits

3. **[COVENANT_SYSTEM.md](COVENANT_SYSTEM.md)** - Core feature documentation
   - 21-year Bitcoin contracts
   - Descriptor-based implementation
   - Explorer UI guide
   - API endpoints

4. **[DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)** - Database documentation
   - All 17 tables documented
   - Foreign key relationships
   - Index strategy
   - Migration notes

---

## 🚀 Quick Start

### For Developers
```bash
# Clone and setup
git clone <repo>
cd hodlxxi
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your settings

# Setup database
createdb hodlxxi
psql hodlxxi < schema.sql

# Run
gunicorn -k eventlet -w 1 -b 127.0.0.1:5000 wsgi:app
```

### For Operators
See **SYSTEM_ARCHITECTURE.md** → "Deployment Architecture"

### For API Users
See **API_REFERENCE.md** for endpoint documentation

---

## 🏗️ System Overview

**HODLXXI** is a Bitcoin-native identity and authorization platform:

- ✅ **Bitcoin signature authentication** (no passwords)
- ✅ **OAuth2/OIDC provider** (Auth0 alternative)
- ✅ **Proof-of-Funds verification** (UTXO-based)
- ✅ **21-year covenant contracts** (core feature)
- 🚧 **Lightning Network** (LNURL-auth, payments - in progress)
- ✅ **Real-time features** (chat, WebSocket)

---

## 📊 Current Status

**Production Stats:**
- App size: 12,804 lines (monolith)
- Routes: 55+ HTTP endpoints
- Database: 17 tables, clean state
- Users: 2 (you + test account)
- OAuth clients: 0 (cleaned)
- Uptime: Days without restart
- Performance: <100ms response time

**Recent Changes:**
- ✅ Removed 175 test OAuth clients
- ✅ Removed dead code (guest_login2)
- ✅ Created comprehensive documentation
- ✅ Database cleaned and optimized
- ✅ Full system backups created

---

## 🎯 Roadmap

### Phase 1: Lightning Integration (Next)
- [ ] Install LND
- [ ] Implement LNURL-auth
- [ ] Enable Lightning payments
- [ ] Automate subscriptions

### Phase 2: Code Refactoring (Month 1)
- [ ] Extract Bitcoin RPC module
- [ ] Modularize auth flows
- [ ] Break up 12k-line monolith
- [ ] Improve test coverage

### Phase 3: Event-Based Architecture (Quarter 1)
- [ ] Design identity_events table
- [ ] Build relay API
- [ ] Implement federation
- [ ] Migrate existing data

---

## 🔐 Security

**Non-Custodial:**
- No private keys stored
- No passwords required
- Bitcoin signatures verify identity
- Covenants enforced by Bitcoin consensus

**Access Levels:**
- `guest` - Anonymous, limited
- `limited` - Standard user
- `full` - Verified Bitcoin identity
- `special` - Admin (whitelisted pubkeys)

---

## 🛠️ Development

**Tech Stack:**
- Python 3.12 + Flask
- PostgreSQL 16
- Redis 7
- Bitcoin Core (remote)
- Nginx + Gunicorn

**Key Files:**
- `app/app.py` - Main application (12,804 lines)
- `app/blueprints/` - Modular routes
- `app/templates/` - Jinja2 HTML
- `app/static/` - Frontend assets

---

## 📖 Learn More

**Bitcoin Concepts:**
- [BIP-380: Descriptors](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
- [Miniscript](https://bitcoin.sipa.be/miniscript/)
- [BIP-322: Generic Message Signing](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki)

**OAuth/OIDC:**
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect](https://openid.net/connect/)

**Lightning Network:**
- [LNURL Specification](https://github.com/lnurl/luds)
- [BOLT11 Invoices](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)

---

## 🤝 Contributing

This is currently a solo project by **alnostru**.

**Future:** Will accept contributions after:
1. Lightning integration complete
2. Event-based refactor started
3. Test coverage >80%

---

## 📝 License

(Add your license here)

---

## 📞 Contact

- Website: https://hodlxxi.com
- Playground: https://hodlxxi.com/playground
- Status: https://hodlxxi.com/health

---

**"Bitcoin identity for the next 21 years"** 🚀
