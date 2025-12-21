# HODLXXI Covenant System

## Overview

The HODLXXI Covenant System enables **21-year Bitcoin contracts** using descriptor-based wallets and Bitcoin script covenants. This is a **core feature** that bridges Bitcoin's programmability with long-term trust agreements.

## What Are HODLXXI Covenants?

A covenant is a Bitcoin script that enforces rules on how funds can be spent in the future. HODLXXI leverages:
- **Bitcoin descriptors** (BIP 380-386)
- **Miniscript** for script composition  
- **Taproot** (BIP 341) for privacy
- **Timelocks** (nLockTime, OP_CHECKLOCKTIMEVERIFY)

### 21-Year Timeline
Covenants expire in **2042** (21 years from ~2021), aligning with Bitcoin's supply schedule and generational planning.

## Architecture

### 1. Descriptor Storage
Covenants are stored as Bitcoin Core descriptors in the wallet:
```
raw(<script_hex>)#<checksum>
```

### 2. Script Classification

**Two account types:**
- **SAVE** (P2WSH): Long-term storage, complex scripts
- **CHECK** (P2WPKH): Liquid funds, simple spending

### 3. Explorer UI

**Features:**
- View all covenants in wallet
- See locked balances (SAVE vs CHECK)
- Display covenant participants (OP_IF/OP_ELSE pubkeys)
- QR codes for easy sharing
- Real-time Bitcoin node stats

## API Endpoints

### List Descriptors
```http
GET /verify_pubkey_and_list?pubkey=<hex>
```

### Decode Script
```http
POST /decode_raw_script
Content-Type: application/json
{"script_hex": "6382..."}
```

### Import Descriptor
```http
POST /import_descriptor
Content-Type: application/json
{"descriptor": "raw(...)#checksum", "label": "MyContract"}
```

### Export Wallet
```http
GET /export_wallet
```

## Bitcoin Core Integration

**Wallet:** `hodlandwatch`  
**Connection:** SSH tunnel to remote full node

**RPC Methods:**
- `listdescriptors()` - Get all wallet descriptors
- `getdescriptorinfo(desc)` - Validate syntax
- `deriveaddresses(desc)` - Get addresses
- `importdescriptors([...])` - Add covenant
- `scantxoutset()` - Get UTXO balances

## Security Model

### Non-Custodial
- HODLXXI **never holds private keys**
- Covenants **enforced by Bitcoin consensus**
- All balances verified against blockchain

## Code Locations

**Main implementation:** `app/app.py`
- Lines 719-1135: Descriptor extraction
- Lines 4533-4650: SAVE/CHECK classification  
- Lines 5488-5860: Explorer UI
- Lines 6555-6898: API endpoints

---

**Status:** Core feature ✅ Production-ready UI ✅ Active development
