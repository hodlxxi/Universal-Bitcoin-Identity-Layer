# Security Requirements and Best Practices

Comprehensive security guide for deploying and maintaining the HODLXXI API.

## Table of Contents
- [Security Architecture](#security-architecture)
- [Authentication Security](#authentication-security)
- [API Security](#api-security)
- [Bitcoin Wallet Security](#bitcoin-wallet-security)
- [Network Security](#network-security)
- [Data Protection](#data-protection)
- [Monitoring and Incident Response](#monitoring-and-incident-response)
- [Compliance and Audit](#compliance-and-audit)

---

## Security Architecture

### Defense in Depth

The system implements multiple layers of security:

```
┌─────────────────────────────────────────┐
│  Layer 1: Network Perimeter             │
│  - Firewall                             │
│  - DDoS Protection                      │
│  - Rate Limiting                        │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│  Layer 2: TLS/SSL Encryption            │
│  - HTTPS Only                           │
│  - TLS 1.3                              │
│  - Perfect Forward Secrecy              │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│  Layer 3: Application Authentication    │
│  - LNURL-auth                           │
│  - OAuth2/OIDC                          │
│  - Cryptographic Signatures             │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│  Layer 4: Authorization                 │
│  - Role-Based Access Control            │
│  - Permission Checks                    │
│  - Resource Isolation                   │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│  Layer 5: Data Protection               │
│  - Encryption at Rest                   │
│  - Secure Key Management                │
│  - Data Minimization                    │
└─────────────────────────────────────────┘
```

---

## Authentication Security

### 1. Cryptographic Signature Verification

**Implementation:**

```python
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import hashlib

def verify_bitcoin_signature(pubkey_hex: str, message: str, signature_hex: str) -> bool:
    """
    Verify Bitcoin message signature using ECDSA
    
    Security considerations:
    - Always verify signatures on the server side
    - Never trust client-provided verification results
    - Use constant-time comparison to prevent timing attacks
    """
    try:
        # Parse public key
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        vk = VerifyingKey.from_string(pubkey_bytes[1:], curve=SECP256k1)
        
        # Hash the message
        message_hash = hashlib.sha256(message.encode()).digest()
        
        # Verify signature
        sig_bytes = bytes.fromhex(signature_hex)
        vk.verify(sig_bytes, message_hash, hashfunc=hashlib.sha256)
        return True
    except (BadSignatureError, ValueError, Exception):
        return False
```

**Best Practices:**

1. **Challenge-Response Authentication**
   ```python
   # Generate unique challenge
   challenge = f"hodlxxi-login:{secrets.token_hex(16)}:{int(time.time())}"
   
   # Store with expiration (5 minutes)
   ACTIVE_CHALLENGES[challenge_id] = {
       'challenge': challenge,
       'expires': time.time() + 300,
       'used': False
   }
   ```

2. **Prevent Replay Attacks**
   ```python
   # Mark challenge as used
   if challenge_data['used']:
       return error("Challenge already used", 400)
   
   challenge_data['used'] = True
   ```

3. **Implement Challenge Expiration**
   ```python
   if challenge_data['expires'] < time.time():
       return error("Challenge expired", 400)
   ```

### 2. Session Management

**Secure Session Configuration:**

```python
# Production settings
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # No JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    SESSION_REFRESH_EACH_REQUEST=True
)
```

**Session Token Security:**

```python
def create_session_token(pubkey: str) -> str:
    """
    Create secure session token using JWT
    """
    payload = {
        'sub': pubkey,
        'iat': int(time.time()),
        'exp': int(time.time()) + 86400,  # 24 hours
        'jti': str(uuid.uuid4()),          # Unique token ID
        'iss': 'hodlxxi-api',              # Issuer
    }
    
    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm='HS256'
    )
```

**Token Validation:**

```python
def validate_session_token(token: str) -> Optional[dict]:
    """
    Validate and decode session token
    
    Security checks:
    - Signature verification
    - Expiration check
    - Issuer validation
    - Token revocation check
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=['HS256'],
            issuer='hodlxxi-api'
        )
        
        # Check if token is revoked
        if is_token_revoked(payload['jti']):
            return None
            
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        return None
```

### 3. Multi-Factor Authentication

**LNURL-auth Integration:**

```python
def create_lnurl_auth_challenge() -> dict:
    """
    Create LNURL-auth challenge for Lightning wallet 2FA
    """
    k1 = secrets.token_hex(32)
    session_id = f"lnauth_{secrets.token_urlsafe(16)}"
    
    # Create LNURL
    callback_url = f"{BASE_URL}/lnurl-auth/verify?session={session_id}&k1={k1}"
    lnurl = lnurl_encode(callback_url)
    
    # Store session
    LNURL_SESSIONS[session_id] = {
        'k1': k1,
        'expires': time.time() + 300,  # 5 minutes
        'authenticated': False
    }
    
    return {
        'session_id': session_id,
        'lnurl': lnurl,
        'k1': k1
    }
```

### 4. Password Security (If Implemented)

**DO NOT implement password authentication for production.** Use cryptographic signatures instead.

If password authentication is absolutely required:

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MiB
    parallelism=4,      # 4 threads
    hash_len=32,        # 32 bytes output
    salt_len=16         # 16 bytes salt
)

def hash_password(password: str) -> str:
    """Hash password using Argon2"""
    return ph.hash(password)

def verify_password(password: str, hash: str) -> bool:
    """Verify password against hash"""
    try:
        ph.verify(hash, password)
        
        # Check if hash needs rehashing
        if ph.check_needs_rehash(hash):
            new_hash = ph.hash(password)
            update_user_password_hash(new_hash)
        
        return True
    except VerifyMismatchError:
        return False
```

---

## API Security

### 1. Rate Limiting

**Implementation:**

```python
from functools import wraps
from flask import request, jsonify
import time
from collections import defaultdict

# Store: {identifier: [(timestamp, count)]}
RATE_LIMIT_STORE = defaultdict(list)

def rate_limit(max_requests: int, window_seconds: int):
    """
    Rate limiting decorator
    
    Args:
        max_requests: Maximum requests allowed
        window_seconds: Time window in seconds
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Identify client (IP + user ID if authenticated)
            identifier = request.remote_addr
            if hasattr(g, 'user_pubkey'):
                identifier = f"{identifier}:{g.user_pubkey}"
            
            now = time.time()
            window_start = now - window_seconds
            
            # Clean old entries
            RATE_LIMIT_STORE[identifier] = [
                (ts, count) for ts, count in RATE_LIMIT_STORE[identifier]
                if ts > window_start
            ]
            
            # Count requests in window
            total_requests = sum(count for _, count in RATE_LIMIT_STORE[identifier])
            
            if total_requests >= max_requests:
                retry_after = window_seconds - (now - RATE_LIMIT_STORE[identifier][0][0])
                return jsonify({
                    'ok': False,
                    'error': 'RATE_LIMIT_EXCEEDED',
                    'retry_after': int(retry_after)
                }), 429
            
            # Add current request
            RATE_LIMIT_STORE[identifier].append((now, 1))
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Usage
@app.route('/api/login')
@rate_limit(max_requests=10, window_seconds=60)
def api_login():
    pass
```

**Production Rate Limits:**

```python
RATE_LIMITS = {
    'authentication': (10, 60),      # 10 requests per minute
    'api_calls': (60, 60),           # 60 requests per minute
    'wallet_operations': (30, 60),   # 30 requests per minute
    'websocket_messages': (30, 60),  # 30 messages per minute
}
```

### 2. Input Validation

**Validate All Inputs:**

```python
from marshmallow import Schema, fields, validate, ValidationError

class SendBitcoinSchema(Schema):
    """Validate Bitcoin send request"""
    address = fields.Str(
        required=True,
        validate=validate.Length(min=26, max=90)
    )
    amount = fields.Float(
        required=True,
        validate=validate.Range(min=0.00000001, max=21000000)
    )
    fee_rate = fields.Int(
        validate=validate.Range(min=1, max=1000)
    )
    subtract_fee = fields.Bool()

def validate_bitcoin_address(address: str) -> bool:
    """
    Validate Bitcoin address format
    
    Supports: P2PKH, P2SH, Bech32, Bech32m
    """
    import re
    
    # P2PKH (1...)
    if re.match(r'^1[A-Za-z0-9]{25,34}$', address):
        return validate_base58_checksum(address)
    
    # P2SH (3...)
    if re.match(r'^3[A-Za-z0-9]{25,34}$', address):
        return validate_base58_checksum(address)
    
    # Bech32/Bech32m (bc1...)
    if address.startswith('bc1'):
        return validate_bech32(address)
    
    return False

@app.route('/api/wallet/send', methods=['POST'])
@require_auth
def api_send_bitcoin():
    """Send Bitcoin with input validation"""
    try:
        # Validate input
        schema = SendBitcoinSchema()
        data = schema.load(request.json)
        
        # Additional validation
        if not validate_bitcoin_address(data['address']):
            return jsonify({
                'ok': False,
                'error': 'INVALID_ADDRESS'
            }), 400
        
        # Process transaction
        result = send_bitcoin(**data)
        return jsonify(result)
        
    except ValidationError as e:
        return jsonify({
            'ok': False,
            'error': 'VALIDATION_ERROR',
            'details': e.messages
        }), 400
```

**Sanitize Outputs:**

```python
def sanitize_error_message(message: str) -> str:
    """
    Remove sensitive information from error messages
    """
    # Remove file paths
    message = re.sub(r'/[\w/]+\.py', '[FILE]', message)
    
    # Remove SQL
    message = re.sub(r'SQL.*?;', '[SQL]', message, flags=re.IGNORECASE)
    
    # Remove IP addresses (optional)
    message = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '[IP]', message)
    
    return message
```

### 3. CORS Configuration

**Secure CORS Setup:**

```python
from flask_cors import CORS

# Production CORS configuration
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://yourdomain.com",
            "https://app.yourdomain.com"
        ],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["X-Request-ID", "X-RateLimit-Remaining"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# DO NOT use "*" in production
# ❌ CORS(app, origins="*")
```

### 4. CSRF Protection

**Implement CSRF Tokens:**

```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# Exempt API endpoints that use Bearer tokens
csrf.exempt('/api/*')

# For cookie-based auth, require CSRF token
@app.route('/web/send-transaction', methods=['POST'])
@require_csrf
def web_send_transaction():
    pass
```

### 5. SQL Injection Prevention

**Use Parameterized Queries:**

```python
# ❌ NEVER do this
cursor.execute(f"SELECT * FROM users WHERE pubkey = '{pubkey}'")

# ✅ ALWAYS do this
cursor.execute("SELECT * FROM users WHERE pubkey = ?", (pubkey,))

# Using SQLite with parameters
def get_pof_status(pubkey: str, covenant_id: str):
    """Safely query database"""
    result = db.execute(
        "SELECT * FROM pof_attestations WHERE pubkey = ? AND covenant_id = ?",
        (pubkey, covenant_id)
    ).fetchone()
    return result
```

---

## Bitcoin Wallet Security

### 1. RPC Connection Security

**Secure RPC Configuration:**

```python
# Environment variables (never hardcode)
RPC_USER = os.getenv("RPC_USER")
RPC_PASS = os.getenv("RPC_PASSWORD")
RPC_HOST = os.getenv("RPC_HOST", "127.0.0.1")
RPC_PORT = int(os.getenv("RPC_PORT", "8332"))

# Use wallet-specific RPC
WALLET = os.getenv("RPC_WALLET", "hodlxxi")

def get_rpc_connection():
    """
    Create secure RPC connection
    
    Security notes:
    - Only connect to localhost in production
    - Use strong RPC credentials
    - Enable RPC authentication in bitcoin.conf
    """
    if RPC_HOST not in ['127.0.0.1', 'localhost']:
        logger.warning(f"RPC_HOST is not localhost: {RPC_HOST}")
    
    rpc_url = f"http://{RPC_USER}:{RPC_PASS}@{RPC_HOST}:{RPC_PORT}"
    if WALLET:
        rpc_url += f"/wallet/{WALLET}"
    
    return AuthServiceProxy(
        rpc_url,
        timeout=30
    )
```

**Bitcoin Core Configuration (`bitcoin.conf`):**

```ini
# RPC Authentication
rpcuser=your_secure_username_here
rpcpassword=your_secure_password_here_min_32_chars

# Only accept local connections
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# Disable RPC server for external connections
server=1

# Wallet settings
wallet=hodlxxi
disablewallet=0

# Security
whitelist=127.0.0.1

# Reduce attack surface
disableprivilegemode=1
```

### 2. Wallet Encryption

**Always use encrypted wallets:**

```bash
# Encrypt wallet
bitcoin-cli -rpcwallet=hodlxxi encryptwallet "your-strong-passphrase"

# Unlock for operations (limited time)
bitcoin-cli -rpcwallet=hodlxxi walletpassphrase "your-passphrase" 60
```

**In Application:**

```python
def unlock_wallet_temporary(duration: int = 60):
    """
    Temporarily unlock wallet for operations
    
    Args:
        duration: Seconds to keep wallet unlocked
    """
    rpc = get_rpc_connection()
    
    # Get passphrase from secure storage (e.g., HashiCorp Vault)
    passphrase = get_wallet_passphrase_from_vault()
    
    try:
        rpc.walletpassphrase(passphrase, duration)
        logger.info(f"Wallet unlocked for {duration} seconds")
    except Exception as e:
        logger.error(f"Failed to unlock wallet: {e}")
        raise
```

### 3. Transaction Verification

**Verify All Transaction Details:**

```python
def verify_transaction_before_broadcast(tx_hex: str, expected_outputs: list) -> bool:
    """
    Verify transaction details before broadcasting
    
    Security checks:
    - Verify outputs match expectations
    - Check fee is reasonable
    - Ensure no unexpected outputs
    """
    rpc = get_rpc_connection()
    
    # Decode transaction
    tx = rpc.decoderawtransaction(tx_hex)
    
    # Verify outputs
    for expected in expected_outputs:
        found = False
        for vout in tx['vout']:
            if (vout['value'] == expected['amount'] and 
                expected['address'] in vout['scriptPubKey'].get('addresses', [])):
                found = True
                break
        
        if not found:
            logger.error(f"Expected output not found: {expected}")
            return False
    
    # Check fee
    total_input = sum_transaction_inputs(tx)
    total_output = sum(vout['value'] for vout in tx['vout'])
    fee = total_input - total_output
    
    if fee > 0.001:  # More than 0.001 BTC fee
        logger.warning(f"High transaction fee: {fee} BTC")
        return False
    
    return True
```

### 4. Cold Storage Integration

**For High-Value Operations:**

```python
def create_psbt_for_cold_signing(recipients: list) -> str:
    """
    Create PSBT for cold wallet signing
    
    Use for:
    - Large transactions
    - Treasury management
    - Multi-signature operations
    """
    rpc = get_rpc_connection()
    
    # Create unsigned transaction
    inputs = select_utxos(recipients)
    outputs = format_outputs(recipients)
    
    # Create PSBT
    psbt = rpc.createpsbt(inputs, outputs)
    
    # Add metadata
    psbt_details = {
        'psbt': psbt,
        'inputs': inputs,
        'outputs': outputs,
        'created_at': int(time.time())
    }
    
    return psbt_details

def verify_and_broadcast_signed_psbt(signed_psbt: str) -> str:
    """
    Verify and broadcast PSBT signed by cold wallet
    """
    rpc = get_rpc_connection()
    
    # Finalize PSBT
    finalized = rpc.finalizepsbt(signed_psbt)
    
    if not finalized['complete']:
        raise ValueError("PSBT not fully signed")
    
    # Broadcast
    txid = rpc.sendrawtransaction(finalized['hex'])
    logger.info(f"Broadcasted transaction: {txid}")
    
    return txid
```

---

## Network Security

### 1. TLS/SSL Configuration

**Minimum TLS 1.2, Prefer TLS 1.3:**

```nginx
# Nginx configuration
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;
    
    # SSL certificates
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    
    # SSL protocols
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Strong ciphers
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    
    # Perfect forward secrecy
    ssl_dhparam /path/to/dhparam.pem;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # CSP
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
}
```

### 2. Firewall Configuration

**UFW (Ubuntu):**

```bash
# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (change port if needed)
ufw allow 22/tcp

# Allow HTTPS only
ufw allow 443/tcp

# Allow Bitcoin Core (localhost only)
ufw allow from 127.0.0.1 to any port 8332

# Enable firewall
ufw enable
```

**iptables:**

```bash
# Flush existing rules
iptables -F

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTPS
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Rate limit new connections
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### 3. DDoS Protection

**Nginx Rate Limiting:**

```nginx
# Define rate limit zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

server {
    # Rate limiting
    limit_req zone=api_limit burst=20 nodelay;
    limit_conn conn_limit 10;
    
    location /api/login {
        limit_req zone=auth_limit burst=5 nodelay;
    }
    
    location /oauth/token {
        limit_req zone=auth_limit burst=5 nodelay;
    }
}
```

**Cloudflare Integration:**

```python
# Verify Cloudflare requests
CLOUDFLARE_IPS = [
    '173.245.48.0/20',
    '103.21.244.0/22',
    # ... other Cloudflare IP ranges
]

@app.before_request
def verify_cloudflare():
    """Ensure requests come through Cloudflare"""
    if not is_cloudflare_ip(request.remote_addr):
        logger.warning(f"Direct access attempt from {request.remote_addr}")
        abort(403)
```

---

## Data Protection

### 1. Encryption at Rest

**Database Encryption:**

```bash
# SQLite with SQLCipher
pip install pysqlcipher3

# Usage
from pysqlcipher3 import dbapi2 as sqlite3

conn = sqlite3.connect('database.db')
conn.execute(f"PRAGMA key = '{encryption_key}'")
conn.execute("PRAGMA cipher_page_size = 4096")
conn.execute("PRAGMA kdf_iter = 256000")
```

### 2. Secrets Management

**DO NOT store secrets in code or config files.**

**Use Environment Variables (Development):**

```bash
# .env file (add to .gitignore)
FLASK_SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here
RPC_PASSWORD=your-rpc-password-here
```

**Use Secrets Manager (Production):**

```python
# AWS Secrets Manager
import boto3

def get_secret(secret_name):
    """Retrieve secret from AWS Secrets Manager"""
    client = boto3.client('secretsmanager', region_name='us-east-1')
    
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except Exception as e:
        logger.error(f"Failed to retrieve secret: {e}")
        raise

# HashiCorp Vault
import hvac

def get_secret_from_vault(path):
    """Retrieve secret from Vault"""
    client = hvac.Client(url='http://vault:8200')
    client.token = os.getenv('VAULT_TOKEN')
    
    secret = client.secrets.kv.v2.read_secret_version(path=path)
    return secret['data']['data']
```

### 3. Data Minimization

**Store Only What You Need:**

```python
# ❌ Don't store sensitive data unnecessarily
user_data = {
    'pubkey': pubkey,
    'email': email,  # Only if required
    'ip_address': ip,  # Don't store
    'user_agent': user_agent,  # Don't store
    'full_transaction_history': []  # Don't store
}

# ✅ Minimal data storage
user_data = {
    'pubkey': pubkey,
    'created_at': timestamp,
    'last_login': timestamp
}
```

### 4. Data Retention

**Implement Data Expiration:**

```python
def prune_expired_data():
    """Remove expired data automatically"""
    now = int(time.time())
    
    # Remove expired challenges
    for challenge_id in list(ACTIVE_CHALLENGES.keys()):
        if ACTIVE_CHALLENGES[challenge_id]['expires'] < now:
            del ACTIVE_CHALLENGES[challenge_id]
    
    # Remove expired PoF attestations
    db.execute("DELETE FROM pof_attestations WHERE expires_at < ?", (now,))
    
    # Remove old chat messages (30 days)
    thirty_days_ago = now - (30 * 24 * 60 * 60)
    CHAT_HISTORY[:] = [
        msg for msg in CHAT_HISTORY
        if msg['timestamp'] > thirty_days_ago
    ]
```

---

## Monitoring and Incident Response

### 1. Security Monitoring

**Log Security Events:**

```python
# Setup security logger
security_logger = logging.getLogger('security')
security_handler = RotatingFileHandler(
    'logs/security.log',
    maxBytes=10485760,
    backupCount=50
)
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s'
))
security_logger.addHandler(security_handler)

# Log authentication events
def log_authentication_attempt(pubkey, success, reason=None):
    """Log all authentication attempts"""
    security_logger.info(json.dumps({
        'event': 'authentication_attempt',
        'pubkey': pubkey,
        'success': success,
        'reason': reason,
        'ip': request.remote_addr,
        'user_agent': request.user_agent.string,
        'timestamp': time.time()
    }))

# Log suspicious activity
def log_suspicious_activity(event_type, details):
    """Log suspicious activity"""
    security_logger.warning(json.dumps({
        'event': 'suspicious_activity',
        'type': event_type,
        'details': details,
        'ip': request.remote_addr,
        'timestamp': time.time()
    }))
```

### 2. Intrusion Detection

**Detect Brute Force Attempts:**

```python
FAILED_ATTEMPTS = defaultdict(list)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes

def check_brute_force(identifier):
    """Check for brute force attempts"""
    now = time.time()
    
    # Clean old attempts
    FAILED_ATTEMPTS[identifier] = [
        timestamp for timestamp in FAILED_ATTEMPTS[identifier]
        if timestamp > now - LOCKOUT_DURATION
    ]
    
    # Check if locked out
    if len(FAILED_ATTEMPTS[identifier]) >= MAX_FAILED_ATTEMPTS:
        log_suspicious_activity('brute_force_detected', {
            'identifier': identifier,
            'attempts': len(FAILED_ATTEMPTS[identifier])
        })
        return False
    
    return True

def record_failed_attempt(identifier):
    """Record failed authentication attempt"""
    FAILED_ATTEMPTS[identifier].append(time.time())
```

### 3. Alerting

**Critical Alerts:**

```python
def send_security_alert(event_type, details):
    """Send security alerts to administrators"""
    
    alert_data = {
        'severity': 'critical',
        'event_type': event_type,
        'details': details,
        'timestamp': time.time()
    }
    
    # Send to multiple channels
    send_email_alert(alert_data)
    send_slack_alert(alert_data)
    log_alert(alert_data)

# Alert on specific events
ALERT_EVENTS = [
    'multiple_failed_authentications',
    'rpc_connection_failure',
    'wallet_unauthorized_access',
    'suspicious_transaction_attempt',
    'rate_limit_abuse'
]
```

### 4. Incident Response Plan

**When Security Incident Detected:**

1. **Immediate Actions:**
   - Isolate affected systems
   - Revoke compromised tokens
   - Block suspicious IPs
   - Enable enhanced logging

2. **Investigation:**
   - Review security logs
   - Identify attack vector
   - Assess damage
   - Document findings

3. **Recovery:**
   - Patch vulnerabilities
   - Restore from backups if needed
   - Reset credentials
   - Update security measures

4. **Post-Incident:**
   - Conduct security audit
   - Update procedures
   - Train team
   - Communicate to users if needed

---

## Compliance and Audit

### 1. Audit Logging

**Comprehensive Audit Trail:**

```python
def log_audit_event(event_type, user, action, details):
    """Log auditable events"""
    audit_logger.info(json.dumps({
        'event_type': event_type,
        'user': user,
        'action': action,
        'details': details,
        'timestamp': time.time(),
        'request_id': g.request_id
    }))

# Log all important actions
@app.after_request
def log_request(response):
    """Log all API requests"""
    if request.path.startswith('/api/'):
        log_audit_event(
            'api_request',
            getattr(g, 'user_pubkey', 'anonymous'),
            f"{request.method} {request.path}",
            {
                'status_code': response.status_code,
                'ip': request.remote_addr
            }
        )
    return response
```

### 2. Regular Security Audits

**Quarterly Security Checklist:**

- [ ] Review and update dependencies
- [ ] Scan for vulnerabilities (OWASP ZAP, Burp Suite)
- [ ] Review access logs for anomalies
- [ ] Test backup and recovery procedures
- [ ] Review and rotate secrets
- [ ] Update TLS certificates
- [ ] Audit user permissions
- [ ] Review security policies
- [ ] Test incident response plan
- [ ] Security training for team

### 3. Penetration Testing

**Annual Penetration Tests:**

```bash
# Example tools for self-assessment
# OWASP ZAP
docker run -t owasp/zap2docker-stable zap-baseline.py -t https://api.yourdomain.com

# Nikto
nikto -h https://api.yourdomain.com

# SQLMap (test for SQL injection)
sqlmap -u "https://api.yourdomain.com/api/endpoint?param=value"
```

---

## Security Checklist

### Pre-Production Checklist

- [ ] All secrets moved to environment variables or secrets manager
- [ ] TLS 1.3 enabled with strong ciphers
- [ ] Rate limiting implemented on all endpoints
- [ ] Input validation on all user inputs
- [ ] SQL injection protection (parameterized queries)
- [ ] CSRF protection enabled
- [ ] CORS properly configured (no wildcards)
- [ ] Security headers configured
- [ ] Bitcoin RPC connection secured (localhost only)
- [ ] Wallet encrypted with strong passphrase
- [ ] Firewall configured (only necessary ports open)
- [ ] DDoS protection enabled
- [ ] Logging and monitoring configured
- [ ] Incident response plan documented
- [ ] Regular backup system in place
- [ ] Security audit completed
- [ ] Penetration testing performed

### Production Monitoring

- [ ] Monitor failed authentication attempts
- [ ] Track rate limit violations
- [ ] Alert on RPC connection failures
- [ ] Monitor unusual transaction patterns
- [ ] Track API error rates
- [ ] Review security logs daily
- [ ] Update dependencies weekly
- [ ] Rotate secrets monthly
- [ ] Security audit quarterly
- [ ] Penetration test annually

---

## Security Contact

**Responsible Disclosure:**

If you discover a security vulnerability, please email:
hodlxxi@proton.me

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Your contact information

**Bug Bounty Program:** Consider implementing a bug bounty program to incentivize security researchers.
