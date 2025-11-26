# Security Configuration Guide

## Overview

This guide covers security configuration, secret management, and deployment best practices for the Universal Bitcoin Identity Layer.

## Table of Contents

1. [Secret Management](#secret-management)
2. [TLS/HTTPS Enforcement](#tlshttps-enforcement)
3. [JWKS and JWT Configuration](#jwks-and-jwt-configuration)
4. [Database Security](#database-security)
5. [Rate Limiting](#rate-limiting)
6. [Security Headers](#security-headers)
7. [Production Checklist](#production-checklist)

---

## Secret Management

### Environment Variables

**CRITICAL:** All secrets must be configured via environment variables. Never commit secrets to version control.

### Required Secrets

#### Flask Application
```bash
# Flask secret key (generate with: python -c "import secrets; print(secrets.token_hex(32))")
FLASK_SECRET_KEY=<64-character-hex-string>

# Flask environment
FLASK_ENV=production  # MUST be 'production' in production
FLASK_DEBUG=false
```

#### Bitcoin RPC
```bash
# Bitcoin Core RPC credentials
RPC_USER=<your-rpc-username>
RPC_PASSWORD=<strong-random-password>
RPC_HOST=127.0.0.1
RPC_PORT=8332
RPC_WALLET=<wallet-name>
```

#### JWT/OIDC
```bash
# JWT configuration
JWT_ALGORITHM=RS256  # MUST be RS256 (asymmetric)
JWT_ISSUER=https://your-domain.com
JWT_AUDIENCE=your-app-id
JWT_EXPIRATION_HOURS=24
```

#### Database
```bash
# PostgreSQL (production)
DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Or separate components
DB_HOST=localhost
DB_PORT=5432
DB_USER=<db-user>
DB_PASSWORD=<strong-db-password>
DB_NAME=bitcoin_identity
```

#### Redis (optional but recommended)
```bash
REDIS_URL=redis://:password@localhost:6379/0

# Or separate components
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=<strong-redis-password>
REDIS_DB=0
```

#### TLS/Security
```bash
# Force HTTPS in production
FORCE_HTTPS=true
SECURE_COOKIES=true

# TURN server credentials (for WebRTC)
TURN_HOST=turn.your-domain.com
TURN_PORT=3478
TURN_SECRET=<turn-shared-secret>
```

### Secret Generation

Generate cryptographically secure secrets:

```bash
# Flask secret key (32 bytes = 64 hex characters)
python -c "import secrets; print(secrets.token_hex(32))"

# Database password (24 characters)
python -c "import secrets; print(secrets.token_urlsafe(24))"

# Redis password (32 characters)
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Secret Storage Options

#### 1. Environment Files (.env)

**Development only:**
```bash
# .env (NEVER commit to git!)
FLASK_SECRET_KEY=abc123...
DATABASE_URL=postgresql://...
```

Add to `.gitignore`:
```
.env
.env.local
.env.production
```

#### 2. System Environment

**Production (systemd):**
```ini
# /etc/systemd/system/bitcoin-identity.service
[Service]
Environment="FLASK_SECRET_KEY=..."
Environment="DATABASE_URL=..."
EnvironmentFile=/etc/bitcoin-identity/secrets.env
```

#### 3. Container Secrets

**Docker:**
```bash
# Pass via command line
docker run -e FLASK_SECRET_KEY=... -e DATABASE_URL=... ...

# Or via env file
docker run --env-file /path/to/secrets.env ...
```

**Kubernetes:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: bitcoin-identity-secrets
type: Opaque
stringData:
  FLASK_SECRET_KEY: "..."
  DATABASE_URL: "..."
```

#### 4. Cloud Secret Managers

**AWS Secrets Manager:**
```python
import boto3
import json

def get_secret():
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId='bitcoin-identity/prod')
    return json.loads(response['SecretString'])
```

**HashiCorp Vault:**
```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=<token>

vault kv get secret/bitcoin-identity/prod
```

---

## TLS/HTTPS Enforcement

### Production Requirements

**MUST enable in production:**
```bash
FORCE_HTTPS=true
SECURE_COOKIES=true
```

### How It Works

The security middleware enforces:
- HTTPS-only connections (redirects HTTP → HTTPS)
- Secure cookie flags (httponly, secure, samesite)
- HSTS headers (HTTP Strict Transport Security)

### Nginx Reverse Proxy Configuration

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL certificates (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## JWKS and JWT Configuration

### RS256 with Key Rotation

**Key Features:**
- Asymmetric signing (RS256) for better security
- Automatic key rotation (default: 90 days)
- Graceful key retirement (maintains old keys for verification)
- Public JWKS endpoint for token verification

### Configuration

```bash
# JWKS directory for key storage
JWKS_DIR=/var/lib/bitcoin-identity/keys

# Key rotation settings
JWKS_ROTATION_DAYS=90  # Rotate primary key every 90 days
JWKS_MAX_RETIRED_KEYS=3  # Keep 3 old keys for verification
```

### Key Rotation Process

1. **Automatic Rotation:** New primary key generated after 90 days
2. **Old Keys Retained:** Up to 3 retired keys kept for verifying existing tokens
3. **JWKS Published:** All active keys (primary + retired) published at `/oauth/jwks.json`
4. **Token Signing:** Only newest key used for signing new tokens
5. **Token Verification:** Any published key can verify tokens

### Manual Key Rotation

```python
from app.jwks import rotate_keys_manually

# Trigger immediate rotation (e.g., after key compromise)
new_kid = rotate_keys_manually("/var/lib/bitcoin-identity/keys")
```

### Key Storage Security

Keys stored with restrictive permissions:
- Private keys: `600` (owner read/write only)
- JWKS document: `644` (world-readable public keys only)

---

## Database Security

### PostgreSQL Configuration

```bash
# Strong password (24+ characters)
DATABASE_URL=postgresql://btc_user:$(python -c "import secrets; print(secrets.token_urlsafe(32))")@localhost:5432/bitcoin_identity

# Connection pooling
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_TIMEOUT=30
```

### Security Best Practices

1. **Dedicated Database User:**
   ```sql
   CREATE USER btc_identity WITH PASSWORD '<strong-password>';
   CREATE DATABASE bitcoin_identity OWNER btc_identity;
   GRANT ALL PRIVILEGES ON DATABASE bitcoin_identity TO btc_identity;
   ```

2. **Connection Encryption:**
   ```bash
   DATABASE_URL=postgresql://user:pass@host:5432/db?sslmode=require
   ```

3. **Network Isolation:**
   - Bind PostgreSQL to localhost only
   - Use firewall rules to restrict access
   - Use Unix sockets when possible

4. **Backups:**
   ```bash
   # Automated encrypted backups
   pg_dump bitcoin_identity | gpg -e -r admin@example.com > backup.sql.gpg
   ```

---

## Rate Limiting

### Configuration

```bash
# Enable rate limiting
RATE_LIMIT_ENABLED=true

# Default limits
RATE_LIMIT_DEFAULT=100 per hour

# Redis backend (recommended)
REDIS_URL=redis://localhost:6379/1
```

### Per-Endpoint Limits

Configured in blueprint code:
- Authentication: `10 per minute`
- OAuth token: `30 per minute`
- RPC commands: `30 per minute`
- LNURL: `20 per minute`

### Bypass Rate Limits

```python
# For trusted internal services
from app.security import limiter

@app.route("/internal/api")
@limiter.exempt
def internal_api():
    return {"status": "ok"}
```

---

## Security Headers

Automatically applied via Flask-Talisman:

```python
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Custom headers in `factory.py`:
```python
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response
```

---

## Production Checklist

### Pre-Deployment

- [ ] All secrets generated with cryptographically secure methods
- [ ] `FLASK_ENV=production` set
- [ ] `FLASK_DEBUG=false` set
- [ ] `FORCE_HTTPS=true` enabled
- [ ] `SECURE_COOKIES=true` enabled
- [ ] Strong database password (24+ characters)
- [ ] Redis password set (if using Redis)
- [ ] TLS certificates installed (Let's Encrypt)
- [ ] JWKS directory created with proper permissions
- [ ] Rate limiting enabled with Redis backend

### Security Verification

```bash
# Test HTTPS enforcement
curl -I http://your-domain.com  # Should redirect to HTTPS

# Test security headers
curl -I https://your-domain.com
# Should include: HSTS, X-Frame-Options, CSP, etc.

# Test JWKS endpoint
curl https://your-domain.com/oauth/jwks.json
# Should return RSA public keys

# Test rate limiting
for i in {1..15}; do curl https://your-domain.com/api/rpc/getblockchaininfo; done
# Should eventually return 429 (rate limited)
```

### Monitoring

Monitor for security events:
- Failed authentication attempts
- Rate limit violations
- Invalid token usage
- Unauthorized RPC access attempts

Check audit logs:
```bash
tail -f /var/log/bitcoin-identity/audit.log | grep -E "WARN|ERROR"
```

### Incident Response

If keys are compromised:

1. **Immediate:** Rotate JWKS keys
   ```python
   from app.jwks import rotate_keys_manually
   rotate_keys_manually("/var/lib/bitcoin-identity/keys")
   ```

2. **Revoke** all active sessions
3. **Audit** access logs
4. **Update** secrets and redeploy
5. **Notify** affected users

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OAuth 2.0 Security](https://tools.ietf.org/html/rfc6819)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)
