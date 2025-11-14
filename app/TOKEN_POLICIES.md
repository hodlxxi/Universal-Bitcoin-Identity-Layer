# Token Expiration and Refresh Policies

Comprehensive guide to token lifecycle management, expiration policies, and refresh mechanisms.

## Table of Contents
- [Token Types](#token-types)
- [Expiration Policies](#expiration-policies)
- [Token Refresh Mechanisms](#token-refresh-mechanisms)
- [Security Considerations](#security-considerations)
- [Implementation Guide](#implementation-guide)
- [Token Revocation](#token-revocation)
- [Client Implementation](#client-implementation)
- [Troubleshooting](#troubleshooting)

---

## Token Types

### 1. Access Tokens (JWT)

**Purpose:** Short-lived tokens for API authentication

**Properties:**
```json
{
  "sub": "02a1b2c3d4e5f6...",      // Subject (user pubkey)
  "iat": 1698765432,                 // Issued at
  "exp": 1698769032,                 // Expires at (1 hour later)
  "jti": "550e8400-e29b-41d4-...",  // JWT ID (unique)
  "iss": "hodlxxi-api",              // Issuer
  "aud": "hodlxxi-clients",          // Audience
  "type": "access_token"
}
```

**Lifetime:** 1 hour (3600 seconds)

**Usage:**
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

### 2. Refresh Tokens

**Purpose:** Long-lived tokens to obtain new access tokens

**Properties:**
```json
{
  "sub": "02a1b2c3d4e5f6...",
  "iat": 1698765432,
  "exp": 1701357432,                 // 30 days
  "jti": "660f9511-f3ac-52e5-...",
  "iss": "hodlxxi-api",
  "type": "refresh_token",
  "family": "rf_family_abc123"       // Token family (for rotation)
}
```

**Lifetime:** 30 days (2,592,000 seconds)

**Storage:** Secure, HTTP-only cookie or secure client storage

---

### 3. Authorization Codes (OAuth2)

**Purpose:** Temporary codes for OAuth2 authorization flow

**Properties:**
```python
{
  'code': 'AUTH_CODE_abc123',
  'client_id': '550e8400-e29b-41d4-...',
  'pubkey': '02a1b2c3d4e5f6...',
  'redirect_uri': 'https://app.example.com/callback',
  'scope': 'openid profile email',
  'created_at': 1698765432,
  'expires_at': 1698766032,          # 10 minutes
  'used': False
}
```

**Lifetime:** 10 minutes (600 seconds)

**Single-use:** Code is invalidated after first use

---

### 4. Session Tokens

**Purpose:** Web session management

**Properties:**
```python
{
  'session_id': 'sess_abc123def456',
  'pubkey': '02a1b2c3d4e5f6...',
  'created_at': 1698765432,
  'expires_at': 1698851832,          # 24 hours
  'last_activity': 1698765432
}
```

**Lifetime:** 24 hours (86,400 seconds) with sliding expiration

---

### 5. LNURL-Auth Sessions

**Purpose:** Lightning wallet authentication

**Properties:**
```python
{
  'session_id': 'lnauth_abc123',
  'k1': 'challenge_hex_string',
  'created_at': 1698765432,
  'expires_at': 1698765732,          # 5 minutes
  'authenticated': False,
  'pubkey': None
}
```

**Lifetime:** 5 minutes (300 seconds)

---

### 6. Challenge Tokens

**Purpose:** Cryptographic authentication challenges

**Properties:**
```python
{
  'challenge_id': 'chal_abc123',
  'challenge': 'hodlxxi-login:abc123:1698765432',
  'created_at': 1698765432,
  'expires_at': 1698765732,          # 5 minutes
  'used': False
}
```

**Lifetime:** 5 minutes (300 seconds)

**Single-use:** Challenge is invalidated after verification

---

## Expiration Policies

### Token Lifetime Matrix

| Token Type | Default Lifetime | Maximum Lifetime | Sliding Window | Single-Use |
|-----------|-----------------|-----------------|----------------|-----------|
| Access Token | 1 hour | 2 hours | No | No |
| Refresh Token | 30 days | 90 days | No | Yes* |
| Authorization Code | 10 minutes | 10 minutes | No | Yes |
| Session Token | 24 hours | 7 days | Yes | No |
| LNURL-Auth Session | 5 minutes | 5 minutes | No | Yes |
| Challenge Token | 5 minutes | 5 minutes | No | Yes |

*Refresh tokens are single-use with token rotation

---

### 1. Access Token Expiration

**Policy:**
- Default lifetime: 1 hour
- No extension mechanism
- Must be refreshed using refresh token
- Immediate revocation on logout

**Implementation:**

```python
def create_access_token(pubkey: str, expires_in: int = 3600) -> str:
    """
    Create access token with expiration
    
    Args:
        pubkey: User's public key
        expires_in: Seconds until expiration (default 1 hour)
    
    Returns:
        JWT access token
    """
    now = int(time.time())
    
    payload = {
        'sub': pubkey,
        'iat': now,
        'exp': now + expires_in,
        'jti': str(uuid.uuid4()),
        'iss': OAUTH_ISSUER,
        'aud': 'hodlxxi-clients',
        'type': 'access_token'
    }
    
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def validate_access_token(token: str) -> Optional[dict]:
    """
    Validate access token
    
    Returns:
        Token payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=['HS256'],
            audience='hodlxxi-clients',
            issuer=OAUTH_ISSUER
        )
        
        # Check token type
        if payload.get('type') != 'access_token':
            logger.warning(f"Invalid token type: {payload.get('type')}")
            return None
        
        # Check if revoked
        if is_token_revoked(payload['jti']):
            logger.info(f"Token revoked: {payload['jti']}")
            return None
        
        return payload
        
    except jwt.ExpiredSignatureError:
        logger.info("Access token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid access token: {e}")
        return None
```

---

### 2. Refresh Token Expiration

**Policy:**
- Default lifetime: 30 days
- Single-use with automatic rotation
- Family-based revocation for security
- Can be revoked manually

**Token Family System:**

Each refresh token belongs to a family. If any token in the family is reused (indicating theft), the entire family is revoked.

```python
# Token family storage
REFRESH_TOKEN_FAMILIES = {}  # family_id -> {tokens: set(), pubkey: str}

def create_refresh_token(pubkey: str, family_id: str = None) -> str:
    """
    Create refresh token with family tracking
    
    Args:
        pubkey: User's public key
        family_id: Existing family ID or None for new family
    """
    now = int(time.time())
    
    # Create new family if needed
    if not family_id:
        family_id = f"rf_family_{secrets.token_hex(16)}"
        REFRESH_TOKEN_FAMILIES[family_id] = {
            'tokens': set(),
            'pubkey': pubkey,
            'created_at': now
        }
    
    payload = {
        'sub': pubkey,
        'iat': now,
        'exp': now + (30 * 24 * 60 * 60),  # 30 days
        'jti': str(uuid.uuid4()),
        'iss': OAUTH_ISSUER,
        'type': 'refresh_token',
        'family': family_id
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
    
    # Track token in family
    REFRESH_TOKEN_FAMILIES[family_id]['tokens'].add(payload['jti'])
    
    return token

def use_refresh_token(token: str) -> dict:
    """
    Use refresh token and issue new tokens
    
    Returns:
        New access and refresh tokens
    
    Raises:
        TokenError: If token is invalid or reused
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=['HS256'],
            issuer=OAUTH_ISSUER
        )
        
        # Verify token type
        if payload.get('type') != 'refresh_token':
            raise TokenError("Invalid token type")
        
        jti = payload['jti']
        family_id = payload['family']
        pubkey = payload['sub']
        
        # Check if token is in family
        family = REFRESH_TOKEN_FAMILIES.get(family_id)
        if not family or jti not in family['tokens']:
            # Token reuse detected - revoke entire family
            logger.error(f"Refresh token reuse detected for family {family_id}")
            revoke_token_family(family_id)
            raise TokenError("Token reuse detected - family revoked")
        
        # Remove used token from family
        family['tokens'].discard(jti)
        
        # Create new tokens
        new_access_token = create_access_token(pubkey)
        new_refresh_token = create_refresh_token(pubkey, family_id)
        
        return {
            'access_token': new_access_token,
            'refresh_token': new_refresh_token,
            'expires_in': 3600,
            'token_type': 'Bearer'
        }
        
    except jwt.ExpiredSignatureError:
        raise TokenError("Refresh token expired")
    except jwt.InvalidTokenError as e:
        raise TokenError(f"Invalid refresh token: {e}")

def revoke_token_family(family_id: str):
    """Revoke all tokens in a family"""
    if family_id in REFRESH_TOKEN_FAMILIES:
        # Add all tokens to revocation list
        for jti in REFRESH_TOKEN_FAMILIES[family_id]['tokens']:
            REVOKED_TOKENS.add(jti)
        
        # Remove family
        del REFRESH_TOKEN_FAMILIES[family_id]
        
        logger.info(f"Revoked token family: {family_id}")
```

---

### 3. Session Token Expiration (Sliding Window)

**Policy:**
- Initial lifetime: 24 hours
- Extends on each request (sliding window)
- Maximum lifetime: 7 days
- Automatically expires after inactivity

```python
def create_session(pubkey: str) -> str:
    """Create new session"""
    session_id = f"sess_{secrets.token_urlsafe(32)}"
    now = int(time.time())
    
    SESSIONS[session_id] = {
        'pubkey': pubkey,
        'created_at': now,
        'last_activity': now,
        'expires_at': now + (24 * 60 * 60),  # 24 hours
        'absolute_expiry': now + (7 * 24 * 60 * 60)  # 7 days max
    }
    
    return session_id

def validate_and_refresh_session(session_id: str) -> bool:
    """
    Validate session and extend if active
    
    Returns:
        True if valid, False otherwise
    """
    session = SESSIONS.get(session_id)
    if not session:
        return False
    
    now = int(time.time())
    
    # Check absolute expiration
    if now > session['absolute_expiry']:
        logger.info(f"Session {session_id} reached absolute expiry")
        del SESSIONS[session_id]
        return False
    
    # Check sliding expiration
    if now > session['expires_at']:
        logger.info(f"Session {session_id} expired due to inactivity")
        del SESSIONS[session_id]
        return False
    
    # Extend session (sliding window)
    session['last_activity'] = now
    session['expires_at'] = min(
        now + (24 * 60 * 60),  # +24 hours
        session['absolute_expiry']  # But not beyond absolute limit
    )
    
    return True
```

---

### 4. Authorization Code Expiration

**Policy:**
- Lifetime: 10 minutes
- Single-use only
- Immediately invalidated after exchange

```python
def create_authorization_code(client_id: str, pubkey: str, redirect_uri: str, scope: str) -> str:
    """Create OAuth2 authorization code"""
    code = f"AUTH_{secrets.token_urlsafe(32)}"
    now = int(time.time())
    
    AUTHORIZATION_CODES[code] = {
        'client_id': client_id,
        'pubkey': pubkey,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'created_at': now,
        'expires_at': now + 600,  # 10 minutes
        'used': False
    }
    
    return code

def exchange_authorization_code(code: str, client_id: str, redirect_uri: str) -> dict:
    """
    Exchange authorization code for tokens
    
    Raises:
        OAuthError: If code is invalid, expired, or already used
    """
    code_data = AUTHORIZATION_CODES.get(code)
    
    if not code_data:
        raise OAuthError("invalid_grant", "Authorization code not found")
    
    # Check expiration
    if time.time() > code_data['expires_at']:
        del AUTHORIZATION_CODES[code]
        raise OAuthError("invalid_grant", "Authorization code expired")
    
    # Check if already used
    if code_data['used']:
        logger.error(f"Authorization code reuse attempt: {code}")
        # Revoke all tokens for this user as precaution
        revoke_user_tokens(code_data['pubkey'])
        raise OAuthError("invalid_grant", "Authorization code already used")
    
    # Verify client and redirect URI
    if code_data['client_id'] != client_id:
        raise OAuthError("invalid_grant", "Client ID mismatch")
    
    if code_data['redirect_uri'] != redirect_uri:
        raise OAuthError("invalid_grant", "Redirect URI mismatch")
    
    # Mark as used
    code_data['used'] = True
    
    # Create tokens
    access_token = create_access_token(code_data['pubkey'])
    refresh_token = create_refresh_token(code_data['pubkey'])
    id_token = create_id_token(code_data['pubkey'])
    
    # Clean up code after short delay (prevent timing attacks)
    threading.Timer(5, lambda: AUTHORIZATION_CODES.pop(code, None)).start()
    
    return {
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': 3600,
        'refresh_token': refresh_token,
        'id_token': id_token,
        'scope': code_data['scope']
    }
```

---

## Token Refresh Mechanisms

### 1. Automatic Access Token Refresh

**Client-Side Implementation:**

```javascript
class TokenManager {
  constructor() {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiry = null;
    this.refreshTimer = null;
  }
  
  setTokens(accessToken, refreshToken, expiresIn) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.tokenExpiry = Date.now() + (expiresIn * 1000);
    
    // Schedule refresh 5 minutes before expiry
    const refreshIn = (expiresIn - 300) * 1000;
    this.scheduleRefresh(refreshIn);
  }
  
  scheduleRefresh(delay) {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    
    this.refreshTimer = setTimeout(() => {
      this.refreshAccessToken();
    }, delay);
  }
  
  async refreshAccessToken() {
    try {
      const response = await fetch('/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'refresh_token',
          refresh_token: this.refreshToken,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET
        })
      });
      
      if (!response.ok) {
        throw new Error('Token refresh failed');
      }
      
      const data = await response.json();
      this.setTokens(data.access_token, data.refresh_token, data.expires_in);
      
      console.log('Access token refreshed');
      
    } catch (error) {
      console.error('Token refresh error:', error);
      // Redirect to login
      window.location.href = '/login';
    }
  }
  
  async apiRequest(url, options = {}) {
    // Check if token needs refresh
    if (Date.now() >= this.tokenExpiry - 60000) {  // Refresh if < 1 min left
      await this.refreshAccessToken();
    }
    
    // Add authorization header
    options.headers = {
      ...options.headers,
      'Authorization': `Bearer ${this.accessToken}`
    };
    
    const response = await fetch(url, options);
    
    // Handle 401 by refreshing token and retrying
    if (response.status === 401) {
      await this.refreshAccessToken();
      
      // Retry request with new token
      options.headers['Authorization'] = `Bearer ${this.accessToken}`;
      return fetch(url, options);
    }
    
    return response;
  }
}

// Usage
const tokenManager = new TokenManager();

// After login
const loginResponse = await fetch('/oauth/token', { /* ... */ });
const tokens = await loginResponse.json();
tokenManager.setTokens(tokens.access_token, tokens.refresh_token, tokens.expires_in);

// Make API requests
const data = await tokenManager.apiRequest('/api/wallet/balance');
```

---

### 2. Refresh Token Rotation

**Security Feature:** Each refresh prevents token reuse attacks

```python
@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    """OAuth2 token endpoint with refresh token rotation"""
    data = request.json
    grant_type = data.get('grant_type')
    
    if grant_type == 'refresh_token':
        refresh_token = data.get('refresh_token')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        
        # Verify client
        client = verify_client_credentials(client_id, client_secret)
        if not client:
            return jsonify({
                'error': 'invalid_client',
                'error_description': 'Invalid client credentials'
            }), 401
        
        try:
            # Use refresh token (rotates automatically)
            tokens = use_refresh_token(refresh_token)
            
            return jsonify(tokens), 200
            
        except TokenError as e:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': str(e)
            }), 400
    
    # ... other grant types
```

---

### 3. Silent Token Refresh

**For Single-Page Applications:**

```javascript
// Using hidden iframe for silent refresh
class SilentTokenRefresh {
  constructor(clientId, redirectUri) {
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.iframe = null;
  }
  
  async refreshTokenSilently() {
    return new Promise((resolve, reject) => {
      // Create hidden iframe
      this.iframe = document.createElement('iframe');
      this.iframe.style.display = 'none';
      
      // Build authorization URL with prompt=none
      const url = new URL('/oauth/authorize', window.location.origin);
      url.searchParams.append('response_type', 'code');
      url.searchParams.append('client_id', this.clientId);
      url.searchParams.append('redirect_uri', this.redirectUri);
      url.searchParams.append('prompt', 'none');
      url.searchParams.append('scope', 'openid profile email');
      
      // Handle response
      const messageHandler = (event) => {
        if (event.origin !== window.location.origin) return;
        
        window.removeEventListener('message', messageHandler);
        document.body.removeChild(this.iframe);
        
        if (event.data.error) {
          reject(new Error(event.data.error));
        } else {
          resolve(event.data.tokens);
        }
      };
      
      window.addEventListener('message', messageHandler);
      
      // Load iframe
      this.iframe.src = url.toString();
      document.body.appendChild(this.iframe);
      
      // Timeout after 10 seconds
      setTimeout(() => {
        window.removeEventListener('message', messageHandler);
        if (this.iframe && this.iframe.parentNode) {
          document.body.removeChild(this.iframe);
        }
        reject(new Error('Silent refresh timeout'));
      }, 10000);
    });
  }
}

// Usage
const silentRefresh = new SilentTokenRefresh(CLIENT_ID, REDIRECT_URI);

try {
  const tokens = await silentRefresh.refreshTokenSilently();
  tokenManager.setTokens(tokens.access_token, tokens.refresh_token, tokens.expires_in);
} catch (error) {
  console.error('Silent refresh failed:', error);
  // Redirect to login
  window.location.href = '/login';
}
```

---

## Token Revocation

### 1. Manual Revocation

```python
# Revoked tokens storage (use Redis in production)
REVOKED_TOKENS = set()

def revoke_token(jti: str):
    """
    Revoke a specific token
    
    Args:
        jti: JWT ID to revoke
    """
    REVOKED_TOKENS.add(jti)
    logger.info(f"Token revoked: {jti}")

def is_token_revoked(jti: str) -> bool:
    """Check if token is revoked"""
    return jti in REVOKED_TOKENS

@app.route('/api/logout', methods=['POST'])
@require_auth
def api_logout():
    """Logout and revoke current token"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=['HS256'],
            options={'verify_exp': False}  # Decode even if expired
        )
        
        # Revoke access token
        revoke_token(payload['jti'])
        
        # Revoke associated refresh token family
        if 'family' in payload:
            revoke_token_family(payload['family'])
        
        return jsonify({'ok': True, 'message': 'Logged out successfully'}), 200
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'ok': False, 'error': 'Logout failed'}), 500
```

### 2. Bulk Revocation

```python
def revoke_user_tokens(pubkey: str):
    """
    Revoke all tokens for a specific user
    
    Use cases:
    - User password change
    - Security breach
    - Account suspension
    """
    # Revoke all refresh token families for user
    families_to_revoke = [
        family_id for family_id, data in REFRESH_TOKEN_FAMILIES.items()
        if data['pubkey'] == pubkey
    ]
    
    for family_id in families_to_revoke:
        revoke_token_family(family_id)
    
    logger.info(f"Revoked all tokens for user: {pubkey}")

def revoke_client_tokens(client_id: str):
    """
    Revoke all tokens for a specific OAuth client
    
    Use cases:
    - Client compromised
    - Client revoked
    """
    # Implementation depends on your token storage
    pass
```

### 3. Automatic Revocation

```python
# Cleanup expired tokens periodically
def cleanup_expired_tokens():
    """Remove expired tokens from storage"""
    now = int(time.time())
    
    # Clean authorization codes
    expired_codes = [
        code for code, data in AUTHORIZATION_CODES.items()
        if data['expires_at'] < now
    ]
    for code in expired_codes:
        del AUTHORIZATION_CODES[code]
    
    # Clean sessions
    expired_sessions = [
        sid for sid, session in SESSIONS.items()
        if session['absolute_expiry'] < now
    ]
    for sid in expired_sessions:
        del SESSIONS[sid]
    
    # Clean token families
    expired_families = [
        family_id for family_id, data in REFRESH_TOKEN_FAMILIES.items()
        if data.get('created_at', 0) + (90 * 24 * 60 * 60) < now  # 90 days
    ]
    for family_id in expired_families:
        del REFRESH_TOKEN_FAMILIES[family_id]
    
    logger.info(f"Cleaned up {len(expired_codes)} codes, {len(expired_sessions)} sessions, {len(expired_families)} families")

# Schedule cleanup every hour
import schedule
schedule.every().hour.do(cleanup_expired_tokens)
```

---

## Security Considerations

### 1. Token Storage Security

**Client-Side Storage Options:**

| Storage | Security | Pros | Cons |
|---------|----------|------|------|
| localStorage | Low | Easy to use | Vulnerable to XSS |
| sessionStorage | Low | Clears on tab close | Vulnerable to XSS |
| Memory | High | Safe from XSS | Lost on refresh |
| HTTP-only Cookie | High | Protected from XSS | Vulnerable to CSRF |
| Secure Cookie | Highest | Protected from XSS & CSRF | Requires HTTPS |

**Recommendation:** Use HTTP-only, Secure cookies for refresh tokens, memory for access tokens.

```javascript
// Store access token in memory
class SecureTokenStorage {
  constructor() {
    this.accessToken = null;
  }
  
  setAccessToken(token) {
    this.accessToken = token;
  }
  
  getAccessToken() {
    return this.accessToken;
  }
  
  clear() {
    this.accessToken = null;
  }
}

// Refresh token stored in HTTP-only cookie (server-side)
@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    # ... token creation ...
    
    response = jsonify({
        'access_token': access_token,
        'expires_in': 3600,
        'token_type': 'Bearer'
    })
    
    # Set refresh token in HTTP-only cookie
    response.set_cookie(
        'refresh_token',
        refresh_token,
        httponly=True,
        secure=True,
        samesite='Strict',
        max_age=30*24*60*60  # 30 days
    )
    
    return response
```

### 2. Token Leakage Prevention

**Never log tokens:**

```python
# ❌ BAD - Logs contain tokens
logger.info(f"User authenticated with token: {access_token}")

# ✅ GOOD - Only log token metadata
logger.info(f"User authenticated with token ID: {payload['jti']}")
```

**Redact tokens in error messages:**

```python
def redact_sensitive_data(text: str) -> str:
    """Remove tokens from text"""
    # Redact JWT tokens
    text = re.sub(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', '[REDACTED_TOKEN]', text)
    return text

@app.errorhandler(Exception)
def handle_error(error):
    error_message = redact_sensitive_data(str(error))
    return jsonify({'error': error_message}), 500
```

### 3. Token Binding

**Bind tokens to client:**

```python
def create_bound_access_token(pubkey: str, client_fingerprint: str) -> str:
    """
    Create access token bound to client fingerprint
    
    Client fingerprint can include:
    - User agent
    - IP address (be careful with proxies)
    - TLS session ID
    """
    payload = {
        'sub': pubkey,
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600,
        'jti': str(uuid.uuid4()),
        'cnf': {
            'fingerprint': hashlib.sha256(client_fingerprint.encode()).hexdigest()
        }
    }
    
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def validate_bound_token(token: str, client_fingerprint: str) -> bool:
    """Validate token binding"""
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
    
    expected_fingerprint = hashlib.sha256(client_fingerprint.encode()).hexdigest()
    actual_fingerprint = payload.get('cnf', {}).get('fingerprint')
    
    return expected_fingerprint == actual_fingerprint
```

---

## Client Implementation

### Complete Example: React Token Management

```javascript
// tokenService.js
class TokenService {
  constructor() {
    this.accessToken = null;
    this.tokenExpiry = null;
    this.refreshTimer = null;
    
    // Try to restore session on init
    this.restoreSession();
  }
  
  async restoreSession() {
    try {
      // Check if refresh token cookie exists by trying to refresh
      const response = await fetch('/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'refresh_token',
          client_id: process.env.REACT_APP_CLIENT_ID
        }),
        credentials: 'include'  // Include cookies
      });
      
      if (response.ok) {
        const data = await response.json();
        this.setTokens(data.access_token, data.expires_in);
        return true;
      }
    } catch (error) {
      console.log('No active session');
    }
    return false;
  }
  
  setTokens(accessToken, expiresIn) {
    this.accessToken = accessToken;
    this.tokenExpiry = Date.now() + (expiresIn * 1000);
    
    // Schedule refresh 5 minutes before expiry
    const refreshIn = Math.max((expiresIn - 300) * 1000, 0);
    this.scheduleRefresh(refreshIn);
  }
  
  scheduleRefresh(delay) {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    
    this.refreshTimer = setTimeout(async () => {
      await this.refreshToken();
    }, delay);
  }
  
  async refreshToken() {
    try {
      const response = await fetch('/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'refresh_token',
          client_id: process.env.REACT_APP_CLIENT_ID
        }),
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error('Refresh failed');
      }
      
      const data = await response.json();
      this.setTokens(data.access_token, data.expires_in);
      
      console.log('Token refreshed successfully');
      
    } catch (error) {
      console.error('Token refresh error:', error);
      this.clearTokens();
      window.location.href = '/login';
    }
  }
  
  async apiRequest(url, options = {}) {
    // Check token expiry
    if (!this.accessToken || Date.now() >= this.tokenExpiry - 60000) {
      await this.refreshToken();
    }
    
    // Add authorization header
    options.headers = {
      ...options.headers,
      'Authorization': `Bearer ${this.accessToken}`
    };
    
    const response = await fetch(url, options);
    
    // Handle 401 with retry
    if (response.status === 401) {
      await this.refreshToken();
      options.headers['Authorization'] = `Bearer ${this.accessToken}`;
      return fetch(url, options);
    }
    
    return response;
  }
  
  async logout() {
    try {
      await this.apiRequest('/api/logout', { method: 'POST' });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      this.clearTokens();
      window.location.href = '/login';
    }
  }
  
  clearTokens() {
    this.accessToken = null;
    this.tokenExpiry = null;
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }
  
  isAuthenticated() {
    return this.accessToken && Date.now() < this.tokenExpiry;
  }
}

export default new TokenService();
```

---

## Troubleshooting

### Common Issues

#### 1. Token Expired Error

**Symptom:** Receiving 401 errors with "EXPIRED_TOKEN"

**Causes:**
- Token refresh not implemented
- Clock skew between client and server
- Refresh token also expired

**Solutions:**
```javascript
// Implement automatic refresh
if (error.error_code === 2003) {  // EXPIRED_TOKEN
  await tokenService.refreshToken();
  return retry(originalRequest);
}

// Handle clock skew
const payload = jwt.decode(token, { complete: true });
const now = Math.floor(Date.now() / 1000);
const skew = payload.payload.iat - now;
if (Math.abs(skew) > 60) {
  console.warn(`Clock skew detected: ${skew} seconds`);
}
```

#### 2. Token Reuse Detection

**Symptom:** All tokens revoked unexpectedly

**Cause:** Refresh token used multiple times

**Prevention:**
```javascript
// Ensure only one refresh happens at a time
class TokenService {
  constructor() {
    this.refreshPromise = null;
  }
  
  async refreshToken() {
    // Return existing refresh promise if already refreshing
    if (this.refreshPromise) {
      return this.refreshPromise;
    }
    
    this.refreshPromise = this._doRefresh();
    
    try {
      await this.refreshPromise;
    } finally {
      this.refreshPromise = null;
    }
  }
  
  async _doRefresh() {
    // Actual refresh implementation
  }
}
```

#### 3. Silent Refresh Fails

**Symptom:** User logged out unexpectedly

**Causes:**
- Third-party cookie blocking
- CORS issues
- Session expired

**Solutions:**
```javascript
// Fallback to regular refresh if silent fails
try {
  await silentRefresh();
} catch (error) {
  console.warn('Silent refresh failed, trying regular refresh');
  try {
    await regularRefresh();
  } catch (error) {
    // Redirect to login
    window.location.href = '/login';
  }
}
```

---

## Production Checklist

- [ ] Access token lifetime: 1 hour
- [ ] Refresh token lifetime: 30 days
- [ ] Refresh token rotation enabled
- [ ] Token family tracking implemented
- [ ] Automatic token refresh before expiry
- [ ] Token revocation on logout
- [ ] Bulk revocation capability
- [ ] Periodic cleanup of expired tokens
- [ ] Tokens stored securely (HTTP-only cookies for refresh)
- [ ] Token binding implemented
- [ ] Rate limiting on token endpoints
- [ ] Token leakage prevention (no logging)
- [ ] Clock skew handling
- [ ] Proper error handling for token errors
- [ ] Session monitoring and alerting
- [ ] Documentation for developers

