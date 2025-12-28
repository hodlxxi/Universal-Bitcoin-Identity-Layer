# Error Code Documentation

Complete reference for all error codes, their meanings, and how to handle them.

## Table of Contents
- [HTTP Status Codes](#http-status-codes)
- [Application Error Codes](#application-error-codes)
- [Authentication Errors](#authentication-errors)
- [OAuth2/OIDC Errors](#oauth2oidc-errors)
- [Bitcoin/Wallet Errors](#bitcoinwallet-errors)
- [WebSocket Errors](#websocket-errors)
- [Proof of Funds Errors](#proof-of-funds-errors)
- [Error Response Format](#error-response-format)
- [Error Handling Best Practices](#error-handling-best-practices)

---

## HTTP Status Codes

### Success Codes (2xx)

| Code | Status | Description |
|------|--------|-------------|
| 200 | OK | Request succeeded |
| 201 | Created | Resource created successfully |
| 202 | Accepted | Request accepted for processing |
| 204 | No Content | Request succeeded, no content to return |

### Client Error Codes (4xx)

| Code | Status | Description |
|------|--------|-------------|
| 400 | Bad Request | Invalid request syntax or parameters |
| 401 | Unauthorized | Authentication required or failed |
| 403 | Forbidden | Authenticated but insufficient permissions |
| 404 | Not Found | Resource does not exist |
| 405 | Method Not Allowed | HTTP method not supported for this endpoint |
| 409 | Conflict | Request conflicts with current state |
| 413 | Payload Too Large | Request body exceeds size limit |
| 422 | Unprocessable Entity | Validation failed |
| 429 | Too Many Requests | Rate limit exceeded |

### Server Error Codes (5xx)

| Code | Status | Description |
|------|--------|-------------|
| 500 | Internal Server Error | Unexpected server error |
| 502 | Bad Gateway | Invalid response from upstream server |
| 503 | Service Unavailable | Service temporarily unavailable |
| 504 | Gateway Timeout | Upstream server timeout |

---

## Application Error Codes

### General Errors (1000-1099)

| Code | Error Name | Description | HTTP Status |
|------|-----------|-------------|-------------|
| 1000 | UNKNOWN_ERROR | Unexpected error occurred | 500 |
| 1001 | INVALID_REQUEST | Request format is invalid | 400 |
| 1002 | MISSING_PARAMETER | Required parameter is missing | 400 |
| 1003 | INVALID_PARAMETER | Parameter value is invalid | 400 |
| 1004 | RESOURCE_NOT_FOUND | Requested resource not found | 404 |
| 1005 | METHOD_NOT_ALLOWED | HTTP method not allowed | 405 |
| 1006 | RATE_LIMIT_EXCEEDED | Too many requests | 429 |
| 1007 | SERVICE_UNAVAILABLE | Service temporarily unavailable | 503 |
| 1008 | MAINTENANCE_MODE | System under maintenance | 503 |

**Example Response:**
```json
{
  "ok": false,
  "error": "MISSING_PARAMETER",
  "error_code": 1002,
  "message": "Required parameter 'pubkey' is missing",
  "details": {
    "missing_fields": ["pubkey"]
  }
}
```

---

## Authentication Errors (2000-2099)

| Code | Error Name | Description | HTTP Status |
|------|-----------|-------------|-------------|
| 2000 | AUTH_REQUIRED | Authentication required | 401 |
| 2001 | INVALID_CREDENTIALS | Invalid username or password | 401 |
| 2002 | INVALID_TOKEN | Access token is invalid | 401 |
| 2003 | EXPIRED_TOKEN | Access token has expired | 401 |
| 2004 | INVALID_SIGNATURE | Cryptographic signature invalid | 401 |
| 2005 | INVALID_CHALLENGE | Challenge string is invalid | 400 |
| 2006 | EXPIRED_CHALLENGE | Challenge has expired | 400 |
| 2007 | CHALLENGE_ALREADY_USED | Challenge already used | 400 |
| 2008 | SESSION_EXPIRED | User session has expired | 401 |
| 2009 | INVALID_PUBKEY | Public key format is invalid | 400 |
| 2010 | PUBKEY_NOT_FOUND | Public key not registered | 404 |
| 2011 | INSUFFICIENT_PERMISSIONS | User lacks required permissions | 403 |
| 2012 | ACCOUNT_DISABLED | User account is disabled | 403 |
| 2013 | ACCOUNT_LOCKED | Account temporarily locked | 403 |
| 2014 | TOO_MANY_LOGIN_ATTEMPTS | Too many failed login attempts | 429 |

**Example Responses:**

```json
// Expired token
{
  "ok": false,
  "error": "EXPIRED_TOKEN",
  "error_code": 2003,
  "message": "Access token expired at 2024-10-29T15:30:00Z",
  "details": {
    "expired_at": 1698765000,
    "current_time": 1698765432
  }
}
```

```json
// Invalid signature
{
  "ok": false,
  "error": "INVALID_SIGNATURE",
  "error_code": 2004,
  "message": "Signature verification failed",
  "details": {
    "pubkey": "02a1b2c3...",
    "challenge": "hodlxxi-login:abc123:1698765432"
  }
}
```

```json
// Rate limited
{
  "ok": false,
  "error": "TOO_MANY_LOGIN_ATTEMPTS",
  "error_code": 2014,
  "message": "Too many failed login attempts. Please try again later.",
  "details": {
    "retry_after": 300,
    "attempts": 5,
    "lockout_until": 1698765732
  }
}
```

---

## OAuth2/OIDC Errors (3000-3099)

### OAuth2 Standard Errors

| Error | Description | HTTP Status |
|-------|-------------|-------------|
| invalid_request | Request is missing required parameter | 400 |
| invalid_client | Client authentication failed | 401 |
| invalid_grant | Authorization grant is invalid | 400 |
| unauthorized_client | Client not authorized for this grant type | 400 |
| unsupported_grant_type | Grant type not supported | 400 |
| invalid_scope | Requested scope is invalid | 400 |
| access_denied | User denied authorization | 403 |
| server_error | Server encountered error | 500 |
| temporarily_unavailable | Server temporarily unavailable | 503 |

### Custom OAuth Errors

| Code | Error Name | Description | HTTP Status |
|------|-----------|-------------|-------------|
| 3000 | OAUTH_INVALID_CLIENT_ID | Client ID not found | 404 |
| 3001 | OAUTH_INVALID_CLIENT_SECRET | Client secret is incorrect | 401 |
| 3002 | OAUTH_INVALID_REDIRECT_URI | Redirect URI not registered | 400 |
| 3003 | OAUTH_INVALID_CODE | Authorization code invalid | 400 |
| 3004 | OAUTH_EXPIRED_CODE | Authorization code expired | 400 |
| 3005 | OAUTH_CODE_ALREADY_USED | Authorization code already used | 400 |
| 3006 | OAUTH_INVALID_REFRESH_TOKEN | Refresh token is invalid | 400 |
| 3007 | OAUTH_EXPIRED_REFRESH_TOKEN | Refresh token has expired | 400 |
| 3008 | OAUTH_INVALID_STATE | State parameter mismatch | 400 |
| 3009 | OAUTH_CLIENT_NOT_APPROVED | Client not approved by user | 403 |
| 3010 | OAUTH_SCOPE_NOT_ALLOWED | Requested scope not allowed | 403 |

**Example Responses:**

```json
// OAuth2 standard error
{
  "error": "invalid_grant",
  "error_description": "Authorization code has expired",
  "error_uri": "https://yourdomain.com/docs/errors#invalid_grant"
}
```

```json
// Custom OAuth error
{
  "ok": false,
  "error": "OAUTH_EXPIRED_CODE",
  "error_code": 3004,
  "message": "Authorization code expired after 10 minutes",
  "details": {
    "code_issued_at": 1698765000,
    "code_expired_at": 1698765600,
    "current_time": 1698765650
  }
}
```

---

## Bitcoin/Wallet Errors (4000-4099)

| Code | Error Name | Description | HTTP Status |
|------|-----------|-------------|-------------|
| 4000 | RPC_CONNECTION_ERROR | Cannot connect to Bitcoin RPC | 503 |
| 4001 | RPC_AUTHENTICATION_ERROR | RPC authentication failed | 500 |
| 4002 | RPC_TIMEOUT | RPC request timed out | 504 |
| 4003 | WALLET_NOT_FOUND | Bitcoin wallet not found | 404 |
| 4004 | WALLET_LOCKED | Wallet is locked | 403 |
| 4005 | INSUFFICIENT_FUNDS | Wallet has insufficient funds | 400 |
| 4006 | INVALID_ADDRESS | Bitcoin address is invalid | 400 |
| 4007 | INVALID_AMOUNT | Transaction amount is invalid | 400 |
| 4008 | AMOUNT_TOO_SMALL | Amount below dust threshold | 400 |
| 4009 | FEE_TOO_LOW | Transaction fee too low | 400 |
| 4010 | TRANSACTION_REJECTED | Transaction rejected by network | 400 |
| 4011 | TRANSACTION_NOT_FOUND | Transaction not found | 404 |
| 4012 | UTXO_NOT_FOUND | UTXO not found or spent | 404 |
| 4013 | INVALID_PSBT | PSBT format is invalid | 400 |
| 4014 | PSBT_DECODE_ERROR | Cannot decode PSBT | 400 |
| 4015 | PSBT_TOO_LARGE | PSBT exceeds size limit | 413 |
| 4016 | INVALID_SIGNATURE_COUNT | Invalid number of signatures | 400 |
| 4017 | MEMPOOL_FULL | Mempool is full | 503 |
| 4018 | DOUBLE_SPEND_DETECTED | Transaction is double-spend | 400 |

**Example Responses:**

```json
// Insufficient funds
{
  "ok": false,
  "error": "INSUFFICIENT_FUNDS",
  "error_code": 4005,
  "message": "Wallet has insufficient funds for this transaction",
  "details": {
    "required_btc": 0.01001500,
    "available_btc": 0.005,
    "required_sat": 1001500,
    "available_sat": 500000,
    "shortfall_btc": 0.00501500,
    "shortfall_sat": 501500
  }
}
```

```json
// Invalid address
{
  "ok": false,
  "error": "INVALID_ADDRESS",
  "error_code": 4006,
  "message": "Invalid Bitcoin address format",
  "details": {
    "address": "invalid_address_123",
    "expected_formats": ["P2PKH", "P2SH", "P2WPKH", "P2WSH", "P2TR"]
  }
}
```

```json
// RPC connection error
{
  "ok": false,
  "error": "RPC_CONNECTION_ERROR",
  "error_code": 4000,
  "message": "Cannot connect to Bitcoin Core RPC server",
  "details": {
    "rpc_host": "127.0.0.1",
    "rpc_port": 8332,
    "error_detail": "Connection refused"
  }
}
```

---

## WebSocket Errors (5000-5099)

| Code | Error Name | Description |
|------|-----------|-------------|
| 5000 | WS_CONNECTION_FAILED | WebSocket connection failed |
| 5001 | WS_AUTHENTICATION_REQUIRED | WebSocket authentication required |
| 5002 | WS_AUTHENTICATION_FAILED | WebSocket authentication failed |
| 5003 | WS_ALREADY_AUTHENTICATED | Already authenticated |
| 5004 | WS_INVALID_MESSAGE_FORMAT | Message format is invalid |
| 5005 | WS_MESSAGE_TOO_LARGE | Message exceeds size limit |
| 5006 | WS_RATE_LIMIT_EXCEEDED | Too many messages sent |
| 5007 | WS_INVALID_EVENT_TYPE | Event type not recognized |
| 5008 | WS_SUBSCRIPTION_FAILED | Failed to subscribe to event |
| 5009 | WS_UNSUBSCRIBE_FAILED | Failed to unsubscribe from event |
| 5010 | WS_BROADCAST_FAILED | Failed to broadcast message |

**Example WebSocket Error Messages:**

```json
// Authentication required
{
  "event": "error",
  "error": "WS_AUTHENTICATION_REQUIRED",
  "error_code": 5001,
  "message": "You must authenticate before sending messages",
  "timestamp": 1698765432
}
```

```json
// Rate limit exceeded
{
  "event": "error",
  "error": "WS_RATE_LIMIT_EXCEEDED",
  "error_code": 5006,
  "message": "Rate limit exceeded. Maximum 30 messages per minute.",
  "details": {
    "messages_sent": 31,
    "limit": 30,
    "window_seconds": 60,
    "retry_after": 15
  },
  "timestamp": 1698765432
}
```

---

## Proof of Funds Errors (6000-6099)

| Code | Error Name | Description | HTTP Status |
|------|-----------|-------------|-------------|
| 6000 | POF_CHALLENGE_EXPIRED | PoF challenge has expired | 400 |
| 6001 | POF_CHALLENGE_NOT_FOUND | Challenge ID not found | 404 |
| 6002 | POF_INVALID_PSBT | PSBT format is invalid | 400 |
| 6003 | POF_PSBT_TOO_LARGE | PSBT exceeds maximum size | 413 |
| 6004 | POF_MISSING_OP_RETURN | OP_RETURN challenge not found in PSBT | 400 |
| 6005 | POF_NO_LIVE_INPUTS | No unspent inputs found in PSBT | 400 |
| 6006 | POF_INSUFFICIENT_AMOUNT | Total amount below minimum threshold | 400 |
| 6007 | POF_MEMBERSHIP_REQUIRED | Must be covenant member | 403 |
| 6008 | POF_VERIFICATION_FAILED | Proof verification failed | 400 |
| 6009 | POF_ATTESTATION_EXPIRED | Existing attestation has expired | 410 |
| 6010 | POF_INVALID_PRIVACY_LEVEL | Privacy level not recognized | 400 |

**Example Responses:**

```json
// Missing OP_RETURN
{
  "ok": false,
  "error": "POF_MISSING_OP_RETURN",
  "error_code": 6004,
  "message": "PSBT must contain OP_RETURN output with challenge",
  "details": {
    "challenge_id": "chal_abc123",
    "expected_challenge": "HODLXXI-PoF:abc123:1698765432"
  }
}
```

```json
// No live inputs
{
  "ok": false,
  "error": "POF_NO_LIVE_INPUTS",
  "error_code": 6005,
  "message": "PSBT contains no unspent inputs",
  "details": {
    "total_inputs": 3,
    "unspent_inputs": 0,
    "spent_inputs": 3
  }
}
```

```json
// Insufficient amount
{
  "ok": false,
  "error": "POF_INSUFFICIENT_AMOUNT",
  "error_code": 6006,
  "message": "Total amount below minimum threshold",
  "details": {
    "minimum_sat": 100000,
    "actual_sat": 50000,
    "shortfall_sat": 50000
  }
}
```

---

## LNURL-Auth Errors (7000-7099)

| Code | Error Name | Description | HTTP Status |
|------|-----------|-------------|-------------|
| 7000 | LNURL_SESSION_NOT_FOUND | LNURL session not found | 404 |
| 7001 | LNURL_SESSION_EXPIRED | Session has expired | 410 |
| 7002 | LNURL_INVALID_K1 | K1 challenge is invalid | 400 |
| 7003 | LNURL_INVALID_SIG | Signature verification failed | 400 |
| 7004 | LNURL_INVALID_KEY | Public key format invalid | 400 |
| 7005 | LNURL_ALREADY_AUTHENTICATED | Session already authenticated | 400 |
| 7006 | LNURL_ENCODE_ERROR | Failed to encode LNURL | 500 |
| 7007 | LNURL_DECODE_ERROR | Failed to decode LNURL | 400 |

**Example Responses:**

```json
// Session not found
{
  "ok": false,
  "error": "LNURL_SESSION_NOT_FOUND",
  "error_code": 7000,
  "message": "LNURL session not found or expired",
  "details": {
    "session_id": "lnauth_abc123"
  }
}
```

```json
// Invalid signature
{
  "ok": false,
  "error": "LNURL_INVALID_SIG",
  "error_code": 7003,
  "message": "LNURL-auth signature verification failed",
  "details": {
    "k1": "challenge_string_here",
    "key": "02a1b2c3...",
    "sig": "304502210..."
  }
}
```

---

## Error Response Format

### Standard Error Response Structure

All API errors follow a consistent format:

```json
{
  "ok": false,
  "error": "ERROR_NAME",
  "error_code": 1234,
  "message": "Human-readable error message",
  "details": {
    "additional": "context",
    "field_errors": ["field1", "field2"]
  },
  "timestamp": 1698765432,
  "request_id": "req_abc123def456"
}
```

### Field Descriptions

- `ok`: Always `false` for errors
- `error`: Error name constant (use this for programmatic handling)
- `error_code`: Numeric error code for categorization
- `message`: Human-readable description
- `details`: Additional context (optional)
- `timestamp`: Unix timestamp when error occurred
- `request_id`: Unique identifier for this request (for support/debugging)

### OAuth2 Error Response Format

OAuth2 endpoints follow the RFC 6749 standard:

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code has expired",
  "error_uri": "https://yourdomain.com/docs/errors#invalid_grant"
}
```

---

## Error Handling Best Practices

### Client-Side Handling

#### 1. Check HTTP Status First

```javascript
if (response.status >= 400) {
  // Handle error
  const errorData = await response.json();
  handleError(errorData);
}
```

#### 2. Use Error Codes for Logic

```javascript
function handleError(errorData) {
  switch (errorData.error_code) {
    case 2003: // EXPIRED_TOKEN
      refreshToken();
      break;
    case 2014: // TOO_MANY_LOGIN_ATTEMPTS
      showLockoutMessage(errorData.details.retry_after);
      break;
    case 4005: // INSUFFICIENT_FUNDS
      showInsufficientFundsDialog(errorData.details);
      break;
    default:
      showGenericError(errorData.message);
  }
}
```

#### 3. Implement Retry Logic

```javascript
async function apiRequest(url, options, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await fetch(url, options);
      
      if (response.status === 429) {
        // Rate limited - wait and retry
        const retryAfter = response.headers.get('Retry-After') || 60;
        await sleep(retryAfter * 1000);
        continue;
      }
      
      if (response.status >= 500) {
        // Server error - retry with backoff
        await sleep(Math.pow(2, attempt) * 1000);
        continue;
      }
      
      return response;
    } catch (error) {
      if (attempt === maxRetries - 1) throw error;
      await sleep(Math.pow(2, attempt) * 1000);
    }
  }
}
```

#### 4. Handle Specific Error Scenarios

```javascript
// Token expiration
if (error.error_code === 2003) {
  const newToken = await refreshAccessToken();
  // Retry original request with new token
  return retryWithNewToken(originalRequest, newToken);
}

// Rate limiting
if (error.error_code === 1006) {
  const retryAfter = error.details.retry_after;
  showRateLimitMessage(retryAfter);
  setTimeout(() => retryRequest(), retryAfter * 1000);
}

// Insufficient funds
if (error.error_code === 4005) {
  const shortfall = error.details.shortfall_btc;
  showInsufficientFundsDialog(shortfall);
}
```

### Server-Side Logging

#### 1. Log All Errors with Context

```python
logger.error(
    f"Error {error_code}: {error_name}",
    extra={
        "error_code": error_code,
        "error_name": error_name,
        "request_id": request_id,
        "user_id": user_id,
        "endpoint": request.path,
        "method": request.method,
        "details": error_details
    }
)
```

#### 2. Different Log Levels

```python
# Client errors (4xx) - INFO or WARNING
logger.info(f"Client error: {error_message}")

# Server errors (5xx) - ERROR
logger.error(f"Server error: {error_message}", exc_info=True)

# Security events - WARNING or ERROR
logger.warning(f"Security: Failed authentication attempt from {ip_address}")
```

#### 3. Include Request ID

Always include a unique request ID in error responses for debugging:

```python
request_id = str(uuid.uuid4())
g.request_id = request_id

# Include in error response
return jsonify({
    "ok": False,
    "error": error_name,
    "request_id": request_id
}), status_code
```

### User-Friendly Error Messages

#### Do's and Don'ts

**❌ Don't:**
```json
{
  "error": "Internal server error: NoneType object has no attribute 'get'"
}
```

**✅ Do:**
```json
{
  "error": "RESOURCE_NOT_FOUND",
  "message": "The requested wallet could not be found. Please check the wallet ID and try again."
}
```

**❌ Don't:**
```json
{
  "error": "Invalid input"
}
```

**✅ Do:**
```json
{
  "error": "INVALID_PARAMETER",
  "message": "The 'amount' parameter must be a positive number",
  "details": {
    "field": "amount",
    "provided_value": "-0.5",
    "expected": "positive number"
  }
}
```

### Security Considerations

#### 1. Don't Leak Sensitive Information

**❌ Don't:**
```json
{
  "error": "SQL error: SELECT * FROM users WHERE password='...' failed"
}
```

**✅ Do:**
```json
{
  "error": "DATABASE_ERROR",
  "message": "A database error occurred. Please try again later.",
  "request_id": "req_abc123"
}
```

#### 2. Rate Limit Error Details

Don't provide exact rate limit information to potential attackers:

**❌ Don't:**
```json
{
  "details": {
    "current_attempts": 4,
    "max_attempts": 5,
    "remaining_attempts": 1
  }
}
```

**✅ Do:**
```json
{
  "message": "Too many requests. Please try again later.",
  "retry_after": 60
}
```

#### 3. Consistent Error Timing

Prevent timing attacks by ensuring error responses take similar time:

```python
# Bad: reveals if user exists
if not user_exists(username):
    return error("User not found")  # Fast response

if not check_password(password):
    return error("Invalid password")  # Slow response

# Good: consistent timing
user = get_user(username)
if not user or not check_password(password):
    sleep(random.uniform(0.1, 0.3))  # Add jitter
    return error("Invalid credentials")
```

---

## Error Recovery Strategies

### 1. Automatic Token Refresh

```javascript
class APIClient {
  async request(url, options) {
    let response = await fetch(url, options);
    
    if (response.status === 401) {
      const errorData = await response.json();
      if (errorData.error_code === 2003) { // EXPIRED_TOKEN
        // Refresh token
        const newToken = await this.refreshToken();
        // Retry with new token
        options.headers.Authorization = `Bearer ${newToken}`;
        response = await fetch(url, options);
      }
    }
    
    return response;
  }
}
```

### 2. Circuit Breaker Pattern

```javascript
class CircuitBreaker {
  constructor(threshold = 5, timeout = 60000) {
    this.failures = 0;
    this.threshold = threshold;
    this.timeout = timeout;
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
  }
  
  async call(fn) {
    if (this.state === 'OPEN') {
      if (Date.now() - this.openedAt > this.timeout) {
        this.state = 'HALF_OPEN';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }
    
    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }
  
  onSuccess() {
    this.failures = 0;
    if (this.state === 'HALF_OPEN') {
      this.state = 'CLOSED';
    }
  }
  
  onFailure() {
    this.failures++;
    if (this.failures >= this.threshold) {
      this.state = 'OPEN';
      this.openedAt = Date.now();
    }
  }
}
```

### 3. Exponential Backoff

```javascript
async function retryWithBackoff(fn, maxRetries = 5) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      
      // Exponential backoff with jitter
      const delay = Math.min(1000 * Math.pow(2, i), 30000);
      const jitter = Math.random() * 1000;
      await sleep(delay + jitter);
    }
  }
}
```

---

## Monitoring and Alerting

### Key Metrics to Monitor

1. **Error Rate by Code**
   - Track frequency of each error code
   - Alert on unusual spikes

2. **Authentication Failures**
   - Monitor failed login attempts
   - Detect potential brute force attacks

3. **RPC Errors**
   - Track Bitcoin RPC connectivity
   - Alert on connection failures

4. **Rate Limit Hits**
   - Monitor rate limit violations
   - Identify abusive clients

### Example Monitoring Setup

```python
# Increment error counter
error_counter.labels(
    error_code=error_code,
    endpoint=endpoint,
    method=method
).inc()

# Track error response time
error_duration.labels(
    error_code=error_code
).observe(response_time)
```

---

## Testing Error Scenarios

### Unit Tests

```python
def test_expired_token_error():
    # Create expired token
    token = create_token(expires_in=-3600)
    
    # Make request
    response = client.get(
        '/api/protected',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    # Assert error response
    assert response.status_code == 401
    data = response.json()
    assert data['error_code'] == 2003
    assert data['error'] == 'EXPIRED_TOKEN'
```

### Integration Tests

```python
def test_insufficient_funds_flow():
    # Setup: Create wallet with low balance
    wallet = create_test_wallet(balance=0.001)
    
    # Attempt to send more than available
    response = client.post('/api/wallet/send', json={
        'address': 'bc1q...',
        'amount': 1.0
    })
    
    # Verify error
    assert response.status_code == 400
    data = response.json()
    assert data['error_code'] == 4005
    assert 'shortfall_btc' in data['details']
```

---

## Support and Debugging

When reporting errors, include:

1. **Request ID** - From error response
2. **Timestamp** - When error occurred
3. **Error Code** - For quick identification
4. **Steps to Reproduce** - What led to the error
5. **Expected vs Actual** - What should have happened

**Example Error Report:**

```
Request ID: req_abc123def456
Timestamp: 2024-10-29T15:30:45Z
Error Code: 4005 (INSUFFICIENT_FUNDS)
Endpoint: POST /api/wallet/send
User: 02a1b2c3d4e5f6...

Steps to reproduce:
1. Login with test account
2. Navigate to send Bitcoin
3. Enter amount: 1.0 BTC
4. Click send

Expected: Transaction should succeed
Actual: Received INSUFFICIENT_FUNDS error

Additional context:
- Wallet balance shown in UI: 1.5 BTC
- Error says available: 0.005 BTC
- Possible balance display bug?
```
