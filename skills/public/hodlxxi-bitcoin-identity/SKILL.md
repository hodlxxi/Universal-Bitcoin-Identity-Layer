---
name: hodlxxi-bitcoin-identity
description: Integrate HODLXXI as a Bitcoin-native identity provider that bridges OAuth2/OIDC and Lightning LNURL-Auth. Use when setting up client registration, authorization flows, JWT verification, or health monitoring for HODLXXI deployments.
---

# HODLXXI Bitcoin Identity

## Overview

Use this skill to integrate HODLXXI (Universal Bitcoin Identity Layer) for agent authentication, LNURL-Auth linking, and JWT-based identity claims.

## Quick start

1. Set a base URL for the HODLXXI deployment.
2. Register an OAuth client to obtain `client_id` and `client_secret`.
3. Run the OAuth2/OIDC authorization code flow (PKCE recommended).
4. Link a Lightning identity via LNURL-Auth.
5. Verify JWTs with the JWKS endpoint.

## Core workflows

### 1) Configure the base URL

Set the base URL to the HODLXXI deployment (update as needed):

```bash
BASE_URL="https://your-hodlxxi-deployment.com"
```

### 2) Register an OAuth client

Register a client to get credentials:

```bash
curl -X POST "$BASE_URL/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name": "YourAgentName", "redirect_uris": ["https://your-callback-url"], "scopes": ["openid", "profile"]}'
```

Store `client_id` and `client_secret` securely.

### 3) Run OAuth2/OIDC authorization code flow

Discover endpoints:

```bash
curl "$BASE_URL/.well-known/openid-configuration"
```

Create an authorization request (PKCE recommended):

```bash
curl "$BASE_URL/oauth/authorize?client_id=your_client_id&redirect_uri=your_callback&response_type=code&scope=openid%20profile&code_challenge=your_challenge&code_challenge_method=S256"
```

Exchange the authorization code for tokens:

```bash
curl -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=received_code&redirect_uri=your_callback&client_id=your_client_id&code_verifier=your_verifier"
```

Expect an access token, ID token (JWT), and optional refresh token.

### 4) Link a Lightning identity with LNURL-Auth

Generate a challenge:

```bash
curl "$BASE_URL/lnurl/auth?tag=login"
```

Sign the LNURL `k1` challenge with the Lightning wallet and verify:

```bash
curl -X POST "$BASE_URL/lnurl/verify" \
  -H "Content-Type: application/json" \
  -d '{"k1": "challenge_from_lnurl", "key": "your_pubkey", "signature": "your_signature"}'
```

### 5) Verify JWTs

Fetch JWKS:

```bash
curl "$BASE_URL/.well-known/jwks.json"
```

Verify with Python (example uses PyJWT):

```python
import jwt
import requests

jwks = requests.get("https://your-hodlxxi-deployment.com/.well-known/jwks.json").json()
public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks["keys"][0])
claims = jwt.decode(your_jwt, public_key, algorithms=["RS256"], audience="your_audience")
print(claims)
```

### 6) Monitor health and metrics

Check liveness and metrics endpoints:

```bash
curl "$BASE_URL/health"
curl "$BASE_URL/metrics/prometheus"
```

## Operational guidance

- Always use HTTPS in production.
- Store secrets outside source control.
- Handle 4xx/5xx responses with retries for transient errors.
- Keep PKCE enabled for auth flows.

## Optional helper script

Use `scripts/verify_signature.py` to validate LNURL signatures locally. Install the dependency first:

```bash
pip install ecdsa
python scripts/verify_signature.py --k1 <hex> --signature <hex> --pubkey <hex>
```
