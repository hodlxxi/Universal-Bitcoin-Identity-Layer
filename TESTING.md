# Testing Guide

> Comprehensive testing documentation for HODLXXI Universal Bitcoin Identity Layer

## Table of Contents

- [Overview](#overview)
- [Testing Philosophy](#testing-philosophy)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Writing Tests](#writing-tests)
- [Test Coverage](#test-coverage)
- [Continuous Integration](#continuous-integration)
- [Testing Best Practices](#testing-best-practices)

---

## Overview

HODLXXI uses a comprehensive testing strategy to ensure reliability, security, and correctness of the Bitcoin identity layer.

### Testing Stack

- **Framework**: pytest 7.0+
- **Coverage**: pytest-cov
- **Mocking**: pytest-mock, unittest.mock
- **Bitcoin Testing**: bitcoin-test-framework
- **API Testing**: pytest-flask, requests-mock
- **WebSocket Testing**: python-socketio[client]
- **Database Testing**: pytest-postgresql
- **Load Testing**: locust

---

## Testing Philosophy

### Test Pyramid

```
           ┌─────────────────┐
           │   E2E Tests     │  <- 10% (Integration/User flows)
           │   (Slow)        │
           └─────────────────┘
         ┌───────────────────────┐
         │   Integration Tests   │  <- 30% (API endpoints, DB)
         │   (Medium)            │
         └───────────────────────┘
       ┌─────────────────────────────┐
       │     Unit Tests              │  <- 60% (Functions, classes)
       │     (Fast)                  │
       └─────────────────────────────┘
```

### Testing Principles

1. **Fast Feedback**: Unit tests run in < 5 seconds
2. **Deterministic**: Tests produce same results every run
3. **Isolated**: Tests don't depend on external services
4. **Comprehensive**: All critical paths covered
5. **Maintainable**: Tests are easy to understand and modify

---

## Test Structure

### Directory Layout

```
tests/
├── __init__.py
├── conftest.py                      # Shared fixtures
├── pytest.ini                       # Pytest configuration
│
├── unit/                            # Unit tests (60% of tests)
│   ├── __init__.py
│   ├── test_auth.py                # Authentication functions
│   ├── test_bitcoin.py             # Bitcoin operations
│   ├── test_crypto.py              # Cryptographic functions
│   ├── test_oauth.py               # OAuth2 logic
│   ├── test_lnurl.py               # LNURL-auth
│   ├── test_pof.py                 # Proof of Funds
│   ├── test_validators.py          # Input validation
│   └── test_utils.py               # Utility functions
│
├── integration/                     # Integration tests (30%)
│   ├── __init__.py
│   ├── test_api_auth.py            # Auth API endpoints
│   ├── test_api_oauth.py           # OAuth endpoints
│   ├── test_api_wallet.py          # Wallet endpoints
│   ├── test_api_chat.py            # Chat endpoints
│   ├── test_api_pof.py             # PoF endpoints
│   ├── test_database.py            # Database operations
│   ├── test_bitcoin_rpc.py         # Bitcoin Core integration
│   └── test_websocket.py           # WebSocket functionality
│
├── e2e/                            # End-to-end tests (10%)
│   ├── __init__.py
│   ├── test_oauth_flow.py         # Complete OAuth flow
│   ├── test_lnurl_flow.py         # Complete LNURL flow
│   ├── test_pof_flow.py           # Complete PoF verification
│   └── test_chat_flow.py          # Complete chat scenario
│
├── performance/                    # Performance tests
│   ├── __init__.py
│   ├── test_load.py               # Load testing
│   ├── test_stress.py             # Stress testing
│   └── locustfile.py              # Locust configuration
│
├── security/                       # Security tests
│   ├── __init__.py
│   ├── test_injection.py          # SQL injection tests
│   ├── test_xss.py                # XSS prevention
│   ├── test_csrf.py               # CSRF protection
│   ├── test_rate_limiting.py      # Rate limit enforcement
│   └── test_crypto_security.py    # Cryptographic security
│
└── fixtures/                       # Test data
    ├── bitcoin_data.json
    ├── oauth_clients.json
    ├── test_psbts/
    └── mock_responses/
```

---

## Running Tests

### Prerequisites

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Start test Bitcoin node (regtest)
bitcoind -regtest -daemon -server -rpcuser=test -rpcpassword=test

# Start test database
docker run -d -p 5433:5432 -e POSTGRES_PASSWORD=test postgres:15
```

### Run All Tests

```bash
# Run entire test suite
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=app --cov-report=html

# Run specific test types
pytest tests/unit/              # Unit tests only
pytest tests/integration/       # Integration tests only
pytest tests/e2e/              # E2E tests only
```

### Run Specific Tests

```bash
# Run single test file
pytest tests/unit/test_auth.py

# Run specific test function
pytest tests/unit/test_auth.py::test_signature_verification

# Run tests matching pattern
pytest -k "oauth"              # All tests with "oauth" in name

# Run tests with marker
pytest -m "slow"               # Tests marked as slow
pytest -m "not slow"           # Exclude slow tests
```

### Run with Options

```bash
# Stop on first failure
pytest -x

# Run last failed tests only
pytest --lf

# Run tests in parallel (4 workers)
pytest -n 4

# Disable warnings
pytest --disable-warnings

# Show local variables on failure
pytest -l

# Drop into debugger on failure
pytest --pdb
```

### Watch Mode (Development)

```bash
# Auto-run tests on file changes
ptw                            # pytest-watch

# With specific options
ptw -- -v --cov=app
```

---

## Writing Tests

### Unit Test Example

```python
# tests/unit/test_crypto.py

import pytest
from app.crypto import verify_bitcoin_signature, generate_challenge

class TestCryptoFunctions:
    """Unit tests for cryptographic functions"""
    
    def test_generate_challenge_returns_hex_string(self):
        """Challenge should be 32-byte hex string"""
        challenge = generate_challenge()
        
        assert isinstance(challenge, str)
        assert len(challenge) == 64  # 32 bytes = 64 hex chars
        assert all(c in '0123456789abcdef' for c in challenge)
    
    def test_generate_challenge_is_random(self):
        """Each challenge should be unique"""
        challenge1 = generate_challenge()
        challenge2 = generate_challenge()
        
        assert challenge1 != challenge2
    
    def test_verify_valid_signature(self):
        """Valid signature should verify successfully"""
        pubkey = "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc"
        message = "test message"
        signature = "3045022100...valid_sig..."  # Mock valid signature
        
        result = verify_bitcoin_signature(pubkey, message, signature)
        
        assert result is True
    
    def test_verify_invalid_signature(self):
        """Invalid signature should fail verification"""
        pubkey = "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc"
        message = "test message"
        signature = "invalid_signature"
        
        result = verify_bitcoin_signature(pubkey, message, signature)
        
        assert result is False
    
    @pytest.mark.parametrize("pubkey,expected", [
        ("02a163...", True),   # Valid compressed pubkey
        ("04a163...", True),   # Valid uncompressed pubkey
        ("invalid", False),    # Invalid format
        ("", False),           # Empty string
    ])
    def test_pubkey_validation(self, pubkey, expected):
        """Test pubkey format validation"""
        from app.validators import is_valid_pubkey
        
        assert is_valid_pubkey(pubkey) == expected
```

### Integration Test Example

```python
# tests/integration/test_api_oauth.py

import pytest
from flask import url_for

class TestOAuthEndpoints:
    """Integration tests for OAuth2 endpoints"""
    
    @pytest.fixture
    def oauth_client(self, db):
        """Create test OAuth client"""
        from app.models import OAuthClient
        
        client = OAuthClient(
            client_id="test_client_id",
            client_secret="test_client_secret",
            client_name="Test App",
            redirect_uris=["http://localhost:3000/callback"]
        )
        db.session.add(client)
        db.session.commit()
        return client
    
    @pytest.fixture
    def authenticated_user(self, client):
        """Create and authenticate test user"""
        # Login and get session
        response = client.post('/api/lnurl-auth/verify', json={
            'k1': 'test_challenge',
            'sig': 'valid_signature',
            'key': 'test_pubkey'
        })
        return response
    
    def test_authorization_endpoint_without_auth(self, client):
        """Should redirect to login if not authenticated"""
        response = client.get('/oauth/authorize?client_id=test&response_type=code')
        
        assert response.status_code == 302
        assert '/login' in response.headers['Location']
    
    def test_authorization_endpoint_with_auth(self, client, authenticated_user, oauth_client):
        """Should show consent screen when authenticated"""
        response = client.get(
            f'/oauth/authorize?'
            f'client_id={oauth_client.client_id}&'
            f'response_type=code&'
            f'redirect_uri=http://localhost:3000/callback&'
            f'scope=openid+profile'
        )
        
        assert response.status_code == 200
        assert b'Authorize' in response.data
        assert oauth_client.client_name.encode() in response.data
    
    def test_token_endpoint_with_valid_code(self, client, oauth_client, db):
        """Should exchange auth code for tokens"""
        from app.models import OAuthCode
        
        # Create authorization code
        code = OAuthCode(
            code='test_auth_code',
            client_id=oauth_client.client_id,
            user_id=1,
            scope=['openid', 'profile'],
            redirect_uri='http://localhost:3000/callback'
        )
        db.session.add(code)
        db.session.commit()
        
        response = client.post('/oauth/token', json={
            'grant_type': 'authorization_code',
            'code': 'test_auth_code',
            'client_id': oauth_client.client_id,
            'client_secret': oauth_client.client_secret,
            'redirect_uri': 'http://localhost:3000/callback'
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert 'expires_in' in data
        assert data['token_type'] == 'Bearer'
    
    def test_token_endpoint_with_invalid_code(self, client, oauth_client):
        """Should reject invalid authorization code"""
        response = client.post('/oauth/token', json={
            'grant_type': 'authorization_code',
            'code': 'invalid_code',
            'client_id': oauth_client.client_id,
            'client_secret': oauth_client.client_secret
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == 'invalid_grant'
```

### E2E Test Example

```python
# tests/e2e/test_oauth_flow.py

import pytest
import time

class TestCompleteOAuthFlow:
    """End-to-end OAuth2 authorization code flow"""
    
    def test_complete_oauth_flow(self, client, oauth_client, bitcoin_wallet):
        """Test complete OAuth2 flow from authorization to API call"""
        
        # Step 1: LNURL-Auth Login
        challenge_response = client.get('/api/lnurl-auth/login')
        assert challenge_response.status_code == 200
        challenge_data = challenge_response.get_json()
        k1 = challenge_data['k1']
        
        # Sign challenge with Bitcoin key
        signature = bitcoin_wallet.sign_message(k1)
        pubkey = bitcoin_wallet.get_pubkey()
        
        # Verify LNURL auth
        auth_response = client.get(
            f'/api/lnurl-auth/verify?'
            f'k1={k1}&'
            f'sig={signature}&'
            f'key={pubkey}'
        )
        assert auth_response.status_code == 200
        
        # Step 2: OAuth Authorization
        auth_url = (
            f'/oauth/authorize?'
            f'client_id={oauth_client.client_id}&'
            f'response_type=code&'
            f'redirect_uri=http://localhost:3000/callback&'
            f'scope=openid+profile&'
            f'state=random_state'
        )
        
        auth_response = client.get(auth_url, follow_redirects=False)
        assert auth_response.status_code == 200
        
        # User approves (simulate form submission)
        approve_response = client.post('/oauth/authorize', data={
            'client_id': oauth_client.client_id,
            'response_type': 'code',
            'redirect_uri': 'http://localhost:3000/callback',
            'scope': 'openid profile',
            'state': 'random_state',
            'approve': 'true'
        }, follow_redirects=False)
        
        assert approve_response.status_code == 302
        location = approve_response.headers['Location']
        assert 'code=' in location
        assert 'state=random_state' in location
        
        # Extract authorization code
        import urllib.parse
        parsed = urllib.parse.urlparse(location)
        params = urllib.parse.parse_qs(parsed.query)
        auth_code = params['code'][0]
        
        # Step 3: Exchange code for tokens
        token_response = client.post('/oauth/token', json={
            'grant_type': 'authorization_code',
            'code': auth_code,
            'client_id': oauth_client.client_id,
            'client_secret': oauth_client.client_secret,
            'redirect_uri': 'http://localhost:3000/callback'
        })
        
        assert token_response.status_code == 200
        token_data = token_response.get_json()
        assert 'access_token' in token_data
        assert 'refresh_token' in token_data
        access_token = token_data['access_token']
        refresh_token = token_data['refresh_token']
        
        # Step 4: Use access token to call API
        profile_response = client.get(
            '/api/users/profile',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        assert profile_response.status_code == 200
        profile_data = profile_response.get_json()
        assert 'bitcoin_pubkey' in profile_data
        assert profile_data['bitcoin_pubkey'] == pubkey
        
        # Step 5: Wait for token expiry (simulate)
        time.sleep(2)  # Assume short expiry for testing
        
        # Access token should now be expired
        expired_response = client.get(
            '/api/users/profile',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        # Might still work or return 401, depends on expiry
        
        # Step 6: Refresh token
        refresh_response = client.post('/oauth/token', json={
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': oauth_client.client_id,
            'client_secret': oauth_client.client_secret
        })
        
        assert refresh_response.status_code == 200
        new_token_data = refresh_response.get_json()
        assert 'access_token' in new_token_data
        new_access_token = new_token_data['access_token']
        
        # Step 7: Use new access token
        new_profile_response = client.get(
            '/api/users/profile',
            headers={'Authorization': f'Bearer {new_access_token}'}
        )
        
        assert new_profile_response.status_code == 200
```

### Security Test Example

```python
# tests/security/test_injection.py

import pytest

class TestSQLInjectionPrevention:
    """Test SQL injection prevention"""
    
    def test_login_sql_injection_attempt(self, client):
        """Should prevent SQL injection in login"""
        malicious_inputs = [
            "admin' OR '1'='1",
            "admin'--",
            "admin' OR 1=1--",
            "'; DROP TABLE users--",
        ]
        
        for injection in malicious_inputs:
            response = client.post('/api/lnurl-auth/verify', json={
                'k1': injection,
                'sig': 'test',
                'key': injection
            })
            
            # Should fail safely, not crash
            assert response.status_code in [400, 401]
            # Database should still exist
            from app.models import User
            assert User.query.count() >= 0  # Query still works

class TestRateLimiting:
    """Test rate limiting enforcement"""
    
    def test_rate_limit_on_auth_endpoint(self, client):
        """Should enforce rate limits"""
        # Make requests up to limit
        for i in range(10):  # Assume limit is 10/min
            response = client.get('/api/lnurl-auth/login')
            assert response.status_code == 200
        
        # Next request should be rate limited
        response = client.get('/api/lnurl-auth/login')
        assert response.status_code == 429
        data = response.get_json()
        assert 'rate_limit_exceeded' in data['error_code']
```

---

## Test Coverage

### Coverage Requirements

- **Minimum Overall Coverage**: 80%
- **Critical Modules**: 95%+
  - Authentication (OAuth, LNURL)
  - Cryptographic functions
  - Proof of Funds
  - Bitcoin wallet operations
- **API Endpoints**: 90%+
- **Utility Functions**: 85%+

### Generate Coverage Report

```bash
# Generate HTML coverage report
pytest --cov=app --cov-report=html

# Open report
open htmlcov/index.html

# Generate terminal report
pytest --cov=app --cov-report=term-missing

# Generate XML (for CI)
pytest --cov=app --cov-report=xml

# Fail if coverage below threshold
pytest --cov=app --cov-fail-under=80
```

### Coverage Configuration

```ini
# .coveragerc

[run]
source = app
omit =
    */tests/*
    */venv/*
    */__pycache__/*
    */site-packages/*
    app/config.py

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
    if __name__ == .__main__.:
    if TYPE_CHECKING:
    @abstractmethod
```

---

## Continuous Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/test.yml

name: Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
          POSTGRES_DB: hodlxxi_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('requirements*.txt') }}
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      
      - name: Install Bitcoin Core
        run: |
          sudo add-apt-repository ppa:bitcoin/bitcoin
          sudo apt-get update
          sudo apt-get install -y bitcoind
      
      - name: Start Bitcoin regtest
        run: |
          bitcoind -regtest -daemon -server \
            -rpcuser=test \
            -rpcpassword=test \
            -rpcport=18443
          sleep 5
      
      - name: Run linter
        run: |
          flake8 app/ --count --select=E9,F63,F7,F82 --show-source --statistics
          flake8 app/ --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
      
      - name: Run type checker
        run: |
          mypy app/ --ignore-missing-imports
      
      - name: Run tests
        env:
          DATABASE_URL: postgresql://postgres:test@localhost:5432/hodlxxi_test
          REDIS_URL: redis://localhost:6379/0
          BITCOIN_RPC_USER: test
          BITCOIN_RPC_PASSWORD: test
          BITCOIN_RPC_HOST: localhost
          BITCOIN_RPC_PORT: 18443
          FLASK_ENV: testing
        run: |
          pytest --cov=app --cov-report=xml --cov-report=term-missing -v
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
          fail_ci_if_error: true
      
      - name: Security scan
        run: |
          bandit -r app/ -f json -o bandit-report.json
      
      - name: Dependency check
        run: |
          safety check --json
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml

repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-json
      - id: check-merge-conflict
      - id: detect-private-key
  
  - repo: https://github.com/psf/black
    rev: 23.1.0
    hooks:
      - id: black
        language_version: python3
  
  - repo: https://github.com/PyCQA/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: ['--max-line-length=127']
  
  - repo: local
    hooks:
      - id: pytest-check
        name: pytest-check
        entry: pytest
        language: system
        pass_filenames: false
        always_run: true
        args: ['--cov=app', '--cov-fail-under=80', '-x']
```

---

## Testing Best Practices

### Do's ✅

1. **Write tests first (TDD)** when adding new features
2. **Use descriptive test names** that explain what is being tested
3. **Keep tests independent** - each test should run in isolation
4. **Use fixtures** for common setup code
5. **Mock external services** (Bitcoin RPC, external APIs)
6. **Test edge cases** and error conditions
7. **Clean up after tests** - use teardown fixtures
8. **Use parametrize** for testing multiple inputs
9. **Keep tests fast** - unit tests should run in milliseconds
10. **Document complex test scenarios** with comments

### Don'ts ❌

1. **Don't test implementation details** - test behavior, not internal state
2. **Don't write flaky tests** - tests should be deterministic
3. **Don't share state between tests** - use fresh fixtures
4. **Don't skip tests without good reason** - fix or remove them
5. **Don't ignore warnings** - they often indicate real issues
6. **Don't test third-party libraries** - trust they work
7. **Don't write tests that depend on network/external services**
8. **Don't commit failing tests** - fix before push
9. **Don't over-mock** - integration tests should test real integrations
10. **Don't forget to update tests** when changing code

### Test Naming Convention

```python
# Good test names
def test_oauth_token_endpoint_returns_access_token_for_valid_code():
    pass

def test_lnurl_auth_rejects_invalid_signature():
    pass

def test_pof_verification_fails_when_balance_below_threshold():
    pass

# Bad test names
def test_oauth():  # Too vague
    pass

def test_1():  # No meaning
    pass

def test_it_works():  # What works?
    pass
```

---

## Troubleshooting Tests

### Common Issues

**Issue**: Tests fail with "Database does not exist"
```bash
# Solution: Create test database
createdb hodlxxi_test
```

**Issue**: Tests fail with "Bitcoin RPC connection refused"
```bash
# Solution: Start Bitcoin regtest node
bitcoind -regtest -daemon -server -rpcuser=test -rpcpassword=test
```

**Issue**: Tests pass locally but fail in CI
```bash
# Check environment variables
# Verify service versions match
# Review CI logs for differences
```

**Issue**: Slow test suite
```bash
# Run tests in parallel
pytest -n auto

# Identify slow tests
pytest --durations=10

# Skip slow tests during development
pytest -m "not slow"
```

---

## Additional Resources

- [pytest Documentation](https://docs.pytest.org/)
- [Testing Flask Applications](https://flask.palletsprojects.com/en/2.3.x/testing/)
- [Bitcoin Test Framework](https://github.com/bitcoin/bitcoin/tree/master/test)
- [Python Testing Best Practices](https://docs.python-guide.org/writing/tests/)

---

**Last Updated**: October 31, 2025  
**Version**: 1.0.0  
**Maintainer**: HODLXXI Team
