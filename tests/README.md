# HODLXXI Test Suite

This directory contains the comprehensive test suite for the HODLXXI Universal Bitcoin Identity Layer.


## Running Tests

### Run all tests
```bash
make test
# or
pytest tests/
```

### Run specific test suites
```bash
# Unit tests only
make test-unit
pytest tests/unit

# Integration tests only
make test-integration
pytest tests/integration

# Run tests in parallel (fast)
make test-fast
pytest tests/ -n auto
```

### Run with coverage
```bash
make test-coverage
# Coverage report will be in htmlcov/index.html
```

### Run specific test file or function
```bash
# Specific file
pytest tests/unit/test_config.py

# Specific test function
pytest tests/unit/test_config.py::TestGetConfig::test_get_config_defaults

# Pattern matching
pytest tests/ -k "auth"  # Run all tests with 'auth' in the name
```

## Test Markers

Tests are organized using pytest markers:

- `@pytest.mark.unit` - Fast, isolated unit tests
- `@pytest.mark.integration` - Tests that involve multiple components
- `@pytest.mark.e2e` - End-to-end user workflow tests
- `@pytest.mark.slow` - Tests that take significant time
- `@pytest.mark.bitcoin` - Tests requiring Bitcoin Core RPC
- `@pytest.mark.auth` - Authentication-related tests
- `@pytest.mark.api` - API endpoint tests
- `@pytest.mark.websocket` - WebSocket functionality tests
- `@pytest.mark.security` - Security-related tests

### Running tests by marker
```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run all except slow tests
pytest -m "not slow"

# Run auth-related tests
pytest -m auth
```

## Writing Tests

### Test File Naming
- Unit tests: `test_<module>.py` or `<module>_test.py`
- Test classes: `class Test<Feature>:`
- Test functions: `def test_<scenario>:`

### Example Test Structure
```python
import pytest

class TestFeature:
    """Test suite for Feature functionality."""

    def test_basic_behavior(self, client):
        """Test basic feature behavior."""
        response = client.get('/endpoint')
        assert response.status_code == 200

    def test_error_handling(self, client):
        """Test error handling."""
        response = client.post('/endpoint', json={})
        assert response.status_code == 400
```

### Using Fixtures

Common fixtures available in `conftest.py`:

- `app` - Flask application instance
- `client` - Flask test client
- `auth_headers` - Authentication headers
- `mock_bitcoin_rpc` - Mocked Bitcoin RPC connection
- `sample_pubkey` - Sample Bitcoin public key
- `oauth_client_data` - Sample OAuth client data
- `jwt_token` - Valid JWT token for testing

Example:
```python
def test_protected_endpoint(client, jwt_token):
    """Test protected endpoint with authentication."""
    headers = {'Authorization': f'Bearer {jwt_token}'}
    response = client.get('/api/protected', headers=headers)
    assert response.status_code == 200
```

## Test Coverage Goals

- **Overall coverage**: 70% minimum (enforced by CI)
- **Critical paths**: 90%+ coverage
  - Authentication flows
  - Bitcoin signature verification
  - OAuth2 token issuance
  - Security-critical functions

### Viewing Coverage Report
```bash
make test-coverage
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## CI/CD Integration

Tests run automatically on:
- Every push to `main`, `develop`, or `claude/**` branches
- Every pull request
- Multiple Python versions (3.9, 3.10, 3.11, 3.12)

### CI Test Matrix
- Unit tests on all Python versions
- Integration tests on Python 3.11
- Tests with PostgreSQL and Redis services
- Security scans and linting

## Debugging Tests

### Run with verbose output
```bash
pytest tests/ -v
```

### Run with print statements visible
```bash
pytest tests/ -s
```

### Drop into debugger on failure
```bash
pytest tests/ --pdb
```

### Run last failed tests
```bash
pytest tests/ --lf
```

### Show local variables on failure
```bash
pytest tests/ -l
```

## Mocking External Services

### Bitcoin RPC
```python
def test_bitcoin_operation(mock_bitcoin_rpc):
    """Test with mocked Bitcoin RPC."""
    mock_bitcoin_rpc.getblockchaininfo.return_value = {'blocks': 700000}
    # Your test code here
```

### WebSocket Testing
```python
def test_websocket(mock_socketio_client):
    """Test WebSocket functionality."""
    mock_socketio_client.emit('event', {'data': 'test'})
    received = mock_socketio_client.get_received()
    assert len(received) > 0
```

## Test Database

Tests use in-memory storage by default. For integration tests requiring a database:

```python
@pytest.mark.integration
def test_with_database():
    """Test requiring real database."""
    # Database is automatically configured in conftest.py
    pass
```

## Performance Testing

For load testing and performance benchmarks, see:
- `tests/performance/` (future)
- External tools: Locust, K6, Apache Bench

## Security Testing

Security-focused tests:
- Input validation and sanitization
- Authentication and authorization
- CSRF protection
- Rate limiting
- SQL injection prevention
- XSS prevention

Run security tests:
```bash
pytest -m security
```

## Best Practices

1. **Keep tests fast** - Unit tests should run in milliseconds
2. **One assertion per test** - Focus on single behavior
3. **Use descriptive names** - Test names should describe the scenario
4. **Arrange-Act-Assert** - Structure tests clearly
5. **Mock external dependencies** - Don't call real APIs in unit tests
6. **Clean up after tests** - Use fixtures with teardown
7. **Test edge cases** - Not just happy paths
8. **Document complex tests** - Add docstrings explaining why

## Troubleshooting

### Import errors
```bash
# Ensure you're in the project root
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Fixture not found
- Check if fixture is defined in `conftest.py`
- Ensure `conftest.py` is in the test directory or parent

### Tests pass locally but fail in CI
- Check environment variables in CI
- Verify Python version compatibility
- Check for timing-dependent tests

## Contributing

When adding new features:
1. Write tests first (TDD approach)
2. Ensure tests pass locally
3. Verify coverage doesn't decrease
4. Update test documentation if needed

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Flask Testing](https://flask.palletsprojects.com/en/latest/testing/)
- [Test-Driven Development](https://martinfowler.com/bliki/TestDrivenDevelopment.html)

---

For questions or issues with tests, please open an issue on GitHub.
