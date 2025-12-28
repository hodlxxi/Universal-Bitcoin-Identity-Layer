# Contributing to HODLXXI

Thank you for your interest in contributing to HODLXXI! We welcome contributions from the community.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Python version, Bitcoin Core version)
- **Logs and error messages** (sanitize any sensitive information)
- **Screenshots** if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide detailed description** of the suggested enhancement
- **Explain why this enhancement would be useful**
- **List any alternatives** you've considered

### Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities. Instead, please email security@hodlxxi.com or see [SECURITY.md](SECURITY.md).

## Development Process

### 1. Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/hodlxxi.com.git
cd hodlxxi.com

### 2. Set Up Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Copy environment template
cp .env.example .env
# Edit .env with your local configuration
```

### 3. Create a Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 4. Make Your Changes

#### Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use descriptive variable and function names
- Add docstrings for functions and classes
- Keep functions focused and concise
- Add comments for complex logic

#### Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=app tests/

# Run specific test
pytest tests/test_auth.py::test_lnurl_auth
```

#### Commit Messages

Write clear, descriptive commit messages:

```
<type>: <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Example:
```
feat: Add support for multi-signature wallets

Implement P2SH multi-sig address generation and transaction signing.
Includes support for 2-of-3 and 3-of-5 configurations.

Closes #123
```

### 5. Test Your Changes

Before submitting:

```bash
# Run all tests
pytest tests/

# Run linter
flake8 app/

# Check types (if using type hints)
mypy app/

# Test locally
python app/app.py
```

### 6. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
```

## Pull Request Guidelines

### PR Title

Use descriptive titles following the commit message format:
- `feat: Add OAuth2 token refresh endpoint`
- `fix: Resolve LNURL-auth session timeout issue`
- `docs: Update production deployment guide`

### PR Description

Include:

1. **What** - What does this PR do?
2. **Why** - Why is this change needed?
3. **How** - How does it work?
4. **Testing** - How was it tested?
5. **Screenshots** - If UI changes
6. **Breaking Changes** - Any breaking changes?

Template:
```markdown
## Description
Brief description of changes

## Motivation
Why this change is needed

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manually tested locally
- [ ] Documentation updated

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added for changes
- [ ] All tests pass locally
- [ ] Breaking changes documented
```

### Review Process

1. **Automated checks** - CI/CD must pass
2. **Code review** - At least one maintainer review required
3. **Testing** - Verify tests are comprehensive
4. **Documentation** - Ensure docs are updated
5. **Security** - Review for security implications

## Development Guidelines

### API Changes

When modifying API endpoints:

1. Update [API_RESPONSE_EXAMPLES.md](app/API_RESPONSE_EXAMPLES.md)
2. Update error codes in [ERROR_CODE_DOCUMENTATION.md](app/ERROR_CODE_DOCUMENTATION.md)
3. Maintain backward compatibility when possible
4. Document breaking changes prominently

### Security Considerations

- Never commit secrets or credentials
- Follow security guidelines in [SECURITY_REQUIREMENTS.md](app/SECURITY_REQUIREMENTS.md)
- Validate all user inputs
- Use parameterized queries for database
- Implement rate limiting for new endpoints
- Review OAuth/auth changes carefully

### Database Changes

- Use migrations for schema changes
- Test with both SQLite and PostgreSQL
- Document migration steps
- Provide rollback procedures

### Documentation

Update documentation for:

- New features
- API changes
- Configuration changes
- Deployment changes

## Project Structure

```
hodlxxi.com/
├── app/
│   ├── app.py              # Main application
│   ├── static/             # Static files
│   └── [docs]              # Documentation
├── tests/                  # Test files
├── .github/
│   └── workflows/          # CI/CD workflows
├── requirements.txt        # Dependencies
└── [config files]
```

## Testing Guidelines

### Writing Tests

```python
import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_lnurl_auth_create(client):
    """Test LNURL-auth session creation"""
    response = client.post('/api/lnurl-auth/create')
    assert response.status_code == 200
    data = response.get_json()
    assert 'lnurl' in data
    assert 'session_id' in data
```

### Test Coverage

- Aim for >80% coverage
- Test edge cases and error conditions
- Test authentication and authorization
- Test rate limiting
- Test input validation

## Release Process

1. Version bump in appropriate files
2. Update CHANGELOG.md
3. Tag release: `git tag v1.2.3`
4. Push tags: `git push --tags`
5. Create GitHub release
6. Deploy to production

## Getting Help

- **Documentation**: Check [app/README.md](app/README.md)
- **Issues**: Search existing issues
- **Discussions**: Use GitHub Discussions
- **Email**: support@hodlxxi.com

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in documentation (for significant contributions)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to HODLXXI!
