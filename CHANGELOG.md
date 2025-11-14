# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive professional CV for repository creator
- Modular blueprint architecture with enhanced security
- OIDC security hardening and RS256 token support
- OIDC discovery endpoint (`/.well-known/openid-configuration`)
- JWKS endpoint for public key distribution
- Prometheus metrics endpoint (`/metrics/prometheus`)
- Redis-backed rate limiting with in-memory fallback
- Postgres persistence layer with SQLAlchemy models
- Lightning Network (LNURL-auth) authentication support
- Production-ready configuration validation
- Typed configuration surface with environment variable support
- Comprehensive documentation suite

### Changed
- Refactored Flask application to use blueprint architecture
- Improved code quality and fixed deprecations
- Made HTTPS optional by default for development environments
- Hardened secret handling and validation
- Updated landing page to match developer preview state
- Refreshed module and deployment guides
- Enhanced root README with architecture overview

### Fixed
- Various code quality issues and deprecation warnings
- Security vulnerabilities in configuration handling

### Security
- Enforced RS256 asymmetric signing for JWT tokens
- Added PKCE validation for OAuth2 flows
- Implemented secure cookie handling
- Added CSRF protection capabilities
- Improved secret validation and enforcement

## [0.1.0] - Initial Development

### Added
- Initial OAuth2/OpenID Connect implementation
- Basic Flask application structure
- Bitcoin RPC integration support
- Health check endpoint
- Basic authentication flows

---

## Release Process

1. Update version number in appropriate files
2. Update this CHANGELOG.md with release date
3. Create git tag: `git tag v1.0.0`
4. Push tags: `git push --tags`
5. Create GitHub release
6. Deploy to production

## Version Numbering

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

[Unreleased]: https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer/compare/HEAD
