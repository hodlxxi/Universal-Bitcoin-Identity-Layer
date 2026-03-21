# Blueprint Architecture & Migration Guide

## Overview

This document describes the modular blueprint architecture for the Universal Bitcoin Identity Layer and provides a migration guide from the monolithic structure.

## Architecture Overview

### Application Factory Pattern

The application uses the **factory pattern** for better testability, configuration management, and modular design:

```
app/
├── factory.py          # Application factory
├── blueprints/         # Modular route blueprints
│   ├── __init__.py
│   ├── admin.py       # Health, metrics, monitoring
│   ├── auth.py        # Authentication (Bitcoin signatures, guest login)
│   ├── bitcoin.py     # Bitcoin RPC operations
│   ├── lnurl.py       # LNURL-Auth challenges
│   ├── oauth.py       # OAuth2/OIDC flows
│   └── ui.py          # Frontend routes
├── utils.py           # Shared utilities
├── jwks.py            # JWKS management with rotation
├── security.py        # Security middleware
├── config.py          # Configuration management
├── database.py        # Database initialization
└── oidc.py            # OIDC discovery (existing)
```

### Blueprint Structure

Each blueprint is **self-contained** with:
- Route definitions
- Request handlers
- Input validation
- Rate limiting
- Audit logging

## Blueprint Details

### 1. Admin Blueprint (`/`)

**Endpoints:**
- `GET /health` - Comprehensive health check
- `GET /health/live` - Kubernetes liveness probe
- `GET /health/ready` - Kubernetes readiness probe
- `GET /metrics` - JSON metrics
- `GET /metrics/prometheus` - Prometheus metrics
- `GET /turn_credentials` - TURN server credentials

**Purpose:** Operational monitoring and infrastructure health

**Rate Limits:** 100/hour per IP

**Example:**
```python
from app.blueprints.admin import admin_bp
app.register_blueprint(admin_bp)
```

### 2. Auth Blueprint (`/`)

**Endpoints:**
- `POST /verify_signature` - Verify Bitcoin signature
- `POST /guest_login` - Guest/PIN login
- `GET /logout` - Clear session

**Purpose:** User authentication and session management

**Rate Limits:**
- `/verify_signature`: 10/minute
- `/guest_login`: 20/minute

**Example:**
```python
from app.blueprints.auth import auth_bp
app.register_blueprint(auth_bp)
```

### 3. Bitcoin Blueprint (`/api`)

**Endpoints:**
- `GET /api/rpc/<cmd>` - Safe RPC commands (read-only)
- `POST /api/verify` - Proof of funds verification
- `POST /api/decode_raw_script` - Decode Bitcoin scripts
- `GET /api/descriptors` - List wallet descriptors

**Purpose:** Bitcoin Core RPC operations

**Rate Limits:** 30/minute per endpoint

**Security:** Whitelist of safe commands only

**Example:**
```python
from app.blueprints.bitcoin import bitcoin_bp
app.register_blueprint(bitcoin_bp, url_prefix="/api")
```

### 4. LNURL Blueprint (`/api/lnurl-auth`)

**Endpoints:**
- `POST /api/lnurl-auth/create` - Create LNURL challenge
- `GET /api/lnurl-auth/callback/<session_id>` - LNURL callback
- `GET /api/lnurl-auth/check/<session_id>` - Check verification
- `GET /api/lnurl-auth/params` - Get LNURL parameters

**Purpose:** Lightning Network authentication

**Rate Limits:** 20/minute

**Example:**
```python
from app.blueprints.lnurl import lnurl_bp
app.register_blueprint(lnurl_bp, url_prefix="/api/lnurl-auth")
```

### 5. OAuth Blueprint (`/oauth`)

**Endpoints:**
- `POST /oauth/register` - Dynamic client registration
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `POST /oauth/introspect` - Token introspection

**Purpose:** OAuth 2.0 / OpenID Connect flows

**Rate Limits:** 30/minute

**Security:** PKCE required, RS256 JWTs

**Example:**
```python
from app.blueprints.oauth import oauth_bp
app.register_blueprint(oauth_bp, url_prefix="/oauth")
```

### 6. UI Blueprint (`/`)

**Endpoints:**
- `GET /` - Homepage
- `GET /dashboard` - User dashboard (requires auth)
- `GET /playground` - API testing playground

**Purpose:** Frontend HTML pages

**Rate Limits:** General limits apply

**Example:**
```python
from app.blueprints.ui import ui_bp
app.register_blueprint(ui_bp)
```

## Application Factory

### Factory Function

**File:** `app/factory.py`

```python
def create_app(config_override: Optional[AppConfig] = None) -> Flask:
    """
    Create and configure Flask application.

    Args:
        config_override: Optional config for testing

    Returns:
        Configured Flask app
    """
    app = Flask(__name__)

    # Load configuration
    cfg = config_override or get_config()
    app.config["APP_CONFIG"] = cfg

    # Initialize JWKS with rotation
    jwks_doc, kid = ensure_rsa_keypair(cfg["JWKS_DIR"])
    app.config["JWKS_DOCUMENT"] = jwks_doc
    app.config["JWT_KID"] = kid

    # Initialize security
    init_security(app, cfg)

    # Initialize database
    init_all()
    init_audit_logger()

    # Register blueprints
    register_blueprints(app)

    # Register error handlers
    register_error_handlers(app)

    return app
```

### Benefits

1. **Testability:** Easy to create test apps with different configs
2. **Modularity:** Blueprints can be developed/tested independently
3. **Configuration:** Clear separation of configuration and code
4. **Reusability:** Same factory can create multiple app instances

## JWKS Enhancement

### Key Rotation Support

**Features:**
- Automatic rotation based on age (default: 90 days)
- Multiple concurrent keys (primary + retired)
- Graceful retirement (maintains old keys for verification)
- Manual rotation support

**Configuration:**
```bash
JWKS_DIR=/var/lib/bitcoin-identity/keys
JWKS_ROTATION_DAYS=90
JWKS_MAX_RETIRED_KEYS=3
```

**Implementation:**
```python
from app.jwks import ensure_rsa_keypair, rotate_keys_manually

# Automatic rotation on app start
jwks_doc, kid = ensure_rsa_keypair(
    jwks_dir="/path/to/keys",
    rotation_days=90,
    max_retired_keys=3
)

# Manual rotation (e.g., after compromise)
new_kid = rotate_keys_manually("/path/to/keys")
```

## Migration Guide

### Phase 1: Parallel Deployment (Current State)

**Status:** Factory and blueprints exist alongside monolithic app.py

**What works:**
- New modular code in `app/blueprints/`
- Enhanced JWKS management
- Comprehensive test suite
- Application factory pattern

**What's preserved:**
- Existing `app/app.py` with all routes
- Backward compatibility
- No breaking changes

**Usage:**
```python
# Option 1: Use old app (default)
from app.app import create_app
app = create_app()

# Option 2: Use new factory
from app.factory import create_app
app = create_app()
```

### Phase 2: Incremental Migration

**Approach:** Gradually move routes from `app.py` to blueprints

**Steps:**

1. **Choose a blueprint** (start with admin or UI)

2. **Identify routes** to migrate:
   ```python
   # app/app.py - OLD
   @app.route("/health")
   def health():
       return jsonify({"status": "healthy"})
   ```

3. **Move to blueprint:**
   ```python
   # app/blueprints/admin.py - NEW
   from flask import Blueprint

   admin_bp = Blueprint("admin", __name__)

   @admin_bp.route("/health")
   def health():
       return jsonify({"status": "healthy"})
   ```

4. **Comment out old route** in app.py:
   ```python
   # Migrated to admin blueprint
   # @app.route("/health")
   # def health():
   #     return jsonify({"status": "healthy"})
   ```

5. **Test thoroughly:**
   ```bash
   pytest tests/test_admin.py -v
   curl http://localhost:5000/health
   ```

6. **Repeat** for remaining routes

### Phase 3: Complete Migration

**When complete:**
- All routes in blueprints
- `app/app.py` contains only legacy compatibility code
- Factory pattern used everywhere
- Full test coverage

**Final structure:**
```
app/
├── factory.py          # Primary app factory
├── blueprints/         # All routes here
├── app.py             # Minimal compatibility wrapper (deprecated)
└── wsgi.py            # Uses factory.create_app()
```

## Utility Functions

### Shared Utilities (`app/utils.py`)

Extracted common functions:

```python
# Bitcoin operations
get_rpc_connection()
derive_legacy_address_from_pubkey()
is_valid_pubkey()
extract_pubkey_from_op_if()
extract_pubkey_from_op_else()
extract_script_from_any_descriptor()

# Authentication
generate_challenge()
load_guest_pins()
get_special_users()

# Validation
validate_hex_format()
secure_random_hex()
```

### Usage in Blueprints

```python
from app.utils import get_rpc_connection, is_valid_pubkey

@bitcoin_bp.route("/api/balance")
def get_balance():
    rpc = get_rpc_connection()
    balance = rpc.getbalance()
    return jsonify({"balance": balance})
```

## Testing

### Test Structure

```
tests/
├── conftest.py               # Shared fixtures
├── test_auth_flows.py       # Authentication tests (130+ tests)
├── test_bitcoin_flows.py    # Bitcoin operations (90+ tests)
├── test_oauth_flows.py      # OAuth2/OIDC flows (80+ tests)
└── test_jwks_rotation.py    # JWKS rotation (70+ tests)
```

### Running Tests

```bash
# All tests
pytest tests/ -v

# Specific blueprint
pytest tests/test_auth_flows.py -v

# With coverage
pytest tests/ --cov=app --cov-report=html

# Specific test class
pytest tests/test_auth_flows.py::TestBitcoinSignatureAuth -v
```

### Test Fixtures

```python
@pytest.fixture
def app():
    """Create test application."""
    test_config = {
        "FLASK_SECRET_KEY": "test_secret",
        "FLASK_ENV": "testing",
        "JWKS_DIR": "/tmp/test_jwks",
        "DATABASE_URL": "sqlite:///:memory:",
        "TESTING": True,
    }
    app = create_app(test_config)
    return app

@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()
```

## Configuration Management

### Environment-Based Config

**File:** `app/config.py`

```python
def get_config() -> AppConfig:
    """Load configuration from environment."""
    cfg = {
        "FLASK_SECRET_KEY": os.getenv("FLASK_SECRET_KEY"),
        "FLASK_ENV": os.getenv("FLASK_ENV", "development"),
        "JWKS_DIR": os.getenv("JWKS_DIR", "keys/"),
        "DATABASE_URL": os.getenv("DATABASE_URL"),
        # ... more config
    }

    # Validate in production
    if cfg["FLASK_ENV"] == "production":
        validate_production_config(cfg)

    return cfg
```

### Config Validation

```python
def validate_production_config(cfg):
    """Ensure production requirements met."""
    required = [
        "FLASK_SECRET_KEY",
        "DATABASE_URL",
        "REDIS_URL",
        "JWT_ISSUER",
    ]

    for key in required:
        if not cfg.get(key):
            raise ValueError(f"Production requires {key}")
```

## Deployment

### Using Factory in Production

**WSGI (Gunicorn):**
```python
# wsgi.py
from app.factory import create_app

app = create_app()
```

**Run:**
```bash
gunicorn wsgi:app -b 0.0.0.0:5000 -w 4
```

**Systemd:**
```ini
[Service]
WorkingDirectory=/opt/bitcoin-identity
Environment="FLASK_ENV=production"
EnvironmentFile=/etc/bitcoin-identity/secrets.env
ExecStart=/opt/bitcoin-identity/venv/bin/gunicorn wsgi:app -b 127.0.0.1:5000 -w 4
```

## Best Practices

### 1. Blueprint Organization

- **One blueprint per domain** (auth, bitcoin, oauth, etc.)
- **Related routes together**
- **Clear URL prefixes**

### 2. Error Handling

```python
@auth_bp.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "bad_request", "message": str(e)}), 400
```

### 3. Rate Limiting

```python
from app.security import limiter

@auth_bp.route("/verify_signature", methods=["POST"])
@limiter.limit("10 per minute")
def verify_signature():
    # Implementation
    pass
```

### 4. Audit Logging

```python
from app.audit_logger import get_audit_logger

audit_logger = get_audit_logger()

@auth_bp.route("/login")
def login():
    audit_logger.log_event(
        "auth.login_attempt",
        pubkey=pubkey,
        ip=request.remote_addr
    )
```

### 5. Testing

```python
# Test each blueprint in isolation
def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "healthy"
```

## Future Enhancements

### Planned Improvements

1. **GraphQL API:** Add GraphQL blueprint for flexible queries
2. **WebSocket Support:** Real-time updates via WebSocket blueprint
3. **API Versioning:** `/api/v1/`, `/api/v2/` blueprints
4. **Admin Panel:** Dedicated admin blueprint with authentication
5. **Metrics Dashboard:** Enhanced monitoring blueprint

### Extension Points

Blueprints make it easy to add new features:

```python
# app/blueprints/graphql.py
from flask import Blueprint
from flask_graphql import GraphQLView

graphql_bp = Blueprint("graphql", __name__)

graphql_bp.add_url_rule(
    "/graphql",
    view_func=GraphQLView.as_view("graphql", schema=schema)
)
```

## Resources

- [Flask Blueprints Documentation](https://flask.palletsprojects.com/en/latest/blueprints/)
- [Application Factory Pattern](https://flask.palletsprojects.com/en/latest/patterns/appfactories/)
- [Testing Flask Applications](https://flask.palletsprojects.com/en/latest/testing/)
