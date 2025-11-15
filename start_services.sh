#!/bin/bash
#
# Quick Start Script for Universal Bitcoin Identity Layer
# Starts all required services and the Flask application
#

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Starting Universal Bitcoin Identity Layer Services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Start PostgreSQL
echo "📦 Starting PostgreSQL..."
if ! service postgresql status > /dev/null 2>&1; then
    service postgresql start
    sleep 2
    echo "✅ PostgreSQL started"
else
    echo "✅ PostgreSQL already running"
fi

# 2. Start Redis
echo "📦 Starting Redis..."
if ! pgrep redis-server > /dev/null 2>&1; then
    redis-server --daemonize yes
    sleep 1
    echo "✅ Redis started"
else
    echo "✅ Redis already running"
fi

# 3. Check for .env file
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Creating minimal configuration..."

    # Generate secrets
    FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

    cat > .env <<EOF
# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=true
FLASK_SECRET_KEY=$FLASK_SECRET

# Application Settings
APP_HOST=0.0.0.0
APP_PORT=5000

# Bitcoin RPC Configuration (configure later)
RPC_HOST=127.0.0.1
RPC_PORT=8332
RPC_USER=bitcoinrpc
RPC_PASSWORD=changeme

# JWT Configuration
JWT_SECRET=$FLASK_SECRET
JWT_ALGORITHM=RS256
JWT_ISSUER=http://localhost:5000
JWT_AUDIENCE=development
JWT_EXPIRATION_HOURS=24
JWKS_DIR=keys

# Database Configuration
DATABASE_URL=postgresql://postgres@localhost:5432/hodlxxi

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# Security (Development mode)
FORCE_HTTPS=false
SECURE_COOKIES=false
CSRF_ENABLED=false

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT=100/hour

# Logging
LOG_LEVEL=INFO
EOF

    echo "✅ Created .env file"
fi

# 4. Setup database if needed
echo "📦 Setting up database..."
if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw hodlxxi; then
    echo "Creating database..."
    sudo -u postgres psql <<SQL
CREATE DATABASE hodlxxi;
SQL
    echo "✅ Database created"
else
    echo "✅ Database already exists"
fi

# 5. Install Python dependencies if needed
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment and installing dependencies..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip --quiet
    pip install -r requirements.txt --quiet
    echo "✅ Dependencies installed"
else
    echo "✅ Virtual environment exists"
fi

# 6. Initialize database tables
if [ -f "scripts/db_init.py" ]; then
    echo "📦 Initializing database tables..."
    source .venv/bin/activate
    python scripts/db_init.py 2>/dev/null || echo "Database already initialized"
fi

# 7. Create keys directory
mkdir -p keys
mkdir -p logs

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ All services started!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Start the application with:"
echo "  source .venv/bin/activate"
echo "  python3 wsgi.py"
echo ""
echo "Or with Gunicorn (production):"
echo "  source .venv/bin/activate"
echo "  gunicorn -w 4 -b 0.0.0.0:5000 wsgi:application"
echo ""
