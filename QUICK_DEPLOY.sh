#!/bin/bash
#
# Quick Production Deployment Script
# Universal Bitcoin Identity Layer
#
# Run this on a fresh Ubuntu 22.04 VPS with:
#   bash <(curl -s https://raw.githubusercontent.com/hodlxxi/Universal-Bitcoin-Identity-Layer/main/QUICK_DEPLOY.sh)
#
# Prerequisites:
#   - Ubuntu 22.04 / Debian 11+
#   - Domain DNS configured (A record pointing to server IP)
#   - Root or sudo access
#

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Universal Bitcoin Identity Layer - Quick Deploy"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Prompt for domain
read -p "Enter your domain (e.g., hodlxxi.com): " DOMAIN
export DOMAIN

# Prompt for email
read -p "Enter email for SSL certificate: " EMAIL
export EMAIL

echo ""
echo "Starting deployment for: $DOMAIN"
echo ""

# ============================================================================
# COMMAND 1: Install system dependencies
# ============================================================================
echo "📦 [1/7] Installing system dependencies..."
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    postgresql \
    redis-server \
    git \
    curl \
    build-essential \
    libpq-dev

echo "✅ System dependencies installed"
echo ""

# ============================================================================
# COMMAND 2: Clone repository
# ============================================================================
echo "📥 [2/7] Cloning repository..."
if [ ! -d "/srv/chat" ]; then
    sudo mkdir -p /srv
    sudo git clone https://github.com/hodlxxi/Universal-Bitcoin-Identity-Layer.git /srv/chat
    sudo chown -R $USER:$USER /srv/chat
else
    echo "Repository already exists at /srv/chat"
fi
cd /srv/chat

echo "✅ Repository cloned"
echo ""

# ============================================================================
# COMMAND 3: Generate secrets and configure environment
# ============================================================================
echo "🔐 [3/7] Generating secrets and configuring environment..."

# Generate secrets
FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
RPC_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")

# Create .env file
cat > .env <<EOF
# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=false
FLASK_SECRET_KEY=$FLASK_SECRET

# Application Settings
APP_NAME=HODLXXI
APP_VERSION=1.0.0
APP_HOST=0.0.0.0
APP_PORT=5000

# Bitcoin RPC Configuration (configure Bitcoin Core separately)
RPC_HOST=127.0.0.1
RPC_PORT=8332
RPC_USER=bitcoinrpc
RPC_PASSWORD=$RPC_PASSWORD
RPC_WALLET=

# JWT Configuration
JWT_SECRET=$FLASK_SECRET
JWT_ALGORITHM=RS256
JWT_ISSUER=https://$DOMAIN
JWT_AUDIENCE=hodlxxi
JWT_EXPIRATION_HOURS=24
JWKS_DIR=keys

# Token Configuration
TOKEN_TTL=3600

# LNURL Configuration
LNURL_BASE_URL=https://$DOMAIN

# CORS Configuration
CORS_ORIGINS=https://$DOMAIN
SOCKETIO_CORS=https://$DOMAIN

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT=100/hour

# Security Configuration (PRODUCTION)
FORCE_HTTPS=true
SECURE_COOKIES=true
CSRF_ENABLED=true

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/app.log

# Database Configuration (PostgreSQL)
DATABASE_URL=postgresql://hodlxxi:$DB_PASSWORD@localhost:5432/hodlxxi

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# Session Configuration
SESSION_LIFETIME_HOURS=24
EOF

echo "✅ Secrets generated and .env configured"
echo ""

# ============================================================================
# COMMAND 4: Set up PostgreSQL database
# ============================================================================
echo "🗄️  [4/7] Setting up PostgreSQL database..."

sudo -u postgres psql <<SQL
-- Create user
CREATE USER hodlxxi WITH PASSWORD '$DB_PASSWORD';

-- Create database
CREATE DATABASE hodlxxi OWNER hodlxxi;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE hodlxxi TO hodlxxi;
SQL

echo "✅ PostgreSQL database created"
echo ""

# ============================================================================
# COMMAND 5: Install Python dependencies and initialize database
# ============================================================================
echo "🐍 [5/7] Installing Python dependencies..."

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "✅ Python dependencies installed"
echo ""

echo "🗄️  [5/7] Initializing database..."
python scripts/db_init.py

echo "✅ Database initialized"
echo ""

# ============================================================================
# COMMAND 6: Create systemd service
# ============================================================================
echo "⚙️  [6/7] Creating systemd service..."

sudo tee /etc/systemd/system/app.service > /dev/null <<EOF
[Unit]
Description=HODLXXI Bitcoin Identity Layer
After=network.target postgresql.service redis.service

[Service]
Type=notify
User=hodlxxi
Group=hodlxxi
WorkingDirectory=/srv/chat
Environment="PATH=/srv/chat/.venv/bin"
EnvironmentFile=/srv/chat/.env
ExecStart=/srv/chat/.venv/bin/gunicorn \\
    --worker-class gevent \\
    --workers 4 \\
    --bind 127.0.0.1:5000 \\
    --timeout 120 \\
    --access-logfile /var/log/hodlxxi/access.log \\
    --error-logfile /var/log/hodlxxi/error.log \\
    --log-level info \\
    wsgi:application

Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/chat/logs /srv/chat/keys

[Install]
WantedBy=multi-user.target
EOF

# Create hodlxxi user if doesn't exist
if ! id "hodlxxi" &>/dev/null; then
    sudo useradd -r -s /bin/false hodlxxi
fi

# Create log directory
sudo mkdir -p /var/log/hodlxxi
sudo chown hodlxxi:hodlxxi /var/log/hodlxxi

# Set ownership
sudo chown -R hodlxxi:hodlxxi /srv/chat

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable app
sudo systemctl start app

echo "✅ Application service created and started"
echo ""

# ============================================================================
# COMMAND 7: Run production deployment script
# ============================================================================
echo "🚀 [7/7] Running production deployment (Nginx + SSL + Security)..."
echo ""

# Update domain in deploy script
sudo sed -i "s/DOMAIN=\"hodlxxi.com\"/DOMAIN=\"$DOMAIN\"/" deployment/deploy-production.sh

# Run deployment (this handles Nginx, SSL, firewall, backups)
sudo bash deployment/deploy-production.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ DEPLOYMENT COMPLETE!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🌐 Your application is now running at:"
echo "   https://$DOMAIN"
echo ""
echo "🔍 Health check:"
echo "   https://$DOMAIN/health"
echo ""
echo "📖 OpenID Configuration:"
echo "   https://$DOMAIN/.well-known/openid-configuration"
echo ""
echo "📝 Next steps:"
echo "   1. Configure Bitcoin Core RPC (update .env with real credentials)"
echo "   2. Test OAuth flow: https://$DOMAIN"
echo "   3. Set up external monitoring"
echo "   4. Test backup restoration: sudo /usr/local/bin/hodlxxi-restore.sh"
echo ""
echo "📊 View logs:"
echo "   sudo journalctl -u app -f"
echo ""
echo "🔒 Secrets saved in: /srv/chat/.env"
echo "    Keep this file secure and backed up!"
echo ""
