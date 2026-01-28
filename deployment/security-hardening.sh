#!/bin/bash
# HODLXXI Security Hardening Script
# Run as root: sudo bash security-hardening.sh

set -e  # Exit on error

echo "========================================"
echo "HODLXXI Security Hardening"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root${NC}"
    echo "Please run: sudo bash security-hardening.sh"
    exit 1
fi

echo -e "${GREEN}Step 1: Configure UFW Firewall${NC}"
echo "----------------------------------------"

# Install UFW if not already installed
if ! command -v ufw &> /dev/null; then
    echo "Installing UFW..."
    apt update
    apt install -y ufw
fi

# Reset UFW to default (just in case)
echo "Configuring UFW rules..."
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (IMPORTANT: Don't lock yourself out!)
ufw allow 22/tcp comment 'SSH'

# Allow HTTP and HTTPS
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# Allow Bitcoin Core (if needed from external)
# ufw allow 8333/tcp comment 'Bitcoin P2P'

# Enable UFW
echo "y" | ufw enable

# Show status
ufw status verbose

echo -e "${GREEN}✓ Firewall configured${NC}"
echo ""

echo -e "${GREEN}Step 2: Install and Configure Fail2ban${NC}"
echo "----------------------------------------"

# Install Fail2ban
if ! command -v fail2ban-client &> /dev/null; then
    echo "Installing Fail2ban..."
    apt install -y fail2ban
fi

# Create local configuration
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
# Ban duration: 1 hour
bantime = 3600

# Number of failures before ban
maxretry = 5

# Time window to track failures
findtime = 600

# Ignore localhost
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/hodlxxi-error.log

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/hodlxxi-error.log

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = /var/log/nginx/hodlxxi-access.log
EOF

# Restart Fail2ban
systemctl restart fail2ban
systemctl enable fail2ban

# Show status
fail2ban-client status

echo -e "${GREEN}✓ Fail2ban configured${NC}"
echo ""

echo -e "${GREEN}Step 3: Secure File Permissions${NC}"
echo "----------------------------------------"

# Secure .env file
if [ -f /srv/app/.env ]; then
    chmod 600 /srv/app/.env
    echo "✓ Secured /srv/app/.env (600)"
fi

# Secure Redis config
if [ -f /etc/redis/redis.conf ]; then
    chmod 640 /etc/redis/redis.conf
    chown redis:redis /etc/redis/redis.conf
    echo "✓ Secured /etc/redis/redis.conf (640)"
fi

# Secure PostgreSQL config (should already be secure, but verify)
if [ -d /etc/postgresql ]; then
    chmod 755 /etc/postgresql
    find /etc/postgresql -name "postgresql.conf" -exec chmod 644 {} \;
    find /etc/postgresql -name "pg_hba.conf" -exec chmod 640 {} \;
    echo "✓ Verified PostgreSQL config permissions"
fi

# Secure log directory
if [ -d /var/log/hodlxxi ]; then
    chmod 750 /var/log/hodlxxi
    echo "✓ Secured /var/log/hodlxxi (750)"
fi

echo -e "${GREEN}✓ File permissions secured${NC}"
echo ""

echo -e "${GREEN}Step 4: Create Dedicated Application User${NC}"
echo "----------------------------------------"

# Check if hodlxxi user exists
if ! id -u hodlxxi > /dev/null 2>&1; then
    echo "Creating hodlxxi user..."
    useradd -r -m -d /home/hodlxxi -s /bin/bash hodlxxi
    echo -e "${GREEN}✓ Created hodlxxi user${NC}"
else
    echo "hodlxxi user already exists"
fi

# Transfer ownership of application files
echo "Updating file ownership..."
chown -R hodlxxi:hodlxxi /srv/app

# Create log directory if it doesn't exist
mkdir -p /var/log/hodlxxi
chown hodlxxi:hodlxxi /var/log/hodlxxi
chmod 750 /var/log/hodlxxi

echo -e "${GREEN}✓ Application ownership transferred to hodlxxi user${NC}"
echo ""

echo -e "${GREEN}Step 5: Update systemd Service${NC}"
echo "----------------------------------------"

# Backup current service file
if [ -f /etc/systemd/system/app.service ]; then
    cp /etc/systemd/system/app.service /etc/systemd/system/app.service.backup
    echo "Backed up app.service to app.service.backup"
fi

# Create new service file with security hardening
cat > /etc/systemd/system/app.service <<'EOF'
[Unit]
Description=HODLXXI Bitcoin Identity Layer
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=hodlxxi
Group=hodlxxi
WorkingDirectory=/srv/app
EnvironmentFile=/srv/app/.env

# Start Gunicorn
ExecStart=/srv/app/venv/bin/gunicorn -k eventlet -w 1 -b 127.0.0.1:5000 wsgi:app

# Restart policy
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/app /var/log/hodlxxi
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo -e "${YELLOW}Note: Service file updated but not restarted yet${NC}"
echo -e "${YELLOW}You'll need to restart the service after Nginx is configured${NC}"
echo ""

echo -e "${GREEN}Step 6: SSH Hardening Recommendations${NC}"
echo "----------------------------------------"

if [ -f /etc/ssh/sshd_config ]; then
    echo "Current SSH configuration:"

    # Check if password authentication is disabled
    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        echo -e "${GREEN}✓ Password authentication: DISABLED (secure)${NC}"
    else
        echo -e "${YELLOW}⚠ Password authentication: ENABLED (consider disabling)${NC}"
        echo "  Recommendation: Set 'PasswordAuthentication no' in /etc/ssh/sshd_config"
    fi

    # Check if root login is disabled
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        echo -e "${GREEN}✓ Root login: DISABLED (secure)${NC}"
    else
        echo -e "${YELLOW}⚠ Root login: ENABLED (consider disabling)${NC}"
        echo "  Recommendation: Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
    fi
fi

echo ""
echo -e "${GREEN}========================================"
echo "Security Hardening Complete!"
echo "========================================${NC}"
echo ""
echo "Summary:"
echo "  ✓ UFW firewall configured (ports 22, 80, 443)"
echo "  ✓ Fail2ban installed and configured"
echo "  ✓ File permissions secured"
echo "  ✓ Dedicated 'hodlxxi' user created"
echo "  ✓ systemd service hardened"
echo ""
echo "Next steps:"
echo "  1. Install and configure Nginx"
echo "  2. Obtain SSL certificate with certbot"
echo "  3. Restart application service: sudo systemctl restart app"
echo ""
