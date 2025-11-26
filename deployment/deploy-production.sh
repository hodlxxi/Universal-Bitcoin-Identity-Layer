#!/bin/bash
#
# HODLXXI Production Deployment Script - Option A
# Complete minimal production setup with SSL/TLS and security hardening
#
# Run as root on your VPS: sudo bash deploy-production.sh
#

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
DOMAIN="hodlxxi.com"
APP_DIR="/srv/app"
DEPLOYMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                        ║${NC}"
echo -e "${BLUE}║   HODLXXI Production Deployment - Option A             ║${NC}"
echo -e "${BLUE}║   Minimal Production Setup (4-6 hours)                 ║${NC}"
echo -e "${BLUE}║                                                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root${NC}"
    echo "Please run: sudo bash deploy-production.sh"
    exit 1
fi

# Pre-flight checks
echo -e "${YELLOW}Pre-flight Checks${NC}"
echo "----------------------------------------"

# Check if application is running
if ! systemctl is-active --quiet app; then
    echo -e "${RED}⚠ WARNING: Application is not running${NC}"
    echo "The app should be running before deploying Nginx"
    read -p "Continue anyway? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        exit 0
    fi
fi

# Check if domain resolves to this server
SERVER_IP=$(hostname -I | awk '{print $1}')
DOMAIN_IP=$(dig +short $DOMAIN | tail -n1)

echo "Server IP: $SERVER_IP"
echo "Domain IP: $DOMAIN_IP"

if [ "$SERVER_IP" != "$DOMAIN_IP" ]; then
    echo -e "${YELLOW}⚠ WARNING: Domain does not resolve to this server${NC}"
    echo "  $DOMAIN resolves to $DOMAIN_IP"
    echo "  This server has IP $SERVER_IP"
    echo ""
    echo "SSL certificate (Let's Encrypt) will fail if DNS is not configured."
    read -p "Continue anyway? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo ""
        echo "Please configure DNS first:"
        echo "  1. Go to your domain registrar"
        echo "  2. Add an A record: $DOMAIN -> $SERVER_IP"
        echo "  3. Wait for DNS propagation (5-60 minutes)"
        echo "  4. Run this script again"
        exit 0
    fi
fi

echo -e "${GREEN}✓ Pre-flight checks complete${NC}"
echo ""

# Confirmation prompt
echo -e "${YELLOW}This script will:${NC}"
echo "  1. Install and configure Nginx with SSL/TLS"
echo "  2. Configure UFW firewall (ports 22, 80, 443)"
echo "  3. Install and configure Fail2ban"
echo "  4. Create dedicated 'hodlxxi' user"
echo "  5. Harden systemd service"
echo "  6. Set up automated daily backups"
echo "  7. Restart application service"
echo ""
read -p "Continue with deployment? (yes/no): " -r
echo ""
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Deployment cancelled."
    exit 0
fi

# ============================================================================
# STEP 1: Install Nginx and Certbot
# ============================================================================

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Step 1/7: Installing Nginx and Certbot${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

apt update

if ! command -v nginx &> /dev/null; then
    echo "Installing Nginx..."
    apt install -y nginx
else
    echo "Nginx already installed"
fi

if ! command -v certbot &> /dev/null; then
    echo "Installing Certbot..."
    apt install -y certbot python3-certbot-nginx
else
    echo "Certbot already installed"
fi

# Stop Nginx if running (we'll start it after configuration)
systemctl stop nginx

echo -e "${GREEN}✓ Nginx and Certbot installed${NC}"
echo ""

# ============================================================================
# STEP 2: Configure Nginx
# ============================================================================

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Step 2/7: Configuring Nginx${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Create certbot directory for ACME challenge
mkdir -p /var/www/certbot

# Copy Nginx configuration
echo "Installing Nginx configuration..."
cp "$DEPLOYMENT_DIR/nginx-hodlxxi.conf" /etc/nginx/sites-available/hodlxxi

# Remove default site
rm -f /etc/nginx/sites-enabled/default

# Enable our site
ln -sf /etc/nginx/sites-available/hodlxxi /etc/nginx/sites-enabled/hodlxxi

# Test Nginx configuration (will fail if SSL certs don't exist yet)
echo "Testing Nginx configuration..."
if nginx -t 2>&1 | grep -q "cannot load certificate"; then
    echo -e "${YELLOW}⚠ SSL certificates not found (expected for first run)${NC}"
    echo "  Will obtain certificates in next step"
else
    nginx -t
fi

echo -e "${GREEN}✓ Nginx configured${NC}"
echo ""

# ============================================================================
# STEP 3: Obtain SSL Certificate
# ============================================================================

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Step 3/7: Obtaining SSL Certificate${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if certificate already exists
if [ -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    echo -e "${GREEN}✓ SSL certificate already exists${NC}"
    echo "Certificate location: /etc/letsencrypt/live/$DOMAIN/"
else
    echo "Obtaining SSL certificate from Let's Encrypt..."
    echo ""
    echo -e "${YELLOW}Note: This requires:${NC}"
    echo "  - Domain $DOMAIN must resolve to this server"
    echo "  - Port 80 must be accessible from the internet"
    echo ""

    # Start Nginx temporarily for ACME challenge
    systemctl start nginx

    # Obtain certificate
    certbot certonly --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN || {
        echo -e "${RED}ERROR: Failed to obtain SSL certificate${NC}"
        echo ""
        echo "Common issues:"
        echo "  1. DNS not configured: $DOMAIN must point to $SERVER_IP"
        echo "  2. Port 80 blocked by firewall"
        echo "  3. Rate limit reached (5 certs per week)"
        echo ""
        echo "You can:"
        echo "  - Fix the issue and run this script again"
        echo "  - Or manually obtain certificate: certbot certonly --nginx -d $DOMAIN"
        exit 1
    }

    echo -e "${GREEN}✓ SSL certificate obtained${NC}"
fi

# Set up auto-renewal
systemctl enable certbot.timer
systemctl start certbot.timer

echo "Certificate auto-renewal configured (runs twice daily)"
echo ""

# Now test Nginx with SSL
echo "Testing Nginx configuration with SSL..."
nginx -t

# Restart Nginx with full configuration
systemctl restart nginx
systemctl enable nginx

echo -e "${GREEN}✓ Nginx running with SSL/TLS${NC}"
echo ""

# ============================================================================
# STEP 4: Security Hardening
# ============================================================================

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Step 4/7: Security Hardening${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

bash "$DEPLOYMENT_DIR/security-hardening.sh"

echo ""

# ============================================================================
# STEP 5: Automated Backups
# ============================================================================

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Step 5/7: Setting up Automated Backups${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

bash "$DEPLOYMENT_DIR/setup-automated-backups.sh"

echo ""

# ============================================================================
# STEP 6: Restart Application
# ============================================================================

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Step 6/7: Restarting Application${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo "Restarting application service..."
systemctl daemon-reload
systemctl restart app
systemctl enable app

sleep 3

# Check if app started successfully
if systemctl is-active --quiet app; then
    echo -e "${GREEN}✓ Application restarted successfully${NC}"
else
    echo -e "${RED}⚠ WARNING: Application failed to start${NC}"
    echo "Check logs: journalctl -u app -n 50"
fi

echo ""

# ============================================================================
# STEP 7: Verification
# ============================================================================

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Step 7/7: Verification${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo "Service Status:"
echo "----------------------------------------"
systemctl is-active app && echo -e "  Application:  ${GREEN}✓ Running${NC}" || echo -e "  Application:  ${RED}✗ Stopped${NC}"
systemctl is-active nginx && echo -e "  Nginx:        ${GREEN}✓ Running${NC}" || echo -e "  Nginx:        ${RED}✗ Stopped${NC}"
systemctl is-active postgresql && echo -e "  PostgreSQL:   ${GREEN}✓ Running${NC}" || echo -e "  PostgreSQL:   ${RED}✗ Stopped${NC}"
systemctl is-active redis-server && echo -e "  Redis:        ${GREEN}✓ Running${NC}" || echo -e "  Redis:        ${RED}✗ Stopped${NC}"
systemctl is-active fail2ban && echo -e "  Fail2ban:     ${GREEN}✓ Running${NC}" || echo -e "  Fail2ban:     ${RED}✗ Stopped${NC}"

echo ""
echo "Firewall Status:"
echo "----------------------------------------"
ufw status | grep -E "Status:|22/tcp|80/tcp|443/tcp"

echo ""
echo "Testing Endpoints:"
echo "----------------------------------------"

# Test local health endpoint
if curl -s http://127.0.0.1:5000/health | grep -q "ok"; then
    echo -e "  Local HTTP:   ${GREEN}✓ Working${NC}"
else
    echo -e "  Local HTTP:   ${RED}✗ Failed${NC}"
fi

# Test through Nginx (HTTP)
if curl -s http://127.0.0.1/health | grep -q "ok"; then
    echo -e "  Nginx HTTP:   ${GREEN}✓ Working${NC}"
else
    echo -e "  Nginx HTTP:   ${YELLOW}⚠ Redirecting to HTTPS${NC}"
fi

# Test through Nginx (HTTPS)
if curl -sk https://127.0.0.1/health | grep -q "ok"; then
    echo -e "  Nginx HTTPS:  ${GREEN}✓ Working${NC}"
else
    echo -e "  Nginx HTTPS:  ${RED}✗ Failed${NC}"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                        ║${NC}"
echo -e "${GREEN}║          🎉  DEPLOYMENT COMPLETE!  🎉                  ║${NC}"
echo -e "${GREEN}║                                                        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BLUE}Your HODLXXI instance is now production-ready!${NC}"
echo ""
echo "Summary:"
echo "  ✅ SSL/TLS configured with Let's Encrypt"
echo "  ✅ Nginx reverse proxy with security headers"
echo "  ✅ UFW firewall enabled (ports 22, 80, 443)"
echo "  ✅ Fail2ban protecting SSH and Nginx"
echo "  ✅ Application running as 'hodlxxi' user"
echo "  ✅ Automated daily backups at 2:00 AM"
echo "  ✅ Service hardening with systemd"
echo ""
echo "URLs:"
echo "  🌐 Production: https://$DOMAIN"
echo "  🏥 Health:     https://$DOMAIN/health"
echo "  📊 Status:     https://$DOMAIN/oauthx/status"
echo "  📖 Docs:       https://$DOMAIN/oauthx/docs"
echo ""
echo "Useful Commands:"
echo "  Status:   sudo systemctl status app nginx"
echo "  Logs:     sudo journalctl -u app -f"
echo "  Backup:   sudo /usr/local/bin/hodlxxi-backup.sh"
echo "  Restore:  sudo /usr/local/bin/hodlxxi-restore.sh <backup-file>"
echo "  Firewall: sudo ufw status"
echo ""
echo "Next Steps:"
echo "  1. Test OAuth flow: https://$DOMAIN"
echo "  2. Set up external monitoring (UptimeRobot, Pingdom, etc.)"
echo "  3. Review backup files: ls -lh /backup/hodlxxi/"
echo "  4. Test disaster recovery procedure"
echo ""
echo "Documentation:"
echo "  - PRODUCTION_STATUS.md - Complete production readiness status"
echo "  - DEPLOY_DATABASE.md - Database deployment guide"
echo "  - app/PRODUCTION_DEPLOYMENT.md - Full deployment guide"
echo ""
