# Production Deployment Guidelines

Comprehensive guide for deploying the HODLXXI API to production environments.

## Table of Contents
- [Infrastructure Requirements](#infrastructure-requirements)
- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Deployment Architecture](#deployment-architecture)
- [Environment Configuration](#environment-configuration)
- [Database Setup](#database-setup)
- [Bitcoin Core Setup](#bitcoin-core-setup)
- [Application Deployment](#application-deployment)
- [Reverse Proxy Configuration](#reverse-proxy-configuration)
- [SSL/TLS Setup](#ssltls-setup)
- [Monitoring and Logging](#monitoring-and-logging)
- [Backup and Recovery](#backup-and-recovery)
- [Scaling Strategies](#scaling-strategies)
- [Troubleshooting](#troubleshooting)

---

## Infrastructure Requirements

### Minimum System Requirements

**Application Server:**
- CPU: 4 cores (2.0 GHz+)
- RAM: 8 GB
- Storage: 50 GB SSD
- OS: Ubuntu 22.04 LTS / Debian 11+

**Bitcoin Core Node:**
- CPU: 4 cores (2.5 GHz+)
- RAM: 16 GB
- Storage: 1 TB SSD (for full node with txindex)
- OS: Ubuntu 22.04 LTS

**Recommended Production Setup:**
- CPU: 8 cores
- RAM: 32 GB
- Storage: 2 TB NVMe SSD
- Network: 100 Mbps+ dedicated
- Backup: Automated daily backups

### Supported Platforms

- **Cloud Providers:** AWS, Google Cloud, DigitalOcean, Linode
- **Bare Metal:** Dedicated servers
- **Container:** Docker, Kubernetes
- **Operating Systems:** Ubuntu 22.04+, Debian 11+, CentOS 8+

---

## Pre-Deployment Checklist

### Security Checklist

- [ ] SSL/TLS certificates obtained (Let's Encrypt or commercial)
- [ ] Strong passwords/passphrases generated (32+ characters)
- [ ] All secrets moved to environment variables or secrets manager
- [ ] Firewall configured (UFW/iptables)
- [ ] SSH key authentication enabled (password auth disabled)
- [ ] Fail2ban installed and configured
- [ ] Bitcoin wallet encrypted
- [ ] Database encryption enabled
- [ ] Security audit completed
- [ ] Penetration testing performed

### Application Checklist

- [ ] All dependencies updated to latest stable versions
- [ ] Environment variables configured
- [ ] Database migrations tested
- [ ] API endpoints tested
- [ ] WebSocket connections tested
- [ ] Rate limiting configured
- [ ] CORS configured properly
- [ ] Error handling tested
- [ ] Logging configured
- [ ] Health check endpoint working

### Infrastructure Checklist

- [ ] Domain name configured and DNS propagated
- [ ] Load balancer configured (if applicable)
- [ ] Reverse proxy configured (Nginx/Apache)
- [ ] SSL termination configured
- [ ] Monitoring tools installed
- [ ] Backup system configured
- [ ] Log rotation configured
- [ ] System updates applied

---

## Deployment Architecture

### Single Server Architecture (Small Scale)

```
┌─────────────────────────────────────┐
│         Internet / Users            │
└───────────────┬─────────────────────┘
                │
                v
┌───────────────────────────────────────┐
│         Nginx (Reverse Proxy)         │
│         SSL Termination               │
└───────────────┬───────────────────────┘
                │
                v
┌───────────────────────────────────────┐
│      Python Flask Application         │
│      - Gunicorn/uWSGI                 │
│      - WebSocket (SocketIO)           │
└───────────────┬───────────────────────┘
                │
                ├──────> SQLite/PostgreSQL
                │
                └──────> Bitcoin Core RPC
                         (localhost:8332)
```

### High Availability Architecture (Large Scale)

```
┌─────────────────────────────────────┐
│         Internet / Users            │
└───────────────┬─────────────────────┘
                │
                v
┌───────────────────────────────────────┐
│        Load Balancer (HAProxy)        │
│        SSL Termination                │
└───────┬─────────┬──────────┬──────────┘
        │         │          │
        v         v          v
    ┌──────┐ ┌──────┐  ┌──────┐
    │Nginx1│ │Nginx2│  │Nginx3│
    └───┬──┘ └───┬──┘  └───┬──┘
        │        │         │
        v        v         v
    ┌─────┐  ┌─────┐  ┌─────┐
    │App 1│  │App 2│  │App 3│
    └──┬──┘  └──┬──┘  └──┬──┘
       │        │         │
       └────────┴─────────┴──────> Redis (Session/Cache)
       │        │         │
       └────────┴─────────┴──────> PostgreSQL (Primary)
       │                              │
       │                              v
       │                          PostgreSQL (Replica)
       │
       └────────────────────────> Bitcoin Core (Full Node)
```

---

## Environment Configuration

### Environment Variables

Create `.env` file (NEVER commit to Git):

```bash
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=production
FLASK_SECRET_KEY=your-64-char-secret-key-here-use-secrets-token-hex-32
DEBUG=false

# JWT Configuration
JWT_SECRET_KEY=your-64-char-jwt-secret-here
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRES=3600
JWT_REFRESH_TOKEN_EXPIRES=2592000

# OAuth Configuration
OAUTH_ISSUER=https://api.yourdomain.com
OAUTH_BASE_URL=https://api.yourdomain.com

# Bitcoin RPC Configuration
RPC_USER=your_rpc_username_here
RPC_PASSWORD=your_strong_rpc_password_32_chars_minimum
RPC_HOST=127.0.0.1
RPC_PORT=8332
RPC_WALLET=hodlxxi

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/hodlxxi
POF_DB_PATH=/var/lib/hodlxxi/pof_attest.db

# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
WORKERS=4
THREADS=2
WORKER_CLASS=gevent
WORKER_CONNECTIONS=1000

# WebSocket Configuration
SOCKETIO_CORS=https://yourdomain.com,https://app.yourdomain.com

# Security Configuration
RATE_LIMIT_ENABLED=true
RATE_LIMIT_STORAGE_URL=redis://localhost:6379/0
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=Lax

# Monitoring
SENTRY_DSN=your-sentry-dsn-here
LOG_LEVEL=INFO

# Email (for alerts)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alerts@yourdomain.com
SMTP_PASSWORD=your-smtp-password
ALERT_EMAIL=admin@yourdomain.com
```

### systemd Environment File

Create `/etc/hodlxxi/environment`:

```bash
# Same as .env but for systemd service
```

Set secure permissions:

```bash
sudo chmod 600 /etc/hodlxxi/environment
sudo chown hodlxxi:hodlxxi /etc/hodlxxi/environment
```

---

## Database Setup

### PostgreSQL (Recommended for Production)

**Installation:**

```bash
# Install PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start and enable
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**Database Setup:**

```bash
# Switch to postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE hodlxxi;
CREATE USER hodlxxi WITH ENCRYPTED PASSWORD 'your_strong_password';
GRANT ALL PRIVILEGES ON DATABASE hodlxxi TO hodlxxi;

# Enable extensions
\c hodlxxi
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

\q
```

**Connection Pooling with PgBouncer:**

```bash
# Install PgBouncer
sudo apt install pgbouncer

# Configure /etc/pgbouncer/pgbouncer.ini
[databases]
hodlxxi = host=127.0.0.1 port=5432 dbname=hodlxxi

[pgbouncer]
listen_addr = 127.0.0.1
listen_port = 6432
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 100
default_pool_size = 20

# Add user to /etc/pgbouncer/userlist.txt
"hodlxxi" "md5<md5_hash_of_password>"

# Start PgBouncer
sudo systemctl start pgbouncer
sudo systemctl enable pgbouncer

# Update DATABASE_URL
DATABASE_URL=postgresql://hodlxxi:password@localhost:6432/hodlxxi
```

### SQLite (Development/Small Scale)

```bash
# Create directory
sudo mkdir -p /var/lib/hodlxxi
sudo chown hodlxxi:hodlxxi /var/lib/hodlxxi

# Database will be created automatically at:
/var/lib/hodlxxi/hodlxxi.db

# Enable WAL mode for better concurrency
sqlite3 /var/lib/hodlxxi/hodlxxi.db "PRAGMA journal_mode=WAL;"
```

---

## Bitcoin Core Setup

### Installation

```bash
# Download Bitcoin Core
wget https://bitcoincore.org/bin/bitcoin-core-26.0/bitcoin-26.0-x86_64-linux-gnu.tar.gz

# Verify signature (important!)
wget https://bitcoincore.org/bin/bitcoin-core-26.0/SHA256SUMS
wget https://bitcoincore.org/bin/bitcoin-core-26.0/SHA256SUMS.asc
sha256sum --ignore-missing --check SHA256SUMS

# Extract
tar xzf bitcoin-26.0-x86_64-linux-gnu.tar.gz
sudo install -m 0755 -o root -g root -t /usr/local/bin bitcoin-26.0/bin/*
```

### Configuration

Create `~/.bitcoin/bitcoin.conf`:

```ini
# Network
testnet=0
regtest=0

# RPC Server
server=1
rpcuser=your_rpc_username
rpcpassword=your_strong_rpc_password_32_chars_minimum
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=8332

# Wallet
wallet=hodlxxi
disablewallet=0

# Performance
dbcache=4096
maxmempool=512

# Transaction Index (required for Proof of Funds)
txindex=1

# Reduce attack surface
disableprivilegemode=1
whitelist=127.0.0.1

# Logging
debug=0
```

### systemd Service

Create `/etc/systemd/system/bitcoind.service`:

```ini
[Unit]
Description=Bitcoin Core Daemon
After=network.target

[Service]
Type=forking
User=bitcoin
Group=bitcoin

ExecStart=/usr/local/bin/bitcoind -daemon \
                                  -conf=/home/bitcoin/.bitcoin/bitcoin.conf \
                                  -pid=/run/bitcoind/bitcoind.pid

ExecStop=/usr/local/bin/bitcoin-cli -conf=/home/bitcoin/.bitcoin/bitcoin.conf stop

PIDFile=/run/bitcoind/bitcoind.pid
Restart=on-failure

# Hardening
PrivateTmp=true
NoNewPrivileges=true
PrivateDevices=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

**Start Bitcoin Core:**

```bash
# Create bitcoin user
sudo useradd -r -m -d /home/bitcoin bitcoin

# Create directories
sudo mkdir /run/bitcoind
sudo chown bitcoin:bitcoin /run/bitcoind

# Start service
sudo systemctl daemon-reload
sudo systemctl start bitcoind
sudo systemctl enable bitcoind

# Check status
sudo systemctl status bitcoind

# Monitor sync progress
bitcoin-cli -conf=/home/bitcoin/.bitcoin/bitcoin.conf getblockchaininfo
```

### Wallet Setup

```bash
# Create and encrypt wallet
bitcoin-cli createwallet "hodlxxi"
bitcoin-cli -rpcwallet=hodlxxi encryptwallet "your_strong_wallet_passphrase"

# Backup wallet
bitcoin-cli -rpcwallet=hodlxxi backupwallet "/secure/backup/location/hodlxxi-wallet-backup-$(date +%Y%m%d).dat"
```

---

## Application Deployment

### Create Application User

```bash
sudo useradd -r -m -d /opt/hodlxxi -s /bin/bash hodlxxi
sudo su - hodlxxi
```

### Install Application

```bash
# Clone repository
cd /opt/hodlxxi
git clone https://github.com/yourusername/hodlxxi-api.git app
cd app

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn gevent

# Install production requirements
pip install psycopg2-binary redis sentry-sdk
```

### Create Production Requirements

Create `requirements-prod.txt`:

```
Flask==3.0.0
python-bitcoinrpc==1.0
Flask-SocketIO==5.3.5
python-socketio==5.10.0
PyJWT==2.8.0
python-dotenv==1.0.0
qrcode==7.4.2
Pillow==10.1.0
requests==2.31.0
bech32==1.2.0
marshmallow==3.20.1
argon2-cffi==23.1.0

# Production
gunicorn==21.2.0
gevent==23.9.1
psycopg2-binary==2.9.9
redis==5.0.1
sentry-sdk[flask]==1.38.0
celery==5.3.4
flower==2.0.1
```

### Create systemd Service

Create `/etc/systemd/system/hodlxxi.service`:

```ini
[Unit]
Description=HODLXXI API Service
After=network.target postgresql.service bitcoind.service redis.service
Wants=postgresql.service bitcoind.service redis.service

[Service]
Type=notify
User=hodlxxi
Group=hodlxxi
WorkingDirectory=/opt/hodlxxi/app

# Environment
EnvironmentFile=/etc/hodlxxi/environment

# Start application with Gunicorn
ExecStart=/opt/hodlxxi/app/venv/bin/gunicorn \
    --bind 127.0.0.1:8000 \
    --workers 4 \
    --threads 2 \
    --worker-class gevent \
    --worker-connections 1000 \
    --timeout 120 \
    --graceful-timeout 30 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --access-logfile /var/log/hodlxxi/access.log \
    --error-logfile /var/log/hodlxxi/error.log \
    --log-level info \
    --capture-output \
    --enable-stdio-inheritance \
    app:app

# Restart policy
Restart=always
RestartSec=10

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hodlxxi /var/log/hodlxxi
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

**Start Application:**

```bash
# Create log directory
sudo mkdir -p /var/log/hodlxxi
sudo chown hodlxxi:hodlxxi /var/log/hodlxxi

# Start service
sudo systemctl daemon-reload
sudo systemctl start hodlxxi
sudo systemctl enable hodlxxi

# Check status
sudo systemctl status hodlxxi

# View logs
sudo journalctl -u hodlxxi -f
```

---

## Reverse Proxy Configuration

### Nginx Configuration

Install Nginx:

```bash
sudo apt install nginx
```

Create `/etc/nginx/sites-available/hodlxxi`:

```nginx
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=60r/m;
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/m;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# Upstream application
upstream hodlxxi_app {
    least_conn;
    server 127.0.0.1:8000 max_fails=3 fail_timeout=30s;
    # Add more servers for load balancing:
    # server 127.0.0.1:8001 max_fails=3 fail_timeout=30s;
    # server 127.0.0.1:8002 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name api.yourdomain.com;
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/api.yourdomain.com/chain.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;

    # Logging
    access_log /var/log/nginx/hodlxxi-access.log combined;
    error_log /var/log/nginx/hodlxxi-error.log warn;

    # Request body size
    client_max_body_size 10M;
    client_body_timeout 60s;
    client_header_timeout 60s;

    # Rate limiting
    limit_req zone=api_limit burst=100 nodelay;
    limit_conn conn_limit 50;

    # Health check endpoint (no rate limit)
    location /health {
        proxy_pass http://hodlxxi_app;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        access_log off;
    }

    # WebSocket connections
    location /socket.io {
        proxy_pass http://hodlxxi_app;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    # Authentication endpoints (stricter rate limit)
    location ~ ^/(api/login|oauth/token|oauth/authorize) {
        limit_req zone=auth_limit burst=5 nodelay;
        proxy_pass http://hodlxxi_app;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # API endpoints
    location /api {
        proxy_pass http://hodlxxi_app;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # CORS headers (if needed)
        # add_header Access-Control-Allow-Origin "https://yourdomain.com" always;
        # add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
        # add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
    }

    # OAuth endpoints
    location /oauth {
        proxy_pass http://hodlxxi_app;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Well-known endpoints
    location /.well-known {
        proxy_pass http://hodlxxi_app;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
    }

    # Root and other endpoints
    location / {
        proxy_pass http://hodlxxi_app;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Enable site:**

```bash
sudo ln -s /etc/nginx/sites-available/hodlxxi /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## SSL/TLS Setup

### Let's Encrypt with Certbot

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d api.yourdomain.com

# Test auto-renewal
sudo certbot renew --dry-run

# Auto-renewal is configured via systemd timer
sudo systemctl status certbot.timer
```

### Manual Certificate Installation

```bash
# If using commercial certificate:
sudo mkdir -p /etc/ssl/private
sudo cp your_certificate.crt /etc/ssl/certs/
sudo cp your_private_key.key /etc/ssl/private/
sudo chmod 600 /etc/ssl/private/your_private_key.key

# Update Nginx configuration with certificate paths
```

---

## Monitoring and Logging

### System Monitoring

**Install Prometheus:**

```bash
# Create prometheus user
sudo useradd --no-create-home --shell /bin/false prometheus

# Download and install
cd /tmp
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar xzf prometheus-2.45.0.linux-amd64.tar.gz
sudo cp prometheus-2.45.0.linux-amd64/prometheus /usr/local/bin/
sudo cp prometheus-2.45.0.linux-amd64/promtool /usr/local/bin/
sudo chown prometheus:prometheus /usr/local/bin/prometheus /usr/local/bin/promtool

# Create directories
sudo mkdir -p /etc/prometheus /var/lib/prometheus
sudo chown prometheus:prometheus /etc/prometheus /var/lib/prometheus
```

**Configure Prometheus** (`/etc/prometheus/prometheus.yml`):

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'hodlxxi-api'
    static_configs:
      - targets: ['localhost:8000']
  
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
  
  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['localhost:9187']
```

**Install Grafana:**

```bash
# Add Grafana repository
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -

# Install
sudo apt-get update
sudo apt-get install grafana

# Start and enable
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
```

### Application Logging

**Configure structured logging in app:**

```python
import logging
import json
from logging.handlers import RotatingFileHandler

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)

# Configure logger
handler = RotatingFileHandler(
    '/var/log/hodlxxi/app.log',
    maxBytes=10485760,  # 10MB
    backupCount=20
)
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)
```

### Log Aggregation with ELK Stack

**Install Elasticsearch:**

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update && sudo apt-get install elasticsearch
```

**Install Logstash and Kibana similarly**

---

## Backup and Recovery

### Automated Backup Script

Create `/usr/local/bin/hodlxxi-backup.sh`:

```bash
#!/bin/bash

# Configuration
BACKUP_DIR="/backup/hodlxxi"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup database
echo "Backing up database..."
sudo -u postgres pg_dump hodlxxi | gzip > "$BACKUP_DIR/hodlxxi_db_$DATE.sql.gz"

# Backup Bitcoin wallet
echo "Backing up Bitcoin wallet..."
bitcoin-cli -rpcwallet=hodlxxi backupwallet "$BACKUP_DIR/wallet_$DATE.dat"

# Backup application config
echo "Backing up configuration..."
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" /etc/hodlxxi /opt/hodlxxi/app/.env

# Backup PoF database
echo "Backing up PoF database..."
cp /var/lib/hodlxxi/pof_attest.db "$BACKUP_DIR/pof_$DATE.db"

# Remove old backups
echo "Cleaning old backups..."
find "$BACKUP_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "*.dat" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "*.db" -mtime +$RETENTION_DAYS -delete

# Upload to S3 (optional)
if [ -n "$AWS_S3_BUCKET" ]; then
    echo "Uploading to S3..."
    aws s3 sync "$BACKUP_DIR" "s3://$AWS_S3_BUCKET/hodlxxi-backups/"
fi

echo "Backup completed: $DATE"
```

**Make executable and schedule:**

```bash
sudo chmod +x /usr/local/bin/hodlxxi-backup.sh

# Add to crontab (daily at 2 AM)
sudo crontab -e
0 2 * * * /usr/local/bin/hodlxxi-backup.sh >> /var/log/hodlxxi/backup.log 2>&1
```

### Disaster Recovery Plan

**Recovery Steps:**

1. **Restore Database:**
```bash
# PostgreSQL
sudo -u postgres psql -c "DROP DATABASE IF EXISTS hodlxxi;"
sudo -u postgres psql -c "CREATE DATABASE hodlxxi;"
gunzip -c backup.sql.gz | sudo -u postgres psql hodlxxi
```

2. **Restore Bitcoin Wallet:**
```bash
bitcoin-cli stop
cp wallet_backup.dat ~/.bitcoin/hodlxxi/wallet.dat
bitcoin-cli start
```

3. **Restore Application:**
```bash
tar -xzf config_backup.tar.gz -C /
sudo systemctl restart hodlxxi
```

---

## Scaling Strategies

### Horizontal Scaling

**Add Application Servers:**

```bash
# Server 2, 3, etc.
# Follow same deployment steps
# Update Nginx upstream:

upstream hodlxxi_app {
    least_conn;
    server 10.0.1.10:8000 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8000 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8000 max_fails=3 fail_timeout=30s;
}
```

### Database Scaling

**PostgreSQL Replication:**

```bash
# Primary server postgresql.conf
wal_level = replica
max_wal_senders = 3
wal_keep_size = 64

# Create replication user
CREATE USER replicator WITH REPLICATION ENCRYPTED PASSWORD 'password';

# Replica server
pg_basebackup -h primary_ip -D /var/lib/postgresql/data -U replicator -v -P
```

### Redis for Session/Cache

```bash
# Install Redis
sudo apt install redis-server

# Configure /etc/redis/redis.conf
bind 127.0.0.1
maxmemory 2gb
maxmemory-policy allkeys-lru

# Update application to use Redis
REDIS_URL=redis://localhost:6379/0
```

---

## Troubleshooting

### Common Issues

**1. Application Won't Start**

```bash
# Check logs
sudo journalctl -u hodlxxi -n 100

# Check if port is in use
sudo netstat -tlnp | grep 8000

# Check permissions
sudo ls -la /var/log/hodlxxi
sudo ls -la /var/lib/hodlxxi
```

**2. Bitcoin RPC Connection Failed**

```bash
# Check Bitcoin Core is running
sudo systemctl status bitcoind

# Test RPC connection
bitcoin-cli -rpcuser=user -rpcpassword=pass getblockchaininfo

# Check logs
sudo tail -f ~/.bitcoin/debug.log
```

**3. WebSocket Connection Issues**

```bash
# Check Nginx WebSocket configuration
sudo nginx -t

# Test WebSocket connection
wscat -c wss://api.yourdomain.com/socket.io

# Check for blocked WebSocket protocols
```

**4. SSL Certificate Errors**

```bash
# Renew certificate
sudo certbot renew

# Check certificate expiry
openssl x509 -in /etc/letsencrypt/live/domain/fullchain.pem -noout -dates

# Test SSL configuration
curl -vI https://api.yourdomain.com
```

**5. High Memory Usage**

```bash
# Check process memory
ps aux | grep gunicorn | awk '{sum+=$6} END {print sum/1024 " MB"}'

# Reduce worker count in systemd service
--workers 2

# Enable memory limits in systemd
MemoryMax=2G
```

---

## Post-Deployment Checklist

- [ ] Application accessible via HTTPS
- [ ] SSL certificate valid and auto-renewing
- [ ] All services running (bitcoind, postgresql, nginx, hodlxxi)
- [ ] Health check endpoint responding
- [ ] WebSocket connections working
- [ ] Authentication flow tested
- [ ] Bitcoin RPC responding
- [ ] Backups configured and tested
- [ ] Monitoring dashboards configured
- [ ] Log aggregation working
- [ ] Alerts configured
- [ ] Documentation updated
- [ ] Team trained on operations
- [ ] Disaster recovery plan tested
- [ ] Performance testing completed
- [ ] Security scan completed

---

## Support and Maintenance

### Regular Maintenance Tasks

**Daily:**
- Monitor application logs
- Check system resources
- Verify backup completion

**Weekly:**
- Review security alerts
- Update dependencies (if needed)
- Check SSL certificate expiry

**Monthly:**
- Security audit
- Performance review
- Capacity planning
- Update documentation

**Quarterly:**
- Disaster recovery drill
- Penetration testing
- Team training
- Architecture review

---

For additional support, contact: support@yourdomain.com
