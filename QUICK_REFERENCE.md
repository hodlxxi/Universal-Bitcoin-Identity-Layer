# HODLXXI Production Quick Reference

## 🚀 Quick Start


## 🔑 Environment Variables (.env)

```bash
# Required
FLASK_SECRET_KEY=<generate with: openssl rand -hex 32>
JWT_SECRET=<generate with: openssl rand -hex 32>

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# OAuth
OIDC_ISSUER=https://hodlxxi.com
OAUTH_AUDIENCE=bitcoin-api
```

---

## 🛠️ Common Commands

### Redis Management

```bash
# Check Redis status
sudo systemctl status redis-server

# Start/Stop/Restart Redis
sudo systemctl start redis-server
sudo systemctl stop redis-server
sudo systemctl restart redis-server

# Monitor Redis in real-time
redis-cli monitor

# Check Redis memory
redis-cli INFO memory | grep used_memory_human

# List all keys
redis-cli KEYS "*"

# Count keys by pattern
redis-cli --scan --pattern "client:*" | wc -l

# Flush all data (CAREFUL!)
redis-cli FLUSHALL
```

### Application Management

```bash
# Restart app
sudo systemctl restart app

# Check status
sudo systemctl status app

# View logs (live)
sudo journalctl -u app -f

# View last 50 lines
sudo journalctl -u app -n 50 --no-pager

# Check for errors
sudo journalctl -u app | grep -i error
```

### Log Management

```bash
# Watch application logs
tail -f /srv/app/logs/app.log

# Watch audit logs
tail -f /srv/app/logs/audit.log

# Search audit logs for client
grep "client_id.*anon_xxxxx" /srv/app/logs/audit.log

# Search for specific event types
grep "token.access_issued" /srv/app/logs/audit.log

# Parse JSON logs with jq
tail -n 100 /srv/app/logs/audit.log | jq .

# Find rate limit events
grep "rate_limit_exceeded" /srv/app/logs/audit.log | jq .
```

### Health Checks

```bash
# App health
curl http://localhost:5000/health | jq .

# OAuth status
curl http://localhost:5000/oauthx/status | jq .

# Redis health (via Python)
python3 -c "from storage import get_storage; print(get_storage().health_check())"
```

---

## 🔍 Debugging

### Check Redis Connection

```python
python3 << 'EOF'
from storage import get_storage
storage = get_storage()
print(storage.health_check())
EOF
```

### View Client Info

```python
python3 << 'EOF'
from storage import get_storage
storage = get_storage()

# List all clients
clients = storage.get_all_clients()
for c in clients:
    print(f"{c.client_id}: {c.client_type.value}, rate_limit={c.rate_limit}")

# Get specific client
client = storage.get_client("anon_xxxxx")
print(client.to_dict())
EOF
```

### Check Rate Limits

```python
python3 << 'EOF'
from storage import get_storage
storage = get_storage()

client_id = "anon_xxxxx"
info = storage.get_rate_limit_info(client_id)
print(info)
EOF
```

### Check Storage Stats

```python
python3 << 'EOF'
from storage import get_storage
storage = get_storage()
print(storage.get_stats())
EOF
```

---

## 🔐 Security Operations

### Revoke a Token

```python
python3 << 'EOF'
from storage import get_storage
import time

storage = get_storage()

# Revoke by JTI (get from JWT payload)
jti = "token-jti-here"
exp = int(time.time()) + 3600  # When token expires

storage.revoke_token(jti, exp)
print(f"Token {jti} revoked")
EOF
```

### Deactivate a Client

```python
python3 << 'EOF'
from storage import get_storage

storage = get_storage()
client_id = "anon_xxxxx"

storage.deactivate_client(client_id)
print(f"Client {client_id} deactivated")
EOF
```

### View Audit Trail

```bash
# Last 100 security events
grep "security\." /srv/app/logs/audit.log | tail -100 | jq .

# Failed authentications
grep "auth_failed\|validation_failed" /srv/app/logs/audit.log | jq .

# Rate limit violations
grep "rate_limit_exceeded" /srv/app/logs/audit.log | jq .
```

---

## 📊 Monitoring Queries

### Redis Key Counts

```bash
# Total keys
redis-cli DBSIZE

# Clients
redis-cli SCARD clients:all

# Active auth codes
redis-cli KEYS "code:*" | wc -l

# Active LNURL sessions
redis-cli KEYS "lnurl:*" | wc -l

# Revoked tokens
redis-cli KEYS "revoked:*" | wc -l
```

### Client Activity

```bash
# Most active clients (from audit log)
grep "api.request" /srv/app/logs/audit.log | \
  jq -r .client_id | sort | uniq -c | sort -rn | head -10

# Clients by type
python3 << 'EOF'
from storage import get_storage
from collections import Counter

storage = get_storage()
clients = storage.get_all_clients()
types = Counter(c.client_type.value for c in clients)
print(types)
EOF
```

### Performance Metrics

```bash
# Redis response times
redis-cli --latency

# App response times (from audit logs)
grep "duration_ms" /srv/app/logs/audit.log | \
  jq '.duration_ms' | awk '{sum+=$1; count++} END {print "Avg:", sum/count, "ms"}'
```

---

## 🧪 Testing OAuth Flow

```bash
BASE="https://hodlxxi.com"

# 1. Register client
REG=$(curl -s -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["http://localhost:3000/callback"]}' \
  "$BASE/oauth/register")

echo "$REG" | jq .

CID=$(echo "$REG" | jq -r .client_id)
CSEC=$(echo "$REG" | jq -r .client_secret)

# 2. Get auth code
CODE=$(curl -s -i "$BASE/oauth/authorize?client_id=$CID&redirect_uri=http://localhost:3000/callback&response_type=code&scope=read_limited&state=xyz" | \
  grep -i location | sed 's/.*code=\([^&]*\).*/\1/')

# 3. Exchange for token
TOK=$(curl -s -X POST "$BASE/oauth/token" \
  -d "grant_type=authorization_code&client_id=$CID&client_secret=$CSEC&code=$CODE&redirect_uri=http://localhost:3000/callback")

echo "$TOK" | jq .

AT=$(echo "$TOK" | jq -r .access_token)

# 4. Use token
curl -s -H "Authorization: Bearer $AT" "$BASE/api/demo/free" | jq .
```

---

## 🔄 Backup & Restore

### Backup Redis Data

```bash
# Create RDB snapshot
redis-cli SAVE

# Copy snapshot
cp /var/lib/redis/dump.rdb /srv/app/backups/redis_$(date +%Y%m%d_%H%M%S).rdb

# Or use AOF (if enabled)
cp /var/lib/redis/appendonly.aof /srv/app/backups/
```

### Restore Redis Data

```bash
# Stop Redis
sudo systemctl stop redis-server

# Replace dump file
sudo cp /srv/app/backups/redis_YYYYMMDD_HHMMSS.rdb /var/lib/redis/dump.rdb
sudo chown redis:redis /var/lib/redis/dump.rdb

# Start Redis
sudo systemctl start redis-server
```

### Export Clients

```python
python3 << 'EOF'
from storage import get_storage
import json

storage = get_storage()
clients = storage.get_all_clients()

data = [c.to_dict() for c in clients]

with open('clients_backup.json', 'w') as f:
    json.dump(data, f, indent=2)

print(f"Exported {len(data)} clients")
EOF
```

---

## 🚨 Emergency Procedures

### Redis is Down

```bash
# Check status
sudo systemctl status redis-server

# Check logs
sudo journalctl -u redis-server -n 50

# Restart
sudo systemctl restart redis-server

# If corrupted, restore from backup
sudo systemctl stop redis-server
sudo rm /var/lib/redis/dump.rdb
sudo cp /srv/app/backups/redis_latest.rdb /var/lib/redis/dump.rdb
sudo chown redis:redis /var/lib/redis/dump.rdb
sudo systemctl start redis-server
```

### High Memory Usage

```bash
# Check memory
redis-cli INFO memory

# Clear expired keys
redis-cli --scan --pattern "*" | xargs redis-cli TTL | grep -v "^-1$" | wc -l

# If critical, flush non-essential data
redis-cli DEL $(redis-cli KEYS "rate:*")

# Restart Redis
sudo systemctl restart redis-server
```

### App Not Responding

```bash
# Check process
ps aux | grep gunicorn

# Check logs
sudo journalctl -u app -n 100 --no-pager | grep -i error

# Restart
sudo systemctl restart app

# If still failing, check dependencies
cd /srv/app
source venv/bin/activate
pip list | grep redis
```

---

## 📈 Performance Tuning

### Redis Config (/etc/redis/redis.conf)

```conf
# Memory limit
maxmemory 256mb
maxmemory-policy allkeys-lru

# Persistence (for production)
save 900 1
save 300 10
save 60 10000

# Or disable for speed (lose data on crash)
# save ""

# Connection limits
maxclients 10000
timeout 300
```

### Gunicorn Workers

```bash
# Check worker count
ps aux | grep gunicorn | wc -l

# Recommended: (2 x CPU cores) + 1
# Edit /etc/systemd/system/app.service
# Workers=5  # for 2 core system
```

---

## 📚 Additional Resources

- **Redis Docs**: https://redis.io/documentation
- **Flask Best Practices**: https://flask.palletsprojects.com/
- **OAuth 2.0 RFC**: https://tools.ietf.org/html/rfc6749

---

## 🆘 Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| "Cannot connect to Redis" | `sudo systemctl start redis-server` |
| "Permission denied: logs/" | `sudo chown $USER:$USER -R /srv/app/logs` |
| "Invalid audience" | Check JWT_SECRET and OAUTH_AUDIENCE in .env |
| "Rate limit not working" | Verify Redis connection and rate:* keys exist |
| High CPU | Check Gunicorn worker count |
| High memory | Check Redis memory with `redis-cli INFO memory` |

---

**Quick validation:** `python3 validate_production.py`

