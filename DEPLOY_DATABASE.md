# Database Persistence Deployment Guide

This guide will help you deploy the **production-grade database persistence layer** to your VPS.

**⚠️  IMPORTANT**: This is a **breaking change** - the app will now use PostgreSQL + Redis instead of in-memory storage.

---

## 📋 Prerequisites

Your VPS needs:
- Ubuntu 20.04+ (or similar Linux distribution)
- Python 3.9+
- Root or sudo access
- Your app currently running

---

## 🚀 Deployment Steps

### Step 1: Install PostgreSQL and Redis

```bash
# Update package list
sudo apt update

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Install Redis
sudo apt install -y redis-server

# Start services
sudo systemctl start postgresql
sudo systemctl start redis-server

# Enable auto-start on boot
sudo systemctl enable postgresql
sudo systemctl enable redis-server
```

### Step 2: Create Database and User

```bash
# Switch to postgres user
sudo -u postgres psql

# In PostgreSQL prompt, run these commands:
```

```sql
-- Create database user
CREATE USER hodlxxi WITH PASSWORD 'YOUR_SECURE_PASSWORD_HERE';

-- Create database
CREATE DATABASE hodlxxi OWNER hodlxxi;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE hodlxxi TO hodlxxi;

-- Exit PostgreSQL
\q
```

### Step 3: Configure Redis (Optional but Recommended)

```bash
# Edit Redis configuration
sudo nano /etc/redis/redis.conf
```

Add/modify these lines:
```ini
# Set a password
requirepass YOUR_REDIS_PASSWORD_HERE

# Bind to localhost only (for security)
bind 127.0.0.1

# Enable persistence
appendonly yes
appendfsync everysec
```

Restart Redis:
```bash
sudo systemctl restart redis-server
```

### Step 4: Pull Latest Code

```bash
# Navigate to your app directory
cd /path/to/Universal-Bitcoin-Identity-Layer

### Step 5: Install New Dependencies

```bash
# Activate virtual environment (if using one)
source venv/bin/activate  # or wherever your venv is

# Install new dependencies
pip install -r requirements.txt

# Verify alembic and redis are installed
pip list | grep -E "(alembic|redis|SQLAlchemy)"
```

You should see:
```
alembic                1.12.0
redis                  5.0.0
SQLAlchemy             2.0.20
```

### Step 6: Configure Environment Variables

```bash
# Edit your .env file
nano .env
```

**Update these critical settings:**

```bash
# Database Configuration
DATABASE_URL=postgresql://hodlxxi:YOUR_SECURE_PASSWORD_HERE@localhost:5432/hodlxxi

# Or use individual components:
DB_HOST=localhost
DB_PORT=5432
DB_USER=hodlxxi
DB_PASSWORD=YOUR_SECURE_PASSWORD_HERE
DB_NAME=hodlxxi

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=YOUR_REDIS_PASSWORD_HERE
REDIS_DB=0

# Set Flask environment to production
FLASK_ENV=production
FLASK_DEBUG=0

# Ensure these are set with secure values
FLASK_SECRET_KEY=your-random-secret-key-here
JWT_SECRET=your-jwt-secret-here
RPC_PASSWORD=your-bitcoin-rpc-password
```

**Generate secure secrets:**
```bash
# Generate random secrets
python3 -c "import secrets; print(secrets.token_hex(32))"
# Use output for FLASK_SECRET_KEY

python3 -c "import secrets; print(secrets.token_hex(32))"
# Use output for JWT_SECRET
```

### Step 7: Initialize Database

```bash
# Run database initialization
python scripts/db_init.py
```

You should see:
```
============================================================
HODLXXI Database Initialization
============================================================

📊 Database URL: localhost:5432/hodlxxi

🔨 Creating database tables...
✅ All tables created successfully

🔌 Initializing connections...

🏥 Checking database health...

📊 Database Health:
  PostgreSQL: healthy
  Redis: healthy

✅ Database initialization complete!
```

### Step 8: Run Database Migrations

```bash
# Apply all migrations
make db-upgrade

# Or manually:
alembic upgrade head
```

### Step 9: Test the Application

```bash
# Test locally first
python app/app.py
```

Visit `http://your-vps-ip:5000/health` - you should see:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-XX...",
  "version": "1.0.0-alpha",
  "database": {"status": "healthy", "connected": true},
  "redis": {"status": "healthy", "connected": true}
}
```

### Step 10: Restart Production Service

```bash
# If using systemd service
sudo systemctl restart hodlxxi

# If using gunicorn directly
pkill gunicorn
gunicorn --worker-class gevent --workers 4 --bind 0.0.0.0:5000 app.app:app

# If using screen/tmux
# Kill old process and start new one
```

---

## ✅ Verification Checklist

After deployment, verify:

- [ ] PostgreSQL is running: `sudo systemctl status postgresql`
- [ ] Redis is running: `sudo systemctl status redis-server`
- [ ] Database exists: `sudo -u postgres psql -l | grep hodlxxi`
- [ ] Application starts without errors
- [ ] `/health` endpoint shows healthy database and redis
- [ ] Can create OAuth clients (test with `/oauth/register`)
- [ ] Sessions persist across app restarts

---

## 🔄 Database Maintenance Commands

```bash
# Create database backup
make db-backup
# Or: ./scripts/db_backup.sh

# Restore from backup
make db-restore backup=./backups/hodlxxi_backup_YYYYMMDD_HHMMSS.sql.gz

# View migration status
make db-status

# View migration history
make db-history

# Create new migration (after model changes)
make db-migrate message="Add new feature"

# Rollback last migration
make db-downgrade
```

---

## 🔒 Security Recommendations

### Database Security

```bash
# Edit PostgreSQL config
sudo nano /etc/postgresql/14/main/postgresql.conf
```

Ensure:
```ini
listen_addresses = 'localhost'  # Only local connections
```

```bash
# Edit authentication config
sudo nano /etc/postgresql/14/main/pg_hba.conf
```

Restart PostgreSQL:
```bash
sudo systemctl restart postgresql
```

### Redis Security

Already configured in Step 3, but verify:
```bash
# Test Redis is password-protected
redis-cli ping
# Should return: (error) NOAUTH Authentication required

# Test with password
redis-cli -a YOUR_REDIS_PASSWORD_HERE ping
# Should return: PONG
```

### Firewall

```bash
# Ensure PostgreSQL and Redis ports are NOT exposed
sudo ufw status

# PostgreSQL (5432) and Redis (6379) should NOT be in the list
# If they are, remove them:
sudo ufw delete allow 5432
sudo ufw delete allow 6379
```

---

## 📊 Monitoring

### Check Database Size

```bash
sudo -u postgres psql -c "SELECT pg_size_pretty(pg_database_size('hodlxxi'));"
```

### Check Active Connections

```bash
sudo -u postgres psql -c "SELECT count(*) FROM pg_stat_activity WHERE datname='hodlxxi';"
```

### Check Redis Memory Usage

```bash
redis-cli -a YOUR_REDIS_PASSWORD_HERE INFO memory | grep used_memory_human
```

### Application Logs

```bash
# If using systemd
sudo journalctl -u hodlxxi -f

# If using logs directory
tail -f logs/app.log
```

---

## 🔥 Troubleshooting

### Issue: "No module named 'app.models'"

**Solution:**
```bash
# Ensure you're in the project root directory
cd /path/to/Universal-Bitcoin-Identity-Layer

# Verify PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Issue: "could not connect to server: Connection refused"

**Solution:**
```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# If not running
sudo systemctl start postgresql

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

### Issue: "Redis connection refused"

**Solution:**
```bash
# Check if Redis is running
sudo systemctl status redis-server

# If not running
sudo systemctl start redis-server

# Check Redis logs
sudo tail -f /var/log/redis/redis-server.log
```

### Issue: "FATAL: password authentication failed"

**Solution:**
```bash
# Reset PostgreSQL password
sudo -u postgres psql
\password hodlxxi
# Enter new password
\q

# Update .env file with new password
nano .env
```

### Issue: "Migration failed"

**Solution:**
```bash
# Check current migration status
alembic current

# View migration history
alembic history

# If stuck, check database
sudo -u postgres psql hodlxxi
\dt  # List tables
SELECT * FROM alembic_version;  # Check migration version
\q

# Force migration to specific version
alembic stamp head
```

### Issue: "Permission denied" errors

**Solution:**
```bash
# Make scripts executable
chmod +x scripts/*.sh scripts/*.py

# Check file ownership
ls -la /path/to/Universal-Bitcoin-Identity-Layer

# Fix ownership if needed
sudo chown -R yourusername:yourusername /path/to/Universal-Bitcoin-Identity-Layer
```

---

## 📈 Performance Tuning

### PostgreSQL Connection Pooling

The application uses SQLAlchemy connection pooling:
- Pool size: 10 connections
- Max overflow: 20 connections
- Connection recycle: 3600 seconds

If you need to adjust, edit `app/database.py`.

### Redis Optimization

For high traffic, edit `/etc/redis/redis.conf`:
```ini
maxmemory 256mb
maxmemory-policy allkeys-lru
tcp-backlog 511
```

---

## 🔄 Rolling Back (Emergency)

If something goes wrong:

### Option 1: Revert to Previous Code
```bash
git checkout main  # or your previous working branch
pip install -r requirements.txt
sudo systemctl restart hodlxxi
```

### Option 2: Use In-Memory Storage (Temporary)

Edit `app/app.py` - comment out database initialization:
```python
# from app.database import init_all
# init_all()

# Use old storage instead
from app.storage import init_storage
init_storage()
```

---

## 📞 Support

If you encounter issues:

1. **Check logs**: `sudo journalctl -u hodlxxi -f`
2. **Test database**: `python scripts/db_init.py`
3. **Verify config**: `env | grep -E "(DATABASE|REDIS)"`
4. **Health check**: `curl http://localhost:5000/health`

---

## ✅ Success Indicators

You know it's working when:
- ✅ `/health` endpoint returns `"database": {"status": "healthy"}`
- ✅ `/health` endpoint returns `"redis": {"status": "healthy"}`
- ✅ Application restarts don't lose OAuth clients or sessions
- ✅ Users can log in and sessions persist
- ✅ No database connection errors in logs

---

## 🎉 You're Done!

Your HODLXXI application now has production-grade database persistence with:
- ✅ PostgreSQL for reliable data storage
- ✅ Redis for fast session/cache management
- ✅ Alembic for database migrations
- ✅ Automatic backups with `make db-backup`
- ✅ Full transaction support and ACID compliance

**Next steps:**
- Set up automated backups (cron job)
- Configure monitoring/alerting
- Implement security hardening (next phase)
- Set up SSL/TLS certificates

**Need help?** Check the troubleshooting section or create an issue on GitHub.
