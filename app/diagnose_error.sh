#!/bin/bash

echo "=== Checking Python syntax error ==="
echo ""

cd /srv/ubid/app

# Try to compile and show the error
python -m py_compile app.py 2>&1 | head -30

echo ""
echo "=== Checking for Redis import ==="
grep -n "import redis" app.py | head -5

echo ""
echo "=== Checking for redis_client initialization ==="
grep -n "redis_client =" app.py | head -5

echo ""
echo "=== Showing last 100 lines of app.py ==="
tail -100 app.py

echo ""
echo "=== Backup location ==="
ls -lt /root/hodlxxi_backups/ | head -5
