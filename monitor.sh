#!/bin/bash
#
# Real-time Performance Monitor
# Universal Bitcoin Identity Layer
#
# Usage: bash monitor.sh
#

while true; do
    clear
    echo "============================================================"
    echo "  LIVE PERFORMANCE MONITOR - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "============================================================"
    echo ""

    # System Overview
    echo "📊 SYSTEM RESOURCES"
    echo "-------------------"
    echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')% busy"
    echo "RAM: $(free -h | awk '/^Mem:/ {printf "%s used / %s total (%s%%)", $3, $2, int($3/$2*100)}')"
    echo "Disk: $(df -h / | awk 'NR==2 {printf "%s used / %s total (%s)", $3, $2, $5}')"
    echo ""

    # Service Status
    echo "🔧 SERVICES"
    echo "-----------"
    if pgrep -f "python3 wsgi.py" > /dev/null; then
        PID=$(pgrep -f "python3 wsgi.py")
        MEM=$(ps -p $PID -o rss= | awk '{printf "%.1fMB", $1/1024}')
        CPU=$(ps -p $PID -o %cpu=)
        echo "✅ Flask (PID $PID) - CPU: ${CPU}% | MEM: $MEM"
    else
        echo "❌ Flask: Not running"
    fi

    if pgrep postgres > /dev/null; then
        PGMEM=$(ps aux | grep postgres | grep -v grep | awk '{sum+=$4} END {printf "%.1f%%", sum}')
        echo "✅ PostgreSQL - MEM: $PGMEM"
    else
        echo "❌ PostgreSQL: Not running"
    fi

    if pgrep redis-server > /dev/null; then
        REDISMEM=$(redis-cli INFO memory 2>/dev/null | grep used_memory_human: | cut -d: -f2 | tr -d '\r')
        echo "✅ Redis - MEM: $REDISMEM"
    else
        echo "❌ Redis: Not running"
    fi
    echo ""

    # Recent Requests (from logs)
    echo "📝 RECENT REQUESTS (last 5)"
    echo "---------------------------"
    tail -5 /tmp/flask_app.log 2>/dev/null | grep "GET\|POST" | while read line; do
        TIME=$(echo "$line" | grep -oP '\d{2}:\d{2}:\d{2}')
        METHOD=$(echo "$line" | grep -oP '(GET|POST)')
        PATH=$(echo "$line" | grep -oP '(GET|POST) \K[^ ]+')
        CODE=$(echo "$line" | grep -oP 'HTTP/1\.[01]" \K\d+')
        echo "  $TIME | $METHOD $PATH → $CODE"
    done 2>/dev/null || echo "  (no recent requests)"
    echo ""

    # Quick endpoint test
    echo "⚡ ENDPOINT STATUS"
    echo "------------------"

    # Test OIDC endpoint
    OIDC_START=$(date +%s%3N)
    OIDC_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/.well-known/openid-configuration 2>/dev/null)
    OIDC_TIME=$(($(date +%s%3N) - OIDC_START))

    if [[ $OIDC_CODE == "200" ]]; then
        echo "✅ OIDC Config: ${OIDC_TIME}ms"
    else
        echo "❌ OIDC Config: HTTP $OIDC_CODE"
    fi

    # Test metrics endpoint
    METRICS_START=$(date +%s%3N)
    METRICS_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/metrics/prometheus 2>/dev/null)
    METRICS_TIME=$(($(date +%s%3N) - METRICS_START))

    if [[ $METRICS_CODE == "200" ]]; then
        echo "✅ Prometheus: ${METRICS_TIME}ms"
    else
        echo "❌ Prometheus: HTTP $METRICS_CODE"
    fi

    echo ""
    echo "Press Ctrl+C to exit | Refreshing every 3 seconds..."

    sleep 3
done
