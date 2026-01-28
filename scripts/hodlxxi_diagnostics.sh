#!/usr/bin/env bash
# HODLXXI / UBID – Full Diagnostics & Stats Snapshot
# Run as root on your VPS:  bash hodlxxi_diagnostics.sh
set -euo pipefail

APP_NAME="HODLXXI"
APP_DIR="/srv/ubid"
SERVICE_NAME="hodlxxi"
DOMAIN="hodlxxi.com"

# If you use Postgres for app data, set these:
DB_NAME="hodlxxi"
DB_USER="hodlxxi"


# Colors
BOLD="$(tput bold || true)"
RESET="$(tput sgr0 || true)"
GREEN="$(tput setaf 2 || true)"
CYAN="$(tput setaf 6 || true)"
YELLOW="$(tput setaf 3 || true)"

section() {
  echo
  echo "${BOLD}${CYAN}==============================================================${RESET}"
  echo "${BOLD}${CYAN}== $1${RESET}"
  echo "${BOLD}${CYAN}==============================================================${RESET}"
}

subsection() {
  echo
  echo "${BOLD}${YELLOW}-- $1${RESET}"
}

# 0. Basic context
section "0. Context"
echo "App:        $APP_NAME"
echo "App dir:    $APP_DIR"
echo "Service:    $SERVICE_NAME"
echo "Domain:     $DOMAIN"
echo "Run time:   $(date)"
echo "Hostname:   $(hostname)"
echo "User:       $(whoami)"

# 1. System overview
section "1. System Overview"

subsection "1.1 OS & Kernel"
uname -a || true
if command -v lsb_release >/dev/null 2>&1; then
  lsb_release -a || true
fi

subsection "1.2 Uptime / load / users"
uptime || true
w || true

subsection "1.3 CPU & memory snapshot"
free -h || true
echo
echo "Top CPU processes:"
ps aux --sort=-%cpu | head -n 15 || true
echo
echo "Top MEM processes:"
ps aux --sort=-%mem | head -n 15 || true

subsection "1.4 Disk usage"
df -hT || true

# 2. Systemd services & logs
section "2. Services & Logs"

subsection "2.1 Systemd status (app + core services)"
systemctl status "$SERVICE_NAME" --no-pager || true
echo
systemctl status nginx --no-pager || true
echo
systemctl status postgresql --no-pager || true
echo
systemctl status redis-server --no-pager || true

subsection "2.2 Recent app logs (journalctl)"
journalctl -u "$SERVICE_NAME" --no-pager --since "1 hour ago" | tail -n 200 || true

subsection "2.3 Nginx error logs (last 100 lines)"
NGINX_ERR="/var/log/nginx/error.log"
if [ -f "$NGINX_ERR" ]; then
  tail -n 100 "$NGINX_ERR" || true
else
  echo "No $NGINX_ERR found."
fi

# 3. Network & HTTP checks
section "3. Network & HTTP"

subsection "3.1 Listening ports (80/443/5000/etc.)"
ss -ltnp | egrep '(:80|:443|:5000|:5432|:6379)' || true

subsection "3.2 Local app check (Gunicorn/Flask)"
curl -sS -o /tmp/hodlxxi_local.html -w "HTTP %{http_code}\n" "http://127.0.0.1:5000" || true
head -n 5 /tmp/hodlxxi_local.html || true

subsection "3.3 Public HTTPS check"
curl -sS -I "https://$DOMAIN" || true

subsection "3.4 TLS certificate info"
echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null | \
  openssl x509 -noout -dates -subject || true

# 4. App environment snapshot (safe)
section "4. App Environment (safe subset)"

if [ -f "$APP_DIR/.env" ]; then
  echo "Env file: $APP_DIR/.env"
  echo
  echo "# Showing only non-secret lines (filtered by keyword)..."
  egrep -v 'SECRET|PASSWORD|PASS=|KEY=|TOKEN=' "$APP_DIR/.env" || true
else
  echo "No $APP_DIR/.env found."
fi

# 5. Python / Gunicorn / packages
section "5. Python & Gunicorn"

if [ -d "$APP_DIR/venv" ]; then
  subsection "5.1 Python version in venv"
  source "$APP_DIR/venv/bin/activate"
  python -V || true

  subsection "5.2 Gunicorn version"
  gunicorn --version || true

  subsection "5.3 Installed packages (top 40)"
  pip list | head -n 40 || true
else
  echo "No virtualenv found at $APP_DIR/venv"
fi

# 6. Postgres stats (app-level)
section "6. Postgres DB Stats (app-level)"

if command -v psql >/dev/null 2>&1; then
  subsection "6.1 List databases (psql -l)"
  sudo -u postgres psql -c "\l" || true

  subsection "6.2 Tables in $DB_NAME (if exists)"
  sudo -u postgres psql -d "$DB_NAME" -c "\dt" || true

  subsection "6.3 Example counts (adjust table names as needed)"
  # Adjust table names to whatever you actually use.
  # These will fail silently if tables don't exist.
  for tbl in users pof_attestations oauth_clients login_events; do
    echo "Table: $tbl"
    sudo -u postgres psql -d "$DB_NAME" -c "SELECT COUNT(*) AS count FROM $tbl;" 2>/dev/null || echo "  (table $tbl not found)"
    echo
  done

else
  echo "psql not installed or not in PATH."
fi

# 7. PoF (SQLite) stats
section "7. PoF (SQLite) Stats"

if [ -d "$APP_DIR" ] && [ -d "$APP_DIR/venv" ]; then
  subsection "7.1 Resolve PoF DB path via PoFConfig (if available)"
  POF_DB_PATH="$APP_DIR/pof_attest.db"
  if [ -f "$APP_DIR/pof_enhanced.py" ]; then
    POF_DB_PATH="$(cd "$APP_DIR" && source venv/bin/activate && python - << 'PY'
from pof_enhanced import PoFConfig
print(PoFConfig.DB_PATH)
PY
    )" || true
  fi
  echo "PoF DB path (guess): $POF_DB_PATH"

  if command -v sqlite3 >/dev/null 2>&1 && [ -f "$POF_DB_PATH" ]; then
    subsection "7.2 SQLite tables"
    sqlite3 "$POF_DB_PATH" ".tables" || true

    subsection "7.3 Recent PoF attestations"
    sqlite3 "$POF_DB_PATH" "SELECT pubkey,total_sat,privacy_level,datetime(created_at,'unixepoch') FROM pof_attestations ORDER BY created_at DESC LIMIT 10;" || true
  else
    echo "sqlite3 not installed or PoF DB not found."
  fi
else
  echo "App dir or venv missing, skipping PoF stats."
fi

# 8. Redis stats
section "8. Redis Stats"

if command -v redis-cli >/dev/null 2>&1; then
  redis-cli INFO | egrep 'used_memory_human|connected_clients|db0:keys' || true
else
  echo "redis-cli not installed."
fi

# 9. Nginx HTTP stats
section "9. Nginx Access Stats (recent)"

NGINX_ACCESS="/var/log/nginx/access.log"
if [ -f "$NGINX_ACCESS" ]; then
  subsection "9.1 Top endpoints hit (last 1000 lines)"
  tail -n 1000 "$NGINX_ACCESS" | awk '{print $7}' | sort | uniq -c | sort -nr | head -n 20 || true

  subsection "9.2 Recent 50 lines"
  tail -n 50 "$NGINX_ACCESS" || true
else
  echo "No $NGINX_ACCESS found."
fi

# 10. App-specific HTTP checks
section "10. App-specific HTTP Checks"

subsection "10.1 Health/check endpoints (if present)"
for path in "/healthz" "/oauthx/status" "/oauthx/docs" "/api/pof/stats" "/playground" "/dashboard"; do
  echo "GET https://$DOMAIN$path"
  curl -sS -o /tmp/hodlxxi_tmp.html -w "HTTP %{http_code}\n" "https://$DOMAIN$path" || true
  head -n 3 /tmp/hodlxxi_tmp.html || true
  echo
done

# 11. Active sessions / sockets (high-level)
section "11. Active App Sessions / Sockets"

subsection "11.1 Gunicorn worker processes"
ps aux | grep gunicorn | grep -v grep || true

subsection "11.2 Socket.IO / websocket ports (if any)"
ss -ltnp | egrep '(:5000|:6001|:8000)' || true

# 12. Summary hint
section "12. Summary"
echo "Diagnostics complete."
echo "Scroll up to review each section."
echo
echo "${GREEN}Tip:${RESET} Save this output to a file with:"
echo "  bash $0 > hodlxxi_diag_\$(date +%Y%m%d_%H%M%S).log 2>&1"
echo
