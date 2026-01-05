#!/usr/bin/env bash
# HODLXXI / UBID – Route Smoke Tester
# Run as:  bash hodlxxi_route_test.sh
set -euo pipefail

BASE="${BASE:-https://hodlxxi.com}"

BOLD="$(tput bold || true)"
RESET="$(tput sgr0 || true)"
GREEN="$(tput setaf 2 || true)"
YELLOW="$(tput setaf 3 || true)"
RED="$(tput setaf 1 || true)"
CYAN="$(tput setaf 6 || true)"

section() {
  echo
  echo "${BOLD}${CYAN}==============================================================${RESET}"
  echo "${BOLD}${CYAN}== $1${RESET}"
  echo "${BOLD}${CYAN}==============================================================${RESET}"
}

test_get() {
  local path="$1"
  local url="${BASE}${path}"

  # -s silent, -k ignore TLS issues if any, -o /tmp/body, -w to print HTTP code
  local out
  out="$(curl -sk -o /tmp/hodlxxi_route_body -w "%{http_code} %{time_total}" "$url" || true)"
  local code time
  code="$(echo "$out" | awk '{print $1}')"
  time="$(echo "$out" | awk '{print $2}')"

  local color="$GREEN"
  if [[ "$code" == "200" || "$code" == "302" || "$code" == "301" ]]; then
    color="$GREEN"
  elif [[ "$code" == "401" || "$code" == "403" ]]; then
    color="$YELLOW"
  else
    color="$RED"
  fi

  printf "%s%-4s%s  %6.3fs  %s\n" "$color" "$code" "$RESET" "$time" "$path"

  # For non-2xx/3xx, show a tiny snippet of body for debugging
  if [[ "$code" != "200" && "$code" != "301" && "$code" != "302" ]]; then
    head -n 3 /tmp/hodlxxi_route_body | sed 's/^/      body: /'
  fi
}

section "0. Base"
echo "Testing base URL: $BASE"
echo "Run time: $(date)"
echo

# You can freely add/remove paths below.
# 1) Public / core pages
section "1. Core pages"
CORE_PATHS=(
  "/"
  "/login"
  "/upgrade"
  "/home"
  "/playground"
  "/badge"
  "/verified"
)
for p in "${CORE_PATHS[@]}"; do
  test_get "$p"
done

# 2) OAuth / OIDC
section "2. OAuth2 / OIDC"
OAUTH_PATHS=(
  "/oauthx/status"
  "/oauthx/docs"
  "/.well-known/openid-configuration"
  "/oauth/jwks.json"
  "/oauth/authorize"
)
for p in "${OAUTH_PATHS[@]}"; do
  test_get "$p"
done

# 3) PoF / Playground API (GET-only checks)
section "3. PoF / Playground (GET)"
POF_GET_PATHS=(
  "/api/pof/stats"
)
for p in "${POF_GET_PATHS[@]}"; do
  test_get "$p"
done

# 4) Health / misc
section "4. Health / misc"
MISC_PATHS=(
  "/healthz"
  "/dashboard"
  "/robots.txt"
  "/sitemap.xml"
)
for p in "${MISC_PATHS[@]}"; do
  test_get "$p"
done

echo
echo "${GREEN}Done.${RESET} You can edit hodlxxi_route_test.sh to add more routes as your app grows."
echo "Tip: override BASE like:  BASE=http://127.0.0.1:5000 bash hodlxxi_route_test.sh"
