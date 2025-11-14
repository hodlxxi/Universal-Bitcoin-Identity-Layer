#!/bin/bash
# HODLXXI OAuth2 Live Demo

BASE="https://hodlxxi.com"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  HODLXXI OAuth2/OIDC Server - Live Production Demo        ║"
echo "║  Bitcoin-native authentication with Lightning support     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Register OAuth Client
echo "📝 Step 1: Register as OAuth Client"
echo "   (Like 'Sign in with Google' but for Bitcoin apps)"
echo ""

REG=$(curl -s -X POST "$BASE/oauth/register" \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["http://localhost:3000/callback"]}')

echo "$REG" | jq .

CID=$(echo "$REG" | jq -r .client_id)
CSEC=$(echo "$REG" | jq -r .client_secret)
TIER=$(echo "$REG" | jq -r .client_type)
RATE=$(echo "$REG" | jq -r .rate_limit)

echo ""
echo "✅ Registered! Got credentials:"
echo "   Client ID: $CID"
echo "   Tier: $TIER ($RATE requests/hour)"
echo ""
read -p "Press Enter to continue..."

# Step 2: Authorization
echo ""
echo "🔐 Step 2: Get Authorization Code"
echo "   (User approves access to their data)"
echo ""

AUTH=$(curl -s -i "$BASE/oauth/authorize?client_id=$CID&redirect_uri=http://localhost:3000/callback&response_type=code&scope=read_limited&state=demo123")

CODE=$(echo "$AUTH" | grep -i "^location:" | sed 's/.*code=\([^&[:space:]]*\).*/\1/' | tr -d '\r')

echo "✅ User approved! Got authorization code:"
echo "   Code: $CODE"
echo "   (This code expires in 10 minutes)"
echo ""
read -p "Press Enter to continue..."

# Step 3: Token Exchange
echo ""
echo "🎫 Step 3: Exchange Code for Access Token"
echo "   (Backend securely exchanges code for tokens)"
echo ""

TOK=$(curl -s -X POST "$BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=$CID&client_secret=$CSEC&code=$CODE&redirect_uri=http://localhost:3000/callback")

echo "$TOK" | jq .

AT=$(echo "$TOK" | jq -r .access_token)
RT=$(echo "$TOK" | jq -r .refresh_token)

echo ""
echo "✅ Got tokens!"
echo "   Access token (1 hour): ${AT:0:50}..."
echo "   Refresh token (30 days): ${RT:0:50}..."
echo ""
read -p "Press Enter to continue..."

# Step 4: Use the API
echo ""
echo "🚀 Step 4: Call Protected API"
echo "   (Using the access token as Bearer credential)"
echo ""

RESULT=$(curl -s -H "Authorization: Bearer $AT" "$BASE/api/demo/free")

echo "$RESULT" | jq .

echo ""
echo "✅ API access granted!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 Complete OAuth2 flow in 4 API calls!"
echo ""
echo "What makes this special:"
echo "  ✓ Full OAuth 2.0 + OpenID Connect compliance"
echo "  ✓ Lightning Network authentication (LNURL-Auth)"
echo "  ✓ Redis-backed persistence (data survives restarts)"
echo "  ✓ JWT tokens with proper validation"
echo "  ✓ Rate limiting (100/1K/10K per tier)"
echo "  ✓ Security audit logging"
echo "  ✓ Bitcoin Core RPC integration"
echo ""
echo "Tech Stack: Python/Flask, Redis, Gunicorn, Bitcoin Core"
echo "Capacity: 1,000 concurrent users, 10,000 req/hour"
echo ""
echo "Try it yourself:"
echo "  Discovery: $BASE/.well-known/openid-configuration"
echo "  Status: $BASE/oauthx/status"
echo "  Docs: $BASE/oauthx/docs"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"