#!/bin/bash
# HODLXXI Proof-of-Funds - SIGNED (REAL VERSION)

BASE="https://hodlxxi.com"
PUBKEY_ID="alex-signed-proof"
RPC_WALLET="Vmldf33ks130383"

btc() {
  bitcoin-cli -rpcuser=hodlwatch -rpcpassword=Vmldf33ks \
    -rpcwallet="$RPC_WALLET" "$@"
}

echo "========================================"
echo "  HODLXXI SIGNED Proof-of-Funds Test"
echo "========================================"
echo

# Check balance first
BALANCE=$(btc getbalance)
echo "Wallet balance: $BALANCE BTC"

if [ "$BALANCE" = "0.00000000" ]; then
  echo "❌ Wallet is empty!"
  exit 1
fi
echo

echo "== 1) Request PoF challenge =="
CHJSON=$(curl -sS -X POST "$BASE/api/challenge" \
  -H 'Content-Type: application/json' \
  -d "{\"pubkey\":\"$PUBKEY_ID\"}")

echo "$CHJSON" | jq .

CID=$(echo "$CHJSON" | jq -r .challenge_id)
CHALLENGE=$(echo "$CHJSON" | jq -r .challenge)
CHALLENGE_HEX=$(printf "%s" "$CHALLENGE" | xxd -p -c 9999)

echo
echo "Challenge: $CHALLENGE"
echo

echo "== 2) Get UTXOs =="
ALL_UTXOS=$(btc listunspent 0 9999999)
UTXO_COUNT=$(echo "$ALL_UTXOS" | jq 'length')

echo "Found $UTXO_COUNT UTXOs"
echo "$ALL_UTXOS" | jq '.[] | {txid,vout,amount}'
echo

INPUTS=$(echo "$ALL_UTXOS" | jq '[.[] | {txid,vout}]')

echo "== 3) Create UNSIGNED PSBT =="
PSBT_UNSIGNED=$(btc createpsbt "$INPUTS" "[{\"data\":\"$CHALLENGE_HEX\"}]")
echo "Unsigned PSBT (truncated): ${PSBT_UNSIGNED:0:80}..."
echo

echo "== 4) SIGN the PSBT (proving key ownership!) =="
SIGNED_RESULT=$(btc walletprocesspsbt "$PSBT_UNSIGNED")
echo "$SIGNED_RESULT" | jq .

PSBT_SIGNED=$(echo "$SIGNED_RESULT" | jq -r .psbt)
IS_COMPLETE=$(echo "$SIGNED_RESULT" | jq -r .complete)

echo
echo "Signed PSBT (truncated): ${PSBT_SIGNED:0:80}..."
echo "Complete: $IS_COMPLETE"
echo

if [ "$IS_COMPLETE" != "true" ]; then
  echo "⚠<fe0f>  PSBT not fully signed - might fail verification"
fi

echo "== 5) Submit SIGNED PSBT to verify endpoint =="

RESULT=$(curl -sS -X POST "$BASE/api/verify" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg cid "$CID" --arg psbt "$PSBT_SIGNED" \
        '{challenge_id:$cid, psbt:$psbt}')")

echo
echo "========================================"
echo "         VERIFICATION RESULT"
echo "========================================"
echo "$RESULT" | jq .
echo

OK=$(echo "$RESULT" | jq -r .ok)
PROVEN_BTC=$(echo "$RESULT" | jq -r .total_btc // "0")
MESSAGE=$(echo "$RESULT" | jq -r .message // "")

if [ "$OK" = "true" ]; then
  echo "✅ SUCCESS! Cryptographic proof verified:"
  echo "   • Amount proven: $PROVEN_BTC BTC (1,210 sats)"
  echo "   • Signatures validated: YES"
  echo "   • Message: $MESSAGE"
  echo
  echo "🔐 This is REAL Proof-of-Funds with signatures!"
  echo "🎉 Your server now validates cryptographic ownership!"
else
  echo "❌ Verification failed"
  ERROR=$(echo "$RESULT" | jq -r .error // "unknown")
  echo "   Error: $ERROR"
fi
