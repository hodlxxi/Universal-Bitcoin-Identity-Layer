#!/bin/bash
# HODLXXI Proof-of-Funds - FULL WALLET BALANCE

BASE="https://hodlxxi.com"
PUBKEY_ID="alex-full-wallet"
RPC_WALLET="hodlandwatch"

btc() {
  bitcoin-cli -rpcuser=hodlwatch -rpcpassword=Vmldf33ks \
    -rpcwallet="$RPC_WALLET" "$@"
}

echo "========================================"
echo "  HODLXXI Full Wallet Balance Proof"
echo "========================================"
echo

echo "== 1) Request PoF challenge from HODLXXI =="
CHJSON=$(curl -sS -X POST "$BASE/api/playground/pof/challenge" \
  -H 'Content-Type: application/json' \
  -d "{\"pubkey\":\"$PUBKEY_ID\"}")

echo "$CHJSON" | jq .

CID=$(echo "$CHJSON" | jq -r .challenge_id)
CHALLENGE=$(echo "$CHJSON" | jq -r .challenge)
CHALLENGE_HEX=$(printf "%s" "$CHALLENGE" | xxd -p -c 9999)

echo
echo "challenge_id:   $CID"
echo "challenge text: $CHALLENGE"
echo

echo "== 2) Fetching ALL UTXOs from wallet '$RPC_WALLET' =="
ALL_UTXOS=$(btc listunspent 0 9999999)
UTXO_COUNT=$(echo "$ALL_UTXOS" | jq 'length')
TOTAL_BALANCE=$(echo "$ALL_UTXOS" | jq '[.[].amount] | add')

echo "Found $UTXO_COUNT UTXOs"
echo "Total balance: $TOTAL_BALANCE BTC"
echo

echo "UTXO breakdown:"
echo "$ALL_UTXOS" | jq '.[] | {txid,vout,amount}'
echo

echo "== 3) Creating PSBT with ALL $UTXO_COUNT UTXOs =="

# Build inputs array from all UTXOs
INPUTS=$(echo "$ALL_UTXOS" | jq '[.[] | {txid,vout}]')

echo "Inputs (first 3 shown):"
echo "$INPUTS" | jq '.[0:3]'
echo

# Create PSBT with all inputs
PSBT_BASE64=$(btc createpsbt "$INPUTS" "[{\"data\":\"$CHALLENGE_HEX\"}]")

echo "PSBT created successfully!"
echo "PSBT size: ${#PSBT_BASE64} characters"
echo "PSBT (truncated): $(echo "$PSBT_BASE64" | head -c 100)..."
echo

echo "== 4) Submitting PSBT to PoF verify endpoint =="

RESULT=$(curl -sS -X POST "$BASE/api/playground/pof/verify" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg cid "$CID" --arg psbt "$PSBT_BASE64" \
        '{challenge_id:$cid, psbt:$psbt}')")

echo
echo "========================================"
echo "           VERIFICATION RESULT"
echo "========================================"
echo "$RESULT" | jq .
echo

# Parse results
OK=$(echo "$RESULT" | jq -r .ok)
PROVEN_SAT=$(echo "$RESULT" | jq -r .total_sat)
PROVEN_BTC=$(echo "$RESULT" | jq -r .total_btc)
PROVEN_COUNT=$(echo "$RESULT" | jq -r .unspent_count)

if [ "$OK" = "true" ]; then
  echo "✅ SUCCESS! Full wallet balance proven:"
  echo "   • UTXOs proven: $PROVEN_COUNT"
  echo "   • Total amount: $PROVEN_BTC BTC ($PROVEN_SAT sats)"
  echo "   • Privacy: No addresses revealed!"
  echo
  echo "🎉 You just proved ownership of your entire wallet"
  echo "   without revealing a single address or signing anything!"
else
  echo "❌ Verification failed"
  echo "$RESULT" | jq .
fi
