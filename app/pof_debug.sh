#!/bin/bash
BASE="https://hodlxxi.com"
PUBKEY_ID="alex-signed-proof"
RPC_WALLET="Vmldf33ks130383"

btc() {
  bitcoin-cli -rpcuser=hodlwatch -rpcpassword=Vmldf33ks \
    -rpcwallet="$RPC_WALLET" "$@"
}

CHJSON=$(curl -sS -X POST "$BASE/api/playground/pof/challenge" \
  -H 'Content-Type: application/json' \
  -d "{\"pubkey\":\"$PUBKEY_ID\"}")

CID=$(echo "$CHJSON" | jq -r .challenge_id)
CHALLENGE=$(echo "$CHJSON" | jq -r .challenge)
CHALLENGE_HEX=$(printf "%s" "$CHALLENGE" | xxd -p -c 9999)

INPUTS=$(btc listunspent 0 9999999 | jq '[.[] | {txid,vout}]')
PSBT_UNSIGNED=$(btc createpsbt "$INPUTS" "[{\"data\":\"$CHALLENGE_HEX\"}]")

echo "Signing PSBT..."
SIGNED_RESULT=$(btc walletprocesspsbt "$PSBT_UNSIGNED")
PSBT_SIGNED=$(echo "$SIGNED_RESULT" | jq -r .psbt)

echo "Verifying proof..."
RESPONSE=$(curl -sS -X POST "$BASE/api/playground/pof/verify" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg cid "$CID" --arg psbt "$PSBT_SIGNED" \
        '{challenge_id:$cid, psbt:$psbt}')")

echo "Raw response:"
echo "$RESPONSE"
echo
echo "Parsed with jq:"
echo "$RESPONSE" | jq . 2>&1 || echo "Failed to parse JSON"
