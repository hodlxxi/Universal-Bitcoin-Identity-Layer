# NIP-17 Staging Operator Send Smoke

This runbook proves the staging-only opaque envelope path:

operator script -> staging HTTP intake -> opaque envelope storage -> receiver inbox metadata.

It does not prove client-side decryption. It does not enable production intake.

## Safety rules

- Do not run this against production unless a later rollout explicitly says so.
- Do not use private keys.
- Do not send plaintext.
- Do not use real encrypted message material.
- Do not leave `NIP17_MESSAGES_ENABLED=true` enabled after the staging smoke unless actively testing.

## Enable staging intake temporarily

Run on the server:

cd /srv/ubid-staging
source venv/bin/activate

sudo mkdir -p /etc/systemd/system/ubid-staging.service.d

printf '%s\n' '[Service]' 'Environment=NIP17_MESSAGES_ENABLED=true' \
  | sudo tee /etc/systemd/system/ubid-staging.service.d/60-nip17-staging-intake.conf >/dev/null

sudo systemctl daemon-reload
sudo systemctl restart ubid-staging

for i in $(seq 1 30); do
  if ss -ltn | grep -q ':5055 '; then
    break
  fi
  sleep 1
done

for i in $(seq 1 30); do
  code=$(curl -sS -o /tmp/stage_ready_body -w "%{http_code}" \
    -H "X-Forwarded-Proto: https" \
    http://127.0.0.1:5055/health/ready || true)
  if [ "$code" = "200" ]; then
    break
  fi
  sleep 1
done

systemctl is-active ubid-staging
systemctl cat ubid-staging | grep -n 'NIP17_MESSAGES_ENABLED'
curl -sS -H "X-Forwarded-Proto: https" http://127.0.0.1:5055/.well-known/nostr-dm-policy.json \
  | python -m json.tool | grep -E '"enabled"|"intake_enabled"|"relay_publishing"'

Expected:

active
NIP17_MESSAGES_ENABLED=true
enabled=true
intake_enabled=true
relay_publishing=false

## Capture baseline receiver inbox count

Use the same 64-hex receiver pubkey that you will send to.

cd /srv/ubid-staging
source venv/bin/activate

RECEIVER=<64_HEX_RECEIVER_PUBKEY>
STAGE_PID="$(systemctl show -p MainPID --value ubid-staging)"

python scripts/nip17_verify_receiver_inbox.py \
  --receiver-pubkey "$RECEIVER" \
  --runtime-pid "$STAGE_PID" \
  | tee /tmp/nip17_baseline_inbox.json

python -c 'import json; print(json.load(open("/tmp/nip17_baseline_inbox.json"))["total"])'

Save the baseline `total`. After sending one envelope, expected `total` is baseline + 1.

## Send one opaque test envelope

Use a 64-hex Nostr receiver pubkey that you can log in as, or a known test receiver.

cd /srv/ubid-staging
source venv/bin/activate

python scripts/nip17_send_test_envelope.py \
  --base http://127.0.0.1:5055 \
  --receiver-pubkey <64_HEX_RECEIVER_PUBKEY>

Expected response includes:

{
  "ok": true,
  "status_code": 202,
  "plaintext_sent": false,
  "relay_publishing": false
}

## Verify metadata-only inbox with runtime DB context

Use the same receiver pubkey from the send step. This verifier loads the staging runtime env from the service MainPID and prints metadata only.

Expected `total` is the saved baseline count plus one.

cd /srv/ubid-staging
source venv/bin/activate

python scripts/nip17_verify_receiver_inbox.py \
  --receiver-pubkey <64_HEX_RECEIVER_PUBKEY> \
  --runtime-pid "$(systemctl show -p MainPID --value ubid-staging)"

Expected response includes:

{
  "ok": true,
  "database": {
    "is_memory": false
  }
}

The verifier must not print `envelope_json`, `content`, `sig`, ciphertext, plaintext, private keys, or env secrets.

## Verify unauthenticated API remains protected

Unauthenticated API should still return 401:

curl -sS -H "X-Forwarded-Proto: https" \
  http://127.0.0.1:5055/api/messages/nip17/inbox/envelopes

Expected:

{"error":"unauthorized","message":"login required"}

## Disable staging intake again

cd /srv/ubid-staging
source venv/bin/activate

sudo rm -f /etc/systemd/system/ubid-staging.service.d/60-nip17-staging-intake.conf
sudo systemctl daemon-reload
sudo systemctl restart ubid-staging

for i in $(seq 1 30); do
  if ss -ltn | grep -q ':5055 '; then
    break
  fi
  sleep 1
done

for i in $(seq 1 30); do
  code=$(curl -sS -o /tmp/stage_ready_body -w "%{http_code}" \
    -H "X-Forwarded-Proto: https" \
    http://127.0.0.1:5055/health/ready || true)
  if [ "$code" = "200" ]; then
    break
  fi
  sleep 1
done

systemctl is-active ubid-staging
systemctl cat ubid-staging | grep -n 'NIP17_MESSAGES_ENABLED' || true
curl -sS -H "X-Forwarded-Proto: https" http://127.0.0.1:5055/.well-known/nostr-dm-policy.json \
  | python -m json.tool | grep -E '"enabled"|"intake_enabled"|"relay_publishing"'

Expected:

active
enabled=false
intake_enabled=false
relay_publishing=false

Expected: no `NIP17_MESSAGES_ENABLED` line.
