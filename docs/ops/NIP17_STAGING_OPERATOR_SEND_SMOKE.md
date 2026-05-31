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

```bash
cd /srv/ubid-staging
source venv/bin/activate

sudo mkdir -p /etc/systemd/system/ubid-staging.service.d
sudo tee /etc/systemd/system/ubid-staging.service.d/60-nip17-staging-intake.conf >/dev/null <<'EOF'
[Service]
Environment=NIP17_MESSAGES_ENABLED=true
EOF

sudo systemctl daemon-reload
sudo systemctl restart ubid-staging
sleep 3

systemctl is-active ubid-staging
systemctl cat ubid-staging | grep -n 'NIP17_MESSAGES_ENABLED'
```

## Send one opaque test envelope

Use a 64-hex Nostr receiver pubkey that you can log in as, or a known test receiver.

```bash
cd /srv/ubid-staging
source venv/bin/activate

python scripts/nip17_send_test_envelope.py \
  --base http://127.0.0.1:5055 \
  --receiver-pubkey <64_HEX_RECEIVER_PUBKEY>
```

Expected response includes:

```json
{
  "ok": true,
  "status_code": 202,
  "plaintext_sent": false,
  "relay_publishing": false
}
```

## Verify metadata-only inbox API

Use the browser to log in as the same receiver. The `/app` Hybrid Messaging panel should show the stored envelope count and a metadata row.

Unauthenticated API should still return 401:

```bash
curl -sS -H "X-Forwarded-Proto: https" \
  http://127.0.0.1:5055/api/messages/nip17/inbox/envelopes
```

Expected:

```json
{"error":"unauthorized","message":"login required"}
```

## Disable staging intake again

```bash
cd /srv/ubid-staging
source venv/bin/activate

sudo rm -f /etc/systemd/system/ubid-staging.service.d/60-nip17-staging-intake.conf
sudo systemctl daemon-reload
sudo systemctl restart ubid-staging
sleep 3

systemctl is-active ubid-staging
systemctl cat ubid-staging | grep -n 'NIP17_MESSAGES_ENABLED' || true
```

Expected: no `NIP17_MESSAGES_ENABLED` line.
