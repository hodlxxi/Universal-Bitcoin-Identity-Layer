# HODLXXI SDK Auth Challenge Flow

The SDK auth flow is:

1. Create a challenge.
2. Sign the challenge with an external wallet/signer.
3. Verify the signed challenge.

The SDK does not hold private keys.

## Live contract

`POST /api/challenge` requires:

```json
{
  "pubkey": "02..."
}
```

It does not accept an empty body, `public_key`, or `npub`.

Successful response:

```json
{
  "ok": true,
  "challenge_id": "...",
  "challenge": "HODLXXI:login:<timestamp>:<nonce>",
  "expires_in": 300
}
```

Default `POST /api/verify` accepts:

```json
{
  "challenge_id": "...",
  "pubkey": "02...",
  "signature": "..."
}
```

For Nostr mode, create the challenge with `method="nostr"` and verify with `nostr_event`.

## SDK usage

```python
from hodlxxi_sdk import HODLXXIClient

client = HODLXXIClient("https://hodlxxi.com")

challenge = client.create_challenge(pubkey="02...")
signature = external_signer(challenge["challenge"])

verified = client.verify_challenge(
    challenge_id=challenge["challenge_id"],
    pubkey="02...",
    signature=signature,
)
```

## Dry run

```bash
python examples/python/auth_challenge_flow.py \
  --pubkey 02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --dry-run
```

This dry run creates and prints a challenge only. It does not sign or verify.

## Security boundary

Do not paste private keys into examples, scripts, environment files, or source code.

Concrete wallet adapters should be separate and must not make the SDK responsible for secret storage.
