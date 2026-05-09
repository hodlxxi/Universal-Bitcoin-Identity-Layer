# HODLXXI SDK Nostr Auth Challenge Flow

The SDK does not hold Nostr private keys.

The flow is:

1. Create a HODLXXI challenge with `method="nostr"`.
2. Build a Nostr event template.
3. Sign the event externally.
4. Submit the signed event to `/api/verify`.

## Server contract

Create the challenge:

```python
from hodlxxi_sdk import HODLXXIClient

client = HODLXXIClient("https://hodlxxi.com")

challenge = client.create_challenge(
    pubkey="02...",
    method="nostr",
)
```

The server stores the challenge and expects a signed Nostr event during verification.

Required Nostr event fields:

```text
id
pubkey
created_at
kind
tags
content
sig
```

The server requires:

```text
kind == 22242
tag ["challenge", "..."] matches the challenge string
tag ["u", "https://hodlxxi.com/api/verify"] or ["url", "..."] matches the verify URL when present
id recomputes from the Nostr event payload
sig verifies against the x-only Nostr pubkey
```

If the challenge was created with a compressed `02...` or `03...` pubkey, the server expects the Nostr event pubkey to be the x-only 64 hex chars after the first byte.

## Unsigned event template

```json
{
  "pubkey": "...",
  "created_at": 1778350000,
  "kind": 22242,
  "tags": [
    ["challenge", "HODLXXI:login:<timestamp>:<nonce>"],
    ["u", "https://hodlxxi.com/api/verify"]
  ],
  "content": "HODLXXI Nostr auth",
  "id": "<external signer fills event id>",
  "sig": "<external signer fills signature>"
}
```

## Verify with SDK

After external signing:

```python
verified = client.verify_challenge(
    challenge_id=challenge["challenge_id"],
    nostr_event=signed_event,
)
```

## Dry-run example

```bash
python examples/python/nostr_auth_challenge_flow.py \
  --pubkey 02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

This creates a challenge and prints an unsigned Nostr event template. It does not sign or verify.

## Security boundary

Do not paste Nostr private keys into examples, scripts, environment files, or source code.

Concrete Nostr signer adapters should be separate and must not make the SDK responsible for secret storage.
