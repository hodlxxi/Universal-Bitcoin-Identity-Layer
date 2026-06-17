# HODLXXI Python SDK

The HODLXXI SDK gives agents and applications a small Python client for public discovery, agent job requests, and Bitcoin/Nostr-native auth challenge flows.

The SDK does not hold private keys. Applications bring their own signer.

## Install

From a local checkout:

```bash
python -m pip install -e .
```

## 60-second public agent flow

```python
from hodlxxi_sdk import HODLXXIClient

client = HODLXXIClient("https://hodlxxi.com")

print(client.ready())
print(client.capabilities())

job = client.create_job("ping", {"hello": "world"})
print(job)
```


## Job verification

Use `verify_job(job_id)` to read the normalized verifier result for a job:

```python
verification = client.verify_job(job["job_id"])

if verification.get("status") == "no_receipt":
    # The job exists, but the Lightning invoice has not been paid yet.
    # The API returns HTTP 409 with reason=receipt_not_issued, and the SDK
    # returns that JSON body instead of raising.
    print("receipt unavailable until payment confirms")
elif verification.get("status") == "verified":
    print(verification["receipt"])
```

`verify_job()` returns the JSON body for HTTP 200 verified receipts and for the
normalized HTTP 409 `status=no_receipt`, `reason=receipt_not_issued` state. It
raises `HODLXXIHTTPError` for missing jobs such as HTTP 404 `error=not_found` and
for other non-success responses.

## Auth challenge flow

Default Bitcoin-message flow:

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

See:

- `docs/sdk/AUTH_CHALLENGE_FLOW.md`
- `examples/python/auth_challenge_flow.py`

Dry run:

```bash
python examples/python/auth_challenge_flow.py \
  --pubkey 02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --dry-run
```

## Nostr auth flow

```python
from hodlxxi_sdk import HODLXXIClient

client = HODLXXIClient("https://hodlxxi.com")

challenge = client.create_challenge(
    pubkey="02...",
    method="nostr",
)

verified = client.verify_challenge(
    challenge_id=challenge["challenge_id"],
    nostr_event=signed_event,
)
```

See:

- `docs/sdk/NOSTR_AUTH_CHALLENGE_FLOW.md`
- `examples/python/nostr_auth_challenge_flow.py`

Dry run:

```bash
python examples/python/nostr_auth_challenge_flow.py \
  --pubkey 02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

## Receipt helpers

```python
from hodlxxi_sdk import AgentReceipt

receipt = AgentReceipt.from_response(response)
print(receipt.job_id)
print(receipt.status)
print(receipt.is_done)
print(receipt.is_signed)
```

## Signing helpers

```python
from hodlxxi_sdk import Challenge, sign_challenge

signed = sign_challenge(
    Challenge("HODLXXI:login:..."),
    signer=lambda message_bytes: external_wallet_signer(message_bytes),
)
```

The SDK prepares messages and parses responses. It does not manage wallets, private keys, seed phrases, macaroons, or Nostr secret keys.

## Security boundary

Do not paste private keys into examples, scripts, environment files, or source code.

Good integrations keep signing outside the SDK:

- wallet-backed Bitcoin message signer
- hardware signer
- Bitcoin Core signing flow
- browser/extension Nostr signer
- agent runtime signer

## Current examples

- `examples/python/ping_agent.py`
- `examples/python/auth_challenge_flow.py`
- `examples/python/nostr_auth_challenge_flow.py`

## Current docs

- `docs/sdk/AUTH_CHALLENGE_FLOW.md`
- `docs/sdk/NOSTR_AUTH_CHALLENGE_FLOW.md`
