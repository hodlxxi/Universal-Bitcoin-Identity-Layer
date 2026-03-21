# Signature verification flow

## Example request

```json
{
  "job_type": "verify_signature",
  "payload": {
    "message": "hello",
    "signature": "deadbeef",
    "pubkey": "021111111111111111111111111111111111111111111111111111111111111111"
  }
}
```

## Interpretation boundaries

- `valid=true` means the runtime accepted the signature for the supplied message and public key.
- `valid=false` means the runtime did not verify the signature.
- Neither result should be used as a reputation score.
