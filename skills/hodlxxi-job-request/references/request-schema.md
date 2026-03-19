# Job request shape

Submit JSON to `POST /agent/request` using the runtime-advertised job types.

## Base request

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

## Runtime-supported job types in the current implementation

- `ping`
- `verify_signature`
- `covenant_decode`

Always confirm the live `job_types` object from `GET /agent/capabilities` before relying on static examples.
