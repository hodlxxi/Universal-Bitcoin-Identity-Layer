# covenant_decode example

## Example request

```json
{
  "job_type": "covenant_decode",
  "payload": {
    "script_hex": "51b1"
  }
}
```

## Example result fields

Depending on the live runtime, the final result may include fields such as:

- parsed script or descriptor data
- branches
- timelocks
- structured interpretation

Use the runtime receipt as the source of truth for the exact fields returned.
