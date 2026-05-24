# Herald Fixture Demo (Local, Fixture-Only)

This demo is intentionally **fixture-only** and keeps Herald in dry-run safety mode.

## Safety boundaries

- No live relay access when `--fixture` is used.
- No live zaps.
- No outbound spending.
- No private keys.
- No wallet credentials.
- No payment execution.

## Command

```bash
python tools/herald_discovery_scan.py --fixture examples/herald/herald_fixture_events.json | jq .
```

## What to expect

The command prints JSON that includes:

- visible candidates
- per-candidate alignment scores
- scoring reasons
- zap eligibility signal
- suggested zap amounts (policy suggestions only)
- dry-run actions (no spending)

This is the human-visible Herald candidate demo before Stage 7B adds a live relay **read-only** adapter.
