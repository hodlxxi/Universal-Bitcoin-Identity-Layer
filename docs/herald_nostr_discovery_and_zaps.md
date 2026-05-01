# Herald Nostr discovery + alignment zaps (dry-run first)

## Purpose

This module adds a conservative **discovery candidates** pipeline for HODLXXI Herald:

1. discover recent aligned posts from configured relays,
2. score relevance with explicit reason codes,
3. assess zap capability evidence,
4. propose **suggested zap** actions,
5. persist auditable decisions locally.

It is intentionally useful before any live payment path exists.

## Identity model

The feature acts as the **declared Herald public identity**:

- `02019e7a92d22e4467e0afb20ce62976e976d1558e553351e1fb1a886b4a149f92`

The module does **not** use an operator personal key.

## Dry-run policy

Default mode is `HERALD_ZAP_MODE=dry_run`.

- `off`: evaluate and persist only.
- `dry_run`: evaluate and persist; mark dry-run candidates.
- `live`: still conservative and scaffold-only unless transport/signing is wired.

No fake payment success is reported.

## Discovery and scoring

`app/services/herald_nostr_discovery.py` provides:

- configurable relays, hashtags, keywords, spam terms,
- recent window filtering (`HERALD_SEARCH_WINDOW_HOURS`, default 72),
- weighted relevance scoring with reason codes,
- spam and low-information penalties,
- tiered suggested zap amounts:
  - weak: 21 sats
  - strong: 69 sats
  - direct: 210 sats

## Zap eligibility checks

For each author, the engine checks metadata evidence conservatively:

- `lud16`
- `lud06`
- `lnurl_pay`

Output is one of: `true`, `false`, `unknown`.

## Audit storage and dedup

State is stored in JSON (`HERALD_DISCOVERY_STATE_FILE`, default `data/herald_nostr_discovery_state.json`).

Each record stores:

- event and author metadata,
- score/matches/reasons,
- zap eligibility,
- suggested amount/comment,
- action decision (`none|dry_run_candidate|zap_sent|skipped`),
- timestamps.

The store deduplicates by `event_id`.

## CLI scan

Run a manual scan:

```bash
python tools/herald_discovery_scan.py
```

This prints JSON shortlist output suitable for operator review.

## Future live-zap path

`prepare_zap_request(...)` and `execute_zap(...)` are scaffolded interfaces.

To enable real zaps safely in Phase 2, wire:

- relay event transport,
- signer abstraction for declared Herald identity,
- wallet/payment transport,
- production guardrails and rate enforcement.
