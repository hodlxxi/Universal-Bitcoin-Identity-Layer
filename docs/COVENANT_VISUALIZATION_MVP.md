# Covenant Visualization MVP (`covenant_visualize`)

This MVP adds a paid HODLXXI agent capability to explain and visualize covenant-related Bitcoin script structures.

## Why this exists

`covenant_visualize` gives counterparties a machine-readable + human-readable interpretation layer for descriptor/script inputs while preserving the existing payment-first and signed-receipt execution model.

## Capability summary

- `job_type`: `covenant_visualize`
- `suggested_price_sats`: `21`
- Description: explain and visualize covenant/script/descriptor flows.

This job is exposed in:

- `GET /agent/capabilities`
- `GET /.well-known/agent.json`
- `POST /agent/request`

## Request shape

`/agent/request` accepts the existing `payload` field and now also accepts `input` as an alias.

```json
{
  "job_type": "covenant_visualize",
  "input": {
    "descriptor": "raw(...)",
    "script_asm": "OP_IF ... OP_ELSE ... OP_ENDIF",
    "script_hex": "6351...68",
    "network": "bitcoin"
  }
}
```

At least one of `descriptor`, `script_asm`, or `script_hex` is required.

## Result shape

```json
{
  "ok": true,
  "job_type": "covenant_visualize",
  "summary": "...",
  "human_explanation": {"summary": "..."},
  "machine_explanation": {
    "type": "conditional_multisig_timelock",
    "observed": {"ops": [], "keys": [], "timelocks": []},
    "inferred": {"branches": [], "spend_paths": []}
  },
  "mermaid": "flowchart TD\n  start -->|OP_IF| cooperative",
  "timeline": [],
  "graph": {"nodes": [], "edges": []},
  "graphviz_dot": "digraph CovenantFlow {...}",
  "warnings": [],
  "source_type": "script_asm"
}
```

## Parsing + interpretation boundaries

The service is intentionally conservative:

- **Observed:** tokens/opcodes/keys/timelocks that are directly parsed from provided input.
- **Inferred:** branch and spend-path structure inferred from control-flow markers.
- **Heuristic/explanatory:** role labels and economic interpretation notes.

The service does **not** claim complete Miniscript support and does not claim legal/economic covenant certainty from script evidence alone.

## Current limitations

- Descriptor parsing is currently limited to `raw(<hex>)` extraction.
- Script hex decoding is partial by design and reports unsupported opcodes.
- Role assignment (`Key 1`, `Key 2`) is heuristic.
- Timelock classification (`block_height` vs `timestamp`) is a standard threshold heuristic and may still require context.
