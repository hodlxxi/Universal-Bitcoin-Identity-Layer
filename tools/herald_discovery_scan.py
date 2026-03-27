#!/usr/bin/env python3
"""Run a Herald Nostr discovery dry-run scan and print shortlist."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.herald_nostr_discovery import HeraldNostrDiscoveryEngine


def main() -> int:
    engine = HeraldNostrDiscoveryEngine()
    rows = engine.discover_and_evaluate()

    print(
        json.dumps(
            {
                "declared_herald_pubkey": engine.config.declared_herald_pubkey,
                "zap_mode": engine.config.zap_mode,
                "relay_urls": engine.config.relay_urls,
                "candidates_found": len(rows),
                "top_candidates": [
                    {
                        "event_id": item.event_id,
                        "author_pubkey": item.author_pubkey,
                        "score": item.score,
                        "zap_eligible": item.zap_eligible,
                        "suggested_zap_amount_sats": item.suggested_zap_amount_sats,
                        "suggested_comment": item.suggested_comment,
                        "action_taken": item.action_taken,
                        "action_reason": item.action_reason,
                        "reasons": item.reasons,
                    }
                    for item in rows[:20]
                ],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
