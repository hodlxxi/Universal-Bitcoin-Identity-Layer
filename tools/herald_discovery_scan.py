#!/usr/bin/env python3
"""Run a Herald Nostr discovery dry-run scan and print shortlist."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.herald_nostr_discovery import HeraldNostrDiscoveryEngine, HeraldRelayReadonlyClient


class FixtureRelayDiscoveryClient:
    """Relay client that serves local fixture events only."""

    def __init__(self, events: list[dict[str, Any]]):
        self._events = events

    def search_recent_notes(self, **kwargs) -> list[dict[str, Any]]:
        return self._events


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        type=Path,
        default=None,
        help="Load discovery events from a local JSON fixture file.",
    )
    parser.add_argument(
        "--live-relay-readonly",
        action="store_true",
        help="Read public kind-1 notes from configured relays using read-only mode.",
    )
    return parser.parse_args()


def _load_fixture_events(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("fixture JSON must be a list of event objects")
    for idx, row in enumerate(payload):
        if not isinstance(row, dict):
            raise ValueError(f"fixture event at index {idx} must be an object")
    return payload


def main() -> int:
    args = _parse_args()
    relay_client = None
    source_mode = "noop"
    if args.fixture is not None:
        fixture_events = _load_fixture_events(args.fixture)
        relay_client = FixtureRelayDiscoveryClient(fixture_events)
        source_mode = "fixture"
    elif args.live_relay_readonly:
        relay_client = HeraldRelayReadonlyClient(max_events=100, timeout_seconds=8.0)
        source_mode = "live_relay_readonly"

    engine = HeraldNostrDiscoveryEngine(relay_client=relay_client)
    rows = engine.discover_and_evaluate()

    print(
        json.dumps(
            {
                "declared_herald_pubkey": engine.config.declared_herald_pubkey,
                "source_mode": source_mode,
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
