from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.services.herald_nostr_discovery import (
    DECLARED_HERALD_PUBKEY,
    DiscoveryStateStore,
    HeraldDiscoveryConfig,
    HeraldNostrDiscoveryEngine,
    score_alignment,
    suggest_zap_policy,
)


class _FakeRelayClient:
    def __init__(self, events):
        self._events = events

    def search_recent_notes(self, **kwargs):
        return self._events


class _FakeMetadataResolver:
    def __init__(self, metadata_by_pubkey):
        self._meta = metadata_by_pubkey

    def resolve_author_metadata(self, pubkey):
        return self._meta.get(pubkey)


def _sample_event(event_id: str, content: str, *, age_hours: int = 1, pubkey: str = "a" * 64):
    created_at = int((datetime.now(timezone.utc) - timedelta(hours=age_hours)).timestamp())
    return {
        "id": event_id,
        "pubkey": pubkey,
        "kind": 1,
        "created_at": created_at,
        "content": content,
        "tags": [["t", "nostr"], ["t", "bitcoin"]],
    }


def test_scoring_relevant_vs_irrelevant_posts():
    relevant = score_alignment(
        content="HODLXXI UBID for bitcoin agent identity with signed receipts #nostr",
        tags=[["t", "nostr"]],
        alignment_hashtags=["nostr", "bitcoin"],
        alignment_keywords=["bitcoin agent", "signed receipts", "ubid", "hodlxxi"],
        spam_terms=["giveaway"],
    )
    irrelevant = score_alignment(
        content="moon giveaway now",
        tags=[],
        alignment_hashtags=["nostr", "bitcoin"],
        alignment_keywords=["bitcoin agent", "signed receipts"],
        spam_terms=["giveaway", "moon"],
    )

    assert relevant["score"] > irrelevant["score"]
    assert "direct_alignment:hodlxxi_or_ubid" in relevant["reasons"]
    assert "negative:spam_term" in irrelevant["reasons"]


def test_deduplication_skips_seen_events(tmp_path: Path):
    state_file = tmp_path / "discovery.json"
    cfg = HeraldDiscoveryConfig(state_file=state_file)
    event = _sample_event("evt-1", "hodlxxi ubid bitcoin agent #nostr")
    relay = _FakeRelayClient([event])
    resolver = _FakeMetadataResolver({event["pubkey"]: {"lud16": "alice@getalby.com"}})

    engine = HeraldNostrDiscoveryEngine(cfg, relay_client=relay, metadata_resolver=resolver)
    first = engine.discover_and_evaluate()
    second = engine.discover_and_evaluate()

    assert len(first) == 1
    assert len(second) == 0


def test_dry_run_mode_default_does_not_send_zaps(tmp_path: Path):
    state_file = tmp_path / "discovery.json"
    cfg = HeraldDiscoveryConfig(state_file=state_file, zap_mode="dry_run")
    event = _sample_event("evt-2", "hodlxxi bitcoin agent identity #nostr")
    relay = _FakeRelayClient([event])
    resolver = _FakeMetadataResolver({event["pubkey"]: {"lud16": "alice@getalby.com"}})

    engine = HeraldNostrDiscoveryEngine(cfg, relay_client=relay, metadata_resolver=resolver)
    results = engine.discover_and_evaluate()

    assert results[0].action_taken == "dry_run_candidate"
    executed = engine.execute_zap(results[0])
    assert executed["payment_sent"] is False


def test_suggested_zap_tiering_works():
    cfg = HeraldDiscoveryConfig()
    weak = suggest_zap_policy(score=2.5, zap_eligible="unknown", cfg=cfg)
    strong = suggest_zap_policy(score=4.5, zap_eligible="true", cfg=cfg)
    direct = suggest_zap_policy(score=8.0, zap_eligible="true", cfg=cfg)

    assert weak["suggested_zap_amount_sats"] == 21
    assert strong["suggested_zap_amount_sats"] == 69
    assert direct["suggested_zap_amount_sats"] == 210


def test_declared_identity_used_and_no_operator_key_reference(tmp_path: Path):
    cfg = HeraldDiscoveryConfig(state_file=tmp_path / "discovery.json")
    assert cfg.declared_herald_pubkey == DECLARED_HERALD_PUBKEY

    source = Path("app/services/herald_nostr_discovery.py").read_text(encoding="utf-8").lower()
    assert "operator personal key" in source
    assert "logged_in_pubkey" not in source
    assert "dev_agent_admin_token" not in source


def test_spammy_post_filtered_out(tmp_path: Path):
    state_file = tmp_path / "discovery.json"
    cfg = HeraldDiscoveryConfig(state_file=state_file)
    spam_event = _sample_event("evt-spam", "bitcoin giveaway 100x moon")
    relay = _FakeRelayClient([spam_event])
    resolver = _FakeMetadataResolver({})

    engine = HeraldNostrDiscoveryEngine(cfg, relay_client=relay, metadata_resolver=resolver)
    results = engine.discover_and_evaluate()
    store_rows = DiscoveryStateStore(state_file).recent_assessments(limit=10)

    assert results == []
    assert store_rows == []
