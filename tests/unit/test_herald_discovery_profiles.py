from __future__ import annotations

from app.services.herald_discovery_profiles import (
    available_target_profiles,
    list_target_profiles,
    resolve_target_profiles,
)


def test_list_target_profiles_includes_expected_profile_names():
    profiles = list_target_profiles()

    assert available_target_profiles() == [
        "bitcoin-agents",
        "identity",
        "lightning",
        "ai-agents",
        "nostr-dev",
        "volya",
    ]
    assert set(profiles.keys()) == set(available_target_profiles())
    assert profiles["volya"]["min_score"] == 1.0
    assert "keywords" in profiles["bitcoin-agents"]
    assert "hashtags" in profiles["identity"]
    assert "description" in profiles["lightning"]


def test_profile_resolver_merges_terms_and_preserves_order():
    resolved = resolve_target_profiles(
        ["bitcoin-agents", "identity"],
        extra_keywords=["nostr agent", "custom discovery phrase"],
        extra_hashtags=["#bitcoin", "CustomTag"],
    )

    assert resolved.target_profiles == ["bitcoin-agents", "identity"]
    assert resolved.keywords[:8] == [
        "bitcoin agent",
        "lightning agent",
        "autonomous agent",
        "machine payments",
        "signed receipts",
        "zap",
        "lnurl",
        "nostr agent",
    ]
    assert resolved.keywords[-1] == "custom discovery phrase"
    assert resolved.hashtags == ["bitcoin", "nostr", "lightning", "agents", "ai", "identity", "reputation", "customtag"]


def test_repeated_profiles_dedupe_terms_and_use_lowest_min_score():
    resolved = resolve_target_profiles(
        ["bitcoin-agents", "volya", "bitcoin-agents"],
        extra_keywords=["ubid"],
        extra_hashtags=["identity"],
    )

    assert resolved.target_profiles == ["bitcoin-agents", "volya"]
    assert resolved.keywords.count("bitcoin agent") == 1
    assert resolved.keywords.count("ubid") == 1
    assert resolved.hashtags.count("bitcoin") == 1
    assert resolved.hashtags.count("identity") == 1
    assert resolved.min_score == 1.0
