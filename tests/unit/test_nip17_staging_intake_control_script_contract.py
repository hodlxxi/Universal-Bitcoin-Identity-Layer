"""NIP-17 staging intake control script safety contract."""

from pathlib import Path

SCRIPT = Path("scripts/nip17_staging_intake_control.sh")


def test_nip17_staging_intake_control_script_exists():
    assert SCRIPT.exists()
    assert SCRIPT.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash")


def test_nip17_staging_intake_control_refuses_non_staging_service():
    text = SCRIPT.read_text(encoding="utf-8")

    assert 'SERVICE="${NIP17_STAGING_SERVICE:-ubid-staging}"' in text
    assert 'if [ "$SERVICE" != "ubid-staging" ]; then' in text
    assert "refusing to manage non-staging service" in text


def test_nip17_staging_intake_control_uses_only_nip17_flag_dropin():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "NIP17_MESSAGES_ENABLED=1" in text
    assert "/etc/systemd/system/${SERVICE}.service.d" in text
    assert "60-nip17-staging-intake.conf" in text


def test_nip17_staging_intake_control_reports_policy_and_keeps_relay_visible():
    text = SCRIPT.read_text(encoding="utf-8")

    assert ".well-known/nostr-dm-policy.json" in text
    assert "relay_publishing" in text
    assert "intake_enabled" in text
    assert "enabled" in text
