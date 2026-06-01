"""NIP-17 staging operator smoke runbook contract."""

from pathlib import Path

RUNBOOK = Path("docs/ops/NIP17_STAGING_OPERATOR_SEND_SMOKE.md")


def test_staging_smoke_runbook_waits_for_port_and_health_after_restart():
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "ss -ltn | grep -q ':5055 '" in text
    assert "http://127.0.0.1:5055/health/ready" in text
    assert 'if [ "$code" = "200" ]; then' in text
    assert "seq 1 30" in text


def test_staging_smoke_runbook_tracks_baseline_plus_one_count():
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "Capture baseline receiver inbox count" in text
    assert "/tmp/nip17_baseline_inbox.json" in text
    assert 'json.load(open("/tmp/nip17_baseline_inbox.json"))["total"]' in text
    assert "expected `total` is baseline + 1" in text.lower()


def test_staging_smoke_runbook_keeps_safety_boundaries_explicit():
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "Do not run this against production" in text
    assert "Do not use private keys." in text
    assert "Do not send plaintext." in text
    assert "Do not leave `NIP17_MESSAGES_ENABLED=true` enabled after the staging smoke" in text
    assert "relay_publishing" in text


def test_staging_smoke_runbook_disables_intake_after_test():
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "sudo rm -f /etc/systemd/system/ubid-staging.service.d/60-nip17-staging-intake.conf" in text
    assert "systemctl cat ubid-staging | grep -n 'NIP17_MESSAGES_ENABLED' || true" in text
    assert '"enabled"|"intake_enabled"|"relay_publishing"' in text
