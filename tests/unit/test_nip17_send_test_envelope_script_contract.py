"""NIP-17 staging send script contract tests."""

import json

import pytest

from scripts import nip17_send_test_envelope as tool


def test_build_test_gift_wrap_shape_is_valid_and_opaque():
    receiver = "c" * 64

    envelope = tool.build_test_gift_wrap(receiver, created_at=1779570000)

    assert envelope["kind"] == 1059
    assert len(envelope["id"]) == 64
    assert len(envelope["pubkey"]) == 64
    assert envelope["created_at"] == 1779570000
    assert envelope["tags"] == [["p", receiver]]
    assert envelope["content"].startswith("opaque-test-envelope-")
    assert len(envelope["sig"]) == 128


def test_build_test_gift_wrap_rejects_non_hex_receiver():
    with pytest.raises(ValueError):
        tool.build_test_gift_wrap("not-a-hex-pubkey")


def test_default_base_is_staging_only():
    assert tool._is_default_staging_base("http://127.0.0.1:5055")
    assert tool._is_default_staging_base("http://localhost:5055")
    assert not tool._is_default_staging_base("https://hodlxxi.com")
    assert not tool._is_default_staging_base("http://127.0.0.1:5000")


def test_safe_result_does_not_print_envelope_material():
    receiver = "c" * 64
    envelope = tool.build_test_gift_wrap(receiver, created_at=1779570000)

    payload = {
        "ok": True,
        "accepted": True,
        "stored": True,
        "duplicate": False,
        "event_id": envelope["id"],
        "receiver_pubkey": receiver,
        "published": False,
        "plaintext_seen": False,
    }

    result = tool.safe_result(202, payload, envelope)
    rendered = json.dumps(result, sort_keys=True)

    assert result["ok"] is True
    assert result["status_code"] == 202
    assert result["event_id"] == envelope["id"]
    assert result["receiver_pubkey"] == receiver
    assert result["receiver_pubkey_tail"] == receiver[-8:]
    assert result["plaintext_sent"] is False
    assert result["relay_publishing"] is False

    assert envelope["content"] not in rendered
    assert envelope["sig"] not in rendered
    assert "envelope_json" not in rendered


def test_main_refuses_non_staging_base_without_override(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "nip17_send_test_envelope.py",
            "--receiver-pubkey",
            "c" * 64,
            "--base",
            "https://hodlxxi.com",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        tool.main()

    assert exc.value.code != 0
    captured = capsys.readouterr()
    assert "Refusing non-staging base URL" in str(exc.value)
    assert "hodlxxi.env" not in captured.out
    assert "DATABASE_URL" not in captured.out
