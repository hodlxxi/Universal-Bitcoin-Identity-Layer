from app.blueprints.billing_agent import (
    DEFAULT_AGENT_BILLING_MAX_AMOUNT_SATS,
    _agent_billing_max_amount_sats,
)


def test_agent_billing_max_amount_uses_default(monkeypatch):
    monkeypatch.delenv("AGENT_BILLING_MAX_AMOUNT_SATS", raising=False)

    assert _agent_billing_max_amount_sats() == DEFAULT_AGENT_BILLING_MAX_AMOUNT_SATS


def test_agent_billing_max_amount_uses_env(monkeypatch):
    monkeypatch.setenv("AGENT_BILLING_MAX_AMOUNT_SATS", "1234")

    assert _agent_billing_max_amount_sats() == 1234


def test_agent_billing_max_amount_invalid_env_falls_back(monkeypatch):
    monkeypatch.setenv("AGENT_BILLING_MAX_AMOUNT_SATS", "not-an-int")

    assert _agent_billing_max_amount_sats() == DEFAULT_AGENT_BILLING_MAX_AMOUNT_SATS


def test_agent_billing_max_amount_never_less_than_one(monkeypatch):
    monkeypatch.setenv("AGENT_BILLING_MAX_AMOUNT_SATS", "0")

    assert _agent_billing_max_amount_sats() == 1
