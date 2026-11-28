import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from coincurve import PrivateKey

from app.iac_preview import PreviewSettings, create_preview_app
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement_evidence import CONTRACT_VERSION, CurrentEntitlementEvidenceRecord
from app.services.invite_call_v0 import InviteCallStore, SyntheticAccounts, Unavailable, _validate_signal

ORIGIN = "https://iac-preview.test:18443"
RELAY = "turn:127.0.0.1:13478?transport=udp"
SDP = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n"
ICE = {"candidate": "candidate:1 1 udp 2122260223 127.0.0.1 49160 typ relay", "sdpMid": "0", "sdpMLineIndex": 0}


def evidence(subject, at, *, revoked=False):
    now = datetime.fromtimestamp(at, timezone.utc)
    return CurrentEntitlementEvidenceRecord(
        evidence_id=str(uuid.uuid4()),
        contract_version=CONTRACT_VERSION,
        subject_pubkey=subject,
        identity_class=IdentityClass.FULL,
        current_full_relation_satisfied=True,
        evidence_source="synthetic_iac_fixture",
        evidence_version="1",
        source_evidence_sha256="a" * 64,
        observed_at=now,
        valid_until=now + timedelta(seconds=900),
        created_at=now,
        revoked_at=now if revoked else None,
    )


@pytest.mark.parametrize(
    "origin",
    [
        "http://iac-preview.test:18443",
        "https://hodlxxi.com:18443",
        "https://iac-preview.test",
        "https://iac-preview.test:443",
        "https://iac-preview.test:18443/",
        "https://u@iac-preview.test:18443",
    ],
)
def test_preview_requires_dedicated_https_hostname(origin):
    with pytest.raises(ValueError):
        PreviewSettings(origin).validate()


@pytest.mark.parametrize(
    "relay", ["stun:127.0.0.1:13478", "turn:198.51.100.1:13478?transport=udp", "turn:127.0.0.1:13478?transport=tcp"]
)
def test_preview_has_no_external_or_direct_relay_fallback(relay):
    with pytest.raises(ValueError):
        PreviewSettings(ORIGIN, relay, "k" * 32).validate()


def test_factory_defaults_off_and_refuses_production(monkeypatch):
    with pytest.raises(ValueError):
        create_preview_app()
    monkeypatch.setenv("FLASK_ENV", "production")
    with pytest.raises(ValueError):
        create_preview_app(enabled=True, settings=PreviewSettings(ORIGIN), accounts=SyntheticAccounts([], {}))


@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        ("offer", {"sdp": SDP + "a=candidate:1 1 udp 1 192.0.2.1 49160 typ host\r\n"}),
        ("offer", {"sdp": SDP.replace("0.0.0.0", "192.0.2.1")}),
        ("answer", {"sdp": SDP + "x" * 65536}),
        ("answer", {"sdp": SDP, "type": "answer"}),
        ("ice", {**ICE, "candidate": ICE["candidate"].replace("typ relay", "typ srflx")}),
        ("ice", {**ICE, "candidate": ICE["candidate"].replace("127.0.0.1", "127.0.0.2")}),
        ("ice", {**ICE, "candidate": ICE["candidate"] + " raddr 192.0.2.1 rport 41000"}),
        ("ice", {**ICE, "candidate": ICE["candidate"] + " unsupported 1"}),
        ("ice", {**ICE, "candidate": "x" * 4097}),
        ("ice", {**ICE, "sdpMLineIndex": True}),
        ("other", {}),
    ],
)
def test_signaling_bounds_and_candidate_privacy(kind, payload):
    with pytest.raises(Unavailable):
        _validate_signal(kind, payload, "127.0.0.1")


def test_accepts_minimal_trickle_sdp_and_configured_relay_ice():
    _validate_signal("offer", {"sdp": SDP}, "127.0.0.1")
    _validate_signal("answer", {"sdp": SDP}, "127.0.0.1")
    _validate_signal("ice", {**ICE, "candidate": ICE["candidate"] + " generation 0 ufrag a+b"}, "127.0.0.1")


def test_preauth_capacity_expires_without_eviction(monkeypatch):
    monkeypatch.setattr("app.services.invite_call_v0.MAX_CONTEXTS", 2)
    now = [1_700_000_000]
    store = InviteCallStore(ORIGIN, SyntheticAccounts([], {}), None, None, clock=lambda: now[0], elapsed=lambda: now[0])
    _, first = store.bootstrap(None, None)
    store.bootstrap(None, None)
    with pytest.raises(Unavailable):
        store.bootstrap(None, None)
    assert store.bootstrap(first, None)[1] is None
    now[0] += 600
    assert store.bootstrap(None, None)[1] is not None
    assert len(store.preauth) == 1


def test_evidence_is_resolved_with_real_record_and_expiry():
    subject = PrivateKey().public_key_xonly.format().hex()
    now = [1_700_000_000]
    repo = SyntheticAccounts([subject], {subject: evidence(subject, now[0])})
    store = InviteCallStore(ORIGIN, repo, None, None, clock=lambda: now[0], elapsed=lambda: now[0])
    assert store.entitlement(subject).current_full_relation_satisfied
    now[0] += 900
    assert store.entitlement(subject).identity_class is IdentityClass.LIMITED


def test_client_removes_invite_fragment_before_startup_actions():
    client = Path(__file__).resolve().parents[2] / "app/static/iac/client.js"
    harness = """
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const steps = [];
vm.runInNewContext(fs.readFileSync(process.argv[1], "utf8"), {
  location: {pathname: "/invite", hash: "#synthetic-fragment"},
  history: {replaceState: (_state, _title, url) => steps.push(["history", url])},
  document: {addEventListener: (name) => steps.push(["listener", name])},
});
assert.deepEqual(steps, [["history", "/invite"], ["listener", "DOMContentLoaded"]]);
"""
    subprocess.run(["node", "-e", harness, str(client)], capture_output=True, check=True, timeout=10)
