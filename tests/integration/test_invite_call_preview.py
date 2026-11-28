import http.client
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie

import pytest
from coincurve import PrivateKey
from werkzeug.serving import make_server

from app.auth_api_core import _nostr_event_id
from app.iac_preview import MAX_REQUEST, PREAUTH, SESSION, PreviewSettings, QuietPreviewRequests, create_preview_app
from app.services.invite_call_v0 import SyntheticAccounts
from tests.unit.test_invite_call_v0 import ICE, ORIGIN, RELAY, SDP, evidence


def signer(key, challenge):
    """External test-only event originator. Participant keys stay outside the app."""
    event = {
        "pubkey": key.public_key_xonly.format().hex(),
        "created_at": challenge["created_at"],
        "kind": 22242,
        "tags": [["u", challenge["url"]], ["challenge", challenge["challenge"]]],
        "content": "",
    }
    event["id"] = _nostr_event_id(event)
    event["sig"] = key.sign_schnorr(bytes.fromhex(event["id"])).hex()
    return event


class Clock:
    def __init__(self):
        self.now = 1_789_000_000.0
        self.elapsed = 0.0

    def advance(self, seconds):
        self.now += seconds
        self.elapsed += seconds


class Peer:
    def __init__(self, client, clock):
        self.client = client
        self.clock = clock
        self.csrf = None

    def boot(self):
        response = self.client.get("/iac/bootstrap", base_url=ORIGIN)
        assert response.status_code == 200
        self.csrf = response.json["csrf"]
        return response

    def post(self, path, data=None, *, expected=200, step=True):
        if step:
            self.clock.advance(0.6)
        response = self.client.post(
            "/iac/" + path,
            base_url=ORIGIN,
            headers={"Origin": ORIGIN, "X-IAC-CSRF": self.csrf or ""},
            json={} if data is None else data,
        )
        assert response.status_code == expected, path
        assert response.headers["Cache-Control"] == "no-store"
        return response

    def challenge(self, key):
        return self.post("auth/challenge", {"pubkey": key.public_key_xonly.format().hex()}).json

    def complete(self, event):
        response = self.post("auth/verify", {"event": event})
        self.csrf = response.json["csrf"]
        return response

    def login(self, key, token=None):
        self.boot()
        if token is not None:
            self.post("invite/prepare", {"token": token})
        return self.complete(signer(key, self.challenge(key)))


class Scene:
    def __init__(self, *, relay=True):
        self.clock = Clock()
        self.host, self.guest, self.third = (PrivateKey() for _ in range(3))
        subjects = [key.public_key_xonly.format().hex() for key in (self.host, self.guest, self.third)]
        self.host_key, self.guest_key, self.third_key = subjects
        self.accounts = SyntheticAccounts(subjects, {self.host_key: evidence(self.host_key, self.clock.now)})
        self.settings = PreviewSettings(ORIGIN, RELAY, secrets.token_bytes(32)) if relay else PreviewSettings(ORIGIN)
        self.app = self.make_app()

    def make_app(self):
        return create_preview_app(
            enabled=True,
            settings=self.settings,
            accounts=self.accounts,
            clock=lambda: self.clock.now,
            elapsed=lambda: self.clock.elapsed,
        )

    def peer(self):
        return Peer(self.app.test_client(), self.clock)

    def invite(self):
        host = self.peer()
        host.login(self.host)
        link = host.post("invite/issue").json["link"]
        assert link.startswith(ORIGIN + "/invite#")
        token = link.rsplit("#", 1)[1]
        assert len(token) == 43
        return host, token

    def pending(self):
        host, token = self.invite()
        guest = self.peer()
        guest.login(self.guest, token)
        claim = guest.post("invite/claim").json
        assert claim["state"] == "PENDING_CONSENT"
        return host, guest, token, claim["attempt"]

    def room(self):
        host, guest, token, attempt = self.pending()
        assert host.post("attempt/consent", {"attempt": attempt, "accept": True}).json["state"] == "PENDING_CONSENT"
        result = guest.post("attempt/consent", {"attempt": attempt, "accept": True}).json
        assert result["state"] == "AUTHORIZED"
        assert len(result["room"]) == 43
        return host, guest, token, attempt, result["room"]


def test_only_preview_routes_https_headers_and_cookie_rotation(caplog):
    scene = Scene()
    peer = scene.peer()
    app = scene.app
    store = app.extensions["iac_store"]
    assert peer.client.get("/invite", base_url=ORIGIN).status_code == 200
    assert peer.client.head("/iac/bootstrap", base_url=ORIGIN).status_code == 204
    assert store.preauth == store.invites == {}
    worker = {"wsgi.multiprocess": True}
    assert peer.client.get("/iac/bootstrap", base_url=ORIGIN, environ_overrides=worker).status_code == 403
    for path in ("/login", "/oauth/token", "/socket.io/", "/api/verify", "/turn_credentials", "/app", "/wallet"):
        assert peer.client.get(path, base_url=ORIGIN).status_code == 404
    for url in ("http://iac-preview.test:18443", "https://other.test:18443"):
        assert peer.client.get("/iac/bootstrap", base_url=url).status_code == 403
    bootstrap = peer.boot()
    assert bootstrap.json == {"authenticated": False, "csrf": peer.csrf}
    cookie = bootstrap.headers["Set-Cookie"]
    assert cookie.startswith(PREAUTH + "=")
    assert all(value in cookie for value in ("Secure", "HttpOnly", "Path=/", "SameSite=Strict"))
    assert "Domain" not in cookie
    assert "default-src 'none'" in bootstrap.headers["Content-Security-Policy"]
    assert bootstrap.headers["Referrer-Policy"] == "no-referrer"
    assert bootstrap.headers["X-Content-Type-Options"] == "nosniff"
    assert bootstrap.headers["Permissions-Policy"] == "camera=(self), microphone=(self)"
    pre = peer.client.get_cookie(PREAUTH, domain="iac-preview.test").value
    former_csrf = peer.csrf
    proof = signer(scene.guest, peer.challenge(scene.guest))
    verified = peer.complete(proof)
    assert peer.csrf != former_csrf
    auth = verified.headers.getlist("Set-Cookie")[0]
    assert auth.startswith(SESSION + "=")
    assert all(value in auth for value in ("Secure", "HttpOnly", "Path=/", "SameSite=Strict"))
    assert "Domain" not in auth
    bearer = peer.client.get_cookie(SESSION, domain="iac-preview.test").value
    assert bearer != pre
    assert set(verified.json) == {"authenticated", "csrf"}
    assert scene.guest_key not in verified.get_data(as_text=True)
    assert store.entitlement(scene.guest_key).identity_class.value == "limited"
    peer.post("invite/issue", expected=403)
    peer.post("invite/prepare", {"token": "x" * 43}, expected=403)
    peer.post("auth/logout")
    peer.client.set_cookie(SESSION, bearer, domain="iac-preview.test", secure=True)
    peer.post("attempt/status", expected=403)
    peer.client.set_cookie(PREAUTH, pre, domain="iac-preview.test", secure=True)
    peer.csrf = former_csrf
    peer.post("auth/verify", {"event": proof}, expected=403)
    assert all(secret not in caplog.text for secret in (pre, bearer, proof["sig"], scene.guest_key))


@pytest.mark.parametrize(
    "variation",
    ["signature", "signer", "url", "kind", "extra", "extra_tag", "content", "time", "replacement", "expiry"],
)
def test_strict_bip340_proof_contract(variation):
    scene = Scene()
    peer = scene.peer()
    peer.boot()
    challenge = peer.challenge(scene.guest)
    event = signer(scene.guest, challenge)
    if variation == "signature":
        event["sig"] = "0" * 128
    elif variation == "signer":
        event = signer(scene.third, challenge)
    elif variation == "url":
        event = signer(scene.guest, {**challenge, "url": "https://other.test/iac/auth/verify"})
    elif variation == "kind":
        event["kind"] = "22242"
    elif variation == "extra":
        event["role"] = "full"
    elif variation == "extra_tag":
        event["tags"].append(event["tags"][0])
    elif variation == "content":
        event["content"] = "not empty"
    elif variation == "time":
        event["created_at"] += 60
    elif variation == "replacement":
        peer.challenge(scene.guest)
    else:
        scene.clock.advance(120)
    peer.post("auth/verify", {"event": event}, expected=403)
    assert peer.client.get_cookie(SESSION, domain="iac-preview.test") is None


def test_cross_preauth_curve_point_replay_and_concurrent_proof():
    scene = Scene()
    original, other = scene.peer(), scene.peer()
    original.boot()
    other.boot()
    other.post("auth/challenge", {"pubkey": "f" * 64}, expected=403)
    event = signer(scene.guest, original.challenge(scene.guest))
    other.post("auth/verify", {"event": event}, expected=403)
    cookie = original.client.get_cookie(PREAUTH, domain="iac-preview.test").value
    other.client.set_cookie(PREAUTH, cookie, domain="iac-preview.test", secure=True)
    other.csrf = original.csrf

    def submit(peer):
        return peer.client.post(
            "/iac/auth/verify",
            base_url=ORIGIN,
            headers={"Origin": ORIGIN, "X-IAC-CSRF": peer.csrf},
            json={"event": event},
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(submit, [original, other])) == [200, 403]
    assert len(scene.app.extensions["iac_store"].sessions) == 1


def test_protected_json_origin_csrf_and_field_boundary():
    scene = Scene()
    peer = scene.peer()
    anonymous = scene.peer()
    anonymous.post("invite/claim", expected=403)
    peer.login(scene.host)
    header = {"Origin": ORIGIN, "X-IAC-CSRF": peer.csrf, "Content-Type": "application/json"}
    requests = [
        ("/iac/invite/issue", "{}", {key: value for key, value in header.items() if key != "Origin"}, 403),
        ("/iac/invite/issue", "{}", {**header, "Origin": "null"}, 403),
        ("/iac/invite/issue", "{}", {**header, "Origin": "https://other.test"}, 403),
        ("/iac/invite/issue", "{}", {**header, "X-IAC-CSRF": ""}, 403),
        ("/iac/invite/issue", "{}", {**header, "Content-Type": "text/plain"}, 403),
        ("/iac/invite/issue?token=unexpected", "{}", header, 403),
        ("/iac/invite/issue", '{"role":"FULL"}', header, 403),
        ("/iac/invite/issue", '{"role":1,"role":2}', header, 403),
        ("/iac/invite/issue", " " * MAX_REQUEST + "{}", header, 413),
    ]
    for path, data, headers, status in requests:
        response = peer.client.post(path, base_url=ORIGIN, headers=headers, data=data)
        assert response.status_code == status
        assert response.json == {"error": "unavailable"}
        assert "Access-Control-Allow-Origin" not in response.headers
    assert scene.app.extensions["iac_store"].invites == {}


@pytest.mark.parametrize("variant", ["limited", "expired", "revoked", "mismatched", "unknown", "inactive"])
def test_full_issuer_uses_current_real_synthetic_evidence(variant):
    scene = Scene()
    host = scene.peer()
    if variant == "unknown":
        host.boot()
        unknown = PrivateKey()
        host.post("auth/verify", {"event": signer(unknown, host.challenge(unknown))}, expected=403)
        return
    host.login(scene.host)
    if variant == "expired":
        scene.clock.advance(900)
    elif variant == "revoked":
        scene.accounts.evidence[scene.host_key] = evidence(scene.host_key, scene.clock.now, revoked=True)
    elif variant == "mismatched":
        scene.accounts.evidence[scene.host_key] = evidence(scene.guest_key, scene.clock.now)
    elif variant == "inactive":
        scene.accounts.subjects[scene.host_key] = False
    else:
        scene.accounts.evidence.clear()
    host.post("invite/issue", expected=403)


def test_loss_of_full_at_claim_and_authorization_and_afterward():
    scene = Scene()
    host, token = scene.invite()
    guest = scene.peer()
    guest.login(scene.guest, token)
    scene.accounts.evidence.clear()
    guest.post("invite/claim", expected=403)
    scene.accounts.evidence[scene.host_key] = evidence(scene.host_key, scene.clock.now)
    claim = guest.post("invite/claim").json
    host.post("attempt/consent", {"attempt": claim["attempt"], "accept": True})
    scene.accounts.evidence.clear()
    guest.post("attempt/consent", {"attempt": claim["attempt"], "accept": True}, expected=403)
    assert host.post("attempt/status").json["state"] == "CANCELLED"

    scene = Scene()
    host, guest, _, _, room = scene.room()
    scene.accounts.evidence.clear()
    assert host.post("call/turn", {"room": room}).json["urls"] == [RELAY]
    assert guest.post("call/status", {"room": room, "phase": "heartbeat"}).json["state"] == "AUTHORIZED"


def test_atomic_claim_and_consent_with_exact_generation():
    scene = Scene()
    host, token = scene.invite()
    competitors = [scene.peer(), scene.peer()]
    competitors[0].login(scene.guest, token)
    competitors[1].login(scene.third, token)

    def claim(peer):
        return peer.client.post(
            "/iac/invite/claim", base_url=ORIGIN, headers={"Origin": ORIGIN, "X-IAC-CSRF": peer.csrf}, json={}
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(claim, competitors))
    assert sorted(response.status_code for response in responses) == [200, 403]
    stored = next(iter(scene.app.extensions["iac_store"].invites.values()))
    assert stored.token_state == "CLAIMED"
    winner = competitors[next(i for i, response in enumerate(responses) if response.status_code == 200)]
    view = winner.post("invite/claim").json
    assert host.post("attempt/status").json["comparison"] == view["comparison"]
    assert len(view["comparison"]) == 6 and view["comparison"].isdigit()
    denied = scene.peer()
    denied.login(scene.guest if winner is competitors[0] else scene.third)
    denied.post("attempt/consent", {"attempt": view["attempt"], "accept": True}, expected=403)
    host.post("call/turn", {"room": secrets.token_urlsafe(32)}, expected=403)

    def approve(peer):
        return peer.post("attempt/consent", {"attempt": view["attempt"], "accept": True}, step=False).json

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(approve, [host, winner]))
    assert sorted(result["state"] for result in outcomes) == ["AUTHORIZED", "PENDING_CONSENT"]
    assert stored.token_state == "CONSUMED"
    room = winner.post("attempt/status").json["room"]
    assert host.post("attempt/status").json["room"] == room
    assert approve(winner)["room"] == room
    denied.post("call/turn", {"room": room}, expected=403)
    denied.post("call/signal/poll", {"room": room, "ack": 0}, expected=403)
    issuer_grant = host.post("call/turn", {"room": room}).json
    assert issuer_grant["username"] != winner.post("call/turn", {"room": room}).json["username"]
    assert host.post("call/turn", {"room": room}).json == issuer_grant
    assert all(key not in json.dumps(outcomes) for key in (scene.host_key, scene.guest_key, scene.third_key, token))


@pytest.mark.parametrize("ending", ["decline", "timeout", "cancel", "logout"])
def test_claim_cannot_move_to_new_identity_after_terminal_state(ending):
    scene = Scene()
    host, guest, token, attempt = scene.pending()
    if ending == "decline":
        assert host.post("attempt/consent", {"attempt": attempt, "accept": False}).json["state"] == "DECLINED"
    elif ending == "timeout":
        scene.clock.advance(301)
        assert host.post("attempt/status").json["state"] == "EXPIRED"
    elif ending == "cancel":
        assert host.post("attempt/cancel", {"attempt": attempt}).json["state"] == "CANCELLED"
    else:
        host.post("auth/logout")
        assert guest.post("attempt/status").json["state"] == "CANCELLED"
    other = scene.peer()
    other.boot()
    other.post("invite/prepare", {"token": token}, expected=403)
    guest.post("attempt/consent", {"attempt": attempt, "accept": True}, expected=403)


def test_scanner_no_claim_self_invite_expiry_and_single_live_invite():
    scene = Scene()
    host, token = scene.invite()
    scanner = scene.peer()
    assert scanner.client.get("/invite", base_url=ORIGIN).status_code == 200
    assert scanner.client.head("/invite", base_url=ORIGIN).status_code == 200
    assert host.post("attempt/status").json["state"] == "ISSUED"
    host.post("invite/issue", expected=403)
    other = scene.peer()
    other.login(scene.host, token)
    other.post("invite/claim", expected=403)
    scene.clock.advance(901)
    assert host.post("attempt/status").json["state"] == "EXPIRED"
    scanner.boot()
    scanner.post("invite/prepare", {"token": token}, expected=403)


def signal(room, kind, payload):
    return {"room": room, "message": secrets.token_urlsafe(32), "kind": kind, "payload": payload}


def test_ordered_relay_signaling_retry_ack_privacy_and_hangup():
    scene = Scene()
    host, guest, token, _, room = scene.room()
    third = scene.peer()
    third.login(scene.third)
    third.post("call/status", {"room": room, "phase": "heartbeat"}, expected=403)
    offer = signal(room, "offer", {"sdp": SDP})
    answer = signal(room, "answer", {"sdp": SDP})
    candidate = signal(room, "ice", ICE)
    host.post("call/signal/send", offer, expected=403)
    for peer in (host, guest):
        peer.post("call/status", {"room": room, "phase": "ready"})
    guest.post("call/signal/send", offer, expected=403)
    guest.post("call/signal/send", answer, expected=403)
    host.post("call/signal/send", candidate, expected=403)
    host.post("call/signal/send", {**offer, "from": scene.guest_key}, expected=403)
    host.post("call/signal/send", offer)
    host.post("call/signal/send", offer)
    host.post("call/signal/send", {**offer, "payload": {"sdp": SDP + "s=other\r\n"}}, expected=403)
    host.post("call/signal/send", candidate)
    guest.post("call/signal/poll", {"room": room, "ack": 2}, expected=403)
    batch = guest.post("call/signal/poll", {"room": room, "ack": 0}).json["messages"]
    assert [(item["seq"], item["kind"]) for item in batch] == [(1, "offer"), (2, "ice")]
    assert guest.post("call/signal/poll", {"room": room, "ack": 0}, step=False, expected=403).json == {
        "error": "unavailable"
    }
    assert guest.post("call/signal/poll", {"room": room, "ack": 0}).json["messages"] == batch
    assert guest.post("call/signal/poll", {"room": room, "ack": 2}).json["messages"] == []
    guest.post("call/signal/send", answer)
    assert host.post("call/signal/poll", {"room": room, "ack": 0}).json["messages"][0]["kind"] == "answer"
    for peer in (host, guest):
        state = peer.post("call/status", {"room": room, "phase": "connected"}).json["state"]
    assert state == "CONNECTED"
    assert all(value not in json.dumps(batch) for value in (scene.host_key, scene.guest_key, token))
    assert host.post("call/hangup", {"room": room, "failed": False}).json["state"] == "ENDED"
    guest.post("call/turn", {"room": room}, expected=403)
    guest.post("call/signal/poll", {"room": room, "ack": 2}, expected=403)


@pytest.mark.parametrize("cause", ["overflow", "idle", "restart", "logout", "inactive", "missing_relay"])
def test_room_grants_fail_closed(cause, monkeypatch):
    scene = Scene(relay=cause != "missing_relay")
    host, guest, _, _, room = scene.room()
    if cause == "overflow":
        monkeypatch.setattr("app.services.invite_call_v0.MAX_MESSAGES", 1)
        for peer in (host, guest):
            peer.post("call/status", {"room": room, "phase": "ready"})
        host.post("call/signal/send", signal(room, "offer", {"sdp": SDP}))
        host.post("call/signal/send", signal(room, "ice", ICE), expected=403)
        assert guest.post("attempt/status").json["state"] == "FAILED"
    elif cause == "idle":
        scene.clock.advance(60)
        assert host.post("attempt/status").json["state"] == "FAILED"
    elif cause == "restart":
        credential = guest.client.get_cookie(SESSION, domain="iac-preview.test").value
        guest.client = scene.make_app().test_client()
        guest.client.set_cookie(SESSION, credential, domain="iac-preview.test", secure=True)
    elif cause == "logout":
        host.post("auth/logout")
        host.login(scene.host)
        host.post("call/turn", {"room": room}, expected=403)
    elif cause == "inactive":
        scene.accounts.subjects[scene.host_key] = False
    guest.post("call/turn", {"room": room}, expected=403)


def test_authorized_room_survives_invite_expiry_with_heartbeats():
    scene = Scene()
    host, guest, token, _, room = scene.room()
    for _ in range(19):
        scene.clock.advance(48)
        for peer in (host, guest):
            assert peer.post("call/status", {"room": room, "phase": "heartbeat"}).json["room"] == room
    scanner = scene.peer()
    scanner.boot()
    scanner.post("invite/prepare", {"token": token}, expected=403)
    assert guest.post("call/turn", {"room": room}).json["urls"] == [RELAY]


def test_same_room_grace_session_expiry_and_bounded_request_rate():
    scene = Scene()
    host, guest, _, _, room = scene.room()
    scene.clock.advance(45)
    assert host.post("call/status", {"room": room, "phase": "heartbeat"}).json["room"] == room
    assert guest.post("call/status", {"room": room, "phase": "heartbeat"}).json["room"] == room
    host.post("call/turn", {"room": secrets.token_urlsafe(32)}, expected=403)
    scene.clock.advance(1)
    for _ in range(12):
        host.post("attempt/status", step=False)
    host.post("attempt/status", step=False, expected=403)
    scene.clock.advance(1800)
    guest.post("attempt/status", expected=403)


def test_peer_identity_is_not_a_signaling_payload_even_when_a_member():
    scene = Scene()
    host, guest, _, _, room = scene.room()
    for peer in (host, guest):
        peer.post("call/status", {"room": room, "phase": "ready"})
    offer = signal(room, "offer", {"sdp": SDP + "s=" + scene.guest_key + "\r\n"})
    host.post("call/signal/send", offer, expected=403)
    assert guest.post("call/signal/poll", {"room": room, "ack": 0}).json["messages"] == []


class WirePeer:
    """HTTPS client with a private hostname mapping and no global trust changes."""

    def __init__(self, trust):
        self.trust = trust
        self.cookies = {}
        self.csrf = None

    def request(self, path, data=None):
        connection = http.client.HTTPSConnection("iac-preview.test", 18443, timeout=5, context=self.trust)
        connection._create_connection = lambda _address, timeout, source: socket.create_connection(
            ("127.0.0.1", 18443), timeout, source
        )
        headers = {"Cookie": "; ".join(f"{name}={value}" for name, value in self.cookies.items())}
        if data is not None:
            headers.update({"Content-Type": "application/json", "Origin": ORIGIN, "X-IAC-CSRF": self.csrf or ""})
        try:
            connection.request(
                "GET" if data is None else "POST", path, None if data is None else json.dumps(data), headers
            )
            response = connection.getresponse()
            body = response.read()
            for name, value in response.getheaders():
                if name.casefold() == "set-cookie":
                    cookie = SimpleCookie()
                    cookie.load(value)
                    for key, morsel in cookie.items():
                        if morsel["max-age"] == "0":
                            self.cookies.pop(key, None)
                        else:
                            self.cookies[key] = morsel.value
            return response.status, response.headers, body
        finally:
            connection.close()

    def json(self, path, data=None, *, expected=200):
        status, headers, body = self.request("/iac/" + path, data)
        assert status == expected, path
        assert headers["Cache-Control"] == "no-store"
        result = json.loads(body)
        self.csrf = result.get("csrf", self.csrf)
        return result

    def login(self, key, token=None):
        self.json("bootstrap")
        if token is not None:
            self.json("invite/prepare", {"token": token})
        challenge = self.json("auth/challenge", {"pubkey": key.public_key_xonly.format().hex()})
        self.json("auth/verify", {"event": signer(key, challenge)})


@pytest.mark.skipif(os.getenv("IAC_RUN_TLS_SMOKE") != "1", reason="requires explicit isolated network namespace")
def test_verified_isolated_https_and_authorized_turn_probe(tmp_path):
    ip = shutil.which("ip")
    assert ip and shutil.which("openssl") and shutil.which("turnserver") and shutil.which("turnutils_uclient")
    links = subprocess.check_output([ip, "-o", "link", "show"], text=True, timeout=5).splitlines()
    assert len(links) == 1 and links[0].startswith("1: lo:")
    assert "UP" in links[0].split("<")[1].split(">")[0].split(",")
    certificate, key = tmp_path / "test-ca.pem", tmp_path / "test-key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-noenc",
            "-days",
            "1",
            "-subj",
            "/CN=iac-preview.test",
            "-addext",
            "subjectAltName=DNS:iac-preview.test",
            "-out",
            str(certificate),
            "-keyout",
            str(key),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    turn_secret = secrets.token_hex(32)
    scene = Scene()
    scene.settings = PreviewSettings(ORIGIN, RELAY, turn_secret.encode("ascii"))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    coturn = subprocess.Popen(
        [
            "turnserver",
            "-n",
            "--listening-ip=127.0.0.1",
            "--relay-ip=127.0.0.1",
            "--listening-port=13478",
            "--min-port=49160",
            "--max-port=49175",
            "--allow-loopback-peers",
            "--no-cli",
            "--no-tls",
            "--no-dtls",
            "--no-tcp-relay",
            "--no-multicast-peers",
            "--use-auth-secret",
            "--realm=iac-turn.test",
            f"--userdb={tmp_path / 'turn.sqlite'}",
            f"--pidfile={tmp_path / 'turn.pid'}",
            f"--static-auth-secret={turn_secret}",
            "--total-quota=16",
            "--user-quota=8",
            "--log-file=/dev/null",
            "--no-stdout-log",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with make_server(
            "127.0.0.1",
            18443,
            create_preview_app(
                enabled=True,
                settings=scene.settings,
                accounts=SyntheticAccounts(
                    scene.accounts.subjects, {scene.host_key: evidence(scene.host_key, time.time() - 1)}
                ),
            ),
            ssl_context=context,
            request_handler=QuietPreviewRequests,
        ) as server:
            worker = threading.Thread(target=server.serve_forever)
            worker.start()
            try:
                untrusted = WirePeer(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
                with pytest.raises(ssl.SSLCertVerificationError):
                    untrusted.request("/")
                trust = ssl.create_default_context(cafile=str(certificate))
                alice, bob, third = WirePeer(trust), WirePeer(trust), WirePeer(trust)
                status, headers, page = alice.request("/")
                assert status == 200 and b"SYNTHETIC TEST MEMBERSHIP" in page
                assert headers["Referrer-Policy"] == "no-referrer"
                assert "connect-src 'self'" in headers["Content-Security-Policy"]
                alice.login(scene.host)
                token = alice.json("invite/issue", {})["link"].rsplit("#", 1)[1]
                assert bob.request("/invite")[0] == 200
                assert alice.json("attempt/status", {})["state"] == "ISSUED"
                bob.login(scene.guest, token)
                invite = bob.json("invite/claim", {})
                assert alice.json("attempt/status", {})["comparison"] == invite["comparison"]
                consent = {"attempt": invite["attempt"], "accept": True}
                alice.json("attempt/consent", consent)
                room = bob.json("attempt/consent", consent)["room"]
                third.login(scene.third)
                third.json("call/turn", {"room": room}, expected=403)
                assert coturn.poll() is None
                for peer in (alice, bob):
                    relay = peer.json("call/turn", {"room": room})
                    assert relay["urls"] == [RELAY]
                    result = subprocess.run(
                        [
                            "turnutils_uclient",
                            "-y",
                            "-c",
                            "-m",
                            "2",
                            "-n",
                            "2",
                            "-p",
                            "13478",
                            "-u",
                            relay["username"],
                            "-w",
                            relay["credential"],
                            "127.0.0.1",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=20,
                    )
                    assert result.returncode == 0
                    assert "tot_send_msgs=4, tot_recv_msgs=4" in result.stdout
                    assert "Total lost packets 0" in result.stdout
                alice.json("call/hangup", {"room": room, "failed": False})
                bob.json("call/turn", {"room": room}, expected=403)
                assert bob.json("attempt/status", {})["state"] == "ENDED"
            finally:
                server.shutdown()
                worker.join(timeout=5)
                assert not worker.is_alive()
    finally:
        coturn.terminate()
        try:
            coturn.wait(timeout=5)
        except subprocess.TimeoutExpired:
            coturn.kill()
            coturn.wait(timeout=5)
