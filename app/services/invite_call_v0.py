"""Single-process authority for the isolated, synthetic Invite & Call preview."""

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from coincurve import PublicKeyXOnly

from app.auth_api_core import verify_nostr_login_event
from app.services.action_authorization import IdentityClass
from app.services.current_entitlement import (
    EntitlementDecision,
    EntitlementDenied,
    EntitlementUnavailable,
    EvidenceBackedCurrentEntitlementResolver,
    require_active_persisted_user,
)
from app.services.current_entitlement_evidence import CurrentEntitlementEvidenceRecord

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}").fullmatch
_KEY = re.compile(r"[0-9a-f]{64}").fullmatch
_SIG = re.compile(r"[0-9a-f]{128}").fullmatch
_MID = re.compile(r"[A-Za-z0-9_-]{1,32}").fullmatch
_FIELDS = {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}
_LIVE = {"AUTHORIZED", "CONNECTING", "CONNECTED"}
_TERMINAL = {"ENDED", "DECLINED", "CANCELLED", "EXPIRED", "FAILED"}
MAX_CONTEXTS = 128
MAX_RECORDS = 128
MAX_MESSAGES = 128
MAX_QUEUE_BYTES = 256 * 1024
MAX_SIGNAL_IDS = 256
GRACE = 60


class Unavailable(ValueError):
    """Generic denial to avoid disclosing the existence of a grant."""


def _opaque():
    return secrets.token_urlsafe(32)


def _digest(value):
    if type(value) is not str or not _TOKEN(value):
        return None
    return hashlib.sha256(value.encode("ascii")).digest()


def _curve_key(key):
    if type(key) is not str or not _KEY(key):
        raise Unavailable()
    try:
        PublicKeyXOnly(bytes.fromhex(key))
    except ValueError:
        raise Unavailable() from None
    return key


@dataclass
class Budget:
    second: int = -1
    count: int = 0

    def take(self, elapsed, limit):
        second = int(elapsed)
        if second != self.second:
            self.second = second
            self.count = 0
        if self.count >= limit:
            raise Unavailable()
        self.count += 1


@dataclass
class Challenge:
    nonce: str
    subject: str
    issued: float
    expires: float
    invite: bytes | None
    purpose: str


@dataclass
class Preauth:
    expires: float
    csrf: str = field(default_factory=_opaque)
    invite: bytes | None = None
    challenge: Challenge | None = None
    rate: Budget = field(default_factory=Budget)


@dataclass
class Session:
    generation: bytes
    subject: str
    issued: float
    expires: float
    seen: float
    prepared: bytes | None
    csrf: str = field(default_factory=_opaque)
    invite: bytes | None = None
    rate: Budget = field(default_factory=Budget)


@dataclass
class Mailbox:
    messages: list = field(default_factory=list)
    acknowledged: int = 0
    delivered: int = 0
    sequence: int = 0
    last_poll: float = float("-inf")


@dataclass
class Room:
    handle: str
    heartbeat: list
    queues: tuple = field(default_factory=lambda: (Mailbox(), Mailbox()))
    sent: tuple = field(default_factory=lambda: ({}, {}))
    credentials: dict = field(default_factory=dict)
    ready: set = field(default_factory=set)
    connected: set = field(default_factory=set)
    bytes_waiting: int = 0
    offer: bool = False
    answer: bool = False


@dataclass
class Invite:
    issuer: bytes
    expires: float
    state: str = "ISSUED"
    token_state: str = "ISSUED"
    receiver: bytes | None = None
    attempt: str | None = None
    comparison: str | None = None
    deadline: float | None = None
    approvals: set = field(default_factory=set)
    room: Room | None = None
    ended_at: float | None = None


class SyntheticAccounts:
    """Preview-only active records and evidence. There is no storage fallback."""

    def __init__(self, subjects, evidence):
        if len(subjects) > MAX_CONTEXTS or set(evidence) - set(subjects):
            raise ValueError("invalid synthetic fixtures")
        self.subjects = {_curve_key(subject): True for subject in subjects}
        self.evidence = dict(evidence)
        if any(type(record) is not CurrentEntitlementEvidenceRecord for record in self.evidence.values()):
            raise ValueError("invalid synthetic evidence")

    def get_latest(self, subject):
        return self.evidence.get(subject)

    def active(self, subject):
        key = require_active_persisted_user(
            subject, {"pubkey": subject, "is_active": self.subjects.get(subject) is True}
        )
        return EntitlementDecision(key, IdentityClass.LIMITED, False, "synthetic_active_user")


class InviteCallStore:
    def __init__(self, origin, accounts, turn_url, turn_secret, *, clock=time.time, elapsed=time.monotonic):
        if type(accounts) is not SyntheticAccounts:
            raise ValueError("synthetic accounts required")
        self.origin = origin
        self.verify_url = origin + "/iac/auth/verify"
        self.accounts = accounts
        self.turn_url = turn_url
        self.relay_address = turn_url.split(":")[1] if turn_url else None
        self.turn_secret = turn_secret
        self.clock = clock
        self.elapsed = elapsed
        self.lock = threading.Lock()
        self.preauth = {}
        self.sessions = {}
        self.invites = {}
        self.global_rate = Budget()
        self.entitlement = EvidenceBackedCurrentEntitlementResolver(
            accounts, active_user_resolver=accounts.active, clock=lambda: datetime.fromtimestamp(clock(), timezone.utc)
        )

    def _session(self, generation, now):
        session = self.sessions.get(generation)
        if session is None or now >= min(session.expires, session.seen + 1800):
            return None
        try:
            self.accounts.active(session.subject)
        except EntitlementDenied:
            return None
        return session

    def _full(self, session):
        try:
            verdict = self.entitlement(session.subject)
        except (EntitlementDenied, EntitlementUnavailable):
            raise Unavailable() from None
        if (
            verdict.subject != session.subject
            or verdict.identity_class is not IdentityClass.FULL
            or verdict.current_full_relation_satisfied is not True
        ):
            raise Unavailable()

    def _end(self, invite, state, now):
        invite.state = state
        invite.ended_at = now
        invite.room = None
        invite.comparison = None
        invite.approvals.clear()
        if invite.token_state != "CONSUMED":
            invite.token_state = state if state in ("DECLINED", "EXPIRED") else "REVOKED"

    def _prune_preauth(self, now):
        for digest, ctx in tuple(self.preauth.items()):
            if now >= ctx.expires:
                del self.preauth[digest]

    def _sweep(self, now, elapsed):
        self._prune_preauth(now)
        for digest, invite in tuple(self.invites.items()):
            if invite.ended_at is not None:
                if now >= invite.ended_at + 300:
                    del self.invites[digest]
                continue
            if self._session(invite.issuer, now) is None or (
                invite.receiver is not None and self._session(invite.receiver, now) is None
            ):
                self._end(invite, "ENDED" if invite.room else "CANCELLED", now)
            elif invite.room is not None:
                if elapsed >= min(invite.room.heartbeat) + GRACE:
                    self._end(invite, "FAILED", now)
            elif now >= (invite.deadline if invite.deadline is not None else invite.expires):
                self._end(invite, "EXPIRED", now)
        for generation in tuple(self.sessions):
            if self._session(generation, now) is None:
                del self.sessions[generation]

    def bootstrap(self, preauth, bearer):
        """Bootstrap can create preauth, never act on a grant or session."""
        with self.lock:
            now = self.clock()
            self.global_rate.take(self.elapsed(), 96)
            session = self._session(_digest(bearer), now)
            if session:
                return {"authenticated": True, "csrf": session.csrf}, None
            self._prune_preauth(now)
            pre = self.preauth.get(_digest(preauth))
            if pre is not None:
                return {"authenticated": False, "csrf": pre.csrf}, None
            if len(self.preauth) >= MAX_CONTEXTS:
                raise Unavailable()
            bearer = _opaque()
            pre = Preauth(now + 600)
            self.preauth[_digest(bearer)] = pre
            return {"authenticated": False, "csrf": pre.csrf}, bearer

    def execute(self, handler, *, preauth, bearer, csrf, data, before_login):
        """Authorize, mutate and derive the response under the same lock."""
        with self.lock:
            now, elapsed = self.clock(), self.elapsed()
            self.global_rate.take(elapsed, 96)
            self._sweep(now, elapsed)
            session = self._session(_digest(bearer), now)
            pre_key = _digest(preauth)
            ctx = self.preauth.get(pre_key) if before_login and session is None else None
            if not before_login:
                ctx = session
            if ctx is None or _digest(csrf) is None or not hmac.compare_digest(ctx.csrf, csrf):
                raise Unavailable()
            ctx.rate.take(elapsed, 12)
            result = handler(ctx, data, now, elapsed)
            if before_login and handler == self.verify:
                del self.preauth[pre_key]
            if not before_login and ctx.generation in self.sessions:
                ctx.seen = self.clock()
            return result

    def _issued(self, digest, now):
        invite = self.invites.get(digest)
        if invite is None or invite.token_state != "ISSUED" or now >= invite.expires:
            raise Unavailable()
        return invite

    def prepare(self, ctx, data, now, elapsed):
        digest = _digest(data["token"])
        self._issued(digest, now)
        if ctx.invite != digest:
            ctx.challenge = None
        ctx.invite = digest
        return {"prepared": True}

    def challenge(self, ctx, data, now, elapsed):
        subject = _curve_key(data["pubkey"])
        expiry = min(now + 120, ctx.expires)
        if ctx.invite is not None:
            expiry = min(expiry, self._issued(ctx.invite, now).expires)
        nonce = "HODLXXI:IAC:LOGIN:V0:" + secrets.token_hex(32)
        purpose = "invitee" if ctx.invite is not None else "host"
        ctx.challenge = Challenge(nonce, subject, now, expiry, ctx.invite, purpose)
        return {"challenge": nonce, "url": self.verify_url, "created_at": int(now)}

    def verify(self, ctx, data, now, elapsed):
        proof, challenge = data["event"], ctx.challenge
        if challenge is None or now >= challenge.expires or challenge.invite != ctx.invite:
            raise Unavailable()
        if challenge.purpose != ("invitee" if ctx.invite is not None else "host"):
            raise Unavailable()
        if (
            type(proof) is not dict
            or set(proof) != _FIELDS
            or proof["pubkey"] != challenge.subject
            or type(proof["id"]) is not str
            or not _KEY(proof["id"])
            or type(proof["sig"]) is not str
            or not _SIG(proof["sig"])
            or type(proof["kind"]) is not int
            or proof["kind"] != 22242
            or type(proof["created_at"]) is not int
            or not int(challenge.issued) <= proof["created_at"] <= int(now) + 10
            or proof["content"] != ""
            or proof["tags"] != [["u", self.verify_url], ["challenge", challenge.nonce]]
        ):
            raise Unavailable()
        ok, _ = verify_nostr_login_event(
            proof,
            expected_pubkey=challenge.subject,
            expected_challenge=challenge.nonce,
            expected_verify_url=self.verify_url,
            require_verify_url=True,
            now_ts=int(now),
        )
        if not ok:
            raise Unavailable()
        ctx.challenge = None
        now = self.clock()
        if now >= challenge.expires or len(self.sessions) >= MAX_CONTEXTS:
            raise Unavailable()
        if ctx.invite is not None:
            self._issued(ctx.invite, now)
        try:
            self.accounts.active(challenge.subject)
        except EntitlementDenied:
            raise Unavailable() from None
        bearer = _opaque()
        generation = _digest(bearer)
        session = Session(generation, challenge.subject, now, now + 28800, now, ctx.invite)
        self.sessions[generation] = session
        return {"authenticated": True, "csrf": session.csrf}, bearer

    def issue(self, session, data, now, elapsed):
        prior = self.invites.get(session.invite)
        if session.prepared is not None or (prior and prior.ended_at is None) or len(self.invites) >= MAX_RECORDS:
            raise Unavailable()
        self._full(session)
        now = self.clock()
        if self._session(session.generation, now) is None:
            raise Unavailable()
        token = _opaque()
        session.invite = _digest(token)
        self.invites[session.invite] = Invite(session.generation, now + 900)
        return {"link": self.origin + "/invite#" + token}

    def claim(self, session, data, now, elapsed):
        previous = self.invites.get(session.invite)
        if previous is not None and previous.receiver == session.generation:
            return self._view(previous, session)
        invite = self._issued(session.prepared, now)
        issuer = self._session(invite.issuer, now)
        if issuer is None or issuer.subject == session.subject:
            raise Unavailable()
        self._full(issuer)
        now = self.clock()
        self._issued(session.prepared, now)
        if self._session(invite.issuer, now) is None or self._session(session.generation, now) is None:
            raise Unavailable()
        invite.receiver = session.generation
        invite.attempt = _opaque()
        invite.comparison = f"{secrets.randbelow(1_000_000):06d}"
        invite.token_state = "CLAIMED"
        invite.state = "PENDING_CONSENT"
        invite.deadline = min(invite.expires, now + 300)
        session.invite = session.prepared
        return self._view(invite, session)

    def _current(self, session):
        invite = self.invites.get(session.invite)
        if invite is None or session.generation not in (invite.issuer, invite.receiver):
            raise Unavailable()
        return invite

    def _view(self, invite, session):
        view = {"state": invite.state, "host": invite.issuer == session.generation}
        if invite.attempt is not None:
            view["attempt"] = invite.attempt
        if invite.state == "PENDING_CONSENT":
            view.update(comparison=invite.comparison, approved=session.generation in invite.approvals)
        if invite.room is not None:
            view.update(room=invite.room.handle, negotiating=invite.room.offer)
        return view

    def status(self, session, data, now, elapsed):
        if session.invite not in self.invites:
            return {"state": "READY_TO_CLAIM" if session.prepared else "IDLE"}
        return self._view(self._current(session), session)

    def consent(self, session, data, now, elapsed):
        invite = self._current(session)
        if not invite.attempt or data["attempt"] != invite.attempt or type(data["accept"]) is not bool:
            raise Unavailable()
        if invite.room is not None and data["accept"] is True:
            return self._view(invite, session)
        if invite.state != "PENDING_CONSENT":
            raise Unavailable()
        if not data["accept"]:
            self._end(invite, "DECLINED", now)
        else:
            invite.approvals.add(session.generation)
            if len(invite.approvals) == 2:
                issuer = self._session(invite.issuer, now)
                receiver = self._session(invite.receiver, now)
                try:
                    if issuer is None or receiver is None or issuer.subject == receiver.subject:
                        raise Unavailable()
                    self._full(issuer)
                    committed = self.clock()
                    if (
                        committed >= invite.deadline
                        or self._session(invite.issuer, committed) is None
                        or self._session(invite.receiver, committed) is None
                    ):
                        raise Unavailable()
                except Unavailable:
                    self._end(invite, "CANCELLED", now)
                    raise
                invite.room = Room(_opaque(), [elapsed, elapsed])
                invite.token_state = "CONSUMED"
                invite.state = "AUTHORIZED"
                invite.comparison = None
        return self._view(invite, session)

    def cancel(self, session, data, now, elapsed):
        invite = self._current(session)
        if data["attempt"] != invite.attempt or invite.state in _TERMINAL:
            raise Unavailable()
        self._end(invite, "ENDED" if invite.room else "CANCELLED", now)
        return self._view(invite, session)

    def _room(self, session, handle):
        invite = self._current(session)
        room = invite.room
        if invite.state not in _LIVE or room is None or handle != room.handle:
            raise Unavailable()
        return invite, room, int(invite.receiver == session.generation)

    def call_status(self, session, data, now, elapsed):
        invite, room, side = self._room(session, data["room"])
        phase = data["phase"]
        if phase not in ("heartbeat", "ready", "connected"):
            raise Unavailable()
        room.heartbeat[side] = elapsed
        if phase == "ready":
            room.ready.add(side)
        if phase == "connected" and room.answer:
            room.connected.add(side)
            if len(room.connected) == 2:
                invite.state = "CONNECTED"
        return {**self._view(invite, session), "ready": len(room.ready) == 2}

    def turn(self, session, data, now, elapsed):
        _, room, side = self._room(session, data["room"])
        if not self.turn_url or not self.turn_secret:
            raise Unavailable()
        credential = room.credentials.get(side)
        if credential is None or now >= credential["expires_at"]:
            expiry = int(now) + 300
            username = f"{expiry}:{_opaque()}"
            password = base64.b64encode(hmac.digest(self.turn_secret, username.encode(), "sha1")).decode()
            credential = {"urls": [self.turn_url], "username": username, "credential": password, "expires_at": expiry}
            room.credentials[side] = credential
        return dict(credential)

    def send(self, session, data, now, elapsed):
        invite, room, side = self._room(session, data["room"])
        ident, kind, payload = data["message"], data["kind"], data["payload"]
        if _digest(ident) is None:
            raise Unavailable()
        _validate_signal(kind, payload, self.relay_address)
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        other = self.sessions[invite.receiver if side == 0 else invite.issuer]
        if session.subject.encode() in encoded.lower() or other.subject.encode() in encoded.lower():
            raise Unavailable()
        fingerprint = hashlib.sha256(kind.encode() + b"\0" + encoded).digest()
        previous = room.sent[side].get(ident)
        if previous is not None:
            if previous != fingerprint:
                raise Unavailable()
            return {"accepted": True}
        if (
            (kind == "offer" and (side != 0 or room.offer or len(room.ready) != 2))
            or (kind == "answer" and (side != 1 or not room.offer or room.answer))
            or (kind == "ice" and not (room.offer if side == 0 else room.answer))
        ):
            raise Unavailable()
        mailbox = room.queues[1 - side]
        size = len(encoded) + 128
        if (
            len(mailbox.messages) >= MAX_MESSAGES
            or room.bytes_waiting + size > MAX_QUEUE_BYTES
            or len(room.sent[side]) >= MAX_SIGNAL_IDS
        ):
            self._end(invite, "FAILED", now)
            raise Unavailable()
        mailbox.sequence += 1
        mailbox.messages.append((size, {"seq": mailbox.sequence, "kind": kind, "payload": payload}))
        room.bytes_waiting += size
        room.sent[side][ident] = fingerprint
        room.heartbeat[side] = elapsed
        if kind == "offer":
            room.offer = True
            invite.state = "CONNECTING"
        elif kind == "answer":
            room.answer = True
        return {"accepted": True}

    def poll(self, session, data, now, elapsed):
        invite, room, side = self._room(session, data["room"])
        mailbox = room.queues[side]
        ack = data["ack"]
        if type(ack) is not int or not 0 <= ack <= mailbox.delivered or elapsed < mailbox.last_poll + 0.5:
            raise Unavailable()
        mailbox.last_poll = elapsed
        mailbox.acknowledged = max(ack, mailbox.acknowledged)
        room.heartbeat[side] = elapsed
        while mailbox.messages and mailbox.messages[0][1]["seq"] <= mailbox.acknowledged:
            size, _ = mailbox.messages.pop(0)
            room.bytes_waiting -= size
        batch = [message for _, message in mailbox.messages[:16]]
        if batch:
            mailbox.delivered = max(mailbox.delivered, batch[-1]["seq"])
        return {"state": invite.state, "messages": batch}

    def hangup(self, session, data, now, elapsed):
        invite, _, _ = self._room(session, data["room"])
        if type(data["failed"]) is not bool:
            raise Unavailable()
        self._end(invite, "FAILED" if data["failed"] else "ENDED", now)
        return self._view(invite, session)

    def logout(self, session, data, now, elapsed):
        del self.sessions[session.generation]
        self._sweep(now, elapsed)
        return {"authenticated": False}


def _validate_signal(kind, payload, relay_address):
    if type(payload) is not dict:
        raise Unavailable()
    if kind in ("offer", "answer"):
        sdp = payload.get("sdp")
        if (
            set(payload) != {"sdp"}
            or type(sdp) is not str
            or not 0 < len(sdp.encode()) <= 65536
            or not sdp.startswith("v=0\r\n")
            or any(
                line.startswith(("a=candidate:", "a=remote-candidates:"))
                or (line.startswith("c=") and line not in ("c=IN IP4 0.0.0.0", "c=IN IP6 ::"))
                or (line.startswith("a=rtcp:") and line != "a=rtcp:9 IN IP4 0.0.0.0")
                or (line.startswith("o=") and line.split()[-1] not in ("127.0.0.1", "0.0.0.0", "::", "::1"))
                for line in sdp.splitlines()
            )
        ):
            raise Unavailable()
        return
    if kind != "ice" or set(payload) != {"candidate", "sdpMid", "sdpMLineIndex"}:
        raise Unavailable()
    candidate, mid, index = payload["candidate"], payload["sdpMid"], payload["sdpMLineIndex"]
    if (
        type(candidate) is not str
        or not 0 < len(candidate.encode()) <= 4096
        or not candidate.startswith("candidate:")
        or not candidate.isascii()
        or any(ord(char) < 32 or ord(char) == 127 for char in candidate)
        or (mid is not None and (type(mid) is not str or not _MID(mid)))
        or (index is not None and (type(index) is not int or not 0 <= index <= 16))
        or (mid is None and index is None)
    ):
        raise Unavailable()
    parts = candidate.split()
    if (
        len(parts) < 8
        or len(parts) % 2
        or not _MID(parts[0].removeprefix("candidate:"))
        or parts[1] not in ("1", "2")
        or parts[2].lower() != "udp"
        or not re.fullmatch(r"\d{1,10}", parts[3])
        or parts[4] != relay_address
        or not re.fullmatch(r"\d{1,5}", parts[5])
        or not 1024 <= int(parts[5]) <= 65535
        or parts[6:8] != ["typ", "relay"]
    ):
        raise Unavailable()
    extensions = dict(zip(parts[8::2], parts[9::2]))
    if (
        len(extensions) * 2 != len(parts) - 8
        or set(extensions) - {"generation", "network-id", "network-cost", "ufrag"}
        or any(not re.fullmatch(r"[A-Za-z0-9+/_-]{1,256}", value) for value in extensions.values())
    ):
        raise Unavailable()
