"""Strict, pure validation of canonical mirrored Bitcoin covenant pairs."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re

LEG_SCHEMA = "hodlxxi.mirrored_covenant_leg.v1"
PAIR_SCHEMA = "hodlxxi.mirrored_covenant_pair.v1"
VALIDATOR_VERSION = "hodlxxi.mirrored_covenant_pair_validator.v1"
NETWORK = "bitcoin"

_HEX = re.compile(r"[0-9a-f]+\Z")
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_OP_IF, _OP_ELSE, _OP_ENDIF = 0x63, 0x67, 0x68
_OP_DROP, _OP_CHECKSIG = 0x75, 0xAC
_OP_CLTV, _OP_CHECKMULTISIG = 0xB1, 0xAE


class MirroredCovenantErrorCode(Enum):
    INVALID_SCRIPT_HEX = "invalid_script_hex"
    NON_CANONICAL_SCRIPT = "non_canonical_script"
    UNSUPPORTED_TEMPLATE = "unsupported_template"
    INVALID_PUBKEY = "invalid_pubkey"
    XONLY_IDENTITY_COLLISION = "xonly_identity_collision"
    INVALID_LOCK_HEIGHT = "invalid_lock_height"
    INVALID_DELTA = "invalid_delta"
    UNSUPPORTED_DELTA_PROFILE = "unsupported_delta_profile"
    DISALLOWED_DELTA_PROFILE = "disallowed_delta_profile"
    DUPLICATE_SCRIPT = "duplicate_script"
    MIXED_TEMPLATE_FAMILY = "mixed_template_family"
    PARTICIPANT_MISMATCH = "participant_mismatch"
    ROLES_NOT_MIRRORED = "roles_not_mirrored"
    MIDDLE_HEIGHT_MISMATCH = "middle_height_mismatch"
    COOPERATIVE_PARTICIPANT_MISMATCH = "cooperative_participant_mismatch"
    SUBJECT_NOT_PARTICIPANT = "subject_not_participant"


class InvalidMirroredCovenantPair(ValueError):
    """Stable public failure for invalid script or pair input."""

    def __init__(self, code: MirroredCovenantErrorCode, message: str):
        self.code = code
        super().__init__(f"{code.value}: {message}")


class CovenantTemplateFamily(Enum):
    CLTV_ONLY = "cltv_only"
    COOPERATIVE_2_OF_2_CLTV = "cooperative_2_of_2_cltv"


class CovenantDeltaProfile(Enum):
    CURRENT_144 = "current_144"
    LEGACY_777 = "legacy_777"

    @property
    def blocks(self) -> int:
        return {CovenantDeltaProfile.CURRENT_144: 144, CovenantDeltaProfile.LEGACY_777: 777}[self]


def _fail(code: MirroredCovenantErrorCode, message: str) -> None:
    raise InvalidMirroredCovenantPair(code, message)


def _pubkey(data: bytes) -> tuple[str, str]:
    if len(data) != 33 or data[0] not in (2, 3):
        _fail(MirroredCovenantErrorCode.INVALID_PUBKEY, "compressed pubkey must be 33 bytes with prefix 02 or 03")
    x = int.from_bytes(data[1:], "big")
    if x >= _P:
        _fail(MirroredCovenantErrorCode.INVALID_PUBKEY, "pubkey x coordinate is outside the field")
    rhs = (pow(x, 3, _P) + 7) % _P
    y = pow(rhs, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != rhs:
        _fail(MirroredCovenantErrorCode.INVALID_PUBKEY, "pubkey is not a secp256k1 point")
    return data.hex(), data[1:].hex()


def _pubkey_hex(value: object) -> tuple[str, str]:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{66}", value) is None:
        _fail(MirroredCovenantErrorCode.INVALID_PUBKEY, "pubkey must be canonical lowercase 66-hex")
    return _pubkey(bytes.fromhex(value))


@dataclass(frozen=True, slots=True)
class _SmallInteger:
    value: int


_Token = tuple[str, int | bytes | _SmallInteger]


def _height(value: bytes | _SmallInteger) -> int:
    if isinstance(value, _SmallInteger):
        if value.value <= 0:
            _fail(MirroredCovenantErrorCode.INVALID_LOCK_HEIGHT, "zero or negative ScriptNum")
        return value.value
    data = value
    if not data:
        _fail(MirroredCovenantErrorCode.INVALID_LOCK_HEIGHT, "zero is not a positive block height")
    if data == b"\x80":
        _fail(MirroredCovenantErrorCode.INVALID_LOCK_HEIGHT, "negative ScriptNum or negative zero")
    if (data[-1] & 0x7F) == 0 and (len(data) == 1 or not (data[-2] & 0x80)):
        _fail(MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT, "non-minimal ScriptNum")
    if data[-1] & 0x80:
        _fail(MirroredCovenantErrorCode.INVALID_LOCK_HEIGHT, "negative ScriptNum or negative zero")
    value = int.from_bytes(data, "little")
    if value <= 0 or value >= 500_000_000:
        _fail(MirroredCovenantErrorCode.INVALID_LOCK_HEIGHT, "locktime must be a positive block height")
    return value


def _tokens(raw: bytes) -> tuple[_Token, ...]:
    result: list[_Token] = []
    index = 0
    while index < len(raw):
        opcode = raw[index]
        index += 1
        if 1 <= opcode <= 75:
            end = index + opcode
            if end > len(raw):
                _fail(MirroredCovenantErrorCode.INVALID_SCRIPT_HEX, "truncated direct push")
            data = raw[index:end]
            index = end
            # OP_1..OP_16 and OP_1NEGATE are the minimal encoding for these values.
            if len(data) == 1 and (data[0] == 0x81 or 1 <= data[0] <= 16):
                _fail(MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT, "non-minimal direct push")
            result.append(("push", data))
        elif opcode == 0x4C:
            if index >= len(raw):
                _fail(MirroredCovenantErrorCode.INVALID_SCRIPT_HEX, "truncated PUSHDATA1 length")
            length = raw[index]
            index += 1
            if length < 76:
                _fail(MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT, "non-minimal PUSHDATA1 encoding")
            end = index + length
            if end > len(raw):
                _fail(MirroredCovenantErrorCode.INVALID_SCRIPT_HEX, "truncated PUSHDATA1")
            result.append(("push", raw[index:end]))
            index = end
        elif opcode in (0x4D, 0x4E):
            _fail(MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT, "disallowed PUSHDATA encoding")
        elif opcode == 0x00:
            result.append(("small_integer", _SmallInteger(0)))
        elif opcode == 0x4F:
            result.append(("small_integer", _SmallInteger(-1)))
        elif 0x51 <= opcode <= 0x60:
            result.append(("small_integer", _SmallInteger(opcode - 0x50)))
        elif opcode in {
            _OP_IF,
            _OP_ELSE,
            _OP_ENDIF,
            _OP_DROP,
            _OP_CHECKSIG,
            _OP_CLTV,
            _OP_CHECKMULTISIG,
        }:
            result.append(("op", opcode))
        else:
            _fail(MirroredCovenantErrorCode.UNSUPPORTED_TEMPLATE, f"unsupported opcode 0x{opcode:02x}")
    return tuple(result)


def _op(token: _Token, opcode: int) -> bool:
    return token == ("op", opcode)


def _small_integer(token: _Token, value: int) -> bool:
    return token == ("small_integer", _SmallInteger(value))


def _push(token: _Token) -> bytes | None:
    return token[1] if token[0] == "push" and type(token[1]) is bytes else None


def _script_num(token: _Token) -> bytes | _SmallInteger | None:
    return token[1] if token[0] in ("push", "small_integer") else None


@dataclass(frozen=True, slots=True)
class _ParsedLegComponents:
    template_family: CovenantTemplateFamily
    raw_script_hex: str
    script_sha256: str
    receiver_pubkey: str
    receiver_xonly_pubkey: str
    sender_pubkey: str
    sender_xonly_pubkey: str
    receiver_height: int
    sender_height: int
    delta_blocks: int
    cooperative_pubkeys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ParsedCovenantLeg:
    schema: str
    template_family: CovenantTemplateFamily
    raw_script_hex: str
    script_sha256: str
    receiver_pubkey: str
    receiver_xonly_pubkey: str
    sender_pubkey: str
    sender_xonly_pubkey: str
    receiver_height: int
    sender_height: int
    delta_blocks: int
    cooperative_pubkeys: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.schema) is not str or self.schema != LEG_SCHEMA:
            _fail(MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT, "invalid leg schema")
        authoritative = _parse_covenant_leg_components(self.raw_script_hex)
        if any(
            type(getattr(self, field)) is not type(getattr(authoritative, field))
            or getattr(self, field) != getattr(authoritative, field)
            for field in _ParsedLegComponents.__dataclass_fields__
        ):
            _fail(
                MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT,
                "parsed leg fields do not exactly match the authoritative raw script",
            )


def _parse_covenant_leg_components(script_hex: str) -> _ParsedLegComponents:
    if type(script_hex) is not str or not script_hex or _HEX.fullmatch(script_hex) is None or len(script_hex) % 2:
        _fail(MirroredCovenantErrorCode.INVALID_SCRIPT_HEX, "script must be non-empty even lowercase hexadecimal")
    try:
        raw = bytes.fromhex(script_hex)
    except ValueError:
        _fail(MirroredCovenantErrorCode.INVALID_SCRIPT_HEX, "malformed hexadecimal")
    tokens = _tokens(raw)

    cooperative: tuple[str, ...] = ()
    family: CovenantTemplateFamily
    if len(tokens) == 13 and all(
        (
            _op(tokens[0], _OP_IF),
            _op(tokens[2], _OP_CLTV),
            _op(tokens[3], _OP_DROP),
            _op(tokens[5], _OP_CHECKSIG),
            _op(tokens[6], _OP_ELSE),
            _op(tokens[8], _OP_CLTV),
            _op(tokens[9], _OP_DROP),
            _op(tokens[11], _OP_CHECKSIG),
            _op(tokens[12], _OP_ENDIF),
        )
    ):
        family = CovenantTemplateFamily.CLTV_ONLY
        rh, rp, sh, sp = _script_num(tokens[1]), _push(tokens[4]), _script_num(tokens[7]), _push(tokens[10])
    elif len(tokens) == 22 and all(
        (
            _op(tokens[0], _OP_IF),
            _small_integer(tokens[1], 2),
            _small_integer(tokens[4], 2),
            _op(tokens[5], _OP_CHECKMULTISIG),
            _op(tokens[6], _OP_ELSE),
            _op(tokens[7], _OP_IF),
            _op(tokens[9], _OP_CLTV),
            _op(tokens[10], _OP_DROP),
            _op(tokens[12], _OP_CHECKSIG),
            _op(tokens[13], _OP_ELSE),
            _op(tokens[15], _OP_CLTV),
            _op(tokens[16], _OP_DROP),
            _op(tokens[18], _OP_CHECKSIG),
            _op(tokens[19], _OP_ENDIF),
            _op(tokens[20], _OP_ENDIF),
        )
    ):
        # The exact template has 21 tokens, retained separately below for clarity.
        _fail(MirroredCovenantErrorCode.UNSUPPORTED_TEMPLATE, "invalid cooperative template")
    elif len(tokens) == 21 and all(
        (
            _op(tokens[0], _OP_IF),
            _small_integer(tokens[1], 2),
            _small_integer(tokens[4], 2),
            _op(tokens[5], _OP_CHECKMULTISIG),
            _op(tokens[6], _OP_ELSE),
            _op(tokens[7], _OP_IF),
            _op(tokens[9], _OP_CLTV),
            _op(tokens[10], _OP_DROP),
            _op(tokens[12], _OP_CHECKSIG),
            _op(tokens[13], _OP_ELSE),
            _op(tokens[15], _OP_CLTV),
            _op(tokens[16], _OP_DROP),
            _op(tokens[18], _OP_CHECKSIG),
            _op(tokens[19], _OP_ENDIF),
            _op(tokens[20], _OP_ENDIF),
        )
    ):
        family = CovenantTemplateFamily.COOPERATIVE_2_OF_2_CLTV
        c1, c2 = _push(tokens[2]), _push(tokens[3])
        rh, rp, sh, sp = _script_num(tokens[8]), _push(tokens[11]), _script_num(tokens[14]), _push(tokens[17])
        if c1 is None or c2 is None:
            _fail(MirroredCovenantErrorCode.UNSUPPORTED_TEMPLATE, "multisig keys must be direct pushes")
        c1h, _ = _pubkey(c1)
        c2h, _ = _pubkey(c2)
        if c1h == c2h:
            _fail(MirroredCovenantErrorCode.COOPERATIVE_PARTICIPANT_MISMATCH, "cooperative keys must be distinct")
        cooperative = tuple(sorted((c1h, c2h)))
    else:
        _fail(MirroredCovenantErrorCode.UNSUPPORTED_TEMPLATE, "script does not exactly match a supported template")

    if None in (rh, rp, sh, sp):
        _fail(MirroredCovenantErrorCode.UNSUPPORTED_TEMPLATE, "template fields must be direct pushes")
    receiver_height, sender_height = _height(rh), _height(sh)  # type: ignore[arg-type]
    receiver, receiver_x = _pubkey(rp)  # type: ignore[arg-type]
    sender, sender_x = _pubkey(sp)  # type: ignore[arg-type]
    if receiver == sender:
        _fail(MirroredCovenantErrorCode.PARTICIPANT_MISMATCH, "sender and receiver must differ")
    if receiver_x == sender_x:
        _fail(MirroredCovenantErrorCode.XONLY_IDENTITY_COLLISION, "distinct compressed keys share one x-only identity")
    if sender_height <= receiver_height:
        _fail(MirroredCovenantErrorCode.INVALID_LOCK_HEIGHT, "sender height must be later than receiver height")
    if family is CovenantTemplateFamily.COOPERATIVE_2_OF_2_CLTV and cooperative != tuple(sorted((receiver, sender))):
        _fail(
            MirroredCovenantErrorCode.COOPERATIVE_PARTICIPANT_MISMATCH,
            "cooperative set must equal the unilateral participants",
        )
    return _ParsedLegComponents(
        family,
        script_hex,
        hashlib.sha256(raw).hexdigest(),
        receiver,
        receiver_x,
        sender,
        sender_x,
        receiver_height,
        sender_height,
        sender_height - receiver_height,
        cooperative,
    )


def parse_covenant_leg(script_hex: str) -> ParsedCovenantLeg:
    """Strictly parse one authorization-grade raw covenant Script."""
    components = _parse_covenant_leg_components(script_hex)
    return ParsedCovenantLeg(LEG_SCHEMA, *(getattr(components, field) for field in components.__dataclass_fields__))


def _validated_leg(leg: ParsedCovenantLeg) -> ParsedCovenantLeg:
    if type(leg) is not ParsedCovenantLeg:
        _fail(MirroredCovenantErrorCode.ROLES_NOT_MIRRORED, "leg must have exact parsed-leg type")
    return ParsedCovenantLeg(*(getattr(leg, field) for field in ParsedCovenantLeg.__dataclass_fields__))


@dataclass(frozen=True, slots=True)
class ValidatedMirroredCovenantPair:
    schema: str
    validator_version: str
    network: str
    subject_pubkey: str
    subject_xonly_pubkey: str
    counterparty_pubkey: str
    counterparty_xonly_pubkey: str
    template_family: CovenantTemplateFamily
    delta_profile: CovenantDeltaProfile
    delta_blocks: int
    earlier_leg: ParsedCovenantLeg
    later_leg: ParsedCovenantLeg
    incoming_leg_script_sha256: str
    outgoing_leg_script_sha256: str

    def __post_init__(self) -> None:
        if self.schema != PAIR_SCHEMA or type(self.schema) is not str:
            _fail(MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT, "invalid pair schema")
        if self.validator_version != VALIDATOR_VERSION or self.network != NETWORK:
            _fail(MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT, "invalid validator version or network")
        if (
            type(self.template_family) is not CovenantTemplateFamily
            or type(self.delta_profile) is not CovenantDeltaProfile
        ):
            _fail(MirroredCovenantErrorCode.INVALID_DELTA, "invalid enum type")
        if type(self.delta_blocks) is not int:
            _fail(MirroredCovenantErrorCode.INVALID_DELTA, "delta must be an exact int")
        if type(self.earlier_leg) is not ParsedCovenantLeg or type(self.later_leg) is not ParsedCovenantLeg:
            _fail(MirroredCovenantErrorCode.ROLES_NOT_MIRRORED, "legs must have exact parsed-leg type")
        for name in (
            "validator_version",
            "network",
            "subject_pubkey",
            "subject_xonly_pubkey",
            "counterparty_pubkey",
            "counterparty_xonly_pubkey",
            "incoming_leg_script_sha256",
            "outgoing_leg_script_sha256",
        ):
            if type(getattr(self, name)) is not str:
                _fail(MirroredCovenantErrorCode.NON_CANONICAL_SCRIPT, f"{name} must be an exact str")
        earlier = _validated_leg(self.earlier_leg)
        later = _validated_leg(self.later_leg)
        if earlier.raw_script_hex == later.raw_script_hex or earlier.script_sha256 == later.script_sha256:
            _fail(MirroredCovenantErrorCode.DUPLICATE_SCRIPT, "stored raw scripts and hashes must differ")
        subject, subject_x = _pubkey_hex(self.subject_pubkey)
        counterparty, counterparty_x = _pubkey_hex(self.counterparty_pubkey)
        if (
            subject == counterparty
            or subject_x != self.subject_xonly_pubkey
            or counterparty_x != self.counterparty_xonly_pubkey
        ):
            _fail(MirroredCovenantErrorCode.PARTICIPANT_MISMATCH, "pair identities are inconsistent")
        if earlier.template_family is not later.template_family or earlier.template_family is not self.template_family:
            _fail(MirroredCovenantErrorCode.MIXED_TEMPLATE_FAMILY, "stored template families differ")
        if {earlier.receiver_pubkey, earlier.sender_pubkey} != {
            later.receiver_pubkey,
            later.sender_pubkey,
        }:
            _fail(MirroredCovenantErrorCode.PARTICIPANT_MISMATCH, "stored leg participants differ")
        if earlier.sender_pubkey != later.receiver_pubkey or earlier.receiver_pubkey != later.sender_pubkey:
            _fail(MirroredCovenantErrorCode.ROLES_NOT_MIRRORED, "stored legs are not mirrored")
        if earlier.sender_height != later.receiver_height:
            _fail(MirroredCovenantErrorCode.MIDDLE_HEIGHT_MISMATCH, "stored legs lack a shared middle height")
        if (
            earlier.delta_blocks != later.delta_blocks
            or self.delta_blocks != earlier.delta_blocks
            or self.delta_profile.blocks != self.delta_blocks
        ):
            _fail(MirroredCovenantErrorCode.INVALID_DELTA, "stored delta fields are inconsistent")
        if _profile(self.delta_blocks) is not self.delta_profile:
            _fail(MirroredCovenantErrorCode.UNSUPPORTED_DELTA_PROFILE, "stored delta profile is unsupported")
        participants = {earlier.receiver_pubkey, earlier.sender_pubkey}
        if self.template_family is CovenantTemplateFamily.COOPERATIVE_2_OF_2_CLTV:
            expected_cooperative = tuple(sorted(participants))
            if earlier.cooperative_pubkeys != expected_cooperative or later.cooperative_pubkeys != expected_cooperative:
                _fail(
                    MirroredCovenantErrorCode.COOPERATIVE_PARTICIPANT_MISMATCH,
                    "stored cooperative participant sets differ",
                )
        if {subject, counterparty} != participants:
            _fail(MirroredCovenantErrorCode.SUBJECT_NOT_PARTICIPANT, "stored subject is not a participant")
        incoming = earlier if earlier.receiver_pubkey == subject else later
        outgoing = earlier if earlier.sender_pubkey == subject else later
        if (
            self.incoming_leg_script_sha256 != incoming.script_sha256
            or self.outgoing_leg_script_sha256 != outgoing.script_sha256
        ):
            _fail(MirroredCovenantErrorCode.ROLES_NOT_MIRRORED, "subject-relative script hashes are inconsistent")


def _profile(delta: int) -> CovenantDeltaProfile:
    matches = tuple(profile for profile in CovenantDeltaProfile if profile.blocks == delta)
    if len(matches) != 1:
        _fail(MirroredCovenantErrorCode.UNSUPPORTED_DELTA_PROFILE, "delta does not map to one supported profile")
    return matches[0]


def validate_mirrored_covenant_pair(
    first_script_hex: str,
    second_script_hex: str,
    *,
    subject_pubkey: str,
    allowed_delta_profiles: tuple[CovenantDeltaProfile, ...],
) -> ValidatedMirroredCovenantPair:
    """Prove that two raw Scripts form one canonical reciprocal pair."""
    if type(allowed_delta_profiles) is not tuple or any(
        type(p) is not CovenantDeltaProfile for p in allowed_delta_profiles
    ):
        _fail(MirroredCovenantErrorCode.DISALLOWED_DELTA_PROFILE, "allowed profiles must be an exact immutable tuple")
    if len(set(allowed_delta_profiles)) != len(allowed_delta_profiles):
        _fail(MirroredCovenantErrorCode.DISALLOWED_DELTA_PROFILE, "allowed profiles must not contain duplicates")
    subject, subject_x = _pubkey_hex(subject_pubkey)
    if type(first_script_hex) is str and first_script_hex == second_script_hex:
        _fail(MirroredCovenantErrorCode.DUPLICATE_SCRIPT, "raw scripts must differ")
    first, second = parse_covenant_leg(first_script_hex), parse_covenant_leg(second_script_hex)
    if first.script_sha256 == second.script_sha256:
        _fail(MirroredCovenantErrorCode.DUPLICATE_SCRIPT, "script hashes must differ")
    if first.template_family is not second.template_family:
        _fail(MirroredCovenantErrorCode.MIXED_TEMPLATE_FAMILY, "template families differ")
    p1, p2 = {first.receiver_pubkey, first.sender_pubkey}, {second.receiver_pubkey, second.sender_pubkey}
    if p1 != p2:
        _fail(MirroredCovenantErrorCode.PARTICIPANT_MISMATCH, "legs do not contain the same exact participants")
    if first.receiver_pubkey != second.sender_pubkey or first.sender_pubkey != second.receiver_pubkey:
        _fail(MirroredCovenantErrorCode.ROLES_NOT_MIRRORED, "unilateral roles are not reversed")
    earlier, later = sorted((first, second), key=lambda leg: (leg.receiver_height, leg.script_sha256))
    if earlier.sender_height != later.receiver_height:
        _fail(MirroredCovenantErrorCode.MIDDLE_HEIGHT_MISMATCH, "legs do not share one middle height")
    if first.delta_blocks != second.delta_blocks:
        _fail(MirroredCovenantErrorCode.INVALID_DELTA, "leg deltas differ")
    profile = _profile(first.delta_blocks)
    if profile not in allowed_delta_profiles:
        _fail(MirroredCovenantErrorCode.DISALLOWED_DELTA_PROFILE, "delta profile was not explicitly allowed")
    if first.template_family is CovenantTemplateFamily.COOPERATIVE_2_OF_2_CLTV:
        expected = tuple(sorted(p1))
        if first.cooperative_pubkeys != expected or second.cooperative_pubkeys != expected:
            _fail(MirroredCovenantErrorCode.COOPERATIVE_PARTICIPANT_MISMATCH, "cooperative participant sets differ")
    if subject not in p1:
        _fail(MirroredCovenantErrorCode.SUBJECT_NOT_PARTICIPANT, "subject is not an exact participant")
    counterparty = next(item for item in p1 if item != subject)
    counterparty_x = first.receiver_xonly_pubkey if first.receiver_pubkey == counterparty else first.sender_xonly_pubkey
    incoming = first if first.receiver_pubkey == subject else second
    outgoing = first if first.sender_pubkey == subject else second
    return ValidatedMirroredCovenantPair(
        PAIR_SCHEMA,
        VALIDATOR_VERSION,
        NETWORK,
        subject,
        subject_x,
        counterparty,
        counterparty_x,
        first.template_family,
        profile,
        first.delta_blocks,
        earlier,
        later,
        incoming.script_sha256,
        outgoing.script_sha256,
    )


def _leg_payload(leg: ParsedCovenantLeg) -> dict[str, object]:
    return {
        "schema": leg.schema,
        "template_family": leg.template_family.value,
        "raw_script_hex": leg.raw_script_hex,
        "script_sha256": leg.script_sha256,
        "receiver_pubkey": leg.receiver_pubkey,
        "receiver_xonly_pubkey": leg.receiver_xonly_pubkey,
        "sender_pubkey": leg.sender_pubkey,
        "sender_xonly_pubkey": leg.sender_xonly_pubkey,
        "receiver_height": leg.receiver_height,
        "sender_height": leg.sender_height,
        "delta_blocks": leg.delta_blocks,
        "cooperative_pubkeys": list(leg.cooperative_pubkeys),
    }


def _validated_pair(pair: ValidatedMirroredCovenantPair) -> ValidatedMirroredCovenantPair:
    if type(pair) is not ValidatedMirroredCovenantPair:
        _fail(MirroredCovenantErrorCode.ROLES_NOT_MIRRORED, "pair must have exact validated-pair type")
    return ValidatedMirroredCovenantPair(
        *(getattr(pair, field) for field in ValidatedMirroredCovenantPair.__dataclass_fields__)
    )


def canonical_mirrored_pair_bytes(pair: ValidatedMirroredCovenantPair) -> bytes:
    """Return deterministic ASCII-safe canonical JSON for a validated pair."""
    pair = _validated_pair(pair)
    payload = {
        "schema": pair.schema,
        "validator_version": pair.validator_version,
        "network": pair.network,
        "subject_pubkey": pair.subject_pubkey,
        "subject_xonly_pubkey": pair.subject_xonly_pubkey,
        "counterparty_pubkey": pair.counterparty_pubkey,
        "counterparty_xonly_pubkey": pair.counterparty_xonly_pubkey,
        "template_family": pair.template_family.value,
        "delta_profile": pair.delta_profile.value,
        "delta_blocks": pair.delta_blocks,
        "earlier_leg": _leg_payload(pair.earlier_leg),
        "later_leg": _leg_payload(pair.later_leg),
        "incoming_leg_script_sha256": pair.incoming_leg_script_sha256,
        "outgoing_leg_script_sha256": pair.outgoing_leg_script_sha256,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def mirrored_covenant_pair_sha256(pair: ValidatedMirroredCovenantPair) -> str:
    """Hash the exact canonical pair bytes with SHA-256."""
    return hashlib.sha256(canonical_mirrored_pair_bytes(pair)).hexdigest()
