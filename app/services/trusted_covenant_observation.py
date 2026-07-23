"""Dormant adapter for observing explicitly trusted Bitcoin covenant outpoints."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import re
from typing import Callable

from app.services.covenant_relation import (
    EVALUATION_SCHEMA,
    MAX_BITCOIN_SATS,
    MAX_VOUT,
    OBSERVATION_SCHEMA,
    CovenantDirection,
    CovenantRelationEvaluation,
    CovenantRelationObservation,
)

TRUSTED_OUTPOINT_SCHEMA = "hodlxxi.trusted_covenant_outpoint.v1"
ADAPTER_VERSION = "hodlxxi.trusted_covenant_observation_adapter.v1"

_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_EVEN_HEX = re.compile(r"(?:[0-9a-f]{2})+\Z")
_SATS_PER_BITCOIN = Decimal(100_000_000)


class InvalidTrustedCovenantOutpoint(ValueError):
    """A trusted outpoint or adapter input violates the strict contract."""


class TrustedCovenantObservationUnavailable(RuntimeError):
    """Trusted covenant observation could not be completed safely."""

    def __init__(self):
        super().__init__("trusted covenant observation unavailable")


def _require_digest(value: object, field: str) -> None:
    if type(value) is not str or _LOWER_HEX_64.fullmatch(value) is None:
        raise InvalidTrustedCovenantOutpoint(f"{field} must be canonical lowercase 64-hex")


def _require_exact_int(value: object, field: str, minimum: int, maximum: int) -> None:
    if type(value) is not int:
        raise InvalidTrustedCovenantOutpoint(f"{field} must be an exact int")
    if not minimum <= value <= maximum:
        raise InvalidTrustedCovenantOutpoint(f"{field} is outside its permitted range")


@dataclass(frozen=True, slots=True)
class TrustedCovenantOutpoint:
    schema: str
    subject_pubkey: str
    counterparty_pubkey: str
    direction: CovenantDirection
    txid: str
    vout: int
    amount_sats: int
    script_sha256: str
    descriptor_sha256: str | None

    def __post_init__(self) -> None:
        if type(self.schema) is not str or self.schema != TRUSTED_OUTPOINT_SCHEMA:
            raise InvalidTrustedCovenantOutpoint("invalid trusted outpoint schema")
        _require_digest(self.subject_pubkey, "subject_pubkey")
        _require_digest(self.counterparty_pubkey, "counterparty_pubkey")
        if self.subject_pubkey == self.counterparty_pubkey:
            raise InvalidTrustedCovenantOutpoint("subject_pubkey and counterparty_pubkey must differ")
        if type(self.direction) is not CovenantDirection:
            raise InvalidTrustedCovenantOutpoint("direction must be an exact CovenantDirection")
        _require_digest(self.txid, "txid")
        _require_exact_int(self.vout, "vout", 0, MAX_VOUT)
        _require_exact_int(self.amount_sats, "amount_sats", 1, MAX_BITCOIN_SATS)
        _require_digest(self.script_sha256, "script_sha256")
        if self.descriptor_sha256 is not None:
            _require_digest(self.descriptor_sha256, "descriptor_sha256")


def _snapshot_height(value: object) -> int:
    if type(value) is not int or value < 0:
        raise TrustedCovenantObservationUnavailable()
    return value


def _snapshot_hash(value: object) -> str:
    if type(value) is not str or _LOWER_HEX_64.fullmatch(value) is None:
        raise TrustedCovenantObservationUnavailable()
    return value


def _amount_sats(value: object) -> int:
    if type(value) is Decimal:
        bitcoin = value
    elif type(value) is int:
        bitcoin = Decimal(value)
    else:
        raise TrustedCovenantObservationUnavailable()
    if not bitcoin.is_finite():
        raise TrustedCovenantObservationUnavailable()
    satoshis = bitcoin * _SATS_PER_BITCOIN
    if satoshis != satoshis.to_integral_value():
        raise TrustedCovenantObservationUnavailable()
    result = int(satoshis)
    if not 1 <= result <= MAX_BITCOIN_SATS:
        raise TrustedCovenantObservationUnavailable()
    return result


def _observation(definition: TrustedCovenantOutpoint, response: object, best_block: str) -> CovenantRelationObservation:
    if response is None:
        return CovenantRelationObservation(
            schema=OBSERVATION_SCHEMA,
            subject_pubkey=definition.subject_pubkey,
            counterparty_pubkey=definition.counterparty_pubkey,
            direction=definition.direction,
            txid=definition.txid,
            vout=definition.vout,
            amount_sats=definition.amount_sats,
            script_sha256=definition.script_sha256,
            descriptor_sha256=definition.descriptor_sha256,
            confirmations=0,
            unspent=False,
        )
    if type(response) is not dict:
        raise TrustedCovenantObservationUnavailable()
    if _snapshot_hash(response.get("bestblock")) != best_block:
        raise TrustedCovenantObservationUnavailable()
    confirmations = response.get("confirmations")
    if type(confirmations) is not int or confirmations < 0:
        raise TrustedCovenantObservationUnavailable()
    if _amount_sats(response.get("value")) != definition.amount_sats:
        raise TrustedCovenantObservationUnavailable()
    script_pub_key = response.get("scriptPubKey")
    if type(script_pub_key) is not dict:
        raise TrustedCovenantObservationUnavailable()
    script_hex = script_pub_key.get("hex")
    if type(script_hex) is not str or _LOWER_EVEN_HEX.fullmatch(script_hex) is None:
        raise TrustedCovenantObservationUnavailable()
    script_digest = hashlib.sha256(bytes.fromhex(script_hex)).hexdigest()
    if script_digest != definition.script_sha256:
        raise TrustedCovenantObservationUnavailable()
    if definition.descriptor_sha256 is not None:
        descriptor = script_pub_key.get("desc")
        if type(descriptor) is not str or not descriptor:
            raise TrustedCovenantObservationUnavailable()
        if hashlib.sha256(descriptor.encode("utf-8")).hexdigest() != definition.descriptor_sha256:
            raise TrustedCovenantObservationUnavailable()
    return CovenantRelationObservation(
        schema=OBSERVATION_SCHEMA,
        subject_pubkey=definition.subject_pubkey,
        counterparty_pubkey=definition.counterparty_pubkey,
        direction=definition.direction,
        txid=definition.txid,
        vout=definition.vout,
        amount_sats=definition.amount_sats,
        script_sha256=definition.script_sha256,
        descriptor_sha256=definition.descriptor_sha256,
        confirmations=confirmations,
        unspent=True,
    )


class TrustedBitcoinCovenantObservationAdapter:
    """Observe only caller-registered exact outpoints through an injected RPC."""

    def __init__(self, rpc: object, clock: Callable[[], datetime] | None = None):
        for method in ("getblockcount", "getbestblockhash", "gettxout"):
            if not callable(getattr(rpc, method, None)):
                raise InvalidTrustedCovenantOutpoint("rpc does not expose the required callable methods")
        if clock is not None and not callable(clock):
            raise InvalidTrustedCovenantOutpoint("clock must be callable")
        self._rpc = rpc
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def observe(self, outpoints: tuple[TrustedCovenantOutpoint, ...]) -> CovenantRelationEvaluation:
        if type(outpoints) is not tuple or not outpoints:
            raise InvalidTrustedCovenantOutpoint("outpoints must be a non-empty exact tuple")
        if any(type(item) is not TrustedCovenantOutpoint for item in outpoints):
            raise InvalidTrustedCovenantOutpoint("every item must be an exact TrustedCovenantOutpoint")
        subject = outpoints[0].subject_pubkey
        counterparty = outpoints[0].counterparty_pubkey
        if any(item.subject_pubkey != subject for item in outpoints):
            raise InvalidTrustedCovenantOutpoint("all outpoints must bind the same subject")
        if any(item.counterparty_pubkey != counterparty for item in outpoints):
            raise InvalidTrustedCovenantOutpoint("all outpoints must bind the same counterparty")
        identities = {(item.txid, item.vout) for item in outpoints}
        if len(identities) != len(outpoints):
            raise InvalidTrustedCovenantOutpoint("duplicate trusted outpoint")
        ordered = sorted(outpoints, key=lambda item: (item.txid, item.vout, item.direction.value))

        try:
            height_before = _snapshot_height(self._rpc.getblockcount())
            hash_before = _snapshot_hash(self._rpc.getbestblockhash())
            observations = tuple(
                _observation(item, self._rpc.gettxout(item.txid, item.vout, False), hash_before) for item in ordered
            )
            height_after = _snapshot_height(self._rpc.getblockcount())
            hash_after = _snapshot_hash(self._rpc.getbestblockhash())
            if height_before != height_after or hash_before != hash_after:
                raise TrustedCovenantObservationUnavailable()
            observed_at = self._clock()
            if type(observed_at) is not datetime or observed_at.tzinfo is None or observed_at.utcoffset() is None:
                raise TrustedCovenantObservationUnavailable()
            observed_at = observed_at.astimezone(timezone.utc)
            return CovenantRelationEvaluation(
                schema=EVALUATION_SCHEMA,
                network="bitcoin",
                subject_pubkey=subject,
                counterparty_pubkey=counterparty,
                observed_at=observed_at,
                observed_block_height=height_before,
                observations=observations,
            )
        except TrustedCovenantObservationUnavailable:
            raise
        except Exception:
            raise TrustedCovenantObservationUnavailable() from None
