"""Exact, purpose-separated Social attestation of a strict possession proof.

No authority is derived from a caller-supplied validity boolean. This verifier
only authenticates a signature from the explicitly pinned server trust set.
The transaction owner separately checks history, freshness and current Full.
"""

import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from app.services import social_registered_device_session_contract_v1 as contract
from app.services.social_enrollment_v2_finalization_contract import freeze_config

DOMAIN = "HODLXXI_SOCIAL_REGISTERED_DEVICE_SESSION_STATEMENT_V1"
SCHEMA = "hodlxxi.social_registered_device_session_statement.v1"


def statement_preimage(challenge_wire, proof_wire, kid):
    contract.parse_proof_v1(proof_wire, challenge_wire=challenge_wire)
    if not contract._matches(contract._IDENTIFIER, kid):
        contract._deny()
    return (
        DOMAIN + "\0" + contract.canonical(dict(challenge=challenge_wire, proof=proof_wire, kid=kid, schema=SCHEMA))
    ).encode("ascii")


def verify_statement(statement_wire, *, challenge_wire, proof_wire, config, now):
    try:
        cfg = freeze_config(config)
        if not cfg.enabled or not contract._integer(now):
            contract._deny()
        ec = cfg.reservation_config.evidence_config
        challenge = contract.parse_challenge_v1(challenge_wire)
        if (
            challenge["issuer"] != ec.issuer
            or challenge["audience"] != cfg.reservation_config.verification_audience
            or challenge["clientId"] != ec.client_id
            or not challenge["issuedAt"] <= now < challenge["expiresAt"]
        ):
            contract._deny()
        statement = contract._closed(statement_wire, {"kid", "schema", "signature"})
        if statement["schema"] != SCHEMA or type(statement["signature"]) is not str:
            contract._deny()
        key = [k for k in cfg.statement_config._keys if k.kid == statement["kid"]]
        pin = [p for p in cfg.statement_pins if p.key_id == statement["kid"]]
        if len(key) != 1 or len(pin) != 1:
            contract._deny()
        key, pin = key[0], pin[0]
        if (
            pin.fingerprint != key.fingerprint
            or pin.revoked_at is not None
            or not pin.not_before <= challenge["issuedAt"] <= now < challenge["expiresAt"] <= pin.not_after
            or re.fullmatch(r"[0-9a-f]+", statement["signature"]) is None
            or len(statement["signature"]) != 2 * ((key.public_key.key_size + 7) // 8)
        ):
            contract._deny()
        key.public_key.verify(
            bytes.fromhex(statement["signature"]),
            statement_preimage(challenge_wire, proof_wire, statement["kid"]),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        raise contract.RegisteredDeviceSessionContractError() from None
