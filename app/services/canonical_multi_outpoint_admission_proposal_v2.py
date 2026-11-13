"""Canonical multileg Canon V2 admission intent with dual role-separated BTC consent.

This is a SOURCE-BOUND, proposed-only successor to the old equal-value,
two-outpoint V2 proposal. It commits every UTXO, its output script and
amount, the two aggregate balances and the exact parent/genesis basis
into ONE signed digest. It does not write registration, issue a trusted
server nonce, verify live Full or entitle a user to Full.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import uuid
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone

from app.services.canonical_admission_consent_v2 import (
    CHALLENGE_SCHEMA,
    DOMAIN,
    NETWORK,
    TTL_SECONDS,
    VERIFICATION_SCHEMA,
    CanonicalAdmissionConsentChallengeV2,
    CanonicalAdmissionConsentVerificationV2,
    CanonicalAdmissionConsentVerifierUnavailable,
    canonical_admission_consent_challenge_v2_bytes,
    canonical_admission_consent_message_v2,
)
from app.services.canonical_admission_proposal_v2 import (
    CanonicalAdmissionProposalV2,
    SponsorBasisV2,
    canonical_admission_proposal_v2_sha256,
)
from app.services.canonical_genesis_record import (
    CanonicalGenesisEvaluation,
    CanonicalGenesisEvaluationState,
)
from app.services.canonical_multi_outpoint_mirror_v2 import (
    CanonicalMultiOutpointMirrorV2,
    CanonicalMultiOutpointSnapshotV2,
    canonical_multi_outpoint_mirror_v2_bytes,
    canonical_multi_outpoint_mirror_v2_sha256,
    validate_canonical_multi_outpoint_snapshot_v2,
)
from app.services.covenant_relation import CovenantRelationEvaluation
from app.utils import derive_legacy_address_from_pubkey

SCHEMA = "hodlxxi.canonical_multi_outpoint_admission_proposal.v2"
VERSION = "hodlxxi.canonical_multi_outpoint_admission_proposal_service.v2"
BOUNDARY = "proposed_only_unissued_challenge_no_full"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f-]{36}\Z")


class InvalidCanonicalMultiAdmissionProposalV2(ValueError):
    """Exact multileg commitment, parent, observation or consent is invalid."""


def _fail(reason: str) -> None:
    raise InvalidCanonicalMultiAdmissionProposalV2(reason)


def _digest(value: object) -> None:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _fail("digest")


def _id(value: object) -> None:
    if type(value) is not str or _UUID.fullmatch(value) is None:
        _fail("identifier")
    try:
        if str(uuid.UUID(value)) != value:
            _fail("identifier")
    except (TypeError, ValueError):
        _fail("identifier")


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail("timestamp")
    checked = value.astimezone(timezone.utc)
    if checked.microsecond:
        _fail("timestamp_second_precision")
    return checked


def _snapshot(value: object) -> CanonicalMultiOutpointSnapshotV2:
    if type(value) is not CanonicalMultiOutpointSnapshotV2:
        _fail("snapshot_type")
    try:
        return CanonicalMultiOutpointSnapshotV2(
            *(getattr(value, f.name) for f in fields(CanonicalMultiOutpointSnapshotV2))
        )
    except Exception:
        _fail("snapshot_invalid")


def _bundle(value: object) -> CanonicalMultiOutpointMirrorV2:
    if type(value) is not CanonicalMultiOutpointMirrorV2:
        _fail("mirror_type")
    try:
        return CanonicalMultiOutpointMirrorV2(
            *(getattr(value, f.name) for f in fields(CanonicalMultiOutpointMirrorV2))
        )
    except Exception:
        _fail("mirror_invalid")


def _basis_reference(bundle: CanonicalMultiOutpointMirrorV2, basis: object):
    evidence = bundle.script_evidence
    if evidence.sponsor_depth == 0:
        if type(basis) is not CanonicalGenesisEvaluation:
            _fail("root_basis_type")
        try:
            checked = CanonicalGenesisEvaluation(
                *(getattr(basis, f.name) for f in fields(CanonicalGenesisEvaluation))
            )
        except Exception:
            _fail("root_basis_invalid")
        if (
            checked.state is not CanonicalGenesisEvaluationState.GENESIS_ACTIVE
            or checked.compressed_public_key != evidence.sponsor_compressed_pubkey
            or checked.selected_effective_record_id is None
        ):
            _fail("root_basis_inactive")
        return SponsorBasisV2.GENESIS, checked.selected_effective_record_id, checked.selected_effective_record_sha256

    if type(basis) is CanonicalMultiOutpointAdmissionProposalV2:
        checked = CanonicalMultiOutpointAdmissionProposalV2(
            *(getattr(basis, f.name) for f in fields(CanonicalMultiOutpointAdmissionProposalV2))
        )
        previous = checked.mirror.script_evidence
        sha = canonical_multi_outpoint_admission_proposal_v2_sha256(checked)
        parent_id = checked.proposal_id
    elif type(basis) is CanonicalAdmissionProposalV2:
        checked = CanonicalAdmissionProposalV2(*(getattr(basis, f.name) for f in fields(CanonicalAdmissionProposalV2)))
        previous = checked.script_evidence
        sha = canonical_admission_proposal_v2_sha256(checked)
        parent_id = checked.proposal_id
    else:
        _fail("parent_proposal_type")

    if (
        evidence.sponsor_depth != previous.child_depth
        or evidence.sponsor_compressed_pubkey != previous.child_compressed_pubkey
        or evidence.sponsor_xonly_pubkey != previous.child_xonly_pubkey
        or evidence.graph_or_protocol_id != previous.graph_or_protocol_id
        or evidence.child_xonly_pubkey in (previous.child_xonly_pubkey, previous.sponsor_xonly_pubkey)
    ):
        _fail("parent_identity_or_depth")
    # A parent PROPOSAL is not a current effective admission or Full.
    return SponsorBasisV2.PARENT_PROPOSAL, parent_id, sha


@dataclass(frozen=True, slots=True)
class CanonicalMultiOutpointAdmissionProposalV2:
    schema: str
    version: str
    authorization_boundary: str
    proposal_id: str
    proposed_at: datetime
    basis_kind: SponsorBasisV2
    basis_record_id: str
    basis_record_sha256: str
    mirror: CanonicalMultiOutpointMirrorV2
    mirror_sha256: str
    snapshot: CanonicalMultiOutpointSnapshotV2
    sponsor_import_reference_sha256: str
    sponsor_key_proof_reference_sha256: str
    child_acceptance_reference_sha256: str

    def __post_init__(self) -> None:
        if (
            self.schema != SCHEMA
            or self.version != VERSION
            or self.authorization_boundary != BOUNDARY
        ):
            _fail("schema_or_boundary")
        _id(self.proposal_id)
        _id(self.basis_record_id)
        for digest in (
            self.basis_record_sha256,
            self.mirror_sha256,
            self.sponsor_import_reference_sha256,
            self.sponsor_key_proof_reference_sha256,
            self.child_acceptance_reference_sha256,
        ):
            _digest(digest)
        if len({
            self.sponsor_import_reference_sha256,
            self.sponsor_key_proof_reference_sha256,
            self.child_acceptance_reference_sha256,
        }) != 3:
            _fail("distinct_references")
        if type(self.basis_kind) is not SponsorBasisV2:
            _fail("basis_kind")
        mirror = _bundle(self.mirror)
        snapshot = _snapshot(self.snapshot)
        created = _utc(self.proposed_at)
        if (
            self.mirror_sha256 != canonical_multi_outpoint_mirror_v2_sha256(mirror)
            or snapshot.bundle_sha256 != self.mirror_sha256
            or not snapshot.observed_at <= created <= snapshot.observed_at + timedelta(seconds=120)
            or ((self.basis_kind is SponsorBasisV2.GENESIS) != (mirror.script_evidence.sponsor_depth == 0))
        ):
            _fail("snapshot_mirror_or_basis_binding")
        object.__setattr__(self, "mirror", mirror)
        object.__setattr__(self, "snapshot", snapshot)
        object.__setattr__(self, "proposed_at", created)

    @property
    def grants_full(self) -> bool:
        return False

    @property
    def is_effective(self) -> bool:
        return False


def canonical_multi_outpoint_admission_proposal_v2_bytes(value: CanonicalMultiOutpointAdmissionProposalV2) -> bytes:
    if type(value) is not CanonicalMultiOutpointAdmissionProposalV2:
        _fail("proposal_type")
    p = CanonicalMultiOutpointAdmissionProposalV2(
        *(getattr(value, f.name) for f in fields(CanonicalMultiOutpointAdmissionProposalV2))
    )
    payload = {
        "schema": p.schema,
        "version": p.version,
        "authorization_boundary": p.authorization_boundary,
        "proposal_id": p.proposal_id,
        "proposed_at": p.proposed_at.isoformat().replace("+00:00", "Z"),
        "basis_kind": p.basis_kind.value,
        "basis_record_id": p.basis_record_id,
        "basis_record_sha256": p.basis_record_sha256,
        "mirror": json.loads(canonical_multi_outpoint_mirror_v2_bytes(p.mirror)),
        "mirror_sha256": p.mirror_sha256,
        "snapshot": {
            f.name: (
                getattr(p.snapshot, f.name).isoformat().replace("+00:00", "Z")
                if f.name == "observed_at"
                else getattr(p.snapshot, f.name)
            )
            for f in fields(CanonicalMultiOutpointSnapshotV2)
        },
        "sponsor_import_reference_sha256": p.sponsor_import_reference_sha256,
        "sponsor_key_proof_reference_sha256": p.sponsor_key_proof_reference_sha256,
        "child_acceptance_reference_sha256": p.child_acceptance_reference_sha256,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_multi_outpoint_admission_proposal_v2_sha256(value: CanonicalMultiOutpointAdmissionProposalV2) -> str:
    return hashlib.sha256(canonical_multi_outpoint_admission_proposal_v2_bytes(value)).hexdigest()


def create_canonical_multi_outpoint_admission_proposal_v2(
    *,
    proposal_id: str,
    proposed_at: datetime,
    mirror: CanonicalMultiOutpointMirrorV2,
    observation: CovenantRelationEvaluation,
    sponsor_basis: object,
    sponsor_import_reference_sha256: str,
    sponsor_key_proof_reference_sha256: str,
    child_acceptance_reference_sha256: str,
) -> CanonicalMultiOutpointAdmissionProposalV2:
    checked = _bundle(mirror)
    at = _utc(proposed_at)
    snapshot = validate_canonical_multi_outpoint_snapshot_v2(checked, observation, now=at)
    kind, basis_id, basis_sha = _basis_reference(checked, sponsor_basis)
    return CanonicalMultiOutpointAdmissionProposalV2(
        SCHEMA,
        VERSION,
        BOUNDARY,
        proposal_id,
        at,
        kind,
        basis_id,
        basis_sha,
        checked,
        canonical_multi_outpoint_mirror_v2_sha256(checked),
        snapshot,
        sponsor_import_reference_sha256,
        sponsor_key_proof_reference_sha256,
        child_acceptance_reference_sha256,
    )


def validate_canonical_multi_outpoint_admission_proposal_v2_sources(
    proposal: CanonicalMultiOutpointAdmissionProposalV2,
    *,
    mirror: CanonicalMultiOutpointMirrorV2,
    observation: CovenantRelationEvaluation,
    sponsor_basis: object,
    now: datetime,
) -> CanonicalMultiOutpointAdmissionProposalV2:
    if type(proposal) is not CanonicalMultiOutpointAdmissionProposalV2:
        _fail("proposal_type")
    checked = CanonicalMultiOutpointAdmissionProposalV2(
        *(getattr(proposal, f.name) for f in fields(CanonicalMultiOutpointAdmissionProposalV2))
    )
    current = _utc(now)
    actual_mirror = _bundle(mirror)
    observed = validate_canonical_multi_outpoint_snapshot_v2(actual_mirror, observation, now=current)
    kind, basis_id, basis_sha = _basis_reference(actual_mirror, sponsor_basis)
    if (
        checked.mirror_sha256 != canonical_multi_outpoint_mirror_v2_sha256(actual_mirror)
        or checked.snapshot != observed
        or (checked.basis_kind, checked.basis_record_id, checked.basis_record_sha256) != (
            kind, basis_id, basis_sha
        )
        or checked.proposed_at > current
    ):
        _fail("source_or_parent_mismatch")
    return checked


def issue_multi_outpoint_admission_challenge_v2(
    proposal: CanonicalMultiOutpointAdmissionProposalV2, *, now: datetime
) -> CanonicalAdmissionConsentChallengeV2:
    """UNTRUSTED in-memory challenge: requires future durable server issuance."""
    digest = canonical_multi_outpoint_admission_proposal_v2_sha256(proposal)
    at = _utc(now)
    evidence = proposal.mirror.script_evidence
    return CanonicalAdmissionConsentChallengeV2(
        CHALLENGE_SCHEMA,
        DOMAIN,
        NETWORK,
        digest,
        secrets.token_hex(32),
        evidence.sponsor_compressed_pubkey,
        evidence.child_compressed_pubkey,
        at,
        at + timedelta(seconds=TTL_SECONDS),
    )


def _signature(value: object) -> str:
    if type(value) is not str or len(value) != 88:
        _fail("signature_shape")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        _fail("signature_base64")
    if len(raw) != 65 or not 27 <= raw[0] <= 34 or base64.b64encode(raw).decode("ascii") != value:
        _fail("signature_compact")
    return value


def verify_multi_outpoint_admission_signatures_v2(
    proposal: CanonicalMultiOutpointAdmissionProposalV2,
    challenge: CanonicalAdmissionConsentChallengeV2,
    *,
    sponsor_signature: str,
    child_signature: str,
    rpc: object,
    now: datetime,
) -> CanonicalAdmissionConsentVerificationV2:
    """Verify both role-specific signatures. NOT issued, consumed or Full."""
    digest = canonical_multi_outpoint_admission_proposal_v2_sha256(proposal)
    if type(challenge) is not CanonicalAdmissionConsentChallengeV2:
        _fail("challenge_type")
    checked = CanonicalAdmissionConsentChallengeV2(
        *(getattr(challenge, f.name) for f in fields(CanonicalAdmissionConsentChallengeV2))
    )
    evidence = proposal.mirror.script_evidence
    at = _utc(now)
    if (
        checked.proposal_sha256 != digest
        or checked.sponsor_compressed_pubkey != evidence.sponsor_compressed_pubkey
        or checked.child_compressed_pubkey != evidence.child_compressed_pubkey
    ):
        _fail("signed_proposal_or_keys_mismatch")
    if not checked.issued_at <= at < checked.expires_at:
        _fail("expired_or_unissued")
    sponsor_signature = _signature(sponsor_signature)
    child_signature = _signature(child_signature)
    if sponsor_signature == child_signature:
        _fail("same_signature_for_two_roles")
    try:
        hashlib.new("ripemd160")
    except (TypeError, ValueError):
        raise CanonicalAdmissionConsentVerifierUnavailable("ripemd160_unavailable") from None
    method = getattr(rpc, "verifymessage", None)
    if not callable(method):
        raise CanonicalAdmissionConsentVerifierUnavailable("bitcoin_verifymessage_unavailable")
    sponsor_message = canonical_admission_consent_message_v2(checked, role="sponsor")
    child_message = canonical_admission_consent_message_v2(checked, role="child")
    for key, signature, message in (
        (evidence.sponsor_compressed_pubkey, sponsor_signature, sponsor_message),
        (evidence.child_compressed_pubkey, child_signature, child_message),
    ):
        try:
            valid = method(derive_legacy_address_from_pubkey(key), signature, message)
        except Exception:
            raise CanonicalAdmissionConsentVerifierUnavailable("bitcoin_verifymessage_failed") from None
        if type(valid) is not bool:
            raise CanonicalAdmissionConsentVerifierUnavailable("bitcoin_verifymessage_not_boolean")
        if not valid:
            _fail("signer_rejected")
    return CanonicalAdmissionConsentVerificationV2(
        VERIFICATION_SCHEMA,
        digest,
        hashlib.sha256(canonical_admission_consent_challenge_v2_bytes(checked)).hexdigest(),
        hashlib.sha256(sponsor_message.encode("ascii")).hexdigest(),
        hashlib.sha256(child_message.encode("ascii")).hexdigest(),
        hashlib.sha256(sponsor_signature.encode("ascii")).hexdigest(),
        hashlib.sha256(child_signature.encode("ascii")).hexdigest(),
        at,
    )
