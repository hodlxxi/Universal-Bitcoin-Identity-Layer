from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

import app.services.canonical_sponsor_lineage as lineage_module
from app.services.canonical_admission_edge import (
    AdmissionEdgeLifecycle,
    CanonicalAdmissionEdge,
    CanonicalAdmissionLeg,
    canonical_admission_edge_sha256,
)
from app.services.canonical_crt_authorization_policy import (
    CanonicalCrtAuthorizationClass,
    canonical_crt_authorization_evaluation_sha256,
)
from app.services.canonical_crt_authorization_proof import (
    CanonicalCrtAuthorizationProofBasis,
    CanonicalCrtAuthorizationProofConclusion,
    canonical_crt_authorization_proof_bytes,
    canonical_crt_authorization_proof_sha256,
    parse_canonical_crt_authorization_proof,
)
from app.services.canonical_crt_authorization_proof_publication import (
    reference_artifact_bytes,
)
import app.services.canonical_crt_authorization_proof_resolver as resolver_module
from app.services.canonical_crt_authorization_proof_resolver import (
    InvalidCanonicalCrtAuthorizationProofResolution,
    resolve_canonical_crt_authorization_proof_from_snapshot as resolve,
)
from app.services.canonical_crt_membership import (
    CanonicalCrtMembershipReason,
    canonical_crt_membership_evaluation_sha256,
)
from app.services.canonical_genesis_record import (
    CanonicalGenesisLifecycle,
    CanonicalGenesisRecord,
)
from app.services.canonical_sponsor_lineage import (
    CanonicalSponsorLineageEdgeEvidence,
    canonical_sponsor_lineage_evaluation_sha256,
    evaluate_canonical_sponsor_lineage,
)
from tests.unit.test_canonical_admission_edge import NOW, genesis
from tests.unit.test_canonical_genesis_record import record as genesis_record
from tests.unit.test_canonical_sponsor_lineage import lineage_fixture, with_edge_state

FULL_DIGESTS = {
    "genesis": "1e7508f12641f32e8813ddea1dd4b8bc9f0d5e862512773f36a4f414e7db4945",
    "depth3": "48f1d49935e2f5a580fab0c56d350cba036c859bdb726c38a259ef6011ec0b98",
}
MISSING_TARGET_DIGEST = "3b08da361c571121895f97a4c0f2f74995aa4a335b454066906dab044ed0823b"
PR615_TEMPORAL_MISMATCH_DIGEST = "cf8aff59d98a2c0ec7bf62253fcfb1d0cce264517476ddecb6297153080e401c"


def genesis_args(records=None):
    source = genesis()
    return dict(
        participant_id=source.genesis_participant_id,
        compressed_public_key=source.compressed_public_key,
        x_only_public_key=source.x_only_public_key,
        depth=0,
        evaluated_at=source.evaluated_at,
        genesis_records=(genesis_record(),) if records is None else records,
    )


def ordinary_args(items=None, **changes):
    full = lineage_fixture(3)
    target = full[-1].record
    values = dict(
        participant_id=target.child_participant_id,
        compressed_public_key=target.child_compressed_public_key,
        x_only_public_key=target.child_x_only_public_key,
        depth=target.child_depth,
        target_edge_id=target.edge_id,
        evaluated_at=NOW,
        genesis_records=(genesis_record(),),
        edge_evidence=full if items is None else items,
    )
    values.update(changes)
    return values


def _evidence_with_record(item, record):
    return CanonicalSponsorLineageEdgeEvidence(record, item.trusted_registration, item.observation_evaluation)


def _rebind_descendants(items, changed_position):
    for index in range(changed_position + 1, len(items)):
        items[index] = _evidence_with_record(
            items[index],
            replace(
                items[index].record,
                sponsor_basis_record_sha256=canonical_admission_edge_sha256(items[index - 1].record),
            ),
        )
    return tuple(items)


def _replace_role_in_legs(record, role, compressed_key):
    participant_id = compressed_key[2:]
    legs = []
    for leg in record.legs:
        changes = {}
        if leg.sender_participant_id == getattr(record, f"{role}_participant_id"):
            changes.update(
                sender_participant_id=participant_id,
                sender_compressed_public_key=compressed_key,
                sender_x_only_public_key=participant_id,
            )
        if leg.receiver_participant_id == getattr(record, f"{role}_participant_id"):
            changes.update(
                receiver_participant_id=participant_id,
                receiver_compressed_public_key=compressed_key,
                receiver_x_only_public_key=participant_id,
            )
        legs.append(replace(leg, **changes))
    return replace(
        record,
        **{
            f"{role}_participant_id": participant_id,
            f"{role}_compressed_public_key": compressed_key,
            f"{role}_x_only_public_key": participant_id,
            "legs": tuple(legs),
        },
    )


def _assert_structural_limited(proof, reason):
    membership = proof.source_authorization_evaluation.source_membership_evaluation
    assert proof.authorization_class is CanonicalCrtAuthorizationClass.LIMITED
    assert proof.current_full_membership_satisfied is False
    assert proof.membership_reason_code is reason
    assert proof.proof_basis is CanonicalCrtAuthorizationProofBasis.LINEAGE_STRUCTURE
    assert proof.controlling_depth is None
    assert proof.controlling_edge_id is None
    assert proof.source_authorization_evaluation_sha256 == (
        canonical_crt_authorization_evaluation_sha256(proof.source_authorization_evaluation)
    )
    assert proof.source_membership_evaluation_sha256 == (canonical_crt_membership_evaluation_sha256(membership))
    raw = canonical_crt_authorization_proof_bytes(proof)
    assert parse_canonical_crt_authorization_proof(raw) == proof
    return raw


def test_three_resolver_native_end_to_end_vectors_and_round_trip():
    genesis_proof = resolve(**genesis_args())
    depth3_proof = resolve(**ordinary_args())
    missing_proof = resolve(**ordinary_args(lineage_fixture(3)[:-1]))
    assert canonical_crt_authorization_proof_sha256(genesis_proof) == FULL_DIGESTS["genesis"]
    assert canonical_crt_authorization_proof_sha256(depth3_proof) == FULL_DIGESTS["depth3"]
    assert canonical_crt_authorization_proof_sha256(missing_proof) == MISSING_TARGET_DIGEST
    for proof in (genesis_proof, depth3_proof, missing_proof):
        raw = canonical_crt_authorization_proof_bytes(proof)
        assert parse_canonical_crt_authorization_proof(raw) == proof
        assert canonical_crt_authorization_proof_bytes(proof) == raw


def test_missing_target_vector_has_complete_authoritative_semantics_and_time_binding():
    proof = resolve(**ordinary_args(lineage_fixture(3)[:-1]))
    membership = proof.source_authorization_evaluation.source_membership_evaluation
    assert proof.authorization_class is CanonicalCrtAuthorizationClass.LIMITED
    assert proof.membership_reason_code is CanonicalCrtMembershipReason.MISSING_TARGET_EVIDENCE
    assert proof.proof_conclusion is CanonicalCrtAuthorizationProofConclusion.LIMITED_BY_UNKNOWN_MEMBERSHIP
    assert proof.proof_basis is CanonicalCrtAuthorizationProofBasis.TARGET_EVIDENCE
    assert proof.source_state == "unknown"
    assert proof.source_reason_code == "missing_target_evidence"
    assert proof.evaluated_at == NOW
    assert proof.source_authorization_evaluation.evaluated_at == NOW
    assert membership.evaluated_at == NOW


def test_pr615_temporal_mismatch_artifact_remains_exact_valid_and_distinct():
    expected_artifacts = {
        "depth-3-full": FULL_DIGESTS["depth3"],
        "e923-full": FULL_DIGESTS["genesis"],
        "unknown-ordinary-limited": PR615_TEMPORAL_MISMATCH_DIGEST,
    }
    for artifact_id, digest in expected_artifacts.items():
        artifact = reference_artifact_bytes(artifact_id)
        assert sha256(artifact).hexdigest() == digest
        assert canonical_crt_authorization_proof_bytes(parse_canonical_crt_authorization_proof(artifact)) == artifact
    raw = reference_artifact_bytes("unknown-ordinary-limited")
    assert sha256(raw).hexdigest() == PR615_TEMPORAL_MISMATCH_DIGEST
    proof = parse_canonical_crt_authorization_proof(raw)
    membership = proof.source_authorization_evaluation.source_membership_evaluation
    lineage = evaluate_canonical_sponsor_lineage(
        lineage_fixture(3)[-1].record.edge_id,
        edge_evidence=lineage_fixture(3),
        genesis_evaluation=genesis(),
        evaluated_at=NOW,
    )
    assert canonical_sponsor_lineage_evaluation_sha256(lineage) == membership.source_evaluation_sha256
    assert lineage.evaluated_at.isoformat() == "2026-07-26T12:00:00+00:00"
    assert membership.evaluated_at.isoformat() == "2027-07-26T12:00:00+00:00"
    assert membership.reason_code is CanonicalCrtMembershipReason.SOURCE_TIME_MISMATCH
    assert proof.proof_basis is CanonicalCrtAuthorizationProofBasis.SOURCE_BINDING
    shared_later = resolve(**ordinary_args(evaluated_at=membership.evaluated_at))
    assert shared_later.authorization_class is CanonicalCrtAuthorizationClass.FULL
    assert shared_later.membership_reason_code is CanonicalCrtMembershipReason.EXACT_PARTICIPANT_MEMBERSHIP_ACTIVE
    assert canonical_crt_authorization_proof_sha256(shared_later) != PR615_TEMPORAL_MISMATCH_DIGEST


def test_one_timestamp_is_passed_to_every_evaluator(monkeypatch):
    seen = []
    original_genesis = resolver_module.evaluate_canonical_genesis
    original_lineage = resolver_module.evaluate_canonical_sponsor_lineage
    original_membership = resolver_module.evaluate_canonical_crt_membership

    def genesis_wrapper(*args, **kwargs):
        seen.append(("genesis", kwargs["evaluated_at"]))
        return original_genesis(*args, **kwargs)

    def lineage_wrapper(*args, **kwargs):
        seen.append(("lineage", kwargs["evaluated_at"]))
        return original_lineage(*args, **kwargs)

    def membership_wrapper(*args, **kwargs):
        seen.append(("membership", kwargs["evaluated_at"]))
        return original_membership(*args, **kwargs)

    monkeypatch.setattr(resolver_module, "evaluate_canonical_genesis", genesis_wrapper)
    monkeypatch.setattr(resolver_module, "evaluate_canonical_sponsor_lineage", lineage_wrapper)
    monkeypatch.setattr(resolver_module, "evaluate_canonical_crt_membership", membership_wrapper)
    resolver_module.resolve_canonical_crt_authorization_proof_from_snapshot(**ordinary_args())
    assert seen == [("genesis", NOW), ("lineage", NOW), ("membership", NOW)]


@pytest.mark.parametrize(
    ("records", "reason"),
    (
        ((), CanonicalCrtMembershipReason.GENESIS_UNKNOWN),
        (
            (
                replace(
                    genesis_record(),
                    lifecycle_state=CanonicalGenesisLifecycle.PROPOSED,
                    effective_at=None,
                    lifecycle_changed_at=genesis_record().created_at,
                ),
            ),
            CanonicalCrtMembershipReason.GENESIS_PROVISIONAL,
        ),
        (
            (genesis_record(), replace(genesis_record(), record_id="e9230000-0000-4000-8000-000000000002")),
            CanonicalCrtMembershipReason.GENESIS_DISPUTED,
        ),
        (
            (
                replace(
                    genesis_record(),
                    lifecycle_state=CanonicalGenesisLifecycle.REVOKED,
                    contradiction_context=replace(
                        genesis_record().contradiction_context,
                        reason="terminal contradiction",
                        evidence_reference_ids=("canon_genesis_bootstrap_v1",),
                    ),
                ),
            ),
            CanonicalCrtMembershipReason.GENESIS_LINEAGE_INACTIVE,
        ),
    ),
)
def test_genesis_evidence_failures_are_limited(records, reason):
    proof = resolve(**genesis_args(records))
    assert proof.authorization_class is CanonicalCrtAuthorizationClass.LIMITED
    assert proof.membership_reason_code is reason


@pytest.mark.parametrize(
    ("position", "reason"),
    ((2, CanonicalCrtMembershipReason.ANCESTOR_EDGE_INACTIVE), (3, CanonicalCrtMembershipReason.TARGET_EDGE_INACTIVE)),
)
def test_genuine_inactive_snapshots_remain_limited(position, reason):
    items = list(lineage_fixture(3))
    items[position - 1] = with_edge_state(items[position - 1], AdmissionEdgeLifecycle.REVOKED)
    for index in range(position, len(items)):
        from app.services.canonical_admission_edge import (
            canonical_admission_edge_sha256 as recompute_admission_edge_sha256,
        )

        items[index] = replace(
            items[index],
            record=replace(
                items[index].record,
                sponsor_basis_record_sha256=recompute_admission_edge_sha256(items[index - 1].record),
            ),
        )
    proof = resolve(**ordinary_args(tuple(items)))
    assert proof.authorization_class is CanonicalCrtAuthorizationClass.LIMITED
    assert proof.membership_reason_code is reason


@pytest.mark.parametrize(
    ("position", "reason", "basis"),
    (
        (0, CanonicalCrtMembershipReason.ANCESTOR_DISPUTED, CanonicalCrtAuthorizationProofBasis.ANCESTOR_EDGE),
        (2, CanonicalCrtMembershipReason.TARGET_DISPUTED, CanonicalCrtAuthorizationProofBasis.TARGET_EDGE),
    ),
)
def test_target_and_ancestor_disputes_reach_exact_proof_basis(position, reason, basis):
    items = list(lineage_fixture(3))
    items[position] = with_edge_state(items[position], AdmissionEdgeLifecycle.DISPUTED)
    items = _rebind_descendants(items, position)
    proof = resolve(**ordinary_args(items))
    assert proof.authorization_class is CanonicalCrtAuthorizationClass.LIMITED
    assert proof.membership_reason_code is reason
    assert proof.controlling_depth == position + 1
    assert proof.controlling_edge_id == items[position].record.edge_id
    assert proof.proof_basis is basis
    membership = proof.source_authorization_evaluation.source_membership_evaluation
    assert proof.evaluated_at == proof.source_authorization_evaluation.evaluated_at
    assert proof.evaluated_at == membership.evaluated_at == NOW


def test_missing_immediate_parent_is_structural_limited_with_canonical_digests():
    items = lineage_fixture(3)
    proof = resolve(**ordinary_args((items[0], items[2])))
    _assert_structural_limited(proof, CanonicalCrtMembershipReason.MISSING_PARENT_EVIDENCE)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("digest", CanonicalCrtMembershipReason.PARENT_DIGEST_MISMATCH),
        ("identity", CanonicalCrtMembershipReason.PARENT_IDENTITY_MISMATCH),
        ("depth", CanonicalCrtMembershipReason.PARENT_DEPTH_MISMATCH),
    ),
)
def test_parent_binding_failures_are_exact_structural_proofs(mutation, reason, monkeypatch):
    items = list(lineage_fixture(3))
    target = items[2].record
    if mutation == "digest":
        target = replace(target, sponsor_basis_record_sha256="0" * 64)
    elif mutation == "identity":
        monkeypatch.setattr(CanonicalAdmissionLeg, "__post_init__", lambda self: None)
        monkeypatch.setattr(CanonicalAdmissionEdge, "__post_init__", lambda self: None)
        target = _replace_role_in_legs(
            target,
            "sponsor",
            "02" + "7a" * 32,
        )
    else:
        parent = items[0].record
        target = replace(
            target,
            sponsor_basis_record_id=parent.edge_id,
            sponsor_basis_record_sha256=canonical_admission_edge_sha256(parent),
        )
    items[2] = _evidence_with_record(items[2], target)
    proof = resolve(**ordinary_args(tuple(items)))
    _assert_structural_limited(proof, reason)


def test_parent_graph_or_profile_mismatch_is_exact_structural_proof(monkeypatch):
    # CanonicalAdmissionEdge fixes graph/profile by construction. Temporarily
    # bypass only that constructor guard to model a corrupted persisted object;
    # the authoritative lineage evaluator must still fail closed at its own
    # parent-binding boundary.
    monkeypatch.setattr(CanonicalAdmissionEdge, "__post_init__", lambda self: None)
    items = list(lineage_fixture(3))
    forged_parent = replace(items[1].record, graph_or_protocol_id="foreign.graph")
    target = replace(
        items[2].record,
        sponsor_basis_record_sha256=canonical_admission_edge_sha256(forged_parent),
    )
    items[1] = _evidence_with_record(items[1], forged_parent)
    items[2] = _evidence_with_record(items[2], target)
    proof = resolve(**ordinary_args(tuple(items)))
    _assert_structural_limited(proof, CanonicalCrtMembershipReason.PARENT_GRAPH_OR_PROFILE_MISMATCH)


def test_duplicate_edge_id_is_exact_deterministic_structural_proof():
    items = lineage_fixture(3)
    args = ordinary_args(items + (items[0],))
    first = resolve(**args)
    second = resolve(**args)
    assert _assert_structural_limited(
        first, CanonicalCrtMembershipReason.DUPLICATE_EDGE_ID
    ) == _assert_structural_limited(second, CanonicalCrtMembershipReason.DUPLICATE_EDGE_ID)


def test_duplicate_edge_digest_is_exact_deterministic_structural_proof(monkeypatch):
    items = lineage_fixture(3)
    original = lineage_module.canonical_admission_edge_sha256
    collision = original(items[0].record)

    def collision_sha256(record):
        if record.edge_id in {items[0].record.edge_id, items[1].record.edge_id}:
            return collision
        return original(record)

    monkeypatch.setattr(lineage_module, "canonical_admission_edge_sha256", collision_sha256)
    first = resolve(**ordinary_args(items))
    second = resolve(**ordinary_args(items))
    assert _assert_structural_limited(
        first, CanonicalCrtMembershipReason.DUPLICATE_EDGE_DIGEST
    ) == _assert_structural_limited(second, CanonicalCrtMembershipReason.DUPLICATE_EDGE_DIGEST)


def test_duplicate_child_identity_is_exact_deterministic_structural_proof(monkeypatch):
    monkeypatch.setattr(CanonicalAdmissionLeg, "__post_init__", lambda self: None)
    monkeypatch.setattr(CanonicalAdmissionEdge, "__post_init__", lambda self: None)
    items = list(lineage_fixture(3))
    duplicate_key = items[0].record.child_compressed_public_key
    items[2] = _evidence_with_record(items[2], _replace_role_in_legs(items[2].record, "child", duplicate_key))
    target = items[2].record
    changes = dict(
        participant_id=target.child_participant_id,
        compressed_public_key=target.child_compressed_public_key,
        x_only_public_key=target.child_x_only_public_key,
    )
    first = resolve(**ordinary_args(tuple(items), **changes))
    second = resolve(**ordinary_args(tuple(items), **changes))
    assert _assert_structural_limited(
        first, CanonicalCrtMembershipReason.DUPLICATE_CHILD_IDENTITY
    ) == _assert_structural_limited(second, CanonicalCrtMembershipReason.DUPLICATE_CHILD_IDENTITY)


def test_cycle_is_exact_deterministic_structural_proof(monkeypatch):
    items = lineage_fixture(3)
    target_id = items[2].record.edge_id
    original_evaluator = resolver_module.evaluate_canonical_sponsor_lineage

    # Strict positive depths make a canonical cycle algebraically impossible,
    # but PR6.11 retains a defensive visited-edge guard for corrupted traversal
    # state. Seed only that third set construction, after the two duplicate
    # prechecks, while keeping every supplied evidence object canonical.
    def cycle_evaluator(*args, **kwargs):
        constructions = 0

        class CycleSet(set):
            def __init__(self, values=()):
                nonlocal constructions
                constructions += 1
                super().__init__(values)
                if constructions == 3:
                    self.add(target_id)

        lineage_module.set = CycleSet
        try:
            return original_evaluator(*args, **kwargs)
        finally:
            del lineage_module.set

    monkeypatch.setattr(resolver_module, "evaluate_canonical_sponsor_lineage", cycle_evaluator)
    first = resolve(**ordinary_args(items))
    second = resolve(**ordinary_args(items))
    assert _assert_structural_limited(first, CanonicalCrtMembershipReason.CYCLE_DETECTED) == _assert_structural_limited(
        second, CanonicalCrtMembershipReason.CYCLE_DETECTED
    )


def test_extraneous_evidence_is_exact_deterministic_structural_proof():
    items = lineage_fixture(3)
    extra = _evidence_with_record(
        items[0],
        replace(
            items[0].record,
            edge_id="00000000-0000-4000-8000-000000000088",
        ),
    )
    first = resolve(**ordinary_args(items + (extra,)))
    second = resolve(**ordinary_args(items + (extra,)))
    assert _assert_structural_limited(
        first, CanonicalCrtMembershipReason.EXTRANEOUS_EDGE_EVIDENCE
    ) == _assert_structural_limited(second, CanonicalCrtMembershipReason.EXTRANEOUS_EDGE_EVIDENCE)


@pytest.mark.parametrize("bad_depth", (True, 1.0, -1, 2289))
def test_invalid_depth_primitives_raise(bad_depth):
    with pytest.raises(InvalidCanonicalCrtAuthorizationProofResolution):
        resolve(**ordinary_args(depth=bad_depth))


@pytest.mark.parametrize(
    "changes",
    (
        {"compressed_public_key": "02" + "a" * 63},
        {"x_only_public_key": "a" * 63},
        {
            "compressed_public_key": "02" + "a" * 64,
            "x_only_public_key": "b" * 64,
            "participant_id": "b" * 64,
        },
        {"participant_id": 7},
        {"participant_id": "a" * 64},
        {"target_edge_id": "not-a-uuid"},
        {"target_edge_id": "00000000-0000-4000-8000-0000000000AA"},
        {"target_edge_id": None},
    ),
)
def test_invalid_ordinary_request_identity_and_target_matrix(changes):
    with pytest.raises(InvalidCanonicalCrtAuthorizationProofResolution):
        resolve(**ordinary_args(**changes))


def test_invalid_genesis_mode_matrix():
    depth_args = genesis_args()
    depth_args["depth"] = 1
    with pytest.raises(InvalidCanonicalCrtAuthorizationProofResolution):
        resolve(**depth_args)
    target_args = genesis_args()
    target_args["target_edge_id"] = "00000000-0000-4000-8000-000000000042"
    with pytest.raises(InvalidCanonicalCrtAuthorizationProofResolution):
        resolve(**target_args)
    evidence_args = genesis_args()
    evidence_args["edge_evidence"] = lineage_fixture(1)
    with pytest.raises(InvalidCanonicalCrtAuthorizationProofResolution):
        resolve(**evidence_args)


@pytest.mark.parametrize(
    "timestamp",
    (
        datetime(2026, 1, 1),
        datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1))),
        datetime(2026, 1, 1, 0, 0, 0, 1, tzinfo=timezone.utc),
    ),
)
def test_noncanonical_timestamps_raise(timestamp):
    args = genesis_args()
    args["evaluated_at"] = timestamp
    with pytest.raises(InvalidCanonicalCrtAuthorizationProofResolution):
        resolve(**args)


@pytest.mark.parametrize("field,value", (("genesis_records", []), ("edge_evidence", [])))
def test_exact_tuple_requirements(field, value):
    args = ordinary_args()
    args[field] = value
    with pytest.raises(InvalidCanonicalCrtAuthorizationProofResolution):
        resolve(**args)


def test_exact_source_types_and_mixed_modes_raise():
    class GenesisSubclass(CanonicalGenesisRecord):
        pass

    class EvidenceSubclass(CanonicalSponsorLineageEdgeEvidence):
        pass

    with pytest.raises(InvalidCanonicalCrtAuthorizationProofResolution):
        resolve(
            **genesis_args(
                (
                    GenesisSubclass(
                        *(getattr(genesis_record(), field) for field in CanonicalGenesisRecord.__dataclass_fields__)
                    ),
                )
            )
        )
    args = ordinary_args()
    first = args["edge_evidence"][0]
    args["edge_evidence"] = (EvidenceSubclass(first.record, first.trusted_registration, first.observation_evaluation),)
    with pytest.raises(InvalidCanonicalCrtAuthorizationProofResolution):
        resolve(**args)
    with pytest.raises(InvalidCanonicalCrtAuthorizationProofResolution):
        resolve(**genesis_args(), edge_evidence=lineage_fixture(1))


def test_valid_request_with_different_subject_evidence_fails_closed():
    items = lineage_fixture(3)
    before = repr(items)
    requested_key = "02" + "a1" * 32
    proof = resolve(
        **ordinary_args(
            items,
            participant_id=requested_key[2:],
            compressed_public_key=requested_key,
            x_only_public_key=requested_key[2:],
        )
    )
    assert proof.authorization_class is CanonicalCrtAuthorizationClass.LIMITED
    assert proof.membership_reason_code is CanonicalCrtMembershipReason.SOURCE_SUBJECT_MISMATCH
    assert proof.proof_basis is CanonicalCrtAuthorizationProofBasis.SOURCE_BINDING
    assert proof.current_full_membership_satisfied is False
    assert repr(items) == before


def test_malformed_exact_evidence_fails_closed_and_inputs_are_not_mutated():
    items = lineage_fixture(3)
    malformed = replace(items[0])
    object.__setattr__(malformed, "record", object())
    proof = resolve(**ordinary_args((malformed,) + items[1:]))
    assert proof.authorization_class is CanonicalCrtAuthorizationClass.LIMITED
    assert proof.source_reason_code == "malformed_or_untrusted_input"
    before = repr(items)
    resolve(**ordinary_args(items))
    assert repr(items) == before


def test_order_determinism_and_repeat_byte_identity():
    items = lineage_fixture(3)
    first = resolve(**ordinary_args(items))
    second = resolve(**ordinary_args(tuple(reversed(items))))
    third = resolve(**ordinary_args(items))
    assert canonical_crt_authorization_proof_bytes(first) == canonical_crt_authorization_proof_bytes(second)
    assert canonical_crt_authorization_proof_bytes(first) == canonical_crt_authorization_proof_bytes(third)
