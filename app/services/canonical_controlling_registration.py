"""Fail-closed selection of one controlling trusted registration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re

from app.services.canonical_admission_edge import (
    AdmissionEdgeLifecycle,
    CanonicalAdmissionEdge,
    canonical_admission_edge_bytes,
    canonical_admission_edge_sha256,
    parse_canonical_admission_edge,
)
from app.services.canonical_genesis_record import (
    CanonicalGenesisEvaluationState,
    evaluate_canonical_genesis,
)
from app.services.canonical_root_registration_binding import (
    CanonicalRootRegistrationBinding,
    RootRegistrationBindingLifecycle,
    canonical_root_registration_binding_bytes,
    canonical_root_registration_binding_sha256,
    parse_canonical_root_registration_binding,
)
from app.services.trusted_covenant_registration import (
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    canonical_trusted_registration_bytes,
    trusted_registration_sha256,
)

_XONLY = re.compile(r"^[0-9a-f]{64}$")


class ControllingRegistrationUnavailable(RuntimeError):
    """The controlling registration cannot be resolved safely."""

    def __init__(self) -> None:
        super().__init__("controlling registration unavailable")


class ControllingRegistrationSelectionSource(Enum):
    CANONICAL_ADMISSION_EDGE = "canonical_admission_edge"
    CANONICAL_ROOT_REGISTRATION_BINDING = "canonical_root_registration_binding"


@dataclass(frozen=True, slots=True)
class ControllingRegistrationSelection:
    graph_or_protocol_id: str
    subject_xonly_pubkey: str
    selection_source: ControllingRegistrationSelectionSource
    selector_record_id: str
    selector_record_sha256: str
    registration: TrustedCovenantRegistration


def _registration(value: object) -> TrustedCovenantRegistration:
    if type(value) is not TrustedCovenantRegistration:
        raise ValueError()
    canonical_trusted_registration_bytes(value)
    return TrustedCovenantRegistration(
        *(getattr(value, field) for field in TrustedCovenantRegistration.__dataclass_fields__)
    )


def resolve_controlling_registration(
    graph_or_protocol_id: str,
    subject_xonly_pubkey: str,
    *,
    evaluated_at: datetime,
    genesis_repository,
    admission_edge_repository,
    root_registration_binding_repository,
    trusted_registration_repository,
) -> ControllingRegistrationSelection:
    """Resolve an exact pointer-selected registration without granting authority."""
    try:
        if (
            type(graph_or_protocol_id) is not str
            or not graph_or_protocol_id
            or graph_or_protocol_id != graph_or_protocol_id.strip()
            or type(subject_xonly_pubkey) is not str
            or _XONLY.fullmatch(subject_xonly_pubkey) is None
        ):
            raise ValueError()

        genesis = evaluate_canonical_genesis(
            genesis_repository.list_for_graph(graph_or_protocol_id),
            graph_or_protocol_id=graph_or_protocol_id,
            evaluated_at=evaluated_at,
        )
        if (
            genesis.state is not CanonicalGenesisEvaluationState.GENESIS_ACTIVE
            or genesis.selected_effective_record_id is None
            or genesis.selected_effective_record_sha256 is None
            or genesis.graph_or_protocol_id != graph_or_protocol_id
        ):
            raise ValueError()

        if subject_xonly_pubkey == genesis.x_only_public_key:
            raw_selector = root_registration_binding_repository.resolve_effective(
                graph_or_protocol_id,
                subject_xonly_pubkey,
                evaluated_at=evaluated_at,
            )
            if type(raw_selector) is not CanonicalRootRegistrationBinding:
                raise ValueError()
            selector = parse_canonical_root_registration_binding(
                canonical_root_registration_binding_bytes(raw_selector)
            )
            if (
                selector.lifecycle_state is not RootRegistrationBindingLifecycle.EFFECTIVE
                or selector.graph_or_protocol_id != graph_or_protocol_id
                or selector.root_x_only_public_key != subject_xonly_pubkey
            ):
                raise ValueError()
            source = ControllingRegistrationSelectionSource.CANONICAL_ROOT_REGISTRATION_BINDING
            selector_id = selector.binding_id
            selector_digest = canonical_root_registration_binding_sha256(selector)
        else:
            raw_selector = admission_edge_repository.get_effective_for_child(
                graph_or_protocol_id,
                subject_xonly_pubkey,
            )
            if type(raw_selector) is not CanonicalAdmissionEdge:
                raise ValueError()
            selector = parse_canonical_admission_edge(canonical_admission_edge_bytes(raw_selector))
            if (
                selector.lifecycle_state is not AdmissionEdgeLifecycle.EFFECTIVE
                or selector.graph_or_protocol_id != graph_or_protocol_id
                or selector.child_x_only_public_key != subject_xonly_pubkey
            ):
                raise ValueError()
            source = ControllingRegistrationSelectionSource.CANONICAL_ADMISSION_EDGE
            selector_id = selector.edge_id
            selector_digest = canonical_admission_edge_sha256(selector)

        registration = _registration(trusted_registration_repository.get(selector.trusted_registration_id))
        if (
            registration.registration_id != selector.trusted_registration_id
            or registration.lifecycle_state is not TrustedCovenantRegistrationLifecycle.ACTIVE
            or trusted_registration_sha256(registration) != selector.trusted_registration_sha256
            or registration.subject_xonly_pubkey != subject_xonly_pubkey
        ):
            raise ValueError()
        return ControllingRegistrationSelection(
            graph_or_protocol_id,
            subject_xonly_pubkey,
            source,
            selector_id,
            selector_digest,
            registration,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise ControllingRegistrationUnavailable() from None
