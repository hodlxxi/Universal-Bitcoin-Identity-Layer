"""Replay-safe bootstrap engine for the pinned E923 canonical CRT runtime chain."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path

from app.services.canonical_covenant_funding_set import (
    CanonicalCovenantFundingSet,
    canonical_covenant_funding_set_bytes,
    canonical_covenant_funding_set_sha256,
    parse_canonical_covenant_funding_set,
    validate_funding_set_registration,
)
from app.services.canonical_genesis_record import (
    CanonicalGenesisRecord,
    canonical_genesis_record_bytes,
    canonical_genesis_record_sha256,
    evaluate_canonical_genesis,
    parse_canonical_genesis_record,
)
from app.services.canonical_root_registration_binding import (
    CanonicalRootRegistrationBinding,
    canonical_root_registration_binding_bytes,
    canonical_root_registration_binding_sha256,
    parse_canonical_root_registration_binding,
    validate_binding_sources,
)
from app.services.covenant_relation import CovenantDirection
from app.services.mirrored_covenant_pair import (
    CovenantDeltaProfile,
    mirrored_covenant_pair_sha256,
    validate_mirrored_covenant_pair,
)
from app.services.trusted_covenant_registration import (
    RegisteredCovenantOutpoint,
    TrustedCovenantRegistration,
    TrustedCovenantRegistrationLifecycle,
    canonical_trusted_registration_bytes,
    create_trusted_covenant_registration,
    trusted_registration_sha256,
)

BOOTSTRAP_SCHEMA = "hodlxxi.canonical_crt_runtime_bootstrap.v1"
MANIFEST_SCHEMA = "hodlxxi.canonical_crt_runtime_bootstrap_manifest.v1"
MANIFEST_RELATIVE_PATH = "docs/data/e923_canonical_crt_runtime_bootstrap_v1.json"
GENESIS_RELATIVE_PATH = "docs/data/e923_canonical_genesis_record_v1.json"
EXPECTED_SOURCE_RELEASE_SHA = "fa87d2a8561df513f7ae243485869d2fc0ef9098"
EXPECTED_MANIFEST_FILE_SHA256 = "369e6cd1ab5c61b8771e53da6e9cea25d55d4854393ed4e74131e61ad1c8642a"
FAILURE_MESSAGE = "canonical CRT runtime bootstrap unavailable"
AMBIGUOUS_MESSAGE = FAILURE_MESSAGE + "; inspect canonical bootstrap state before any manual retry"

_STEP_NAMES = ("genesis", "trusted_registration", "root_registration_binding", "funding_set")
_TOP_LEVEL_FIELDS = {
    "bootstrap_policy",
    "funding_set",
    "genesis",
    "graph_or_protocol_id",
    "root_registration_binding",
    "schema",
    "source_release_sha",
    "subject_xonly_pubkey",
    "trusted_registration",
}
_POLICY_FIELDS = {
    "installs_scheduler",
    "performs_bitcoin_observation",
    "registration_anchor_selection",
    "registration_anchor_selection_note",
    "writes_entitlement_evidence",
}


class BootstrapMode(Enum):
    DRY_RUN = "dry_run"
    COMMIT = "commit"


class BootstrapUnavailable(RuntimeError):
    def __init__(self, *, commit_boundary: bool = False) -> None:
        super().__init__(AMBIGUOUS_MESSAGE if commit_boundary else FAILURE_MESSAGE)


@dataclass(frozen=True, slots=True)
class BootstrapBundle:
    manifest_sha256: str
    graph_or_protocol_id: str
    subject_xonly_pubkey: str
    genesis: CanonicalGenesisRecord
    trusted_registration: TrustedCovenantRegistration
    root_registration_binding: CanonicalRootRegistrationBinding
    funding_set: CanonicalCovenantFundingSet


def _strict_json(raw: str) -> dict:
    if type(raw) is not str:
        raise ValueError()

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    def reject(_):
        raise ValueError()

    value = json.loads(raw, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
    if type(value) is not dict:
        raise ValueError()
    return value


def _compact(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _whole_second(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError()
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _parse_time(value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ValueError()
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError()
    return parsed


def load_bootstrap_bundle(repository_root: Path | str, *, evaluated_at: datetime) -> BootstrapBundle:
    """Load and completely revalidate the exact source-controlled bootstrap manifest."""
    try:
        root = Path(repository_root)
        if not root.is_absolute():
            raise ValueError()
        raw_bytes = (root / MANIFEST_RELATIVE_PATH).read_bytes()
        if sha256(raw_bytes).hexdigest() != EXPECTED_MANIFEST_FILE_SHA256:
            raise ValueError()
        try:
            manifest = _strict_json(raw_bytes.decode("ascii"))
        except UnicodeDecodeError:
            raise ValueError() from None
        if set(manifest) != _TOP_LEVEL_FIELDS:
            raise ValueError()
        if manifest["schema"] != MANIFEST_SCHEMA or manifest["source_release_sha"] != EXPECTED_SOURCE_RELEASE_SHA:
            raise ValueError()

        policy = manifest["bootstrap_policy"]
        if type(policy) is not dict or set(policy) != _POLICY_FIELDS:
            raise ValueError()
        if (
            policy["registration_anchor_selection"] != "exact_manifest_pinned"
            or type(policy["registration_anchor_selection_note"]) is not str
            or not policy["registration_anchor_selection_note"]
            or policy["writes_entitlement_evidence"] is not False
            or policy["performs_bitcoin_observation"] is not False
            or policy["installs_scheduler"] is not False
        ):
            raise ValueError()

        genesis_meta = manifest["genesis"]
        if type(genesis_meta) is not dict or set(genesis_meta) != {"canonical_record_sha256", "source_path"}:
            raise ValueError()
        if genesis_meta["source_path"] != GENESIS_RELATIVE_PATH:
            raise ValueError()
        genesis = parse_canonical_genesis_record((root / GENESIS_RELATIVE_PATH).read_text())
        if canonical_genesis_record_sha256(genesis) != genesis_meta["canonical_record_sha256"]:
            raise ValueError()

        trusted_meta = manifest["trusted_registration"]
        if type(trusted_meta) is not dict or set(trusted_meta) != {
            "canonical_record",
            "canonical_record_sha256",
            "mirrored_pair",
        }:
            raise ValueError()
        record = trusted_meta["canonical_record"]
        pair_meta = trusted_meta["mirrored_pair"]
        if (
            type(record) is not dict
            or type(pair_meta) is not dict
            or set(pair_meta)
            != {
                "earlier_leg_script_hex",
                "later_leg_script_hex",
                "pair_sha256",
            }
        ):
            raise ValueError()
        if record.get("delta_profile") != CovenantDeltaProfile.LEGACY_777.value:
            raise ValueError()
        pair = validate_mirrored_covenant_pair(
            pair_meta["earlier_leg_script_hex"],
            pair_meta["later_leg_script_hex"],
            subject_pubkey=record["subject_pubkey"],
            allowed_delta_profiles=(CovenantDeltaProfile.LEGACY_777,),
        )
        if (
            mirrored_covenant_pair_sha256(pair) != pair_meta["pair_sha256"]
            or pair_meta["pair_sha256"] != record["pair_sha256"]
        ):
            raise ValueError()
        raw_outpoints = record.get("outpoints")
        if type(raw_outpoints) is not list:
            raise ValueError()
        anchors = tuple(
            RegisteredCovenantOutpoint(
                CovenantDirection(item["direction"]),
                item["txid"],
                item["vout"],
                item["amount_sats"],
                item["witness_script_sha256"],
                item["descriptor_sha256"],
            )
            for item in raw_outpoints
        )
        trusted = create_trusted_covenant_registration(
            pair,
            anchors,
            registration_id=record["registration_id"],
            lifecycle_state=TrustedCovenantRegistrationLifecycle(record["lifecycle_state"]),
            registered_at=_parse_time(record["registered_at"]),
            lifecycle_changed_at=_parse_time(record["lifecycle_changed_at"]),
            superseded_by_registration_id=record["superseded_by_registration_id"],
        )
        if trusted_registration_sha256(trusted) != trusted_meta["canonical_record_sha256"]:
            raise ValueError()
        if _strict_json(canonical_trusted_registration_bytes(trusted).decode("ascii")) != record:
            raise ValueError()

        binding_meta = manifest["root_registration_binding"]
        if type(binding_meta) is not dict or set(binding_meta) != {"canonical_record", "canonical_record_sha256"}:
            raise ValueError()
        binding = parse_canonical_root_registration_binding(binding_meta["canonical_record"])
        if canonical_root_registration_binding_sha256(binding) != binding_meta["canonical_record_sha256"]:
            raise ValueError()

        funding_meta = manifest["funding_set"]
        if type(funding_meta) is not dict or set(funding_meta) != {"canonical_record", "canonical_record_sha256"}:
            raise ValueError()
        funding = parse_canonical_covenant_funding_set(_compact(funding_meta["canonical_record"]))
        funding = validate_funding_set_registration(funding, trusted)
        if canonical_covenant_funding_set_sha256(funding) != funding_meta["canonical_record_sha256"]:
            raise ValueError()

        graph = manifest["graph_or_protocol_id"]
        subject = manifest["subject_xonly_pubkey"]
        if (
            graph != genesis.graph_or_protocol_id
            or subject != genesis.identity_anchor.x_only_public_key
            or subject != trusted.subject_xonly_pubkey
            or graph != binding.graph_or_protocol_id
            or subject != binding.root_x_only_public_key
            or subject != funding.subject_xonly_pubkey
            or binding.trusted_registration_id != trusted.registration_id
            or funding.trusted_registration_id != trusted.registration_id
        ):
            raise ValueError()
        evaluation = evaluate_canonical_genesis(
            (genesis,), graph_or_protocol_id=graph, evaluated_at=_whole_second(evaluated_at)
        )
        validate_binding_sources(
            binding,
            genesis_evaluation=evaluation,
            trusted_registration=trusted,
        )
        return BootstrapBundle(
            EXPECTED_MANIFEST_FILE_SHA256,
            graph,
            subject,
            genesis,
            trusted,
            binding,
            funding,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise BootstrapUnavailable() from None


def _same_genesis(existing, expected) -> bool:
    try:
        return type(existing) is CanonicalGenesisRecord and canonical_genesis_record_bytes(
            existing
        ) == canonical_genesis_record_bytes(expected)
    except Exception:
        return False


def _same_trusted(existing, expected) -> bool:
    try:
        return (
            type(existing) is TrustedCovenantRegistration
            and canonical_trusted_registration_bytes(existing) == canonical_trusted_registration_bytes(expected)
            and mirrored_covenant_pair_sha256(existing.mirrored_pair)
            == mirrored_covenant_pair_sha256(expected.mirrored_pair)
            and existing.mirrored_pair.earlier_leg.raw_script_hex == expected.mirrored_pair.earlier_leg.raw_script_hex
            and existing.mirrored_pair.later_leg.raw_script_hex == expected.mirrored_pair.later_leg.raw_script_hex
        )
    except Exception:
        return False


def _same_binding(existing, expected) -> bool:
    try:
        return type(existing) is CanonicalRootRegistrationBinding and canonical_root_registration_binding_bytes(
            existing
        ) == canonical_root_registration_binding_bytes(expected)
    except Exception:
        return False


def _same_funding(existing, expected) -> bool:
    try:
        return type(existing) is CanonicalCovenantFundingSet and canonical_covenant_funding_set_bytes(
            existing
        ) == canonical_covenant_funding_set_bytes(expected)
    except Exception:
        return False


def _state(
    bundle: BootstrapBundle,
    *,
    genesis_repository,
    trusted_registration_repository,
    root_registration_binding_repository,
    funding_set_repository,
) -> dict[str, str]:
    try:
        genesis_rows = genesis_repository.list_for_graph(bundle.graph_or_protocol_id)
        if any(item.record_id != bundle.genesis.record_id for item in genesis_rows):
            raise ValueError()
        binding_rows = root_registration_binding_repository.list_for_root(
            bundle.graph_or_protocol_id, bundle.subject_xonly_pubkey
        )
        if any(item.binding_id != bundle.root_registration_binding.binding_id for item in binding_rows):
            raise ValueError()
        funding_rows = funding_set_repository.list_by_registration(bundle.trusted_registration.registration_id)
        if any(item.funding_set_id != bundle.funding_set.funding_set_id for item in funding_rows):
            raise ValueError()
        current = {
            "genesis": genesis_repository.get(bundle.genesis.record_id),
            "trusted_registration": trusted_registration_repository.get(bundle.trusted_registration.registration_id),
            "root_registration_binding": root_registration_binding_repository.get(
                bundle.root_registration_binding.binding_id
            ),
            "funding_set": funding_set_repository.get(bundle.funding_set.funding_set_id),
        }
        expected = {
            "genesis": bundle.genesis,
            "trusted_registration": bundle.trusted_registration,
            "root_registration_binding": bundle.root_registration_binding,
            "funding_set": bundle.funding_set,
        }
        comparators = {
            "genesis": _same_genesis,
            "trusted_registration": _same_trusted,
            "root_registration_binding": _same_binding,
            "funding_set": _same_funding,
        }
        state = {}
        for name in _STEP_NAMES:
            value = current[name]
            if value is None:
                state[name] = "append"
            elif comparators[name](value, expected[name]):
                state[name] = "unchanged"
            else:
                raise ValueError()
        return state
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise BootstrapUnavailable() from None


def _result(
    bundle: BootstrapBundle, mode: BootstrapMode, actions: dict[str, str], *, append_performed: bool
) -> dict[str, object]:
    if set(actions) != set(_STEP_NAMES):
        raise ValueError()
    outcome = "preview" if mode is BootstrapMode.DRY_RUN else ("applied" if append_performed else "unchanged")
    return {
        "schema": BOOTSTRAP_SCHEMA,
        "mode": mode.value,
        "outcome": outcome,
        "graph_or_protocol_id": bundle.graph_or_protocol_id,
        "subject_xonly_pubkey": bundle.subject_xonly_pubkey,
        "manifest_sha256": bundle.manifest_sha256,
        "actions": {name: actions[name] for name in _STEP_NAMES},
        "append_performed": append_performed,
        "appended_count": sum(1 for value in actions.values() if value == "appended"),
        "writes_entitlement_evidence": False,
        "performs_bitcoin_observation": False,
        "installs_scheduler": False,
    }


def execute_bootstrap(
    bundle: BootstrapBundle,
    *,
    mode: BootstrapMode,
    evaluated_at: datetime,
    genesis_repository,
    trusted_registration_repository,
    root_registration_binding_repository,
    funding_set_repository,
) -> dict[str, object]:
    """Preview or apply the exact chain. Each append is followed by exact readback."""
    commit = mode is BootstrapMode.COMMIT
    try:
        if type(bundle) is not BootstrapBundle or type(mode) is not BootstrapMode:
            raise ValueError()
        evaluated_at = _whole_second(evaluated_at)
        state = _state(
            bundle,
            genesis_repository=genesis_repository,
            trusted_registration_repository=trusted_registration_repository,
            root_registration_binding_repository=root_registration_binding_repository,
            funding_set_repository=funding_set_repository,
        )
        if not commit:
            return _result(
                bundle,
                mode,
                {name: ("would_append" if state[name] == "append" else "unchanged") for name in _STEP_NAMES},
                append_performed=False,
            )

        actions: dict[str, str] = {}
        if state["genesis"] == "append":
            genesis_repository.append(bundle.genesis)
            if not _same_genesis(genesis_repository.get(bundle.genesis.record_id), bundle.genesis):
                raise ValueError()
            actions["genesis"] = "appended"
        else:
            actions["genesis"] = "unchanged"

        if state["trusted_registration"] == "append":
            trusted_registration_repository.append(bundle.trusted_registration)
            if not _same_trusted(
                trusted_registration_repository.get(bundle.trusted_registration.registration_id),
                bundle.trusted_registration,
            ):
                raise ValueError()
            actions["trusted_registration"] = "appended"
        else:
            actions["trusted_registration"] = "unchanged"

        if state["root_registration_binding"] == "append":
            root_registration_binding_repository.append(bundle.root_registration_binding, evaluated_at=evaluated_at)
            if not _same_binding(
                root_registration_binding_repository.get(bundle.root_registration_binding.binding_id),
                bundle.root_registration_binding,
            ):
                raise ValueError()
            actions["root_registration_binding"] = "appended"
        else:
            actions["root_registration_binding"] = "unchanged"

        if state["funding_set"] == "append":
            funding_set_repository.append(bundle.funding_set)
            if not _same_funding(funding_set_repository.get(bundle.funding_set.funding_set_id), bundle.funding_set):
                raise ValueError()
            actions["funding_set"] = "appended"
        else:
            actions["funding_set"] = "unchanged"

        final_state = _state(
            bundle,
            genesis_repository=genesis_repository,
            trusted_registration_repository=trusted_registration_repository,
            root_registration_binding_repository=root_registration_binding_repository,
            funding_set_repository=funding_set_repository,
        )
        if any(final_state[name] != "unchanged" for name in _STEP_NAMES):
            raise ValueError()
        return _result(bundle, mode, actions, append_performed=any(value == "appended" for value in actions.values()))
    except (KeyboardInterrupt, SystemExit):
        raise
    except BootstrapUnavailable:
        if commit:
            raise BootstrapUnavailable(commit_boundary=True) from None
        raise
    except Exception:
        raise BootstrapUnavailable(commit_boundary=commit) from None
