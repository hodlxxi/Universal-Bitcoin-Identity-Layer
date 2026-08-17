"""One-shot operator boundary for canonical-root entitlement refreshes."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Callable, Sequence
import uuid

from app.services.action_authorization import IdentityClass
from app.services.canonical_root_entitlement_refresh import (
    REFRESH_CONTRACT_VERSION,
    CanonicalRootEntitlementRefreshMode,
    CanonicalRootEntitlementRefreshOutcome,
    CanonicalRootEntitlementRefreshResult,
)
from app.services.canonical_root_entitlement_policy import CanonicalRootEntitlementDecision
from app.services.current_entitlement_evidence import CurrentEntitlementEvidenceRecord
from app.services.covenant_relation import MAX_BITCOIN_SATS
from app.services.edge_local_covenant_observation import EdgeLocalCovenantRelationResult

RUNNER_SCHEMA = "hodlxxi.canonical_root_entitlement_refresh_runner.v1"
FAILURE_MESSAGE = "canonical root entitlement refresh runner unavailable"
AMBIGUOUS_MESSAGE = FAILURE_MESSAGE + "; inspect current evidence before any manual retry"
_SUBJECT = re.compile(r"[0-9a-f]{64}\Z")
_MAX_GRAPH_LENGTH = 256


class CanonicalRootEntitlementRefreshRunnerUnavailable(RuntimeError):
    def __init__(self, *, commit_boundary: bool = False) -> None:
        super().__init__(AMBIGUOUS_MESSAGE if commit_boundary else FAILURE_MESSAGE)


@dataclass(frozen=True, slots=True)
class RunnerRequest:
    graph_or_protocol_id: str
    subject_xonly_pubkey: str
    mode: CanonicalRootEntitlementRefreshMode
    lock_directory: str | None


def parse_runner_argv(argv: Sequence[str]) -> RunnerRequest:
    """Parse the deliberately small CLI without constructing dependencies."""
    try:
        if type(argv) not in (list, tuple) or any(type(x) is not str for x in argv):
            raise ValueError()
        values: dict[str, str] = {}
        modes: list[str] = []
        index = 0
        while index < len(argv):
            token = argv[index]
            if token in ("--dry-run", "--commit"):
                modes.append(token)
                index += 1
                continue
            if token not in ("--graph", "--subject", "--lock-directory") or index + 1 >= len(argv):
                raise ValueError()
            if token in values or argv[index + 1].startswith("--"):
                raise ValueError()
            values[token] = argv[index + 1]
            index += 2
        graph = values.get("--graph")
        subject = values.get("--subject")
        if (
            type(graph) is not str
            or not graph
            or graph.strip() != graph
            or len(graph) > _MAX_GRAPH_LENGTH
            or type(subject) is not str
            or _SUBJECT.fullmatch(subject) is None
            or len(modes) != 1
        ):
            raise ValueError()
        commit = modes[0] == "--commit"
        lock_directory = values.get("--lock-directory")
        if commit is not (lock_directory is not None):
            raise ValueError()
        if lock_directory is not None and not os.path.isabs(lock_directory):
            raise ValueError()
        return RunnerRequest(
            graph,
            subject,
            CanonicalRootEntitlementRefreshMode.COMMIT if commit else CanonicalRootEntitlementRefreshMode.DRY_RUN,
            lock_directory,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise CanonicalRootEntitlementRefreshRunnerUnavailable() from None


class LinuxSubjectFileExecutionGuard:
    """Linux host-level, non-blocking, subject-scoped exclusive guard."""

    exclusive = True

    def __init__(self, lock_directory: str) -> None:
        directory_descriptor = None
        try:
            if type(lock_directory) is not str or not os.path.isabs(lock_directory):
                raise ValueError()
            if os.path.realpath(lock_directory) != os.path.normpath(lock_directory):
                raise ValueError()
            info = os.lstat(lock_directory)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ValueError()
            if info.st_uid != os.geteuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError()
            flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            directory_descriptor = os.open(lock_directory, flags)
            opened = os.fstat(directory_descriptor)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError()
            self._directory_descriptor = directory_descriptor
            self._directory = lock_directory
        except (KeyboardInterrupt, SystemExit) as interrupt:
            if directory_descriptor is not None:
                try:
                    os.close(directory_descriptor)
                except BaseException:
                    pass
            raise interrupt
        except Exception:
            if directory_descriptor is not None:
                try:
                    os.close(directory_descriptor)
                except Exception:
                    pass
            raise CanonicalRootEntitlementRefreshRunnerUnavailable(commit_boundary=True) from None

    def _filename(self, subject: str) -> str:
        if type(subject) is not str or _SUBJECT.fullmatch(subject) is None:
            raise CanonicalRootEntitlementRefreshRunnerUnavailable(commit_boundary=True)
        digest = hashlib.sha256(subject.encode("ascii")).hexdigest()
        return "canonical-root-" + digest + ".lock"

    def _path(self, subject: str) -> str:
        """Inspection-only path; acquisition always uses the retained directory fd."""
        return os.path.join(self._directory, self._filename(subject))

    def close(self) -> None:
        """Close the retained directory descriptor exactly once."""
        directory_descriptor = self._directory_descriptor
        self._directory_descriptor = None
        if directory_descriptor is None:
            return
        try:
            os.close(directory_descriptor)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise CanonicalRootEntitlementRefreshRunnerUnavailable(commit_boundary=True) from None

    @contextmanager
    def hold(self, subject_xonly_pubkey: str):
        descriptor: int | None = None
        acquired = False
        boundary_error = False
        pending_interrupt: BaseException | None = None
        directory_descriptor = self._directory_descriptor
        self._directory_descriptor = None
        try:
            if directory_descriptor is None:
                raise ValueError()
            filename = self._filename(subject_xonly_pubkey)
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(filename, flags, 0o600, dir_fd=directory_descriptor)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise ValueError()
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            yield self
        except (KeyboardInterrupt, SystemExit) as exc:
            pending_interrupt = exc
        except CanonicalRootEntitlementRefreshRunnerUnavailable:
            raise
        except Exception:
            boundary_error = True
        finally:
            if descriptor is not None:
                if acquired:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    except (KeyboardInterrupt, SystemExit) as exc:
                        if pending_interrupt is None:
                            pending_interrupt = exc
                    except Exception:
                        boundary_error = True
                try:
                    os.close(descriptor)
                except (KeyboardInterrupt, SystemExit) as exc:
                    if pending_interrupt is None:
                        pending_interrupt = exc
                except Exception:
                    boundary_error = True
            if directory_descriptor is not None:
                try:
                    os.close(directory_descriptor)
                except (KeyboardInterrupt, SystemExit) as exc:
                    if pending_interrupt is None:
                        pending_interrupt = exc
                except Exception:
                    boundary_error = True
            if pending_interrupt is not None:
                raise pending_interrupt
            if boundary_error:
                raise CanonicalRootEntitlementRefreshRunnerUnavailable(commit_boundary=True) from None


def _utc_text(value: object) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError()
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def normalized_result(result: object, request: RunnerRequest) -> dict[str, object]:
    """Return a closed, bounded operational projection of an exact result."""
    if type(result) is not CanonicalRootEntitlementRefreshResult:
        raise CanonicalRootEntitlementRefreshRunnerUnavailable(
            commit_boundary=request.mode is CanonicalRootEntitlementRefreshMode.COMMIT
        )
    try:
        if (
            type(result.edge_local_result) is not EdgeLocalCovenantRelationResult
            or type(result.decision) is not CanonicalRootEntitlementDecision
            or (result.evidence is not None and type(result.evidence) is not CurrentEntitlementEvidenceRecord)
        ):
            raise ValueError()
        relation = EdgeLocalCovenantRelationResult(
            *(
                getattr(result.edge_local_result, field)
                for field in EdgeLocalCovenantRelationResult.__dataclass_fields__
            )
        )
        decision = CanonicalRootEntitlementDecision(
            *(getattr(result.decision, field) for field in CanonicalRootEntitlementDecision.__dataclass_fields__)
        )
        evidence = (
            None
            if result.evidence is None
            else CurrentEntitlementEvidenceRecord(
                *(getattr(result.evidence, field) for field in CurrentEntitlementEvidenceRecord.__dataclass_fields__)
            )
        )
        canonical = CanonicalRootEntitlementRefreshResult(
            result.contract_version,
            result.mode,
            result.outcome,
            result.graph_or_protocol_id,
            result.subject_xonly_pubkey,
            result.evaluated_at,
            relation,
            decision,
            evidence,
            result.append_performed,
        )
        numeric = (
            relation.recognized_outpoint_count,
            relation.qualifying_observation_count,
            relation.observed_block_height,
            relation.incoming_sats,
            relation.outgoing_sats,
        )
        if (
            canonical.contract_version != REFRESH_CONTRACT_VERSION
            or result.graph_or_protocol_id != request.graph_or_protocol_id
            or result.subject_xonly_pubkey != request.subject_xonly_pubkey
            or result.mode is not request.mode
            or type(decision.identity_class) is not IdentityClass
            or decision.identity_class not in (IdentityClass.FULL, IdentityClass.LIMITED)
            or any(type(value) is not int or value < 0 for value in numeric)
            or relation.recognized_outpoint_count < 1
            or relation.qualifying_observation_count > relation.recognized_outpoint_count
            or relation.incoming_sats > MAX_BITCOIN_SATS
            or relation.outgoing_sats > MAX_BITCOIN_SATS
            or type(relation.current_full_relation_satisfied) is not bool
            or type(decision.current_full_relation_satisfied) is not bool
            or _SUBJECT.fullmatch(relation.counterparty_xonly_pubkey) is None
            or relation.counterparty_xonly_pubkey == request.subject_xonly_pubkey
            or any(
                type(value) is not str or _SUBJECT.fullmatch(value) is None
                for value in (
                    relation.selector_record_sha256,
                    relation.trusted_registration_sha256,
                    relation.funding_set_sha256,
                    relation.relation_source_evidence_sha256,
                    decision.source_evidence_sha256,
                )
            )
            or any(
                type(value) is not str or str(uuid.UUID(value)) != value
                for value in (
                    relation.selector_record_id,
                    relation.trusted_registration_id,
                    relation.funding_set_id,
                )
            )
        ):
            raise ValueError()
        allowed = (
            (CanonicalRootEntitlementRefreshOutcome.PREVIEW,)
            if request.mode is CanonicalRootEntitlementRefreshMode.DRY_RUN
            else (CanonicalRootEntitlementRefreshOutcome.APPENDED, CanonicalRootEntitlementRefreshOutcome.UNCHANGED)
        )
        if result.outcome not in allowed:
            raise ValueError()
        payload = {
            "schema": RUNNER_SCHEMA,
            "mode": result.mode.value,
            "outcome": result.outcome.value,
            "graph_or_protocol_id": result.graph_or_protocol_id,
            "subject_xonly_pubkey": result.subject_xonly_pubkey,
            "evaluated_at": _utc_text(result.evaluated_at),
            "observed_at": _utc_text(relation.observed_at),
            "observed_block_height": relation.observed_block_height,
            "identity_class": decision.identity_class.value,
            "current_full": decision.current_full_relation_satisfied,
            "recognized_count": relation.recognized_outpoint_count,
            "qualifying_count": relation.qualifying_observation_count,
            "incoming_sats": relation.incoming_sats,
            "outgoing_sats": relation.outgoing_sats,
            "append_performed": result.append_performed,
            "evidence_id": None if evidence is None else evidence.evidence_id,
            "valid_until": None if evidence is None else _utc_text(evidence.valid_until),
            "source_evidence_sha256": decision.source_evidence_sha256,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(encoded) > 4096:
            raise ValueError()
        return payload
    except (KeyboardInterrupt, SystemExit):
        raise
    except CanonicalRootEntitlementRefreshRunnerUnavailable:
        raise
    except Exception:
        raise CanonicalRootEntitlementRefreshRunnerUnavailable(
            commit_boundary=request.mode is CanonicalRootEntitlementRefreshMode.COMMIT
        ) from None


def _runtime_dependencies(mode: CanonicalRootEntitlementRefreshMode) -> dict[str, object]:
    """Lazily assemble existing adapters after argv validation."""
    # Refuse the application's development fallbacks. Values remain entirely
    # outside argv and are never included in output or errors.
    if not all(os.environ.get(name) for name in ("DATABASE_URL", "RPC_HOST", "RPC_PORT", "RPC_USER", "RPC_PASSWORD")):
        raise CanonicalRootEntitlementRefreshRunnerUnavailable()
    from app.database import get_session, init_database
    from app.services.canonical_admission_edge_storage import SqlAlchemyCanonicalAdmissionEdgeRepository
    from app.services.canonical_covenant_funding_set_storage import SqlAlchemyCanonicalCovenantFundingSetRepository
    from app.services.canonical_genesis_record_storage import SqlAlchemyCanonicalGenesisRecordRepository
    from app.services.canonical_root_registration_binding_storage import (
        SqlAlchemyCanonicalRootRegistrationBindingRepository,
    )
    from app.services.trusted_covenant_registration_storage import SqlAlchemyTrustedCovenantRegistrationRepository
    from app.utils import get_rpc_connection

    init_database(create_tables=False)
    genesis = SqlAlchemyCanonicalGenesisRecordRepository(get_session)
    admission = SqlAlchemyCanonicalAdmissionEdgeRepository(get_session)
    trusted = SqlAlchemyTrustedCovenantRegistrationRepository(get_session)
    binding = SqlAlchemyCanonicalRootRegistrationBindingRepository(
        get_session, genesis_repository=genesis, trusted_registration_repository=trusted
    )
    funding = SqlAlchemyCanonicalCovenantFundingSetRepository(get_session, trusted_registration_repository=trusted)
    dependencies = dict(
        genesis_repository=genesis,
        admission_edge_repository=admission,
        root_registration_binding_repository=binding,
        trusted_registration_repository=trusted,
        funding_set_repository=funding,
        rpc_factory=get_rpc_connection,
    )
    if mode is CanonicalRootEntitlementRefreshMode.COMMIT:
        from app.services.current_entitlement_evidence_storage import SqlAlchemyCurrentEntitlementEvidenceRepository

        dependencies["evidence_repository"] = SqlAlchemyCurrentEntitlementEvidenceRepository(get_session)
    return dependencies


def execute_request(
    request: RunnerRequest,
    *,
    dependency_factory: Callable[[CanonicalRootEntitlementRefreshMode], dict[str, object]] = _runtime_dependencies,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    """Execute exactly one already-validated request."""
    commit = request.mode is CanonicalRootEntitlementRefreshMode.COMMIT
    guard: LinuxSubjectFileExecutionGuard | None = None
    try:
        dependencies = dependency_factory(request.mode)
        from app.services.canonical_root_entitlement_refresh import refresh_canonical_root_entitlement

        kwargs = dict(evaluated_at=clock(), mode=request.mode, **dependencies)
        if commit:
            guard = LinuxSubjectFileExecutionGuard(request.lock_directory)  # type: ignore[arg-type]
            kwargs["execution_guard"] = guard
        result = refresh_canonical_root_entitlement(
            request.graph_or_protocol_id, request.subject_xonly_pubkey, **kwargs
        )
        payload = normalized_result(result, request)
    except (KeyboardInterrupt, SystemExit):
        raise
    except CanonicalRootEntitlementRefreshRunnerUnavailable:
        raise
    except Exception:
        raise CanonicalRootEntitlementRefreshRunnerUnavailable(commit_boundary=commit) from None
    finally:
        if guard is not None:
            active = sys.exc_info()[1]
            try:
                guard.close()
            except (KeyboardInterrupt, SystemExit):
                if not isinstance(active, (KeyboardInterrupt, SystemExit)):
                    raise
            except CanonicalRootEntitlementRefreshRunnerUnavailable:
                if not isinstance(active, (KeyboardInterrupt, SystemExit)):
                    raise
    return payload


def run(
    argv: Sequence[str],
    *,
    dependency_factory: Callable[[CanonicalRootEntitlementRefreshMode], dict[str, object]] = _runtime_dependencies,
) -> str:
    request = parse_runner_argv(argv)
    payload = execute_request(request, dependency_factory=dependency_factory)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
