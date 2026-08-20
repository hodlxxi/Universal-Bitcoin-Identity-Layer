"""One-shot operator boundary for canonical CRT runtime bootstrap V1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Callable, Sequence

from app.services.canonical_crt_runtime_bootstrap import (
    AMBIGUOUS_MESSAGE,
    BOOTSTRAP_SCHEMA,
    BootstrapMode,
    BootstrapUnavailable,
    FAILURE_MESSAGE,
    execute_bootstrap,
    load_bootstrap_bundle,
)

COMMIT_ACK = "CANONICAL-CRT-RUNTIME-BOOTSTRAP-V1"
RUNNER_SCHEMA = "hodlxxi.canonical_crt_runtime_bootstrap_runner.v1"


@dataclass(frozen=True, slots=True)
class BootstrapRequest:
    mode: BootstrapMode
    lock_directory: str | None


def parse_bootstrap_argv(argv: Sequence[str]) -> BootstrapRequest:
    """Validate the deliberately small CLI contract before constructing dependencies."""
    try:
        if type(argv) not in (list, tuple) or any(type(value) is not str for value in argv):
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
            if token not in ("--lock-directory", "--ack") or index + 1 >= len(argv):
                raise ValueError()
            if token in values or argv[index + 1].startswith("--"):
                raise ValueError()
            values[token] = argv[index + 1]
            index += 2
        if len(modes) != 1:
            raise ValueError()
        commit = modes[0] == "--commit"
        lock_directory = values.get("--lock-directory")
        ack = values.get("--ack")
        if commit:
            if type(lock_directory) is not str or not os.path.isabs(lock_directory) or ack != COMMIT_ACK:
                raise ValueError()
        elif lock_directory is not None or ack is not None:
            raise ValueError()
        return BootstrapRequest(BootstrapMode.COMMIT if commit else BootstrapMode.DRY_RUN, lock_directory)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise BootstrapUnavailable() from None


def _runtime_dependencies() -> dict[str, object]:
    """Build only database persistence adapters; bootstrap never constructs Bitcoin RPC or evidence storage."""
    if not os.environ.get("DATABASE_URL"):
        raise BootstrapUnavailable()
    try:
        from app.database import get_session, init_database
        from app.services.canonical_covenant_funding_set_storage import SqlAlchemyCanonicalCovenantFundingSetRepository
        from app.services.canonical_genesis_record_storage import SqlAlchemyCanonicalGenesisRecordRepository
        from app.services.canonical_root_registration_binding_storage import SqlAlchemyCanonicalRootRegistrationBindingRepository
        from app.services.trusted_covenant_registration_storage import SqlAlchemyTrustedCovenantRegistrationRepository

        init_database(create_tables=False)
        genesis = SqlAlchemyCanonicalGenesisRecordRepository(get_session)
        trusted = SqlAlchemyTrustedCovenantRegistrationRepository(get_session)
        binding = SqlAlchemyCanonicalRootRegistrationBindingRepository(
            get_session,
            genesis_repository=genesis,
            trusted_registration_repository=trusted,
        )
        funding = SqlAlchemyCanonicalCovenantFundingSetRepository(
            get_session,
            trusted_registration_repository=trusted,
        )
        return {
            "genesis_repository": genesis,
            "trusted_registration_repository": trusted,
            "root_registration_binding_repository": binding,
            "funding_set_repository": funding,
        }
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise BootstrapUnavailable() from None


def _compact(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def execute_request(
    request: BootstrapRequest,
    *,
    dependency_factory: Callable[[], dict[str, object]] = _runtime_dependencies,
    repository_root: Path | str | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    guard_factory=None,
) -> dict[str, object]:
    """Execute exactly one preview or locked commit against the pinned manifest."""
    commit = request.mode is BootstrapMode.COMMIT
    guard = None
    try:
        if type(request) is not BootstrapRequest:
            raise ValueError()
        root = Path(repository_root) if repository_root is not None else Path(__file__).resolve().parents[2]
        evaluated_at = clock().astimezone(timezone.utc).replace(microsecond=0)
        bundle = load_bootstrap_bundle(root, evaluated_at=evaluated_at)
        dependencies = dependency_factory()
        if commit:
            if guard_factory is None:
                from app.services.canonical_root_entitlement_refresh_runner import LinuxSubjectFileExecutionGuard

                guard_factory = LinuxSubjectFileExecutionGuard
            guard = guard_factory(request.lock_directory)
            with guard.hold(bundle.subject_xonly_pubkey):
                payload = execute_bootstrap(
                    bundle,
                    mode=request.mode,
                    evaluated_at=evaluated_at,
                    **dependencies,
                )
        else:
            payload = execute_bootstrap(
                bundle,
                mode=request.mode,
                evaluated_at=evaluated_at,
                **dependencies,
            )
        if payload.get("schema") != BOOTSTRAP_SCHEMA:
            raise ValueError()
        result = dict(payload)
        result["schema"] = RUNNER_SCHEMA
        encoded = _compact(result)
        if len(encoded) > 4096:
            raise ValueError()
        return result
    except (KeyboardInterrupt, SystemExit):
        raise
    except BootstrapUnavailable:
        if commit:
            raise BootstrapUnavailable(commit_boundary=True) from None
        raise
    except Exception:
        raise BootstrapUnavailable(commit_boundary=commit) from None
    finally:
        if guard is not None:
            try:
                guard.close()
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                raise BootstrapUnavailable(commit_boundary=commit) from None


def run(argv: Sequence[str]) -> str:
    request = parse_bootstrap_argv(argv)
    payload = execute_request(request)
    try:
        encoded = _compact(payload)
        if len(encoded) > 4096:
            raise ValueError()
        return encoded
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise BootstrapUnavailable(commit_boundary=request.mode is BootstrapMode.COMMIT) from None


__all__ = [
    "AMBIGUOUS_MESSAGE",
    "COMMIT_ACK",
    "FAILURE_MESSAGE",
    "BootstrapRequest",
    "execute_request",
    "parse_bootstrap_argv",
    "run",
]
