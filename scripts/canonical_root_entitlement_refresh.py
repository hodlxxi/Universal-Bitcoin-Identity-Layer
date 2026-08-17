#!/usr/bin/env python3
"""Execute one explicitly requested canonical-root entitlement refresh."""

from __future__ import annotations

import sys
import os
from pathlib import Path
import re

_WORKTREE = str(Path(__file__).resolve().parents[1])
if _WORKTREE not in sys.path:
    sys.path.insert(0, _WORKTREE)

_FAILURE_MESSAGE = "canonical root entitlement refresh runner unavailable"
_AMBIGUOUS_MESSAGE = _FAILURE_MESSAGE + "; inspect current evidence before any manual retry"
_SUBJECT = re.compile(r"[0-9a-f]{64}\Z")


def _validated_argv(argv):
    """Validate the complete CLI contract before any application import."""
    if type(argv) not in (list, tuple) or any(type(value) is not str for value in argv):
        raise ValueError()
    values = {}
    modes = []
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
    graph, subject = values.get("--graph"), values.get("--subject")
    if (
        type(graph) is not str
        or not graph
        or graph.strip() != graph
        or len(graph) > 256
        or type(subject) is not str
        or _SUBJECT.fullmatch(subject) is None
        or len(modes) != 1
    ):
        raise ValueError()
    lock_directory = values.get("--lock-directory")
    commit = modes[0] == "--commit"
    if commit is not (lock_directory is not None):
        raise ValueError()
    if lock_directory is not None and not os.path.isabs(lock_directory):
        raise ValueError()
    return list(argv)


def main(argv=None) -> int:
    try:
        validated = _validated_argv(sys.argv[1:] if argv is None else argv)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        sys.stderr.write(_FAILURE_MESSAGE + "\n")
        return 2
    try:
        from app.services.canonical_root_entitlement_refresh_runner import run

        output = run(validated)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        message = str(exc)
        if message not in (_FAILURE_MESSAGE, _AMBIGUOUS_MESSAGE):
            message = _FAILURE_MESSAGE
        sys.stderr.write(message + "\n")
        return 2
    if type(output) is not str or len(output) > 4096:
        sys.stderr.write(_FAILURE_MESSAGE + "\n")
        return 2
    sys.stdout.write(output + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
