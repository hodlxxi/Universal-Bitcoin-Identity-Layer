#!/usr/bin/env python3
"""Preview or execute the pinned canonical CRT runtime bootstrap V1."""

from __future__ import annotations

import os
from pathlib import Path
import sys

_WORKTREE = str(Path(__file__).resolve().parents[1])
if _WORKTREE not in sys.path:
    sys.path.insert(0, _WORKTREE)

_FAILURE_MESSAGE = "canonical CRT runtime bootstrap unavailable"
_AMBIGUOUS_MESSAGE = _FAILURE_MESSAGE + "; inspect canonical bootstrap state before any manual retry"
_ACK = "CANONICAL-CRT-RUNTIME-BOOTSTRAP-V1"


def _validated_argv(argv):
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
        if type(lock_directory) is not str or not os.path.isabs(lock_directory) or ack != _ACK:
            raise ValueError()
    elif lock_directory is not None or ack is not None:
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
        from app.services.canonical_crt_runtime_bootstrap_runner import run

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
