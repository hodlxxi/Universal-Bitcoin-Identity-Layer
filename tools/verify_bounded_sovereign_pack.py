#!/usr/bin/env python3
"""Validate the bounded sovereign agent documentation pack."""

from __future__ import annotations

import sys
from pathlib import Path

PACK_DIR = Path(__file__).resolve().parents[1] / "bounded_sovereign_agent_pack"
EXPECTED_FILES = {
    "BOUNDED_SOVEREIGN_AUDIT.md": [
        "## Purpose",
        "## Current Repo Truth",
        "## Gaps Versus A Bounded Sovereignty Claim",
        "## Minimal Conclusion",
    ],
    "IMPLEMENTATION_PLAN_8_STEPS.md": [
        "## Objective",
        "## Dependency Notes",
        "## Step 1 — Freeze the current truth",
        "## Exit Criteria",
    ],
    "PATCH_TARGETS.md": [
        "## Purpose",
        "## Existing Targets",
        "## New Targets",
        "## Non-Targets For This PR",
    ],
    "POLICY_MANIFEST_SPEC.md": [
        "## Purpose",
        "## Current Repo Truth",
        "## Required Fields",
        "## Verification Expectations",
    ],
    "ACTION_LOG_SPEC.md": [
        "## Purpose",
        "## Current Repo Truth",
        "## Required Record Shape",
        "## Minimal Safe Rollout",
    ],
    "SPENDING_POLICY_SPEC.md": [
        "## Purpose",
        "## Current Repo Truth",
        "## Required Limits",
        "## Public Verifiability Requirements",
    ],
    "PUBLIC_PROOF_SURFACES.md": [
        "## Purpose",
        "## Existing Public Surfaces",
        "## Proposed New Proof Surfaces",
        "## Reviewer Checklist",
    ],
    "RISKS_AND_GUARDRAILS.md": [
        "## Purpose",
        "## Primary Risks",
        "## Required Guardrails",
        "## Minimal Acceptable Future State",
    ],
    "MINIMAL_PATCH_SKETCHES.md": [
        "## Purpose",
        "## Sketch 1 — Signed policy manifest helper",
        "## Sketch 5 — Operator approval record",
        "## Out of Scope In This PR",
    ],
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)


def main() -> int:
    errors: list[str] = []

    if not PACK_DIR.exists() or not PACK_DIR.is_dir():
        errors.append(f"missing pack directory: {PACK_DIR}")
    else:
        for name, sections in EXPECTED_FILES.items():
            path = PACK_DIR / name
            if not path.exists():
                errors.append(f"missing file: {path.relative_to(PACK_DIR.parent)}")
                continue
            text = path.read_text(encoding="utf-8").strip()
            if not text:
                errors.append(f"empty file: {path.relative_to(PACK_DIR.parent)}")
                continue
            for section in sections:
                if section not in text:
                    errors.append(f"missing section '{section}' in {path.relative_to(PACK_DIR.parent)}")

    if errors:
        for error in errors:
            fail(error)
        return 1

    print("Bounded sovereign pack verification passed.")
    print(f"Checked directory: {PACK_DIR.relative_to(PACK_DIR.parent.parent)}")
    print(f"Checked files: {len(EXPECTED_FILES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
