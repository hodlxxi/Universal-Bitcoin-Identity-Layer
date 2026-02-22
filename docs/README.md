# HODLXXI Documentation (Docs v2)

## Purpose
Provide the canonical map for HODLXXI documentation, with clear navigation for both new readers and readers coming from v1.

## Start Here
If you are new to HODLXXI, read in this order:
1. [00_overview.md](00_overview.md)
2. [principles.md](principles.md)
3. [trust_trees.md](trust_trees.md)
4. [descriptor_pruning.md](descriptor_pruning.md)

## Docs Map

### A) Model and philosophy
- [00_overview.md](00_overview.md) — project model, scope, and non-goals
- [principles.md](principles.md) — durable design principles
- [trust_trees.md](trust_trees.md) — Sponsorship / Recursive Accountability
- [intergenerational_design.md](intergenerational_design.md) — time horizon and continuity logic

### B) Mechanisms and boundaries
- [covenant_patterns.md](covenant_patterns.md) — covenant usage patterns
- [descriptor_pruning.md](descriptor_pruning.md) — local pruning semantics
- [sybil_and_identity.md](sybil_and_identity.md) — identity and Sybil posture
- [threat_model.md](threat_model.md) — adversarial and coordination risks
- [implementation_boundaries.md](implementation_boundaries.md) — explicit limitations and non-claims

### C) Coordination and rollout
- [governance.md](governance.md) — local governance and forkability
- [migration_v1_to_v2.md](migration_v1_to_v2.md) — semantic migration notes

## Reader Paths
- **Protocol/design reader**: `00_overview` → `principles` → `trust_trees` → `threat_model`
- **Operator/product reader**: `00_overview` → `implementation_boundaries` → `governance`
- **Legacy/v1 reader**: jump to [migration_v1_to_v2.md](migration_v1_to_v2.md), then use redirects below

## Redirects from v1
- `SYSTEM_ARCHITECTURE.md` → [00_overview.md](00_overview.md)
- `COVENANT_SYSTEM.md` → [covenant_patterns.md](covenant_patterns.md)
- `QUICK_REFERENCE.md` → [00_overview.md](00_overview.md) and [principles.md](principles.md)
- `API_REFERENCE.md`, `DEV_ONBOARDING_CHECKLIST.md`, `FRONTEND_BACKEND_WIRING.md`, `UI_UNIFICATION.md`, `CI_PING.md` → [archive/](archive/)

## Archive Policy
`docs/archive/` keeps v1 and implementation-heavy material for historical continuity and backward lookup. Current conceptual guidance is always in Docs v2.
