# Migration v1 → v2

## Purpose
Explain what changed from documentation v1 to v2, and why the updated structure better reflects HODLXXI’s intended model.

## Semantic changes (v1 → v2)
- Reframed HODLXXI as a framework for **local Trust Domains**, including private and invite-gated operation.
- Elevated **Sponsorship / Recursive Accountability** (Trust Trees) as the central security mechanism.
- Clarified that optional long-term lock patterns are **commitment signals**, not primary trust value.
- Defined **Descriptor Pruning** as local refusal/local Edge deletion only.
- Removed interpretations that could imply protocol bans, confiscation, or Bitcoin consensus modification.
- Replaced score-like framing with **observable interaction history** and metric non-reduction.
- Re-centered governance around Right to Exit, Forkability over voting, and local policy autonomy.
- Added explicit implementation boundaries to reduce over-claiming.
- Consolidated overlapping conceptual content into a clean docs map.
- Archived v1 implementation-heavy docs for lookup continuity.

## Structural changes
- Created a dedicated docs entrypoint: `docs/README.md`
- Introduced focused concept documents (`trust_trees`, `descriptor_pruning`, `sybil_and_identity`, etc.)
- Moved legacy docs into `docs/archive/` instead of deleting them

## Changelog-style summary
### Added
- New Docs v2 structure and conceptual documents
- Migration guidance and implementation boundary page

### Changed
- Terminology normalized across docs (Trust Domain, Trust Tree, Sponsor, Branch, Edge, Descriptor Pruning)
- Core narrative shifted from ambiguous global framing to explicit local-domain framing

### Archived
- v1 architecture/API/UI wiring docs now in `docs/archive/`
