# HODLXXI Overview

## Purpose
Define what HODLXXI is, what it is not, and how its updated model should be interpreted across deployments.

## One-sentence definition
HODLXXI is a Bitcoin-native identity and covenant framework for **local Trust Domains** that coordinate through Sponsorship accountability and long-horizon interaction history.

## System context
HODLXXI currently operates as a Flask-based web platform with identity, proof-of-funds, covenant, and OAuth2/OIDC capabilities, plus real-time communication features. Docs v2 focuses on the conceptual model that can be implemented in multiple ways.

## Core model
1. Participants enter a Trust Domain through social admission (often via a **Sponsor**).
2. Admission creates accountable relationships in a **Trust Tree**.
3. Participants build reputation through repeated observable interactions.
4. Optional long-term lock patterns can signal commitment.
5. Risk response is local (including local edge removal), not global protocol punishment.

## What HODLXXI is not
- Not a global permissionless reputation marketplace by default
- Not a universal, protocol-level social enforcement layer
- Not a scalar trust score product
- Not tied to one canonical implementation

## Why this design
HODLXXI treats trust as a function of:
- **time** (behavior across cycles),
- **reciprocity** (mutual obligations and responses), and
- **context** (which Trust Domain observed what).

This preserves social meaning that would otherwise be lost in metric-only systems.

## Key terms used throughout Docs v2
- **Trust Domain**: local membership and policy boundary
- **Trust Tree**: Sponsor-linked accountability graph
- **Sponsor**: participant introducing another participant
- **Branch**: downstream subtree of sponsored participants
- **Edge**: an accountable relationship link
- **Descriptor Pruning**: local refusal/edge deletion behavior

## Next documents
- [principles.md](principles.md)
- [trust_trees.md](trust_trees.md)
- [descriptor_pruning.md](descriptor_pruning.md)
- [implementation_boundaries.md](implementation_boundaries.md)
