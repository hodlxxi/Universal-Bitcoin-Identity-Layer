# HODLXXI Action Authorization Policy v1

## Purpose and status

`hodlxxi.action-policy.v1` is the canonical, deterministic authorization policy
foundation for future authenticated HODLXXI actions. It combines a validated
actor key, current entitlement evidence, exact granted scopes, resource
ownership, and an already-verified step-up result into an audit-safe decision.

This policy does not enable actions or change production authorization. No
route, blueprint, action endpoint, or MCP endpoint is registered by this work.
A future Authenticated Action MCP may call this policy only after it supplies
the required authentication, current-entitlement, ownership, and step-up
boundaries.

## Identity classes

- `anonymous`: no authenticated user entitlement; denied.
- `guest`: guest access; denied for every action in this policy.
- `limited`: eligible for the five limited/full actions below.
- `full`: eligible for limited/full actions and, when the current relation is
  satisfied, the two full-only actions below.
- `operator`: never receives an implicit bypass. Operator actions belong to a
  separate future control plane and are denied by this ordinary user-action
  policy.

The legacy `special` access level is not part of this policy.

## Exact action and scope matrix

| Action | Exact required scope | Allowed identity | Ownership | Current full relation | Step-up |
| --- | --- | --- | --- | --- | --- |
| `self_read` | `self:read` | limited, full | actor itself | no | no |
| `job_create` | `job:create` | limited, full | actor-bound future job | no | no |
| `job_read_self` | `job:read:self` | limited, full | resource owner equals actor | no | no |
| `job_receipt_read_self` | `job:receipt:read:self` | limited, full | resource owner equals actor | no | no |
| `action_receipt_read_self` | `action:receipt:read:self` | limited, full | resource owner equals actor | no | no |
| `covenant_draft_create` | `covenant:draft:create` | full | actor-bound future draft | required | required |
| `covenant_draft_read_self` | `covenant:draft:read:self` | full | resource owner equals actor | required | no |

Scopes match exactly. A broad scope such as `read`, `write`, or
`covenant_create` cannot satisfy a narrow required scope. Granted scopes must
be a bounded ordinary iterable of non-empty strings; bare strings, byte
strings, mappings, malformed elements, and iteration failures deny with
`invalid_scope_set`. A valid empty scope collection denies with
`missing_scope`. Unknown actions and additional scopes grant no authority.

## Current entitlement boundary

Caller-supplied or stale session access levels are not authoritative. Every
eligible evaluation asks an injected resolver for a current
`EntitlementSnapshot`. The snapshot contains only authorization evidence: the
actor public key, identity class, whether the current full relation is
satisfied, an evidence source/version, and an optional observation timestamp.

The resolver is intentionally independent of Flask sessions, OAuth claims,
database sessions, and MCP. An unavailable resolver, resolver exception,
malformed evidence, or actor mismatch denies access. A current limited result
therefore overrides any previous full session state. Full-only actions require
both a current `full` identity and a currently satisfied full relation. The
relation evidence must be the actual boolean `True`; truthy strings, numbers,
containers, and objects do not satisfy this requirement.

The existing balance helper is not wired as a production resolver because it
performs Bitcoin RPC reads and writes request-local display state. A narrow,
genuinely read-only production entitlement resolver must be introduced and
wired by a later change.

## Actor identity and ownership

Actor and owner keys use the repository's existing canonical x-only public-key
normalization. This accepts supported npub, x-only hex, and compressed hex
representations and compares their canonical form. Missing or malformed actors
deny. Bearer scope possession alone does not prove control of the actor key.

For every self-owned resource read, the caller must supply a valid resource
owner. A missing or malformed owner denies, and a canonical owner different
from the actor denies. Create actions bind their future resource to the actor;
they do not authorize selection of a different owner.

## Step-up boundary

The policy consumes only the boolean result of a separate future verifier. It
does not create challenges, validate signatures, or implement cryptography.
`covenant_draft_create` denies unless step-up verification is explicitly true
and every other requirement also passes.

## Stable decision structure

Each decision serializes to a stable audit-safe dictionary with:

- `allowed` and one primary `reason_code`;
- canonical `actor_pubkey` when valid;
- `identity_class` and `current_access_level` from current evidence;
- `action`, `required_scope`, and `policy_version`;
- canonical `resource_owner_pubkey` when relevant;
- `ownership_required` and `step_up_required`.

Decisions never contain bearer tokens, client secrets, signatures, private
keys, raw session content, wallet balances, or resolver exception messages.
Checks run in a fixed order so identical inputs produce identical decisions.
Unknown caller-supplied action values are represented as the bounded value
`unknown`; raw unknown input is never reflected into an audit decision.

## Fail-closed behavior

Stable denial reasons include missing or invalid actor, unknown action,
unavailable entitlement, entitlement actor mismatch, anonymous or guest
identity, operator control-plane separation, missing scope, insufficient
identity, missing current full relation, required or mismatched ownership, and
required step-up. Resolver exceptions are reduced to
`entitlement_unavailable`; exception details are not exposed.

## MCP relationships

The existing public Read-Only MCP is a separate sidecar and remains unchanged:
its tools, endpoint, discovery, protocol, version, and deployment are outside
this policy. This policy is a future dependency for an Authenticated Action MCP,
but this version creates no Action MCP package or endpoint and executes no
action.

## Explicit non-goals

This work does not:

- issue or validate OAuth tokens, harden bearer handling, or change OAuth
  routes, claims, scopes, registration, or introspection;
- add or authorize message submission, descriptor operations, labels, Bitcoin
  RPC, Lightning operations, account PAYG changes, or generic writes;
- provide wallet, LND, shell, database, private-key, administrative, or
  operator-control-plane access;
- add models, migrations, configuration, dependencies, production wiring, or
  production authorization changes;
- deploy, restart services, or modify the public Read-Only MCP.
