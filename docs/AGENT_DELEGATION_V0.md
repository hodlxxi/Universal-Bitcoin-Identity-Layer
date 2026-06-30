# Agent Delegation v0

Agent Delegation v0 is contract-only. It documents intended safety boundaries for future delegated identities, policy, revocation, and verification surfaces. It does not add delegation runtime authority.

## Current runtime boundary

The current runtime does **not** expose `/.well-known/agent-delegation.json`, `/agent/delegations`, or a new delegation runtime endpoint. `/agent/policy` must not be introduced as part of this contract unless a separate policy PR intentionally adds it with schemas and tests.

A QR Pointer to a future delegation record is discovery-only. Scanning or resolving such a pointer does not grant authority, prove identity, create consent, create approval, create delegation, execute work, validate a receipt, create a payment, or establish trust.

## Forbidden authority markers

Delegation contracts must reject or explicitly forbid raw command execution scopes and unlimited authority markers, including shell execution, arbitrary commands, wildcard authority, unrestricted filesystem/network/wallet access, and unbounded spend authority.

Real delegation support requires runtime records, policy evaluation, revocation, verification surfaces, auditability, and least-authority scopes before any delegation endpoint is advertised as live.
