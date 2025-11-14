# HODLXXI Application Documentation Index

This directory contains the in-depth references that back the Universal Bitcoin Identity Layer.  Each document focuses on a specific operational concern—protocol behavior, security guarantees, or deployment—and is intended to be used alongside the root [`README.md`](../README.md) for a complete overview of the stack.

The table below highlights what each guide covers and when to reach for it.

| Document | Size | When to Use It | Key Topics |
| --- | --- | --- | --- |
| [`API_RESPONSE_EXAMPLES.md`](./API_RESPONSE_EXAMPLES.md) | ~17 KB | Building or debugging client integrations | Endpoint catalogue, auth flows, pagination, websocket events |
| [`ERROR_CODE_DOCUMENTATION.md`](./ERROR_CODE_DOCUMENTATION.md) | ~24 KB | Diagnosing failures or wiring monitoring/alerting | Error map (1000-7099), HTTP mappings, remediation playbooks |
| [`SECURITY_REQUIREMENTS.md`](./SECURITY_REQUIREMENTS.md) | ~31 KB | Performing security reviews or preparing for production | Defense-in-depth model, transport/security headers, incident response |
| [`TOKEN_POLICIES.md`](./TOKEN_POLICIES.md) | ~33 KB | Managing session lifecycles or client refresh logic | TTL matrix, rotation guidance, compromise response |
| [`PRODUCTION_DEPLOYMENT.md`](./PRODUCTION_DEPLOYMENT.md) | ~29 KB | Deploying the app or auditing an existing environment | Infra prerequisites, database/Redis setup, observability, HA patterns |
| [`OAUTH_LNURL_SPECIFICATION.md`](./OAUTH_LNURL_SPECIFICATION.md) | ~48 KB | Implementing OAuth2/OIDC or LNURL-auth consumers | Grant flows, PKCE, scope catalogue, LNURL auth handshake |

## How to Navigate the Docs

1. **Start with the protocol and flows** – Use the OAuth/OIDC + LNURL specification to understand how wallets and relying parties authenticate.
2. **Explore the API catalogue** – Cross-reference the response examples while building or debugging client calls.
3. **Wire up error handling** – Map error codes to retry policies, alerting, and client messaging.
4. **Lock down deployments** – Follow the security and deployment guides when standing up a new environment or running an audit.
5. **Plan for lifecycle events** – Review the token policy sheet before implementing refresh/rotation logic.

> Tip: The documentation intentionally leans on plain Markdown files so they can be diffed in reviews and kept under the same version control as the application code. When you change a subsystem, update the relevant doc in this directory alongside your code change.

## Related Files Outside This Directory

- [`ARCHITECTURE.md`](../ARCHITECTURE.md) – High-level component diagram and data flow.
- [`TESTING.md`](../TESTING.md) – Current test coverage and how to execute the suites.
- [`deployment/`](../deployment/) – Operator runbooks and hardening scripts.

If you spot drift between the implementation and these docs, open an issue or update the Markdown in the same pull request as your code change so reviewers can validate both.
