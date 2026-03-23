# RISKS_AND_GUARDRAILS

## Security risks

### 1. Agent key compromise
If the signing key is stolen, an attacker can publish apparently valid manifests, budget statements, and action logs.

**Guardrails**
- keep agent private key outside the repo and outside public routes
- publish policy continuity hashes so sudden changes are visible
- add explicit key-rotation checkpoint events
- document revocation/rotation process before enabling broader powers

### 2. Policy bypass by direct codepath
Because the repo has both monolith and factory routes, a new policy check may be added in one path while another path still bypasses it.

**Guardrails**
- enforce sovereign actions only through one helper
- verify route registration in the monolith-backed runtime
- add tests for direct route access and bypass attempts

### 3. Prompt injection / model abuse
If an LLM or upstream caller can ask for arbitrary actions, it may try to route around policy.

**Guardrails**
- action executor must accept only explicit action enums
- deny unknown actions
- never translate free-form text directly into shell or wallet operations
- log denials publicly where safe

## Operational risks

### 4. Docs-vs-runtime drift
The repo already contains partial drift between documented blueprint architecture and the monolith-backed runtime.

**Guardrails**
- treat `wsgi.py` + active route handlers as source of truth
- update docs only after runtime behavior is implemented
- add proof-surface tests that hit live routes

### 5. Partial implementation mistaken for full sovereignty
The repo may look more autonomous than it really is once policy docs exist.

**Guardrails**
- clearly state when spending is disabled
- clearly separate self-executable, escalated, and forbidden actions
- avoid language like “fully autonomous” or “independent of operator”

### 6. Availability impact from over-tight logging
If every action blocks on expensive signing or DB writes, operational endpoints may degrade.

**Guardrails**
- keep action-log writes simple and append-only
- cap publication frequency for status snapshots
- paginate public log endpoints

## Centralization truths

The bounded sovereign agent will still remain centralized in important ways:

- operator controls deployment and infrastructure
- operator controls secret provisioning
- operator can still update code
- public claims depend on honest publication of proof surfaces

**Claims to avoid**
- “fully decentralized”
- “trustless”
- “independent of operator”
- “cannot be overridden”

Safer language:

- “bounded operational sovereignty”
- “policy-bounded authority”
- “publicly verifiable autonomy claims”
- “limited operational budget”
- “signed action history”

## Wallet abuse risks

### 7. Unrestricted wallet drain
The largest financial risk is turning a current inbound-only flow into open-ended outbound control.

**Guardrails**
- no unrestricted payment capability
- no sweep capability
- no raw macaroon exposure to agent logic
- require spend-class checks and caps
- keep outbound execution disabled until policy/logging are stable

### 8. Hidden self-dealing or policy laundering
An agent could appear bounded while actually routing funds to operator-controlled destinations.

**Guardrails**
- require spend class and beneficiary class metadata
- forbid peer transfers and exchange withdrawals in first stage
- log denied and escalated payment attempts
- publish signed budget summaries and spend totals

## Admin abuse risks

### 9. Silent override powers
Operators may still be able to edit DB state or code without corresponding public evidence.

**Guardrails**
- publish policy version/hash and previous-policy hash
- create action-log events for manifest publication and pause/resume events
- document any operator-only override as an explicit centralized trust assumption

### 10. Broad admin routes reused as sovereign capabilities
Current dev/admin helpers are too broad or too environment-specific to hand to the agent.

**Guardrails**
- do not expose `systemctl`, shell, or wide admin controls via capability executor
- do not repurpose dev-only routes as public sovereign routes
- keep capability executor action list extremely small

## Audit/log tampering risks

### 11. Deleting or rewriting history
If action logs or receipts can be pruned, the public proof story collapses.

**Guardrails**
- append-only writes only
- no delete/update route for signed history
- continuity endpoints should expose head hashes
- migrations must publish signed checkpoint events

### 12. Selective publication
A service could omit embarrassing denied or failed actions from public feeds.

**Guardrails**
- publish both allow and deny decisions where safe
- record chain counts and latest head hashes
- optionally expose daily signed checkpoints even when there are zero actions

## Concrete forbidden powers

The agent must **not** get:

- unrestricted root shell
- unrestricted hot wallet drain
- unrestricted secret export
- log/history deletion powers
- silent policy change authority
- arbitrary subprocess execution
- arbitrary systemd control
- arbitrary Bitcoin RPC write methods
- arbitrary LND payment methods

## Minimum guardrail set for first implementation

1. deny-by-default policy engine
2. explicit forbidden-action list in public manifest
3. append-only signed action history
4. public policy version continuity
5. bounded spending disabled by default until audited
6. narrow capability executor with enum-based actions only
7. no root/shell/systemd capabilities
8. no unrestricted wallet authority
