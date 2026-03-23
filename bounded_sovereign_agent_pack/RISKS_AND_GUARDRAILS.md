# Risks and Guardrails

## Purpose

Document the concrete failure modes and the minimum guardrails required before bounded operational sovereignty can be claimed responsibly.

## Primary Risks

### Operator overclaim risk
The docs could imply stronger autonomy than the runtime enforces.

### Signing-key concentration risk
One operator-controlled key currently signs capabilities and receipts.

### Wallet authority expansion risk
A future implementation could accidentally couple identity signing, billing, and fund movement too tightly.

### Silent policy drift risk
Code could gain new powers while docs and proof surfaces still describe old limits.

### History ambiguity risk
The current receipt chain shows completed jobs, but not yet denied actions, operator approvals, or policy decisions.

## Required Guardrails

### Documentation guardrails
- Use bounded-operational-sovereignty language only.
- Mark every major artifact as existing, partially present, or new.
- Treat code as source of truth and docs as commentary.

### Runtime guardrails
- Zero-default sensitive capabilities.
- Payment-before-completion must stay intact for paid jobs.
- No root, shell, or unrestricted wallet delegation to the agent runtime.
- Sensitive actions must require explicit operator approval and durable logging.

### Key-management guardrails
- Keep agent identity signing isolated from wallet-sensitive credentials where possible.
- Publish key rotation procedure before any policy governance depends on signatures.

### Public-verification guardrails
- Publish active policy digests.
- Publish signed action history.
- Preserve continuity checks for both receipts and any future action chain.

## Red Lines

Do not ship a bounded-sovereignty feature that:
- can spend without a published budget;
- can sign Bitcoin transactions without explicit operator-approved scope;
- can execute arbitrary shell commands;
- can escalate to root;
- presents itself as requiring no trust or as separate from operator control when that is not publicly enforced.

## Minimal Acceptable Future State

A future implementation is only credible if a third party can inspect the active policy, verify the signer, review the action history, and confirm that sensitive actions were either impossible or explicitly approved under published limits.
