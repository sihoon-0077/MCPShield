# ADR-002: AI proposes evidence; deterministic policy and validators decide

- Status: Accepted
- Scope: Hackathon MVP

## Decision

AI semantic analysis may produce a non-deterministic finding and adversarial test suggestions. It cannot alone create a terminal revocation. Deterministic hash, policy, canary, signature, nonce, and quorum checks remain outside the model.

## Reason

Semantic mismatch detection benefits from language understanding, while irreversible admission state requires reproducible and independently reviewable evidence.

## Consequences

- AI outages degrade the scan to an explicit fallback or inconclusive result.
- AI-only findings are labeled non-deterministic.
- Validator attestations bind to an evidence hash rather than a model score.
- Benchmarks must report deterministic and semantic layers separately.
