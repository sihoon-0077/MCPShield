# ADR-002: AI proposes evidence; deterministic policy and validators decide

- Status: Accepted
- Scope: Hackathon MVP

## Decision

AI semantic analysis may produce a non-deterministic finding and adversarial test suggestions. It cannot alone create a terminal revocation. Deterministic hash, policy, canary, signature, nonce, and quorum checks remain outside the model.

## Reason

Semantic mismatch detection benefits from language understanding, while irreversible admission state requires reproducible and independently reviewable evidence.

## Consequences

- AI outages degrade the scan to an explicit fallback or inconclusive result.
- A V3 validator that configured an AI witness and got no answer signs ABSTAIN (`AI_UNAVAILABLE`) instead of PASS; a deterministic FAIL still stands. The same holds when remote AI is allowed but no endpoint is set (`AI_NOT_CONFIGURED`), and the validator refuses to start with settings the AI transport would refuse. The evidence file records which model was configured and whether it answered (2026-11-02).
- AI-only findings are labeled non-deterministic.
- Validator attestations bind to an evidence hash rather than a model score.
- Benchmarks must report deterministic and semantic layers separately.
