# Hackathon Implementation Matrix

| Requirement | Prototype implementation | Runnable proof |
|---|---|---|
| Safe and malicious releases | `demo/fixtures/mail-mcp-1.0.0`, `mail-mcp-1.0.1` | `npm.cmd run scan:safe`, `npm.cmd run scan:malicious` |
| Exact release identity | canonical artifact digest and tool-surface hash | Gateway/scanner identity tests |
| Static, AI, sandbox evidence | shared import rules, structured AI fallback/remote opt-in, canary observer | `npm.cmd run test:security` |
| 2-of-3 validators | Solidity `ReleaseRegistry`, EIP-712 signatures, nonce/deadline/replay checks | `npm.cmd run test:backend` |
| Chain projection and recovery | event indexer, reorg rewind, receipt reconciliation, idempotent API writes | concurrent EVM smoke test |
| Pre-spawn enforcement | artifact-owned Gateway admission and runtime surface guard | `npm.cmd run test:gateway`, LIVE smoke |
| Two-Gateway revocation | Gateway A/B LIVE Compose probes with shared evidence | Docker Compose E2E job |
| One-screen dashboard | LIVE/REPLAY evidence, release status, findings, votes, events, admission | Next production build and browser QA |
| Reproducible delivery | Docker Compose, CI, offline replay, non-Docker LIVE/EVM smoke | `npm.cmd test`, `npm.cmd run stack:up` |
| Evaluation | 10 paired deterministic benchmark runs with confusion matrix and latency | `npm.cmd run benchmark:security` |

The prototype intentionally excludes a token, DAO, marketplace, custom foundation model, and unverifiable claims about mutable remote MCP servers.
