# Contributing to MCPShield

Read `AGENTS.md`, `WORKTREE_COLLABORATION_RULES.md`, and `docs/interface-contract.md` before editing code.

## Branch ownership

- `feature/security-ai`: scanner, fixtures, sandbox, evidence, benchmark
- `feature/blockchain-backend`: API, database, contracts, validator, indexer
- `feature/frontend-gateway-devops`: dashboard, gateway, Docker, CI, demo UX
- `main`: shared contracts, integration, release readiness
- `review/reviewer`: read-only review; no commits

Do not modify another role's owned paths to work around an interface mismatch. Report the mismatch to Main and update the shared contract first.

## Completion gate

A change is complete only when it has:

- an acceptance or regression test;
- explicit timeout and failure handling;
- no real secret or personal data;
- a documented run or disable path;
- deterministic demo behavior;
- review by someone other than the author;
- no Critical or High unresolved review finding.

## Commit guidance

Keep commits scoped and describe the outcome, for example:

```text
feat(scanner): detect undeclared canary egress
fix(gateway): block before process spawn on timeout
test(contract): cover EIP-712 domain replay
docs(demo): document deterministic reset flow
```

## Local verification

Run the component's build, unit tests, integration tests, and the root demo smoke test before requesting merge. If Docker is unavailable, state which Docker-only tests were skipped; do not report them as passing.

