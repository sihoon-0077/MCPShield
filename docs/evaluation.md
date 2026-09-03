# Evaluation

## Environment

- Date: 2026-09-04
- Host: Windows, Node.js 24.13.0
- Docker runtime: unavailable on this host
- Chain tests: Ganache JavaScript fallback because the optional native uWS binary did not match Node 24

## Automated results

| Suite | Result |
|---|---|
| Backend, API, indexer, reconciler, contract | 18/18 passed |
| Security and AI pipeline | 25/25 passed |
| Gateway | 20/20 passed |
| Clean-reset Replay smoke | 10/10 passed |
| LIVE non-Docker E2E | passed |
| EVM indexer-first receipt-race E2E | passed |
| Tracked-file secret scan | passed |
| Backend typecheck | passed |
| Next.js production build | passed |
| Production dependency audit | 0 vulnerabilities |

The LIVE smoke starts an ephemeral Fastify Backend, registers both releases, submits scans, signs validator A/B EIP-712 votes, reaches `VERIFIED` and `REVOKED`, executes the safe child, and proves the malicious marker child produces no stdout because admission blocks first.

## Detector benchmark

Command:

```powershell
npm.cmd run benchmark:security
```

The current harness performs 10 paired runs over one reviewed safe fixture and one reviewed malicious fixture:

| Metric | Result |
|---|---:|
| True positives | 10 |
| True negatives | 10 |
| False positives | 0 |
| False negatives | 0 |
| Recall | 1.0 |
| Precision | 1.0 |
| False-positive rate | 0.0 |
| Canary detection | 1.0 |

Observed local latency for the latest 10 paired run was 87 ms average / 124 ms p95 for the safe fixture and 104 ms average / 110 ms p95 for the malicious fixture.

These are 20 repeated observations of two fixtures, not 20 independent real-world packages. They prove deterministic demo behavior and regression resistance, not population-level model quality. Timing is host-dependent and should be regenerated on the presentation machine.

## Known gaps

- Docker image build and runtime isolation were statically inspected but not executed on this host. CI is configured to build the full Compose stack and verify two independent LIVE Gateway block-evidence records.
- The local preload observer is useful evidence collection, not a tamper-proof sandbox boundary.
- Base Sepolia gas, transaction, and explorer measurements require deployment credentials.
- A broader benign and adversarial corpus is required before making external recall/FPR claims.
- The full development tree currently reports nine advisories through Ganache and solc transitive dependencies. They are excluded from production images and the production-only audit is clean; replace the local-chain test runner before treating the development toolchain as a hardened environment.
