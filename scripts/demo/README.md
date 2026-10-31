# Reproducible demo

```powershell
npm.cmd run demo:reset
npm.cmd run demo:run
npm.cmd run demo:mcp-e2e
npm.cmd run demo:live-smoke
npm.cmd run demo:evm-smoke
npm.cmd run stack:up
```

`demo:run` proves the Gateway computes identity from an immutable artifact snapshot, starts only the safe manifest entrypoint, and makes two independent revoked-release checks before any malicious entrypoint can start. The bundled data is always labeled `REPLAY`.

`demo:mcp-e2e` uses the official MCP TypeScript v2 client to spawn the Gateway over stdio. It performs the real `initialize`, `tools/list`, and `tools/call` flow for `mail-mcp@1.0.0`, then proves `mail-mcp@1.0.1` is rejected during admission before an MCP handshake can complete.

`demo:live-smoke` starts an ephemeral Backend without Docker, runs the real scanner for both fixtures, submits their random scan IDs and canonical evidence, produces signed 2-of-3 votes, and proves the LIVE Gateway allows only the verified snapshot. It verifies the Backend latest-scan endpoint, cleans up the process, and writes no database file.

`demo:evm-smoke` needs no Docker. It starts Ganache, deploys the contract, runs register/scan/two signed votes/admission through the EVM Backend, and verifies the indexer's projected chain events.

`stack:up` deploys the registry on the local chain, passes its address to the EVM Backend and indexer, and seeds both synthetic releases. Gateway A and B each submit the malicious fixture's Gateway-computed identity to LIVE admission; they become healthy only after writing machine-readable `BLOCK`/`spawnAttempted:false` evidence for the Dashboard. Open `http://localhost:3000` and select `LIVE`.

Run `npm run stack:scan` to execute another malicious-fixture scan as a one-shot, read-only Compose job. The Dashboard automatically selects this newest random scan through the Backend latest-scan endpoint. Its exfiltration sink is created ephemerally inside that isolated container. The optional `standalone-sink` profile exists only for manual inspection and is not published to the host.

The predictable Compose credentials and validator keys are public development values for synthetic localhost data. Never reuse them or expose these services on a shared host. Override `ADMIN_API_TOKEN`, `SCANNER_API_TOKEN`, and `SINK_TOKEN` when needed. Stop the stack with `npm run stack:down`.

The Compose stack above still runs the V1 registry through the legacy `/api` (ADR-005). The V3 path runs without Compose:

## V3 rehearsal stack (ADR-008, no Docker)

```powershell
npm.cmd run demo:v3          # local Ganache, fresh ReleaseRegistryV3, operator API, three validators, dashboard
npm.cmd run demo:v3-smoke    # same stack, drives 1.0.0 and 1.0.1 itself, checks chain and admission, exits
```

`scripts/demo/v3-local-stack.mts` runs the parts of the final demo that do not need Docker, with no compose stack involved:

- **Chain:** an in-process Ganache (chain 31337, one block per second, public test keys) with a fresh `ReleaseRegistryV3`.
- **Operator API:** the `/v1` control plane on V3, with its chain outbox and indexer.
- **Validators:** A, B and C each keep their own copy of the fixtures. Each one scans its copy and signs its own evidence hash and verdict, then votes through the operator relay. C sends a direct emergency quarantine when its own sandbox sees a deterministic critical finding.
- **Dashboard:** `next dev` on `http://127.0.0.1:3000/console`. The admin login token is in the data directory's `stack-local.json`.

In the console:
1. Register the fixture `mail-mcp-1.0.0`.
2. Request on-chain registration (admin).
3. Request a scan.
4. The validators vote by themselves within seconds. The workflow panel shows each validator's verdict, evidence hash, dissent and late votes, read from chain.
5. Check admission.
6. Repeat with `mail-mcp-1.0.1`.

Without Docker the operator's own scan stays `INCONCLUSIVE`. That is expected: on V3 the operator's scan only sets the round window, and the validators decide. `--data <dir>` keeps the SQLite store, tokens and keys for the next run; without it a temporary directory is deleted on exit. Use a fresh data directory for each fresh local chain: the chain restarts empty while old records would stay. `next dev` rewrites `apps/dashboard/next-env.d.ts`; do not commit that change. `gateway-trust.json` in the data directory holds the public values a Gateway needs.

`--base-sepolia` uses the V3 deployment in `deployments/base-sepolia-v3.json`, or the file given with `--deployment`. It reads the relayer and validator keys from `MCPSHIELD_SECRETS_DIR` (default `~/.mcpshield-secrets`) and sends **real testnet transactions**. `--deploy` first deploys a fresh V3 set and writes its record to the data directory. A release whose bytes were already revoked on that deployment cannot be voted on again, so a full rerun of the 1.0.1 story needs a fresh deployment. Public Base RPCs cap `eth_getLogs` at 200 blocks; the indexer uses that bound, and `--index-from <block>` skips older history.