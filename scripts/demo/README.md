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
