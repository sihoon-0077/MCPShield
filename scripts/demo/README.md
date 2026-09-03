# Reproducible demo

```powershell
npm.cmd run demo:reset
npm.cmd run demo:run
npm.cmd run demo:live-smoke
npm.cmd run stack:up
```

`demo:run` proves the safe release starts and two gateway instances reject the revoked release before its marker process can run. The bundled data is always labeled `REPLAY`.

`demo:live-smoke` starts an ephemeral Backend without Docker, registers both releases, stores scans, produces signed 2-of-3 votes, and proves the LIVE Gateway allows only the verified release. It cleans up the Backend process and writes no database file.

`stack:up` builds the Backend, seeds both synthetic releases and their signed 2-of-3 decisions, then starts the LIVE dashboard and two health-monitored gateways. Open `http://localhost:3000` and select `LIVE`. The local chain is available on loopback port 8545 for contract exploration; the default Backend ledger remains the deterministic `LOCAL_DEMO` projection so the stack does not depend on a dynamically deployed address.

After the Security/AI files are present, run `npm run stack:scan` to execute the malicious fixture scanner as a one-shot, read-only Compose job. Its exfiltration sink is created ephemerally inside that isolated container. The optional `standalone-sink` profile exists only for manual inspection and is not published to the host.

The predictable Compose credentials and validator keys are public development values for synthetic localhost data. Never reuse them or expose these services on a shared host. Override `ADMIN_API_TOKEN`, `SCANNER_API_TOKEN`, and `SINK_TOKEN` when needed. Stop the stack with `npm run stack:down`.
