import { test } from "node:test";
import { assertConsortiumReport, runConsortiumScene } from "./consortium-scene.js";

// Capstone v2.1 CAP2-307/308 and the three Gateway measurements (ADR-004/006).
// Local EVM + REPORT FIXTURE scanner double; testnet evidence is recorded separately.
test("consortium scene: chain-checking company keeps enforcing when the operator is down or captured", { timeout: 240_000 }, async () => {
  assertConsortiumReport(await runConsortiumScene({ latencySamples: 5 }), 5);
});
