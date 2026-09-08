import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
import type { ControlOptions } from "../../apps/api/src/control-plane.js";

// Loopback-only synthetic preview; separate ephemeral SQL/artifacts and no chain signer.
const directory = await mkdtemp(join(tmpdir(), "mcpshield-console-preview-"));
const store = await ControlStore.open(join(directory, "control.sqlite"));
const options: ControlOptions = { store, credentials: [
  { tenantId: "preview-team", role: "admin", token: "synthetic-preview-admin-token" },
  { tenantId: "preview-team", role: "reader", token: "synthetic-preview-reader-token" },
], artifactPath: join(directory, "artifacts"), evidencePath: join(directory, "evidence"), evidenceKey: randomBytes(32).toString("hex") };
const app = await buildApp({ databasePath: ":memory:", adminApiToken: "synthetic-unused-legacy-admin", scannerApiToken: "synthetic-unused-legacy-scanner", controlPlane: options });
await app.listen({ host: "127.0.0.1", port: 4198 });
let pending: Promise<unknown> | undefined;
const timer = setInterval(() => {
  if (pending) return;
  pending = runControlWorkerOnce(store, options).catch(() => process.stderr.write("Preview worker failed; inspect job status.\n")).finally(() => { pending = undefined; });
}, 500);
console.log("Synthetic control preview API: http://127.0.0.1:4198 (no chain attestation)");
console.log("Dashboard MCPSHIELD_API_URL=http://127.0.0.1:4198; admin token: synthetic-preview-admin-token; reader token: synthetic-preview-reader-token");
for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, async () => {
  clearInterval(timer);
  await pending;
  await app.close();
  await rm(directory, { recursive: true, force: true });
});
