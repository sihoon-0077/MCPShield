import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
import type { ControlOptions } from "../../apps/api/src/control-plane.js";
import { hash } from "../../apps/api/src/control-plane.js";
import { scopedBaselinePreparedPolicy } from "../../apps/api/src/control-policy.js";

// Loopback-only synthetic preview; separate ephemeral SQL/artifacts and no chain signer.
const directory = await mkdtemp(join(tmpdir(), "mcpshield-console-preview-"));
const store = await ControlStore.open(join(directory, "control.sqlite"));
const options: ControlOptions = { store, credentials: [
  { tenantId: "preview-team", role: "admin", token: "synthetic-preview-admin-token" },
  { tenantId: "preview-team", role: "reader", token: "synthetic-preview-reader-token" },
], artifactPath: join(directory, "artifacts"), evidencePath: join(directory, "evidence"), evidenceKey: randomBytes(32).toString("hex") };
const app = await buildApp({ databasePath: ":memory:", adminApiToken: "synthetic-unused-legacy-admin", scannerApiToken: "synthetic-unused-legacy-scanner", controlPlane: options });
if (process.argv.includes("--baseline-ui")) {
  // Display-only records, never executable evidence: no source paths, bindings, Docker config or chain signer.
  const document = scopedBaselinePreparedPolicy("LOCAL_CONTRACT_TEST"), policyHash = hash(document);
  await store.put("preview-team", "policy", policyHash, { policyHash, document, version: document.version,
    alias: "SYNTHETIC_UI_ONLY-baseline-2.1", createdAt: new Date().toISOString(), deprecatedAt: null });
  for (const version of ["1.0.0", "1.0.1"]) {
    const sourceId = hash({ syntheticBrowserSource: version }), runtimeId = hash({ syntheticBrowserRuntime: version });
    const common = { toolId: hash("SYNTHETIC_UI_ONLY"), version, status: "UNVERIFIED", policyHash: null, reportRoot: null,
      validUntil: null, chain: null, artifactDigest: `sha256:${sourceId.slice(2)}`, manifestDigest: `sha256:${sourceId.slice(2)}`, toolSurfaceHash: hash("synthetic-tools") };
    await store.put("preview-team", "release", sourceId, { ...common, releaseId: sourceId, sourceType: "npm", legacyReleaseId: `SYNTHETIC_UI_ONLY-source@${version}` });
    await store.put("preview-team", "release", runtimeId, { ...common, releaseId: runtimeId, sourceReleaseId: sourceId,
      sourceType: "prepared-npm", runtimeProfile: "restricted-node-docker-v2", semanticEvidenceMode: "LOCAL_CONTRACT_TEST",
      providerQuality: "PROVIDER_QUALITY_NOT_MEASURED", legacyReleaseId: `SYNTHETIC_UI_ONLY-runtime@${version}` });
  }
  console.log("SYNTHETIC_UI_ONLY: baseline display records are UNVERIFIED; prepare/scan must reject missing execution authority.");
}
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
