import { execFile } from "node:child_process";
import { mkdir, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const exec = promisify(execFile);
const gateway = process.env.MCPSHIELD_GATEWAY_ENTRYPOINT ?? fileURLToPath(new URL("../../apps/gateway/src/index.mjs", import.meta.url));
const artifact = process.env.MCPSHIELD_PROBE_ARTIFACT;
const evidenceFile = process.env.MCPSHIELD_GATEWAY_EVIDENCE_FILE;
const gatewayName = process.env.MCPSHIELD_GATEWAY_NAME;

if (!artifact || !evidenceFile || !gatewayName) throw new Error("MCPSHIELD_PROBE_ARTIFACT, MCPSHIELD_GATEWAY_EVIDENCE_FILE, and MCPSHIELD_GATEWAY_NAME are required");

let stderr = "";
try {
  await exec(process.execPath, [gateway, "run", "--artifact", artifact, "--mode", "live"], { env: process.env, maxBuffer: 1024 * 1024 });
  throw new Error("Malicious Gateway probe was unexpectedly allowed");
} catch (error) {
  if (error.code !== 3) throw error;
  stderr = error.stderr;
}

const records = stderr.split(/\r?\n/).filter(Boolean).flatMap((line) => {
  try { return [JSON.parse(line)]; } catch { return []; }
});
const admission = records.find((record) => record.event === "admission");
const decision = records.find((record) => record.schemaVersion === "1.0.0" && record.decision);
if (!admission || !decision || admission.source !== "LIVE" || decision.source !== "LIVE" ||
  decision.decision !== "BLOCK" || decision.releaseStatus !== "REVOKED" || decision.reasonCode !== "RELEASE_REVOKED") {
  throw new Error("Gateway probe did not produce canonical LIVE revoked-release evidence");
}

const evidence = {
  schemaVersion: "1.0.0",
  gateway: gatewayName,
  releaseId: decision.releaseId,
  artifactDigest: admission.artifactDigest,
  toolSurfaceHash: admission.toolSurfaceHash,
  decision: decision.decision,
  releaseStatus: decision.releaseStatus,
  reasonCode: decision.reasonCode,
  checkedAt: decision.checkedAt,
  source: decision.source,
  spawnAttempted: false,
};
const temporary = `${evidenceFile}.${process.pid}.tmp`;
await mkdir(dirname(evidenceFile), { recursive: true });
await writeFile(temporary, `${JSON.stringify(evidence)}\n`, { mode: 0o640 });
await rename(temporary, evidenceFile);
process.stdout.write(`${JSON.stringify(evidence)}\n`);
