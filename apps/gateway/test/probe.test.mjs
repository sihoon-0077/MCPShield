import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const gateway = fileURLToPath(new URL("../src/index.mjs", import.meta.url));
const probe = fileURLToPath(new URL("../../../scripts/demo/gateway-probe.mjs", import.meta.url));
const maliciousFixture = fileURLToPath(new URL("../../../demo/fixtures/mail-mcp-1.0.1", import.meta.url));

test("Compose probe records canonical LIVE block-before-spawn evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-probe-"));
  const evidenceFile = join(directory, "gateway-a.json");
  const server = createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const identity = JSON.parse(body);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ schemaVersion: "1.0.0", releaseId: identity.releaseId, decision: "BLOCK", releaseStatus: "REVOKED", reasonCode: "RELEASE_REVOKED", checkedAt: new Date().toISOString(), source: "LIVE" }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  try {
    const child = spawn(process.execPath, [probe], { windowsHide: true, env: { ...process.env, MCPSHIELD_GATEWAY_ENTRYPOINT: gateway, MCPSHIELD_PROBE_ARTIFACT: maliciousFixture, MCPSHIELD_GATEWAY_EVIDENCE_FILE: evidenceFile, MCPSHIELD_GATEWAY_NAME: "Gateway A LIVE probe", MCPSHIELD_API_URL: `http://127.0.0.1:${port}` }, stdio: "pipe" });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const code = await new Promise((resolve, reject) => { child.once("error", reject); child.once("exit", resolve); });
    assert.equal(code, 0, stderr);
    const evidence = JSON.parse(await readFile(evidenceFile, "utf8"));
    assert.deepEqual({ gateway: evidence.gateway, releaseId: evidence.releaseId, decision: evidence.decision, releaseStatus: evidence.releaseStatus, reasonCode: evidence.reasonCode, source: evidence.source, spawnAttempted: evidence.spawnAttempted }, { gateway: "Gateway A LIVE probe", releaseId: "mail-mcp@1.0.1", decision: "BLOCK", releaseStatus: "REVOKED", reasonCode: "RELEASE_REVOKED", source: "LIVE", spawnAttempted: false });
    assert.match(evidence.artifactDigest, /^sha256:[0-9a-f]{64}$/);
    assert.match(evidence.toolSurfaceHash, /^0x[0-9a-f]{64}$/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
