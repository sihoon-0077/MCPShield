import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const port = 31_000 + (process.pid % 1_000);
const apiUrl = `http://127.0.0.1:${port}`;
const env = {
  ...process.env,
  ADMIN_API_TOKEN: "dev_admin_token_32_characters",
  SCANNER_API_TOKEN: "dev_scanner_token_32_characters",
  CORS_ALLOWLIST: "http://localhost:3000",
  DATABASE_PATH: ":memory:",
  API_HOST: "127.0.0.1",
  API_PORT: String(port),
  VALIDATOR_ADDRESSES: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
  ATTESTATION_CHAIN_ID: "31337",
  ATTESTATION_CONTRACT: "0x0000000000000000000000000000000000000001",
  MCPSHIELD_API_URL: apiUrl,
};

function run(args, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, args, { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], ...options });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => { stdout += chunk; });
    child.stderr?.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("exit", (code, signal) => resolvePromise({ code, signal, stdout, stderr }));
  });
}

async function waitForHealth() {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(`${apiUrl}/health`, { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch {}
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
  throw new Error("Backend did not become healthy");
}

const backend = spawn(process.execPath, ["--import", "tsx", "apps/api/src/server.ts"], { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
let backendStderr = "";
backend.stderr.on("data", (chunk) => { backendStderr += chunk; });

try {
  await waitForHealth();
  const seeded = await run(["scripts/demo/seed.mjs"]);
  assert.equal(seeded.code, 0, seeded.stderr || seeded.stdout);

  const safe = await run(["apps/gateway/src/index.mjs", "run", "--artifact", "demo/fixtures/mail-mcp-1.0.0", "--mode", "live"]);
  assert.equal(safe.code, 0, safe.stderr);
  assert.match(safe.stdout, /"ok":true/);

  const blocked = await run(["apps/gateway/src/index.mjs", "run", "--artifact", "demo/fixtures/mail-mcp-1.0.1", "--mode", "live"]);
  assert.equal(blocked.code, 3, blocked.stderr);
  assert.equal(blocked.stdout, "");
  assert.match(blocked.stderr, /RELEASE_REVOKED/);

  const summary = await Promise.all(["mail-mcp@1.0.0", "mail-mcp@1.0.1"].map(async (releaseId) => {
    const response = await fetch(`${apiUrl}/api/releases/${encodeURIComponent(releaseId)}`);
    assert.equal(response.status, 200);
    return (await response.json()).release;
  }));
  assert.deepEqual(summary.map((release) => release.status), ["VERIFIED", "REVOKED"]);
  const latestScans = await Promise.all(["mail-mcp@1.0.0", "mail-mcp@1.0.1"].map(async (releaseId) => {
    const response = await fetch(`${apiUrl}/api/releases/${encodeURIComponent(releaseId)}/scans/latest`);
    assert.equal(response.status, 200);
    return (await response.json()).scan;
  }));
  assert.match(latestScans[0].scanId, /^[0-9a-f-]{36}$/);
  assert.notEqual(latestScans[0].scanId, latestScans[1].scanId);
  assert.equal(latestScans[1].scanStatus, "FAILED");
  assert.ok(latestScans[1].findings.some(({ code }) => code === "CANARY_EXFILTRATION"));
  console.log(JSON.stringify({ source: "LIVE", safe: "ALLOW", malicious: "BLOCK_BEFORE_SPAWN", statuses: summary.map((release) => release.status), latestScanIds: latestScans.map(({ scanId }) => scanId), result: "PASS" }, null, 2));
} finally {
  const exited = new Promise((resolvePromise) => backend.once("exit", resolvePromise));
  if (backend.exitCode === null && backend.signalCode === null) backend.kill("SIGTERM");
  await Promise.race([
    exited,
    new Promise((resolvePromise) => setTimeout(resolvePromise, 2_000)),
  ]);
  if (backend.exitCode === null && backend.signalCode === null) {
    backend.kill("SIGKILL");
    throw new Error(`Backend did not stop cleanly: ${backendStderr}`);
  }
}
