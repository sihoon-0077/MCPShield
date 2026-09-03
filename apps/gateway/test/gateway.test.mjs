import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { AdmissionBlockedError, getAdmission, runRelease } from "../src/index.mjs";

const safeDigest = `sha256:${"a".repeat(64)}`;
const maliciousDigest = `sha256:${"c".repeat(64)}`;
const safeSurface = `0x${"b".repeat(64)}`;
const maliciousSurface = `0x${"d".repeat(64)}`;

test("mock safe release runs", async () => {
  const result = await runRelease({
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: safeDigest,
    toolSurfaceHash: safeSurface,
    mode: "mock",
    command: process.execPath,
    args: ["-e", "process.stdout.write('started')"],
    capture: true
  });
  assert.equal(result.decision.source, "MOCK");
  assert.equal(result.stdout, "started");
});

test("revoked release is blocked before spawn", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-"));
  const marker = join(dir, "spawned.txt");
  await assert.rejects(
    runRelease({
      releaseId: "mail-mcp@1.0.1",
      artifactDigest: maliciousDigest,
      toolSurfaceHash: maliciousSurface,
      mode: "mock",
      command: process.execPath,
      args: ["-e", `require('fs').writeFileSync(${JSON.stringify(marker)}, 'bad')`]
    }),
    AdmissionBlockedError
  );
  await assert.rejects(readFile(marker), { code: "ENOENT" });
  await rm(dir, { recursive: true, force: true });
});

test("live admission timeout fails closed", async () => {
  const fetchImpl = (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => reject(options.signal.reason));
  });
  await assert.rejects(getAdmission({
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: safeDigest,
    toolSurfaceHash: safeSurface,
    mode: "live",
    timeoutMs: 10,
    fetchImpl
  }), /timeout|aborted/i);
});

test("stdio wrapper transparently proxies newline-delimited JSON-RPC after admission", async () => {
  const gateway = fileURLToPath(new URL("../src/index.mjs", import.meta.url));
  const command = [process.execPath, "-e", "process.stdin.pipe(process.stdout)"];
  const child = spawn(process.execPath, [gateway, "stdio"], {
    env: { ...process.env, MCPSHIELD_MODE: "mock", MCPSHIELD_RELEASE_ID: "mail-mcp@1.0.0", MCPSHIELD_ARTIFACT_DIGEST: safeDigest, MCPSHIELD_TOOL_SURFACE_HASH: safeSurface, MCPSHIELD_COMMAND_JSON: JSON.stringify(command) },
    stdio: ["pipe", "pipe", "pipe"]
  });
  let output = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { output += chunk; });
  const message = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) + "\n";
  child.stdin.end(message);
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  assert.equal(code, 0);
  assert.equal(output, message);
});

test("digest mismatch is blocked before spawn", async () => {
  await assert.rejects(runRelease({
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: `sha256:${"f".repeat(64)}`,
    toolSurfaceHash: safeSurface,
    mode: "mock",
    command: process.execPath,
    args: ["-e", "process.exit(99)"]
  }), (error) => error instanceof AdmissionBlockedError && error.decision.reasonCode === "DIGEST_MISMATCH");
});

test("tool surface mismatch is blocked before spawn", async () => {
  await assert.rejects(runRelease({
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: safeDigest,
    toolSurfaceHash: `0x${"f".repeat(64)}`,
    mode: "mock",
    command: process.execPath,
    args: ["-e", "process.exit(99)"],
  }), (error) => error instanceof AdmissionBlockedError && error.decision.reasonCode === "DIGEST_MISMATCH");
});

test("live request sends the exact artifact and surface identities", async () => {
  let requestBody;
  const fetchImpl = async (_url, options) => {
    requestBody = JSON.parse(options.body);
    return new Response(JSON.stringify({
      schemaVersion: "1.0.0",
      releaseId: "mail-mcp@1.0.0",
      decision: "ALLOW",
      releaseStatus: "VERIFIED",
      reasonCode: "RELEASE_VERIFIED",
      checkedAt: new Date().toISOString(),
      source: "LIVE",
    }), { status: 200, headers: { "content-type": "application/json" } });
  };
  await getAdmission({
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: safeDigest,
    toolSurfaceHash: safeSurface,
    mode: "live",
    fetchImpl,
  });
  assert.deepEqual(requestBody, {
    schemaVersion: "1.0.0",
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: safeDigest,
    toolSurfaceHash: safeSurface,
  });
});

test("inconsistent ALLOW response fails closed", async () => {
  const fetchImpl = async () => new Response(JSON.stringify({
    schemaVersion: "1.0.0",
    releaseId: "mail-mcp@1.0.0",
    decision: "ALLOW",
    releaseStatus: "REVOKED",
    reasonCode: "RELEASE_REVOKED",
    checkedAt: new Date().toISOString(),
    source: "LIVE",
  }), { status: 200 });
  await assert.rejects(getAdmission({
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: safeDigest,
    toolSurfaceHash: safeSurface,
    mode: "live",
    fetchImpl,
  }), /inconsistent allow decision/);
});

test("replay requires both artifact and tool surface hashes", async () => {
  const replayFile = fileURLToPath(new URL("../../../scripts/demo/replay.json", import.meta.url));
  const decision = await getAdmission({
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: safeDigest,
    toolSurfaceHash: `0x${"e".repeat(64)}`,
    mode: "replay",
    replayFile,
  });
  assert.equal(decision.decision, "BLOCK");
  assert.equal(decision.reasonCode, "DIGEST_MISMATCH");
});
