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

test("mock safe release runs", async () => {
  const result = await runRelease({
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: safeDigest,
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
    mode: "live",
    timeoutMs: 10,
    fetchImpl
  }), /timeout|aborted/i);
});

test("stdio wrapper connects the configured MCP process after admission", async () => {
  const gateway = fileURLToPath(new URL("../src/index.mjs", import.meta.url));
  const command = [process.execPath, "-e", "process.stdin.pipe(process.stdout)"];
  const child = spawn(process.execPath, [gateway, "stdio"], {
    env: { ...process.env, MCPSHIELD_MODE: "mock", MCPSHIELD_RELEASE_ID: "mail-mcp@1.0.0", MCPSHIELD_ARTIFACT_DIGEST: safeDigest, MCPSHIELD_COMMAND_JSON: JSON.stringify(command) },
    stdio: ["pipe", "pipe", "pipe"]
  });
  let output = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stdin.end("mcp-ping\n");
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  assert.equal(code, 0);
  assert.equal(output, "mcp-ping\n");
});

test("digest mismatch is blocked before spawn", async () => {
  await assert.rejects(runRelease({
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: `sha256:${"f".repeat(64)}`,
    mode: "mock",
    command: process.execPath,
    args: ["-e", "process.exit(99)"]
  }), (error) => error instanceof AdmissionBlockedError && error.decision.reasonCode === "DIGEST_MISMATCH");
});
