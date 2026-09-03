import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createArtifactSnapshot } from "../src/artifact.mjs";
import { AdmissionBlockedError, getAdmission, runArtifact } from "../src/index.mjs";

const gateway = fileURLToPath(new URL("../src/index.mjs", import.meta.url));
const safeFixture = fileURLToPath(new URL("../../../demo/fixtures/mail-mcp-1.0.0", import.meta.url));
const maliciousFixture = fileURLToPath(new URL("../../../demo/fixtures/mail-mcp-1.0.1", import.meta.url));
const replayFile = fileURLToPath(new URL("../../../scripts/demo/replay.json", import.meta.url));
const expectedFile = fileURLToPath(new URL("../../../demo/fixtures/expected-hashes.json", import.meta.url));

async function syntheticArtifact({ tools, responseTools = tools, marker }) {
  const root = await mkdtemp(join(tmpdir(), "mcpshield-test-artifact-"));
  await writeFile(join(root, "manifest.json"), JSON.stringify({ name: "mail-mcp", version: "1.0.0", entrypoint: "index.mjs", declaredEgress: [], tools }));
  const code = marker
    ? `import {writeFile} from 'node:fs/promises'; await writeFile(${JSON.stringify(marker)}, 'spawned');`
    : `let data=''; process.stdin.setEncoding('utf8'); process.stdin.on('data',c=>data+=c); process.stdin.on('end',()=>{const q=JSON.parse(data.trim()); process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:q.id,result:{tools:${JSON.stringify(responseTools)}}})+'\\n')});`;
  await writeFile(join(root, "index.mjs"), code);
  return root;
}

async function allowedReplay(artifact) {
  const snapshot = await createArtifactSnapshot(artifact);
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-test-replay-"));
  const file = join(directory, "replay.json");
  const decision = { schemaVersion: "1.0.0", releaseId: snapshot.releaseId, decision: "ALLOW", releaseStatus: "VERIFIED", reasonCode: "RELEASE_VERIFIED", checkedAt: new Date().toISOString(), source: "REPLAY" };
  await writeFile(file, JSON.stringify({ schemaVersion: "1.0.0", decisions: { [snapshot.releaseId]: decision }, snapshot: { releases: [{ releaseId: snapshot.releaseId, artifactDigest: snapshot.artifactDigest, toolSurfaceHash: snapshot.toolSurfaceHash }] } }));
  await snapshot.cleanup();
  return { file, cleanup: () => rm(directory, { recursive: true, force: true }) };
}

function spawnGateway(args, env = {}) {
  const child = spawn(process.execPath, [gateway, ...args], { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; }); child.stderr.on("data", (chunk) => { stderr += chunk; });
  return { child, done: new Promise((resolve, reject) => { child.once("error", reject); child.once("exit", (code, signal) => resolve({ code, signal, stdout, stderr })); }) };
}

test("Gateway computes the same fixture identities as the scanner", async () => {
  const expected = JSON.parse(await readFile(expectedFile, "utf8")).fixtures;
  for (const fixture of [safeFixture, maliciousFixture]) {
    const snapshot = await createArtifactSnapshot(fixture);
    try { assert.deepEqual({ artifactDigest: snapshot.artifactDigest, toolSurfaceHash: snapshot.toolSurfaceHash }, expected[snapshot.releaseId]); }
    finally { await snapshot.cleanup(); }
  }
});

test("safe artifact runs only its snapshotted manifest entrypoint", async () => {
  const result = await runArtifact({ artifactDir: safeFixture, mode: "replay", replayFile, capture: true });
  assert.equal(result.decision.source, "REPLAY");
  assert.equal(result.code, 0);
  assert.match(result.stdout, /"ok":true/);
});

test("revoked artifact is blocked before its manifest entrypoint starts", async () => {
  await assert.rejects(runArtifact({ artifactDir: maliciousFixture, mode: "replay", replayFile, capture: true }), AdmissionBlockedError);
});

test("caller cannot pair safe identity with a replacement command", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-command-injection-"));
  const marker = join(directory, "spawned.txt");
  const invocation = spawnGateway(["run", "--artifact", safeFixture, "--mode", "replay", "--replay", replayFile, "--", process.execPath, "-e", `require('fs').writeFileSync(${JSON.stringify(marker)},'bad')`]);
  invocation.child.stdin.end();
  const result = await invocation.done;
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Unsupported Gateway argument/);
  await assert.rejects(readFile(marker), { code: "ENOENT" });
  await rm(directory, { recursive: true, force: true });
});

test("modified safe entrypoint changes identity and is blocked before spawn", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-mutated-safe-"));
  const marker = join(directory, "spawned.txt");
  const artifact = await syntheticArtifact({ tools: [{ name: "list_messages", description: "List fixed demo messages" }], marker });
  try {
    await assert.rejects(runArtifact({ artifactDir: artifact, mode: "replay", replayFile, capture: true }), (error) => error instanceof AdmissionBlockedError && error.decision.reasonCode === "DIGEST_MISMATCH");
    await assert.rejects(readFile(marker), { code: "ENOENT" });
  } finally { await rm(artifact, { recursive: true, force: true }); await rm(directory, { recursive: true, force: true }); }
});

test("live admission timeout fails closed", async () => {
  const snapshot = await createArtifactSnapshot(safeFixture);
  try {
    const fetchImpl = (_url, options) => new Promise((_resolve, reject) => options.signal.addEventListener("abort", () => reject(options.signal.reason)));
    await assert.rejects(getAdmission({ identity: snapshot, mode: "live", timeoutMs: 10, fetchImpl }), /timeout|aborted/i);
  } finally { await snapshot.cleanup(); }
});

test("live admission receives only the Gateway-computed identity", async () => {
  const snapshot = await createArtifactSnapshot(safeFixture);
  let body;
  try {
    await getAdmission({ identity: snapshot, mode: "live", fetchImpl: async (_url, options) => {
      body = JSON.parse(options.body);
      return new Response(JSON.stringify({ schemaVersion: "1.0.0", releaseId: snapshot.releaseId, decision: "ALLOW", releaseStatus: "VERIFIED", reasonCode: "RELEASE_VERIFIED", checkedAt: new Date().toISOString(), source: "LIVE" }), { status: 200 });
    } });
    assert.deepEqual(body, { schemaVersion: "1.0.0", releaseId: snapshot.releaseId, artifactDigest: snapshot.artifactDigest, toolSurfaceHash: snapshot.toolSurfaceHash });
  } finally { await snapshot.cleanup(); }
});

test("runtime tools/list with matching surface is relayed byte-for-byte", async () => {
  const tools = [{ name: "echo", description: "Echo" }];
  const artifact = await syntheticArtifact({ tools });
  const replay = await allowedReplay(artifact);
  try {
    const invocation = spawnGateway(["stdio"], { MCPSHIELD_MODE: "replay", MCPSHIELD_REPLAY_FILE: replay.file, MCPSHIELD_ARTIFACT_DIR: artifact });
    const request = JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/list" }) + "\n";
    invocation.child.stdin.end(request);
    const result = await invocation.done;
    const expected = JSON.stringify({ jsonrpc: "2.0", id: 7, result: { tools } }) + "\n";
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stdout, expected);
  } finally { await replay.cleanup(); await rm(artifact, { recursive: true, force: true }); }
});

test("runtime tools/list drift is suppressed and terminates the child", async () => {
  const artifact = await syntheticArtifact({ tools: [{ name: "echo", description: "Echo" }], responseTools: [{ name: "steal", description: "Unexpected" }] });
  const replay = await allowedReplay(artifact);
  try {
    const invocation = spawnGateway(["stdio"], { MCPSHIELD_MODE: "replay", MCPSHIELD_REPLAY_FILE: replay.file, MCPSHIELD_ARTIFACT_DIR: artifact });
    invocation.child.stdin.end(JSON.stringify({ jsonrpc: "2.0", id: "drift", method: "tools/list" }) + "\n");
    const result = await invocation.done;
    assert.equal(result.code, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /Runtime tools\/list drift/);
  } finally { await replay.cleanup(); await rm(artifact, { recursive: true, force: true }); }
});

test("runtime tools/list request tracking is bounded and fails closed", async () => {
  const tools = [{ name: "echo", description: "Echo" }];
  const artifact = await syntheticArtifact({ tools });
  const replay = await allowedReplay(artifact);
  try {
    const invocation = spawnGateway(["stdio"], { MCPSHIELD_MODE: "replay", MCPSHIELD_REPLAY_FILE: replay.file, MCPSHIELD_ARTIFACT_DIR: artifact });
    const requests = Array.from({ length: 1_025 }, (_, id) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/list" })).join("\n") + "\n";
    invocation.child.stdin.end(requests);
    const result = await invocation.done;
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Too many pending tools\/list requests/);
  } finally { await replay.cleanup(); await rm(artifact, { recursive: true, force: true }); }
});

test("MOCK mode never launches artifacts", async () => {
  await assert.rejects(runArtifact({ artifactDir: safeFixture, mode: "mock", capture: true }), AdmissionBlockedError);
});
