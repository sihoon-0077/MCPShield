import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { Transform } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createArtifactSnapshot, toolSurfaceHash } from "./artifact.mjs";

const STATUSES = new Set(["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED"]);
const SOURCES = new Set(["LIVE", "MOCK", "REPLAY"]);
const REASONS = new Set(["RELEASE_VERIFIED", "RELEASE_UNVERIFIED", "RELEASE_QUARANTINED", "RELEASE_REVOKED", "DIGEST_MISMATCH", "STATUS_UNAVAILABLE"]);
const DECISION_KEYS = new Set(["schemaVersion", "releaseId", "decision", "releaseStatus", "reasonCode", "checkedAt", "source"]);
const RUNTIME_GUARD = fileURLToPath(new URL("./runtime-guard.cjs", import.meta.url));

export class AdmissionBlockedError extends Error {
  constructor(decision) {
    super(`MCPShield blocked ${decision.releaseId}: ${decision.reasonCode}`);
    this.name = "AdmissionBlockedError";
    this.decision = decision;
  }
}

export class ToolSurfaceDriftError extends Error {
  constructor(expected, observed) {
    super(`Runtime tools/list drift: expected ${expected}, observed ${observed}`);
    this.name = "ToolSurfaceDriftError";
    this.expected = expected;
    this.observed = observed;
  }
}

function log(event, fields = {}) {
  process.stderr.write(`${JSON.stringify({ time: new Date().toISOString(), event, ...fields })}\n`);
}

function validateDecision(value, releaseId) {
  if (!value || value.schemaVersion !== "1.0.0" || value.releaseId !== releaseId) throw new Error("Admission response does not match schemaVersion/releaseId");
  if (Object.keys(value).some((key) => !DECISION_KEYS.has(key))) throw new Error("Admission response contains unknown fields");
  if (!new Set(["ALLOW", "BLOCK"]).has(value.decision) || !STATUSES.has(value.releaseStatus)) throw new Error("Admission response contains an unknown decision or releaseStatus");
  if (!REASONS.has(value.reasonCode) || !SOURCES.has(value.source) || Number.isNaN(Date.parse(value.checkedAt))) throw new Error("Admission response contains invalid metadata");
  if ((value.decision === "ALLOW") !== (value.releaseStatus === "VERIFIED" && value.reasonCode === "RELEASE_VERIFIED")) throw new Error("Admission response has an inconsistent allow decision");
  return value;
}

function mockDecision(identity) {
  return validateDecision({ schemaVersion: "1.0.0", releaseId: identity.releaseId, decision: "BLOCK", releaseStatus: "UNVERIFIED", reasonCode: "STATUS_UNAVAILABLE", checkedAt: new Date().toISOString(), source: "MOCK" }, identity.releaseId);
}

export async function getAdmission({ identity, mode = process.env.MCPSHIELD_MODE ?? "live", apiBaseUrl = process.env.MCPSHIELD_API_URL ?? "http://127.0.0.1:3001", replayFile = process.env.MCPSHIELD_REPLAY_FILE, timeoutMs = Number(process.env.MCPSHIELD_ADMISSION_TIMEOUT_MS ?? 3000), fetchImpl = fetch }) {
  if (!identity?.releaseId || !identity.artifactDigest || !identity.toolSurfaceHash) throw new Error("Gateway-owned artifact identity is required");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) throw new Error("Admission timeout must be between 1 and 30000ms");
  if (mode === "mock") return mockDecision(identity);
  if (mode === "replay") {
    if (!replayFile) throw new Error("MCPSHIELD_REPLAY_FILE is required in replay mode");
    const replay = JSON.parse(await readFile(replayFile, "utf8"));
    const saved = replay.decisions?.[identity.releaseId];
    const expected = replay.snapshot?.releases?.find((release) => release.releaseId === identity.releaseId);
    if (!saved || !expected) throw new Error(`Replay has no admission evidence for ${identity.releaseId}`);
    if (expected.artifactDigest !== identity.artifactDigest || expected.toolSurfaceHash !== identity.toolSurfaceHash) {
      return validateDecision({ ...saved, decision: "BLOCK", reasonCode: "DIGEST_MISMATCH", source: "REPLAY" }, identity.releaseId);
    }
    return validateDecision({ ...saved, source: "REPLAY" }, identity.releaseId);
  }
  if (mode !== "live") throw new Error(`Unknown MCPShield mode: ${mode}`);
  const response = await fetchImpl(`${apiBaseUrl.replace(/\/$/, "")}/api/admission/check`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ schemaVersion: "1.0.0", releaseId: identity.releaseId, artifactDigest: identity.artifactDigest, toolSurfaceHash: identity.toolSurfaceHash }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`Admission API returned ${response.status}`);
  return validateDecision(await response.json(), identity.releaseId);
}

function childEnvironment() {
  const configured = (process.env.MCPSHIELD_CHILD_ENV_ALLOWLIST ?? "")
    .split(",").map((key) => key.trim()).filter((key) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(key));
  const denied = /^(?:NODE_OPTIONS|NODE_PATH|LD_|DYLD_)/i;
  const allowed = new Set([
    "PATH", "Path", "PATHEXT", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
    ...configured.filter((key) => !denied.test(key)),
  ]);
  const env = { MCP_SHIELD_GATEWAY: "1" };
  for (const key of allowed) if (process.env[key] !== undefined) env[key] = process.env[key];
  return env;
}

function spawnSnapshot(snapshot) {
  if (!process.allowedNodeEnvironmentFlags.has("--permission")) throw new Error("Node permission model is required");
  return spawn(process.execPath, ["--permission", `--allow-fs-read=${snapshot.root}`,
    `--allow-fs-read=${RUNTIME_GUARD}`, "--disallow-code-generation-from-strings",
    "--require", RUNTIME_GUARD, snapshot.entrypoint],
    { cwd: snapshot.root, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"], env: childEnvironment() });
}

function lineTransform(onMessage) {
  let pending = Buffer.alloc(0);
  const inspect = (line) => {
    const text = line.toString("utf8").trim();
    if (!text) return;
    let message;
    try { message = JSON.parse(text); } catch { throw new Error("MCP stdio emitted invalid newline-delimited JSON-RPC"); }
    onMessage(message);
  };
  return new Transform({
    transform(chunk, _encoding, callback) {
      try {
        pending = Buffer.concat([pending, Buffer.from(chunk)]);
        if (pending.byteLength > 1024 * 1024) throw new Error("MCP JSON-RPC line exceeds 1 MiB");
        let newline;
        while ((newline = pending.indexOf(0x0a)) !== -1) {
          const line = pending.subarray(0, newline + 1);
          pending = pending.subarray(newline + 1);
          inspect(line);
          this.push(line);
        }
        callback();
      } catch (error) { callback(error); }
    },
    flush(callback) {
      try { if (pending.length) { inspect(pending); this.push(pending); } callback(); } catch (error) { callback(error); }
    },
  });
}

const idKey = (id) => `${typeof id}:${JSON.stringify(id)}`;

function eachMessage(value, inspect) {
  if (!Array.isArray(value)) return inspect(value);
  if (!value.length) throw new Error("Empty JSON-RPC batches are not allowed");
  for (const message of value) inspect(message);
}

export function runtimeSurfaceGuards(expectedHash, tools = []) {
  const listRequests = new Map();
  const allowedTools = new Set(tools.map(({ name }) => name));
  const makeRoom = () => {
    if (listRequests.size < 1_024) return;
    const completed = [...listRequests].find(([, state]) => state === "COMPLETE");
    if (completed) listRequests.delete(completed[0]);
    else throw new Error("Too many pending tools/list requests");
  };
  const requests = lineTransform((value) => eachMessage(value, (message) => {
    if (!message || typeof message !== "object" || Array.isArray(message)) throw new Error("JSON-RPC batch contains an invalid request");
    if (message.jsonrpc !== "2.0") return;
    if (message.method === "tools/call" && !allowedTools.has(message.params?.name)) {
      throw new Error(`Undeclared runtime tool call: ${String(message.params?.name)}`);
    }
    if (Object.hasOwn(message, "id")) {
      const key = idKey(message.id);
      if (message.method === "tools/list") {
        if (listRequests.get(key) === "PENDING") throw new Error("Duplicate pending tools/list request id");
        if (!listRequests.has(key)) makeRoom();
        listRequests.set(key, "PENDING");
      } else if (listRequests.get(key) === "COMPLETE") listRequests.delete(key);
    }
  }));
  const responses = lineTransform((value) => eachMessage(value, (message) => {
    if (!message || typeof message !== "object" || Array.isArray(message)) throw new Error("JSON-RPC batch contains an invalid response");
    const key = Object.hasOwn(message, "id") ? idKey(message.id) : undefined;
    if (!key || !listRequests.has(key)) return;
    if (listRequests.get(key) === "COMPLETE") throw new Error("Duplicate tools/list response");
    listRequests.set(key, "COMPLETE");
    if (message.error) return;
    if (!Array.isArray(message.result?.tools)) throw new ToolSurfaceDriftError(expectedHash, "INVALID_TOOLS_LIST");
    const observed = toolSurfaceHash(message.result.tools);
    if (observed !== expectedHash) throw new ToolSurfaceDriftError(expectedHash, observed);
  }));
  return { requests, responses };
}

function terminateChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const force = setTimeout(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }, 500);
  force.unref();
}

async function admittedSnapshot(artifactDir, options) {
  const snapshot = await createArtifactSnapshot(artifactDir);
  try {
    const decision = await getAdmission({ ...options, identity: snapshot });
    log("admission", { releaseId: snapshot.releaseId, artifactDigest: snapshot.artifactDigest, toolSurfaceHash: snapshot.toolSurfaceHash, decision: decision.decision, status: decision.releaseStatus, source: decision.source });
    if (decision.decision !== "ALLOW" || decision.releaseStatus !== "VERIFIED") throw new AdmissionBlockedError(decision);
    if (snapshot.runtimePolicyIssues.length) throw new Error(`Gateway runtime policy rejected ${snapshot.runtimePolicyIssues[0].path}: ${snapshot.runtimePolicyIssues[0].reason}`);
    return { snapshot, decision };
  } catch (error) {
    await snapshot.cleanup();
    throw error;
  }
}

export async function runArtifact({ artifactDir, capture = false, executionTimeoutMs = 15_000, ...options }) {
  const { snapshot, decision } = await admittedSnapshot(artifactDir, options);
  try {
    const child = spawnSnapshot(snapshot);
    let stdout = "";
    let stderr = "";
    let outputBytes = 0;
    let outputError;
    const receive = (target, chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > 1_048_576) {
        outputError ??= new Error("Child output exceeded 1048576 bytes");
        terminateChild(child);
        return;
      }
      if (capture) target === "stdout" ? stdout += chunk : stderr += chunk;
      else target === "stdout" ? process.stdout.write(chunk) : process.stderr.write(chunk);
    };
    child.stdout.on("data", (chunk) => receive("stdout", chunk));
    child.stderr.on("data", (chunk) => receive("stderr", chunk));
    const result = await new Promise((resolve, reject) => {
      let settled = false;
      let timeoutError;
      const finish = (callback) => { if (settled) return; settled = true; clearTimeout(timer); callback(); };
      const timer = setTimeout(() => { timeoutError = new Error(`Child execution timed out after ${executionTimeoutMs}ms`); terminateChild(child); }, executionTimeoutMs);
      child.once("error", (error) => finish(() => reject(error)));
      child.once("exit", (code, signal) => finish(() => outputError ? reject(outputError) : timeoutError ? reject(timeoutError) : signal ? reject(new Error(`Child terminated by ${signal}`)) : resolve({ code: code ?? 1, stdout, stderr })));
    });
    return { decision, identity: { releaseId: snapshot.releaseId, artifactDigest: snapshot.artifactDigest, toolSurfaceHash: snapshot.toolSurfaceHash }, ...result };
  } finally { await snapshot.cleanup(); }
}

export async function proxyArtifactStdio({ artifactDir, ...options }) {
  const { snapshot } = await admittedSnapshot(artifactDir, options);
  const child = spawnSnapshot(snapshot);
  const { requests, responses } = runtimeSurfaceGuards(snapshot.toolSurfaceHash, snapshot.tools);
  let terminalError;
  let cleaned = false;
  const cleanup = (signal = "SIGTERM") => {
    if (cleaned) return;
    cleaned = true;
    process.stdin.unpipe(requests);
    requests.unpipe(child.stdin);
    child.stdout.unpipe(responses);
    responses.unpipe(process.stdout);
    child.stderr.unpipe(process.stderr);
    if (child.exitCode === null && child.signalCode === null) terminateChild(child);
  };
  process.stdin.pipe(requests).pipe(child.stdin);
  child.stdout.pipe(responses).pipe(process.stdout);
  child.stderr.pipe(process.stderr);
  const fail = (error) => { terminalError = error; log("gateway_runtime_blocked", { releaseId: snapshot.releaseId, error: error.message }); cleanup(); };
  requests.once("error", fail);
  responses.once("error", fail);
  const handlers = new Map();
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) { const handler = () => cleanup(signal); handlers.set(signal, handler); process.once(signal, handler); }
  try {
    return await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code, signal) => terminalError ? reject(terminalError) : signal ? reject(new Error(`Child terminated by ${signal}`)) : resolve(code ?? 1));
    });
  } finally {
    cleanup();
    for (const [signal, handler] of handlers) process.removeListener(signal, handler);
    await snapshot.cleanup();
  }
}

async function stdio() {
  const artifactDir = process.env.MCPSHIELD_ARTIFACT_DIR;
  if (!artifactDir) throw new Error("MCPSHIELD_ARTIFACT_DIR is required");
  process.exitCode = await proxyArtifactStdio({ artifactDir });
}

function serve() {
  const port = Number(process.env.PORT ?? 8787);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be valid");
  createServer((request, response) => {
    response.setHeader("cache-control", "no-store");
    if (request.method === "GET" && request.url === "/health") { response.writeHead(200, { "content-type": "application/json" }); return response.end(JSON.stringify({ schemaVersion: "1.0.0", status: "ok", mode: (process.env.MCPSHIELD_MODE ?? "live").toUpperCase() })); }
    response.writeHead(404, { "content-type": "application/json" }); response.end(JSON.stringify({ error: "not_found" }));
  }).listen(port, "0.0.0.0", () => log("gateway_ready", { port }));
}

function parseRun(args) {
  const allowed = new Set(["--artifact", "--mode", "--replay"]);
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index]; const value = args[index + 1];
    if (!allowed.has(key) || value === undefined) throw new Error(`Unsupported Gateway argument: ${key ?? "<missing>"}`);
    parsed[key.slice(2)] = value;
  }
  if (!parsed.artifact) throw new Error("--artifact is required");
  return parsed;
}

async function main() {
  const [subcommand = "stdio", ...args] = process.argv.slice(2);
  if (subcommand === "stdio") return stdio();
  if (subcommand === "serve") return serve();
  if (subcommand !== "run") throw new Error(`Unknown command: ${subcommand}`);
  const parsed = parseRun(args);
  try {
    const result = await runArtifact({ artifactDir: parsed.artifact, mode: parsed.mode ?? process.env.MCPSHIELD_MODE ?? "live", replayFile: parsed.replay ?? process.env.MCPSHIELD_REPLAY_FILE });
    process.exitCode = result.code;
  } catch (error) {
    if (error instanceof AdmissionBlockedError) { process.stderr.write(`${JSON.stringify(error.decision)}\n`); process.exitCode = 3; return; }
    throw error;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main().catch((error) => { log("gateway_error", { name: error.name, message: error.message }); process.exitCode = error instanceof AdmissionBlockedError ? 3 : 1; });
