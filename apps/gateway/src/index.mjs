import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";

const RELEASE_ID = /^.+@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const ARTIFACT_DIGEST = /^sha256:[0-9a-f]{64}$/;
const TOOL_SURFACE_HASH = /^0x[0-9a-f]{64}$/;
const STATUSES = new Set(["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED"]);
const SOURCES = new Set(["LIVE", "MOCK", "REPLAY"]);
const REASONS = new Set(["RELEASE_VERIFIED", "RELEASE_UNVERIFIED", "RELEASE_QUARANTINED", "RELEASE_REVOKED", "DIGEST_MISMATCH", "STATUS_UNAVAILABLE"]);
const DECISION_KEYS = new Set(["schemaVersion", "releaseId", "decision", "releaseStatus", "reasonCode", "checkedAt", "source"]);

const MOCK_RELEASES = new Map([
  ["mail-mcp@1.0.0", { artifactDigest: `sha256:${"a".repeat(64)}`, toolSurfaceHash: `0x${"b".repeat(64)}`, status: "VERIFIED" }],
  ["mail-mcp@1.0.1", { artifactDigest: `sha256:${"c".repeat(64)}`, toolSurfaceHash: `0x${"d".repeat(64)}`, status: "REVOKED" }],
]);

export class AdmissionBlockedError extends Error {
  constructor(decision) {
    super(`MCPShield blocked ${decision.releaseId}: ${decision.reasonCode}`);
    this.name = "AdmissionBlockedError";
    this.decision = decision;
  }
}

function log(event, fields = {}) {
  process.stderr.write(`${JSON.stringify({ time: new Date().toISOString(), event, ...fields })}\n`);
}

function mismatchDecision(releaseId, releaseStatus, source, checkedAt = new Date().toISOString()) {
  return {
    schemaVersion: "1.0.0",
    releaseId,
    decision: "BLOCK",
    releaseStatus,
    reasonCode: "DIGEST_MISMATCH",
    checkedAt,
    source,
  };
}

function decisionFor(releaseId, artifactDigest, toolSurfaceHash, source) {
  const expected = MOCK_RELEASES.get(releaseId);
  const releaseStatus = expected?.status ?? "UNVERIFIED";
  const mismatch = expected && (expected.artifactDigest !== artifactDigest || expected.toolSurfaceHash !== toolSurfaceHash);
  if (mismatch) return mismatchDecision(releaseId, releaseStatus, source);
  const allow = releaseStatus === "VERIFIED";
  return {
    schemaVersion: "1.0.0",
    releaseId,
    decision: allow ? "ALLOW" : "BLOCK",
    releaseStatus,
    reasonCode: expected ? `RELEASE_${releaseStatus}` : "STATUS_UNAVAILABLE",
    checkedAt: new Date().toISOString(),
    source,
  };
}

function validateDecision(value, releaseId) {
  if (!value || value.schemaVersion !== "1.0.0" || value.releaseId !== releaseId) {
    throw new Error("Admission response does not match schemaVersion/releaseId");
  }
  if (Object.keys(value).some((key) => !DECISION_KEYS.has(key))) {
    throw new Error("Admission response contains unknown fields");
  }
  if (!new Set(["ALLOW", "BLOCK"]).has(value.decision) || !STATUSES.has(value.releaseStatus)) {
    throw new Error("Admission response contains an unknown decision or releaseStatus");
  }
  if (!REASONS.has(value.reasonCode) || !SOURCES.has(value.source) || Number.isNaN(Date.parse(value.checkedAt))) {
    throw new Error("Admission response contains an invalid reasonCode, source, or checkedAt");
  }
  if ((value.decision === "ALLOW") !== (value.releaseStatus === "VERIFIED" && value.reasonCode === "RELEASE_VERIFIED")) {
    throw new Error("Admission response has an inconsistent allow decision");
  }
  return value;
}

function assertIdentity(releaseId, artifactDigest, toolSurfaceHash) {
  if (!RELEASE_ID.test(releaseId)) throw new Error(`Invalid releaseId: ${releaseId}`);
  if (!ARTIFACT_DIGEST.test(artifactDigest)) throw new Error(`Invalid artifactDigest: ${artifactDigest}`);
  if (!TOOL_SURFACE_HASH.test(toolSurfaceHash)) throw new Error(`Invalid toolSurfaceHash: ${toolSurfaceHash}`);
}

export async function getAdmission({
  releaseId,
  artifactDigest,
  toolSurfaceHash,
  mode = process.env.MCPSHIELD_MODE ?? "live",
  apiBaseUrl = process.env.MCPSHIELD_API_URL ?? "http://127.0.0.1:3001",
  replayFile = process.env.MCPSHIELD_REPLAY_FILE,
  timeoutMs = Number(process.env.MCPSHIELD_ADMISSION_TIMEOUT_MS ?? 3000),
  fetchImpl = fetch,
}) {
  assertIdentity(releaseId, artifactDigest, toolSurfaceHash);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
    throw new Error("Admission timeout must be an integer between 1 and 30000ms");
  }

  if (mode === "mock") return validateDecision(decisionFor(releaseId, artifactDigest, toolSurfaceHash, "MOCK"), releaseId);
  if (mode === "replay") {
    if (!replayFile) throw new Error("MCPSHIELD_REPLAY_FILE is required in replay mode");
    const replay = JSON.parse(await readFile(replayFile, "utf8"));
    const saved = replay.decisions?.[releaseId];
    if (!saved) throw new Error(`Replay has no admission decision for ${releaseId}`);
    const expected = replay.snapshot?.releases?.find((release) => release.releaseId === releaseId);
    if (!expected || expected.artifactDigest !== artifactDigest || expected.toolSurfaceHash !== toolSurfaceHash) {
      return validateDecision(mismatchDecision(releaseId, saved.releaseStatus ?? "UNVERIFIED", "REPLAY", saved.checkedAt), releaseId);
    }
    return validateDecision({ ...saved, source: "REPLAY" }, releaseId);
  }
  if (mode !== "live") throw new Error(`Unknown MCPShield mode: ${mode}`);

  const response = await fetchImpl(`${apiBaseUrl.replace(/\/$/, "")}/api/admission/check`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ schemaVersion: "1.0.0", releaseId, artifactDigest, toolSurfaceHash }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`Admission API returned ${response.status}`);
  return validateDecision(await response.json(), releaseId);
}

function allowedCommands() {
  const configured = process.env.MCPSHIELD_ALLOWED_COMMANDS;
  return new Set((configured ? configured.split(",") : ["node", "node.exe", "npx", "npx.cmd"])
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean));
}

function assertCommand(command) {
  if (!command || !allowedCommands().has(basename(command).toLowerCase())) {
    throw new Error(`Command is not allowlisted: ${command || "<empty>"}`);
  }
}

function spawnChild(command, args, stdio) {
  assertCommand(command);
  return spawn(command, args, { shell: false, windowsHide: true, stdio });
}

function execute(command, args, { capture = false, timeoutMs = 15_000 } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new Error("Execution timeout must be a positive integer");
  return new Promise((resolve, reject) => {
    const child = spawnChild(command, args, capture ? ["ignore", "pipe", "pipe"] : "inherit");
    let stdout = "";
    let stderr = "";
    let settled = false;
    child.stdout?.on("data", (chunk) => { stdout += chunk; });
    child.stderr?.on("data", (chunk) => { stderr += chunk; });
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback();
    };
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      finish(() => reject(new Error(`Child execution timed out after ${timeoutMs}ms`)));
    }, timeoutMs);
    child.once("error", (error) => finish(() => reject(error)));
    child.once("exit", (code, signal) => finish(() => signal
      ? reject(new Error(`Child terminated by ${signal}`))
      : resolve({ code: code ?? 1, stdout, stderr })));
  });
}

export async function runRelease({ releaseId, artifactDigest, toolSurfaceHash, command, args = [], capture = false, executionTimeoutMs, ...admissionOptions }) {
  const decision = await getAdmission({ releaseId, artifactDigest, toolSurfaceHash, ...admissionOptions });
  log("admission", { releaseId, decision: decision.decision, status: decision.releaseStatus, source: decision.source });
  if (decision.decision !== "ALLOW" || decision.releaseStatus !== "VERIFIED") throw new AdmissionBlockedError(decision);
  const result = await execute(command, args, { capture, timeoutMs: executionTimeoutMs ?? 15_000 });
  log("process_exit", { releaseId, command: basename(command), code: result.code });
  return { decision, ...result };
}

export async function proxyStdio({ releaseId, artifactDigest, toolSurfaceHash, command, args = [], ...admissionOptions }) {
  const decision = await getAdmission({ releaseId, artifactDigest, toolSurfaceHash, ...admissionOptions });
  log("admission", { releaseId, decision: decision.decision, status: decision.releaseStatus, source: decision.source });
  if (decision.decision !== "ALLOW" || decision.releaseStatus !== "VERIFIED") throw new AdmissionBlockedError(decision);

  const child = spawnChild(command, args, ["pipe", "pipe", "pipe"]);
  process.stdin.pipe(child.stdin);
  child.stdout.pipe(process.stdout);
  child.stderr.pipe(process.stderr);

  let cleaned = false;
  const cleanup = (signal = "SIGTERM") => {
    if (cleaned) return;
    cleaned = true;
    process.stdin.unpipe(child.stdin);
    child.stdout.unpipe(process.stdout);
    child.stderr.unpipe(process.stderr);
    if (!child.killed && child.exitCode === null) child.kill(signal);
  };
  const signalHandlers = new Map();
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    const handler = () => cleanup(signal);
    signalHandlers.set(signal, handler);
    process.once(signal, handler);
  }
  const removeHandlers = () => {
    for (const [signal, handler] of signalHandlers) process.removeListener(signal, handler);
  };

  return new Promise((resolve, reject) => {
    child.once("error", (error) => {
      cleanup();
      removeHandlers();
      reject(error);
    });
    child.once("exit", (code, signal) => {
      cleanup();
      removeHandlers();
      log("process_exit", { releaseId, command: basename(command), code, signal });
      signal ? reject(new Error(`Child terminated by ${signal}`)) : resolve(code ?? 1);
    });
  });
}

async function stdio() {
  const releaseId = process.env.MCPSHIELD_RELEASE_ID;
  const artifactDigest = process.env.MCPSHIELD_ARTIFACT_DIGEST;
  const toolSurfaceHash = process.env.MCPSHIELD_TOOL_SURFACE_HASH;
  const command = JSON.parse(process.env.MCPSHIELD_COMMAND_JSON ?? "[]");
  if (!releaseId || !artifactDigest || !toolSurfaceHash || !Array.isArray(command) || !command.every((item) => typeof item === "string") || command.length === 0) {
    throw new Error("MCPSHIELD_RELEASE_ID, MCPSHIELD_ARTIFACT_DIGEST, MCPSHIELD_TOOL_SURFACE_HASH, and a non-empty JSON-array MCPSHIELD_COMMAND_JSON are required");
  }
  process.exitCode = await proxyStdio({ releaseId, artifactDigest, toolSurfaceHash, command: command[0], args: command.slice(1) });
}

function serve() {
  const port = Number(process.env.PORT ?? 8787);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be valid");
  createServer((request, response) => {
    response.setHeader("cache-control", "no-store");
    if (request.method === "GET" && request.url === "/health") {
      response.writeHead(200, { "content-type": "application/json" });
      return response.end(JSON.stringify({ schemaVersion: "1.0.0", status: "ok", mode: (process.env.MCPSHIELD_MODE ?? "live").toUpperCase() }));
    }
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not_found" }));
  }).listen(port, "0.0.0.0", () => log("gateway_ready", { port }));
}

function option(args, name, fallback) {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1];
}

async function main() {
  const [subcommand = "stdio", ...args] = process.argv.slice(2);
  if (subcommand === "stdio") return stdio();
  if (subcommand === "serve") return serve();
  if (subcommand !== "run") throw new Error(`Unknown command: ${subcommand}`);
  const split = args.indexOf("--");
  const command = split === -1 ? [] : args.slice(split + 1);
  try {
    const result = await runRelease({
      releaseId: option(args, "--release"),
      artifactDigest: option(args, "--digest"),
      toolSurfaceHash: option(args, "--surface"),
      mode: option(args, "--mode", process.env.MCPSHIELD_MODE ?? "live"),
      replayFile: option(args, "--replay", process.env.MCPSHIELD_REPLAY_FILE),
      command: command[0],
      args: command.slice(1),
    });
    process.exitCode = result.code;
  } catch (error) {
    if (error instanceof AdmissionBlockedError) {
      process.stderr.write(`${JSON.stringify(error.decision)}\n`);
      process.exitCode = 3;
      return;
    }
    throw error;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((error) => {
    if (error instanceof AdmissionBlockedError) {
      log("gateway_blocked", { ...error.decision });
      process.exitCode = 3;
    } else {
      log("gateway_error", { message: error.message });
      process.exitCode = 1;
    }
  });
}
