import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { createArtifactSnapshot } from "./artifact.mjs";
import { runtimeSurfaceGuards } from "./protocol-guard.mjs";
export { runtimeSurfaceGuards, ToolSurfaceDriftError } from "./protocol-guard.mjs";
import { admissionFetch, getSignedAdmission } from "./signed-admission.mjs";
import { currentTraceId, recordAdmission, withSpan } from "../../../packages/telemetry/index.mjs";

const STATUSES = new Set(["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED"]);
const SOURCES = new Set(["LIVE", "MOCK", "REPLAY"]);
const REASONS = new Set(["RELEASE_VERIFIED", "RELEASE_UNVERIFIED", "RELEASE_QUARANTINED", "RELEASE_REVOKED", "DIGEST_MISMATCH", "STATUS_UNAVAILABLE"]);
const DECISION_KEYS = new Set(["schemaVersion", "releaseId", "decision", "releaseStatus", "reasonCode", "checkedAt", "source"]);
const RUNTIME_GUARD = fileURLToPath(new URL("./runtime-guard.cjs", import.meta.url));
const MCP_LANDING_PAGE = readFileSync(new URL("./mcp-landing.html", import.meta.url));

export class AdmissionBlockedError extends Error {
  constructor(decision) {
    super(`MCPShield blocked ${decision.releaseId}: ${decision.reasonCode} (${decision.releaseStatus})${decision.reportUrl ? `; report: ${decision.reportUrl}` : ""}`);
    this.name = "AdmissionBlockedError";
    this.decision = decision;
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

export async function getAdmission(options) {
  return withSpan("admission.check", { "mcpshield.release_id": options.identity?.releaseId }, async () => {
    const started = performance.now();
    let decision = "BLOCK";
    let source = String(options.mode ?? process.env.MCPSHIELD_MODE ?? "live").toUpperCase();
    try {
      const result = await checkAdmission(options);
      decision = result.decision; source = result.cacheHit ? "CACHE" : result.source;
      return result;
    } finally {
      recordAdmission({ decision, source, riskTier: ["READ_PUBLIC", "READ_PRIVATE"].includes(options.operationClass) ? "READ_ONLY" : "WRITE", durationSeconds: (performance.now() - started) / 1000 });
      const traceId = currentTraceId();
      if (traceId && !/^0+$/.test(traceId)) log("admission_checked", { traceId, decision, source });
    }
  });
}

async function checkAdmission({ identity, mode = process.env.MCPSHIELD_MODE ?? "live", apiBaseUrl = process.env.MCPSHIELD_API_URL ?? "http://127.0.0.1:3001", replayFile = process.env.MCPSHIELD_REPLAY_FILE, timeoutMs = Number(process.env.MCPSHIELD_ADMISSION_TIMEOUT_MS ?? 3000), fetchImpl = fetch, ...signedOptions }) {
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
  if (signedOptions.policyHash || process.env.MCPSHIELD_POLICY_HASH) {
    return getSignedAdmission({ ...signedOptions, identity, apiBaseUrl, timeoutMs, fetchImpl });
  }
  if ((signedOptions.admissionMode ?? process.env.MCPSHIELD_ADMISSION_MODE ?? "strict") !== "strict") throw new Error("Balanced admission requires a signed policy trust context");
  const response = await admissionFetch(`${apiBaseUrl.replace(/\/$/, "")}/api/admission/check`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ schemaVersion: "1.0.0", releaseId: identity.releaseId, artifactDigest: identity.artifactDigest, toolSurfaceHash: identity.toolSurfaceHash }),
  }, fetchImpl, timeoutMs);
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

async function spawnSnapshot(snapshot, options) {
  if (snapshot.prepared) return snapshot.spawn(() => admitSnapshot(snapshot, options));
  if (!process.allowedNodeEnvironmentFlags.has("--permission")) throw new Error("Node permission model is required");
  const child = spawn(process.execPath, ["--permission", `--allow-fs-read=${snapshot.root}`,
    `--allow-fs-read=${RUNTIME_GUARD}`, "--disallow-code-generation-from-strings",
    "--require", RUNTIME_GUARD, snapshot.entrypoint],
    { cwd: snapshot.root, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"], env: childEnvironment() });
  await once(child, "spawn");
  return child;
}

function terminateChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const force = setTimeout(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }, 500);
  force.unref();
}

function childSurfaceGuards(child, snapshot, options) {
  return runtimeSurfaceGuards(snapshot.toolSurfaceHash, snapshot.tools, recheckSession(snapshot, options), {
    sendInternal: (message) => new Promise((resolve, reject) => child.stdin.write(`${JSON.stringify(message)}\n`, (error) => error ? reject(error) : resolve())),
  });
}

function stderrSummary(chunk) {
  const text = chunk.toString("utf8");
  const category = /ERR_ACCESS_DENIED|permission/i.test(text) ? "PERMISSION_DENIED" : /Code generation from strings disallowed|EvalError/.test(text) ? "CODE_GENERATION_DENIED" : /runtime egress is disabled/.test(text) ? "EGRESS_DENIED" : "CHILD_DIAGNOSTIC";
  return `${JSON.stringify({ event: "child_stderr_suppressed", bytes: chunk.length, category })}\n`;
}

async function admittedSnapshot(artifactDir, options) {
  let snapshot;
  if (options.preparedIdentityPath) {
    if (artifactDir) throw new Error("PREPARED_IDENTITY_AMBIGUOUS");
    if ((options.mode ?? process.env.MCPSHIELD_MODE ?? "live") !== "live" || !(options.policyHash ?? process.env.MCPSHIELD_POLICY_HASH)) throw new Error("PREPARED_SIGNED_LIVE_REQUIRED");
    const { createPreparedSnapshot } = await import("./prepared.mjs");
    snapshot = await createPreparedSnapshot(options.preparedIdentityPath);
  } else snapshot = await createArtifactSnapshot(artifactDir);
  try {
    const configuredId = options.controlReleaseId ?? process.env.MCPSHIELD_CONTROL_RELEASE_ID;
    if (snapshot.prepared && configuredId && configuredId !== snapshot.releaseId) throw new Error("PREPARED_CONTROL_RELEASE_MISMATCH");
    const decision = await admitSnapshot(snapshot, options);
    return { snapshot, decision };
  } catch (error) {
    await snapshot.cleanup();
    throw error;
  }
}

async function admitSnapshot(snapshot, options) {
  const decision = await checkedDecision(snapshot, options, "__admission__", "ADMISSION", operationClass(snapshot.tools));
  log("admission", { releaseId: snapshot.releaseId, artifactDigest: snapshot.artifactDigest, toolSurfaceHash: snapshot.toolSurfaceHash, decision: decision.decision, status: decision.releaseStatus, source: decision.source, cacheHit: decision.cacheHit, expiresAt: decision.expiresAt });
  if (decision.decision !== "ALLOW" || decision.releaseStatus !== "VERIFIED") throw new AdmissionBlockedError(decision);
  if (snapshot.runtimePolicyIssues.length) throw new Error(`Gateway runtime policy rejected ${snapshot.runtimePolicyIssues[0].path}: ${snapshot.runtimePolicyIssues[0].reason}`);
  return decision;
}

export async function inspectArtifact({ artifactDir, rollout = "observe", ...options }) {
  if (!["observe", "warn", "enforce"].includes(rollout)) throw new Error("Rollout must be observe, warn, or enforce");
  const snapshot = await createArtifactSnapshot(artifactDir);
  try {
    const decision = await getAdmission({ ...options, identity: snapshot, operationClass: operationClass(snapshot.tools) });
    return { ...decision, rollout, artifactDigest: snapshot.artifactDigest, toolSurfaceHash: snapshot.toolSurfaceHash,
      assessment: rollout === "observe" ? "RECORD_ONLY" : rollout === "warn" && decision.decision !== "ALLOW" ? "REVIEW_REQUIRED" : decision.decision,
      spawnAttempted: false };
  } finally { await snapshot.cleanup(); }
}

function operationClass(tools) {
  return tools.length && tools.every((tool) => tool.annotations?.readOnlyHint === true && tool.annotations?.destructiveHint === false) ? "READ_PRIVATE" : "WRITE_EXTERNAL";
}

async function checkedDecision(snapshot, options, toolName, phase, actionClass) {
  const receiptPath = options.receiptPath ?? process.env.MCPSHIELD_RECEIPT_DB;
  const record = async (decision) => {
    if (!receiptPath || ["READ_PUBLIC", "READ_PRIVATE"].includes(actionClass)) return;
    const { appendConfiguredReceipt } = await import("./receipts.mjs");
    const result = appendConfiguredReceipt(receiptPath, {
      agentIdHash: options.receiptAgentHash ?? process.env.MCPSHIELD_RECEIPT_AGENT_HASH,
      requestedScopeHash: options.receiptScopeHash ?? process.env.MCPSHIELD_RECEIPT_SCOPE_HASH,
      releaseId: options.controlReleaseId ?? process.env.MCPSHIELD_CONTROL_RELEASE_ID ?? decision.releaseId,
      policyHash: options.policyHash ?? process.env.MCPSHIELD_POLICY_HASH,
      toolName, phase, operationClass: actionClass, decision: decision.decision, reasonCode: decision.reasonCode,
      source: decision.source, traceId: currentTraceId() ?? null,
    });
    log("private_receipt_appended", { receiptId: result.receipt.receiptId, receiptHash: result.receiptHash, assurance: "LOCAL_UNANCHORED" });
  };
  let decision;
  try { decision = await getAdmission({ ...options, identity: snapshot, operationClass: actionClass }); }
  catch (error) {
    await record({ decision: "BLOCK", reasonCode: "STATUS_UNAVAILABLE", source: String(options.mode ?? process.env.MCPSHIELD_MODE ?? "live").toUpperCase() });
    throw error;
  }
  await record(decision);
  return decision;
}

function recheckSession(snapshot, options) {
  return async (message) => {
    const decision = await checkedDecision(snapshot, options, message.params.name, "CALL", operationClass(snapshot.tools.filter((tool) => tool.name === message.params.name)));
    if (decision.decision !== "ALLOW" || decision.releaseStatus !== "VERIFIED") {
      throw new AdmissionBlockedError(decision);
    }
  };
}

export async function runArtifact({ artifactDir, capture = false, executionTimeoutMs = 15_000, input, ...options }) {
  if (!Number.isSafeInteger(executionTimeoutMs) || executionTimeoutMs < 1 || executionTimeoutMs > 120_000) throw new TypeError("Execution timeout must be between 1 and 120000ms");
  if (input !== undefined && (typeof input !== "string" || Buffer.byteLength(input) > 1_048_576)) {
    throw new TypeError("Child input must be a string no larger than 1048576 bytes");
  }
  if (options.preparedIdentityPath && input === undefined) throw new Error("PREPARED_MCP_INPUT_REQUIRED");
  const { snapshot, decision } = await admittedSnapshot(artifactDir, options);
  let guarded;
  try {
    const child = await spawnSnapshot(snapshot, options);
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
      const safeChunk = target === "stderr" ? stderrSummary(chunk) : chunk;
      if (capture) target === "stdout" ? stdout += safeChunk : stderr += safeChunk;
      else target === "stdout" ? process.stdout.write(safeChunk) : process.stderr.write(safeChunk);
    };
    guarded = input === undefined ? undefined : childSurfaceGuards(child, snapshot, options);
    const failOutput = (error) => { outputError ??= error; terminateChild(child); };
    child.stdin.once("error", failOutput);
    if (guarded) {
      guarded.requests.once("error", failOutput);
      guarded.responses.once("error", failOutput);
      guarded.requests.pipe(child.stdin);
      child.stdout.pipe(guarded.responses);
      guarded.responses.on("data", (chunk) => receive("stdout", chunk));
      guarded.requests.end(input);
    } else child.stdout.on("data", (chunk) => receive("stdout", chunk));
    child.stderr.on("data", (chunk) => receive("stderr", chunk));
    const result = await new Promise((resolve, reject) => {
      let settled = false;
      let timeoutError;
      const finish = (callback) => { if (settled) return; settled = true; clearTimeout(timer); callback(); };
      const timer = setTimeout(() => { timeoutError = new Error(`Child execution timed out after ${executionTimeoutMs}ms`); terminateChild(child); }, executionTimeoutMs);
      child.once("error", (error) => finish(() => reject(error)));
      child.once("close", (code, signal) => finish(() => outputError ? reject(outputError) : timeoutError ? reject(timeoutError) : signal ? reject(new Error(`Child terminated by ${signal}`)) : resolve({ code: code ?? 1, stdout, stderr })));
    });
    return { decision, identity: { releaseId: snapshot.releaseId, artifactDigest: snapshot.artifactDigest, toolSurfaceHash: snapshot.toolSurfaceHash }, ...result };
  } finally { guarded?.close(); await snapshot.cleanup(); }
}

export async function proxyArtifactStdio({ artifactDir, ...options }) {
  const { snapshot } = await admittedSnapshot(artifactDir, options);
  let child;
  try { child = await spawnSnapshot(snapshot, options); }
  catch (error) { await snapshot.cleanup(); throw error; }
  const guards = childSurfaceGuards(child, snapshot, options);
  const { requests, responses } = guards;
  let terminalError;
  let cleaned = false;
  let disconnectTimer;
  let stderrBytes = 0;
  const cleanup = (signal = "SIGTERM") => {
    if (cleaned) return;
    cleaned = true;
    clearTimeout(disconnectTimer);
    process.stdin.unpipe(requests);
    requests.unpipe(child.stdin);
    child.stdout.unpipe(responses);
    responses.unpipe(process.stdout);
    child.stderr.removeListener("data", diagnostic);
    process.stdout.removeListener("close", cleanup);
    guards.close();
    if (child.exitCode === null && child.signalCode === null) terminateChild(child);
  };
  const fail = (error) => { terminalError ??= error; log("gateway_runtime_blocked", { releaseId: snapshot.releaseId, error: error.message }); cleanup(); };
  const diagnostic = (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > 1_048_576) { fail(new Error("Child stderr exceeded 1 MiB")); return; }
    process.stderr.write(stderrSummary(chunk));
  };
  requests.once("error", fail);
  responses.once("error", fail);
  child.stdin.once("error", fail);
  process.stdin.pipe(requests).pipe(child.stdin);
  child.stdout.pipe(responses).pipe(process.stdout);
  child.stderr.on("data", diagnostic);
  requests.once("finish", () => { disconnectTimer = setTimeout(() => cleanup(), 500); });
  process.stdout.once("close", cleanup);
  const handlers = new Map();
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) { const handler = () => cleanup(signal); handlers.set(signal, handler); process.once(signal, handler); }
  try {
    return await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => terminalError ? reject(terminalError) : signal ? reject(new Error(`Child terminated by ${signal}`)) : resolve(code ?? 1));
    });
  } finally {
    cleanup();
    for (const [signal, handler] of handlers) process.removeListener(signal, handler);
    await snapshot.cleanup();
  }
}

const listMessagesInput = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "mcpshield-http-gateway", version: "1.0.0" } } },
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", id: 2, method: "tools/list" },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_messages", arguments: {} } },
].map(JSON.stringify).join("\n") + "\n";

async function callListMessages(options) {
  const execution = await runArtifact({ ...options, capture: true, input: listMessagesInput });
  const responses = execution.stdout.trim().split(/\r?\n/).filter(Boolean).map(JSON.parse);
  const called = responses.find(({ id }) => id === 3);
  if (called?.error || !Array.isArray(called?.result?.content)) throw new Error("Verified MCP tool returned an invalid result");
  return called.result;
}

export function createRemoteMcpServer(options = {}) {
  const server = new McpServer(
    { name: "mcpshield-mail", version: "1.0.0" },
    { instructions: "Use list_messages to read synthetic demo mail through MCPShield's verified execution gateway." },
  );
  server.registerTool("list_messages", {
    title: "List demo messages",
    description: "Use this to read the fixed synthetic mail list after MCPShield verifies the release. It never accesses real mail.",
    inputSchema: z.object({}).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async () => {
    try { return await callListMessages(options); }
    catch (error) {
      const reason = error instanceof AdmissionBlockedError ? error.decision.reasonCode : "EXECUTION_FAILED";
      log("remote_mcp_blocked", { reason });
      return { isError: true, content: [{ type: "text", text: error instanceof AdmissionBlockedError ? error.message : `MCPShield blocked this call: ${reason}` }] };
    }
  });
  return server;
}

export function createGatewayHttpServer(options = {}) {
  const handler = createMcpHandler(() => createRemoteMcpServer(options), {
    onerror: (error) => log("remote_mcp_error", { message: error.message }),
  });
  const mcp = toNodeHandler(handler);
  const server = createServer((request, response) => {
    response.setHeader("cache-control", "no-store");
    const pathname = new URL(request.url ?? "/", "http://localhost").pathname;
    if (pathname === "/mcp") {
      if (request.method === "GET" && request.headers.accept?.includes("text/html")) {
        response.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
        });
        response.end(MCP_LANDING_PAGE);
        return;
      }
      void Promise.resolve(mcp(request, response)).catch((error) => {
        log("remote_mcp_error", { message: error.message });
        if (!response.headersSent) { response.writeHead(500); response.end(); }
        else response.destroy(error);
      });
      return;
    }
    if (request.method === "GET" && pathname === "/health") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ schemaVersion: "1.0.0", status: "ok", mode: (options.mode ?? process.env.MCPSHIELD_MODE ?? "live").toUpperCase(), mcpEndpoint: "/mcp" }));
      return;
    }
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not_found" }));
  });
  server.once("close", () => void handler.close());
  return server;
}

async function stdio(args) {
  if (args.length && (args.length !== 2 || args[0] !== "--prepared-identity" || !args[1])) throw new Error("Unsupported stdio argument");
  const preparedIdentityPath = args[1] ?? process.env.MCPSHIELD_PREPARED_IDENTITY;
  const artifactDir = process.env.MCPSHIELD_ARTIFACT_DIR;
  if (!artifactDir && !preparedIdentityPath) throw new Error("MCPSHIELD_ARTIFACT_DIR or a local prepared identity is required");
  process.exitCode = await proxyArtifactStdio({ artifactDir, preparedIdentityPath });
}

function serve() {
  const port = Number(process.env.MCPSHIELD_GATEWAY_PORT ?? process.env.PORT ?? 8787);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be valid");
  const host = process.env.MCPSHIELD_GATEWAY_HOST ?? "0.0.0.0";
  createGatewayHttpServer({
    artifactDir: process.env.MCPSHIELD_ARTIFACT_DIR ?? process.env.MCPSHIELD_PROBE_ARTIFACT,
    mode: process.env.MCPSHIELD_MODE ?? "live",
    apiBaseUrl: process.env.MCPSHIELD_API_URL,
    replayFile: process.env.MCPSHIELD_REPLAY_FILE,
  }).listen(port, host, () => log("gateway_ready", { host, port, mcpEndpoint: "/mcp" }));
}

function parseRun(args, inspect = false) {
  const allowed = new Set(["--artifact", "--mode", "--replay", ...(inspect ? ["--rollout"] : [])]);
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
  if (subcommand === "stdio") return stdio(args);
  if (subcommand === "serve") return serve();
  if (!["run", "inspect"].includes(subcommand)) throw new Error(`Unknown command: ${subcommand}`);
  const parsed = parseRun(args, subcommand === "inspect");
  if (subcommand === "inspect") {
    const assessment = await inspectArtifact({ artifactDir: parsed.artifact, mode: parsed.mode, replayFile: parsed.replay, rollout: parsed.rollout });
    process.stdout.write(`${JSON.stringify(assessment)}\n`);
    return;
  }
  try {
    const result = await runArtifact({ artifactDir: parsed.artifact, mode: parsed.mode ?? process.env.MCPSHIELD_MODE ?? "live", replayFile: parsed.replay ?? process.env.MCPSHIELD_REPLAY_FILE });
    process.exitCode = result.code;
  } catch (error) {
    if (error instanceof AdmissionBlockedError) { process.stderr.write(`${JSON.stringify(error.decision)}\n`); process.exitCode = 3; return; }
    throw error;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main().catch((error) => { log("gateway_error", { name: error.name, message: error.message }); process.exitCode = error instanceof AdmissionBlockedError ? 3 : 1; });
