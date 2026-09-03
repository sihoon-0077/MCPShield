import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";

const RELEASE_ID = /^.+@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const ARTIFACT_DIGEST = /^sha256:[0-9a-f]{64}$/;
const STATUSES = new Set(["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED"]);
const SOURCES = new Set(["LIVE", "MOCK", "REPLAY"]);
const REASONS = new Set(["RELEASE_VERIFIED", "RELEASE_UNVERIFIED", "RELEASE_QUARANTINED", "RELEASE_REVOKED", "DIGEST_MISMATCH", "STATUS_UNAVAILABLE"]);
const DECISION_KEYS = new Set(["schemaVersion", "releaseId", "decision", "releaseStatus", "reasonCode", "checkedAt", "source"]);

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

const MOCK_DIGESTS = new Map([
  ["mail-mcp@1.0.0", `sha256:${"a".repeat(64)}`],
  ["mail-mcp@1.0.1", `sha256:${"c".repeat(64)}`]
]);

function decisionFor(releaseId, artifactDigest, source) {
  const expectedDigest = MOCK_DIGESTS.get(releaseId);
  const safe = releaseId === "mail-mcp@1.0.0";
  const mismatch = expectedDigest !== artifactDigest;
  return {
    schemaVersion: "1.0.0",
    releaseId,
    decision: safe && !mismatch ? "ALLOW" : "BLOCK",
    releaseStatus: safe ? "VERIFIED" : expectedDigest ? "REVOKED" : "UNVERIFIED",
    reasonCode: mismatch ? "DIGEST_MISMATCH" : safe ? "RELEASE_VERIFIED" : "RELEASE_REVOKED",
    checkedAt: new Date().toISOString(),
    source
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
  return value;
}

export async function getAdmission({
  releaseId,
  artifactDigest,
  mode = process.env.MCPSHIELD_MODE ?? "live",
  apiBaseUrl = process.env.MCPSHIELD_API_URL ?? "http://127.0.0.1:3001",
  replayFile = process.env.MCPSHIELD_REPLAY_FILE,
  timeoutMs = Number(process.env.MCPSHIELD_ADMISSION_TIMEOUT_MS ?? 3000),
  fetchImpl = fetch
}) {
  if (!RELEASE_ID.test(releaseId)) throw new Error(`Invalid releaseId: ${releaseId}`);
  if (!ARTIFACT_DIGEST.test(artifactDigest)) throw new Error(`Invalid artifactDigest: ${artifactDigest}`);

  if (mode === "mock") return validateDecision(decisionFor(releaseId, artifactDigest, "MOCK"), releaseId);
  if (mode === "replay") {
    if (!replayFile) throw new Error("MCPSHIELD_REPLAY_FILE is required in replay mode");
    const replay = JSON.parse(await readFile(replayFile, "utf8"));
    const saved = replay.decisions?.[releaseId];
    if (!saved) throw new Error(`Replay has no admission decision for ${releaseId}`);
    const expectedDigest = replay.snapshot?.releases?.find((release) => release.releaseId === releaseId)?.artifactDigest;
    if (expectedDigest !== artifactDigest) {
      return validateDecision({ ...saved, decision: "BLOCK", reasonCode: "DIGEST_MISMATCH", source: "REPLAY" }, releaseId);
    }
    return validateDecision({ ...saved, source: "REPLAY" }, releaseId);
  }
  if (mode !== "live") throw new Error(`Unknown MCPShield mode: ${mode}`);

  const response = await fetchImpl(`${apiBaseUrl.replace(/\/$/, "")}/api/admission/check`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ schemaVersion: "1.0.0", releaseId, artifactDigest }),
    signal: AbortSignal.timeout(timeoutMs)
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

function execute(command, args, { capture = false, timeoutMs = 15_000 } = {}) {
  if (!command || !allowedCommands().has(basename(command).toLowerCase())) {
    throw new Error(`Command is not allowlisted: ${command || "<empty>"}`);
  }
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      shell: false,
      windowsHide: true,
      stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit"
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => { stdout += chunk; });
    child.stderr?.on("data", (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      if (signal) return reject(new Error(`Child terminated by ${signal}`));
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

export async function runRelease({ releaseId, artifactDigest, command, args = [], capture = false, ...admissionOptions }) {
  const decision = await getAdmission({ releaseId, artifactDigest, ...admissionOptions });
  log("admission", { releaseId, decision: decision.decision, status: decision.releaseStatus, source: decision.source });
  if (decision.decision !== "ALLOW" || decision.releaseStatus !== "VERIFIED") {
    throw new AdmissionBlockedError(decision);
  }
  const result = await execute(command, args, { capture });
  log("process_exit", { releaseId, command: basename(command), code: result.code });
  return { decision, ...result };
}

async function stdio() {
  const releaseId = process.env.MCPSHIELD_RELEASE_ID;
  const artifactDigest = process.env.MCPSHIELD_ARTIFACT_DIGEST;
  const command = JSON.parse(process.env.MCPSHIELD_COMMAND_JSON ?? "[]");
  if (!releaseId || !artifactDigest || !Array.isArray(command) || !command.every((item) => typeof item === "string")) {
    throw new Error("MCPSHIELD_RELEASE_ID, MCPSHIELD_ARTIFACT_DIGEST, and JSON-array MCPSHIELD_COMMAND_JSON are required");
  }
  const result = await runRelease({ releaseId, artifactDigest, command: command[0], args: command.slice(1) });
  process.exitCode = result.code;
}

function serve() {
  const port = Number(process.env.PORT ?? 8787);
  createServer((request, response) => {
    if (request.method === "GET" && request.url === "/health") {
      response.writeHead(200, { "content-type": "application/json" });
      return response.end(JSON.stringify({ status: "ok", mode: process.env.MCPSHIELD_MODE ?? "live" }));
    }
    response.writeHead(404).end();
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
      mode: option(args, "--mode", process.env.MCPSHIELD_MODE ?? "live"),
      replayFile: option(args, "--replay", process.env.MCPSHIELD_REPLAY_FILE),
      command: command[0],
      args: command.slice(1)
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
