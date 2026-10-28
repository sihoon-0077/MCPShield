import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { HDNodeWallet, id, verifyTypedData } from "ethers";
import { runArtifact, AdmissionBlockedError } from "../../gateway/src/index.mjs";
import { scanRelease } from "../../../services/scanner/src/scanner.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtures = {
  safe: resolve(root, "demo/fixtures/mail-mcp-1.0.0"),
  malicious: resolve(root, "demo/fixtures/mail-mcp-1.0.1"),
};
const releaseIds = { safe: "mail-mcp@1.0.0", malicious: "mail-mcp@1.0.1" };
const actions = [
  "SCAN_SAFE", "VOTE_SAFE_A", "VOTE_SAFE_B", "RUN_SAFE", "SELECT_MALICIOUS",
  "SCAN_MALICIOUS", "VOTE_FAIL_A", "VOTE_FAIL_B", "RUN_MALICIOUS",
];
const mnemonic = "test test test test test test test test test test test junk";
const wallets = [1, 2].map((index) => HDNodeWallet.fromPhrase(mnemonic, undefined, `m/44'/60'/0'/0/${index}`));
const domain = { name: "MCPShield", version: "1", chainId: 31337, verifyingContract: "0x0000000000000000000000000000000000000001" };
const types = { Attestation: [
  { name: "releaseKey", type: "bytes32" }, { name: "decision", type: "uint8" },
  { name: "evidenceHash", type: "bytes32" }, { name: "nonce", type: "uint256" },
  { name: "deadline", type: "uint256" },
] };

export class JudgeDemoError extends Error {
  constructor(message, statusCode = 400, code = "DEMO_REQUEST_INVALID") {
    super(message); this.statusCode = statusCode; this.code = code;
  }
}

const event = (type, detail) => ({ at: new Date().toISOString(), type, detail });
const cleanFinding = ({ code, severity, stage, message }) => ({ code, severity, stage, message });
const mcpInput = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "mcpshield-judge-lab", version: "1.0.0" } } },
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", id: 2, method: "tools/list" },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_messages", arguments: {} } },
].map(JSON.stringify).join("\n") + "\n";

function mcpResult(stdout) {
  const responses = stdout.trim().split(/\r?\n/).filter(Boolean).map(JSON.parse);
  const initialized = responses.find(({ id }) => id === 1);
  const listed = responses.find(({ id }) => id === 2);
  const called = responses.find(({ id }) => id === 3);
  if (responses.length !== 3 || initialized?.error || initialized?.result?.serverInfo?.name !== "mail-mcp") throw new Error("MCP initialize failed");
  if (listed?.error || listed?.result?.tools?.length !== 1 || listed.result.tools[0].name !== "list_messages") throw new Error("MCP tools/list failed");
  if (called?.error || called?.result?.isError === true || called?.result?.content?.length !== 1 || called.result.content[0].type !== "text") throw new Error("MCP tools/call failed");
  const result = JSON.parse(called.result.content[0].text);
  if (JSON.stringify(result) !== JSON.stringify({ ok: true, messages: [{ id: "demo-1", subject: "Welcome" }] })) throw new Error("Unexpected MCP tool result");
  return result;
}

export function createJudgeDemo({ ttlMs = 15 * 60_000, maxSessions = 100 } = {}) {
  // ponytail: one-process TTL storage is enough for the single-instance demo; use Redis when scaling horizontally.
  const sessions = new Map();
  const scans = new Map();
  const busy = new Set();

  function purge() {
    const now = Date.now();
    for (const [sessionId, session] of sessions) if (Date.parse(session.expiresAt) <= now) {
      sessions.delete(sessionId); scans.delete(sessionId); busy.delete(sessionId);
    }
  }

  function read(sessionId) {
    purge();
    const session = sessions.get(sessionId);
    if (!session) throw new JudgeDemoError("Demo session was not found or expired", 404, "DEMO_SESSION_NOT_FOUND");
    return session;
  }

  function view(session) {
    return structuredClone({ ...session, nextAction: actions[session.step] ?? null, complete: session.step === actions.length });
  }

  function create() {
    purge();
    if (sessions.size >= maxSessions) throw new JudgeDemoError("Demo capacity is temporarily full", 503, "DEMO_CAPACITY_FULL");
    const sessionId = randomUUID();
    const session = {
      schemaVersion: "1.0.0", source: "LIVE_DEMO", synthetic: true, ledgerMode: "LOCAL_DEMO",
      sessionId, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + ttlMs).toISOString(),
      step: 0, selectedRelease: releaseIds.safe,
      releases: [
        { releaseId: releaseIds.safe, scanStatus: "NOT_RUN", status: "UNVERIFIED" },
        { releaseId: releaseIds.malicious, scanStatus: "NOT_RUN", status: "UNVERIFIED" },
      ],
      findings: [], votes: [], executions: [], events: [event("SESSION_CREATED", "Isolated synthetic judge session created")],
    };
    sessions.set(sessionId, session); scans.set(sessionId, {});
    return view(session);
  }

  async function signVote(session, key, walletIndex, decision) {
    const scan = scans.get(session.sessionId)[key];
    if (!scan) throw new JudgeDemoError("Scan evidence is required before voting", 409, "DEMO_SCAN_REQUIRED");
    const releaseId = releaseIds[key];
    const nonce = key === "safe" ? 0 : 1;
    const deadline = Math.floor(Date.now() / 1000) + 900;
    const value = { releaseKey: id(releaseId), decision: decision === "PASS" ? 0 : 1, evidenceHash: scan.evidenceHash, nonce, deadline };
    const signature = await wallets[walletIndex].signTypedData(domain, types, value);
    const signer = verifyTypedData(domain, types, value, signature);
    session.votes.push({ validator: `Demo Validator ${walletIndex ? "B" : "A"}`, address: signer, releaseId, decision, signatureHash: id(signature), at: new Date().toISOString() });
    session.events.push(event("VALIDATOR_VOTE", `${decision} signed by Demo Validator ${walletIndex ? "B" : "A"}`));
  }

  async function admissionRun(session, key, allow) {
    const releaseId = releaseIds[key];
    const fetchImpl = async (_url, options) => {
      const identity = JSON.parse(options.body);
      const scan = scans.get(session.sessionId)[key];
      if (!scan || identity.releaseId !== releaseId || identity.artifactDigest !== scan.artifactDigest || identity.toolSurfaceHash !== scan.toolSurfaceHash) {
        throw new Error("Admission identity does not match the scanned release");
      }
      return new Response(JSON.stringify({
        schemaVersion: "1.0.0", releaseId, decision: allow ? "ALLOW" : "BLOCK",
        releaseStatus: allow ? "VERIFIED" : "REVOKED", reasonCode: allow ? "RELEASE_VERIFIED" : "RELEASE_REVOKED",
        checkedAt: new Date().toISOString(), source: "LIVE",
      }), { status: 200, headers: { "content-type": "application/json" } });
    };
    try {
      const result = await runArtifact({ artifactDir: fixtures[key], mode: "live", fetchImpl, capture: true, input: mcpInput });
      session.executions.push({ releaseId, decision: "ALLOW", spawnAttempted: true, result: mcpResult(result.stdout), at: new Date().toISOString() });
      session.events.push(event("ARTIFACT_EXECUTED", "Verified safe MCP tool executed in the restricted Gateway runtime"));
    } catch (error) {
      if (!(error instanceof AdmissionBlockedError) || allow) throw error;
      session.executions.push({ releaseId, decision: "BLOCK", spawnAttempted: false, reasonCode: error.decision.reasonCode, at: new Date().toISOString() });
      session.events.push(event("BLOCK_BEFORE_SPAWN", "Revoked artifact was rejected before its entrypoint started"));
    }
  }

  async function act(sessionId, action) {
    const session = read(sessionId);
    const expected = actions[session.step];
    if (action !== expected) throw new JudgeDemoError(`Expected ${expected ?? "no further action"}`, 409, "DEMO_ACTION_OUT_OF_ORDER");
    if (busy.has(sessionId)) throw new JudgeDemoError("A demo action is already running", 409, "DEMO_ACTION_BUSY");
    busy.add(sessionId);
    try {
      if (action === "SCAN_SAFE" || action === "SCAN_MALICIOUS") {
        const key = action === "SCAN_SAFE" ? "safe" : "malicious";
        const scan = await scanRelease({ fixtureDir: fixtures[key], baselineDir: key === "malicious" ? fixtures.safe : undefined, sandbox: "local", source: "LIVE", logger() {} });
        scans.get(sessionId)[key] = scan;
        const release = session.releases.find((item) => item.releaseId === releaseIds[key]);
        release.scanStatus = scan.scanStatus;
        session.findings.push(...scan.findings.map(cleanFinding));
        session.events.push(event("SCAN_COMPLETED", `${releaseIds[key]} finished with ${scan.scanStatus}`));
      } else if (action === "VOTE_SAFE_A") await signVote(session, "safe", 0, "PASS");
      else if (action === "VOTE_SAFE_B") { await signVote(session, "safe", 1, "PASS"); session.releases[0].status = "VERIFIED"; session.events.push(event("QUORUM_REACHED", "2-of-3 PASS changed the safe release to VERIFIED")); }
      else if (action === "RUN_SAFE") await admissionRun(session, "safe", true);
      else if (action === "SELECT_MALICIOUS") { session.selectedRelease = releaseIds.malicious; session.events.push(event("UPDATE_SELECTED", "Signed candidate mail-mcp@1.0.1 selected")); }
      else if (action === "VOTE_FAIL_A") await signVote(session, "malicious", 0, "FAIL");
      else if (action === "VOTE_FAIL_B") { await signVote(session, "malicious", 1, "FAIL"); session.releases[1].status = "REVOKED"; session.events.push(event("QUORUM_REACHED", "2-of-3 FAIL changed the malicious release to REVOKED")); }
      else if (action === "RUN_MALICIOUS") await admissionRun(session, "malicious", false);
      session.step += 1;
      return view(session);
    } finally { busy.delete(sessionId); }
  }

  function remove(sessionId) {
    read(sessionId); sessions.delete(sessionId); scans.delete(sessionId); busy.delete(sessionId);
  }

  return { actions, create, get: (sessionId) => view(read(sessionId)), act, remove };
}
