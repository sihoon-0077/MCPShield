// Consortium scene (capstone v2.1, ADR-004/005/006): two companies, one shared chain.
// Gateway A trusts the operator's hosted Control API; Gateway B trusts only
// company B's own Control API, which reads the same ReleaseRegistryV2 itself.
// Local EVM (Ganache) + explicit REPORT FIXTURE scanner double; not testnet,
// not a Docker scan, and both companies share one local RPC endpoint here.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as pause } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import ganache from "ganache";
import { Contract, Wallet, id as keccakText } from "ethers";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { buildApp } from "../../apps/api/src/app.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
import { V2Relayer, runChainActionOnce } from "../../apps/api/src/chain-outbox.js";
import { v2ChainReader } from "../../apps/api/src/registry-v2-client.js";
import { defaultPolicy, hash, type ControlOptions } from "../../apps/api/src/control-plane.js";
// @ts-expect-error Shared scanner/Gateway are ESM JavaScript.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared scanner/Gateway are ESM JavaScript.
import { artifactDigest, loadManifest, toolSurfaceHash } from "../../services/scanner/src/scanner.mjs";
// @ts-expect-error Shared scanner/Gateway are ESM JavaScript.
import { getAdmission } from "../../apps/gateway/src/index.mjs";

const gatewayEntry = fileURLToPath(new URL("../../apps/gateway/src/index.mjs", import.meta.url));
const CHAIN_ID = 1337;
// Headroom for CI runners shared with other Ganache suites; upper bounds only, latency is unaffected when nothing is slow.
const READER_BUDGET_MS = 5000, GATEWAY_ADMISSION_TIMEOUT_MS = "8000", CALL_TIMEOUT_MS = 10_000, CHILD_TIMEOUT_MS = 30_000;
type Mode = "HONEST" | "DOWN" | "COMPROMISED";
type Session = { client: Client; stderr: () => string };
type CallResult = { ok: boolean; startedAt: number; at: number; ms: number; error?: string; gatewayBlocked?: string | null; lastAdmission?: { status: string; reasonCode: string } | null };
export type SceneOptions = { latencySamples?: number; pollIntervalMs?: number; propagationTimeoutMs?: number; log?: (line: string) => void };

const percentile = (values: number[], p: number) => {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return Number(sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)].toFixed(2));
};
const summary = (values: number[]) => ({ n: values.length, p50: percentile(values, 50), p95: percentile(values, 95), max: values.length ? Number(Math.max(...values).toFixed(2)) : null });
const jsonLines = (text: string) => text.split(/\r?\n/).map((line) => { try { return JSON.parse(line); } catch { return undefined; } }).filter(Boolean);
const failureClass = (message?: string) => !message ? null : /previously revoked/.test(message) ? "LOCAL_REVOCATION_JOURNAL"
  : /expired or has an invalid lifetime/.test(message) ? "SIGNED_CACHE_EXPIRED"
  : /strict or non-read-only calls fail closed/.test(message) ? "UNAVAILABLE_FAIL_CLOSED" : "OTHER";

// The operator endpoint Gateway A is configured with. The scene switches what answers it.
function operatorEndpoint(targets: { HONEST: () => string; COMPROMISED: () => string }) {
  let mode: Mode = "HONEST";
  const server: Server = createServer(async (request: IncomingMessage, response) => {
    if (mode === "DOWN") { request.socket.destroy(); return; }
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const headers = Object.fromEntries(Object.entries(request.headers)
      .filter(([key, value]) => typeof value === "string" && !["host", "connection", "content-length"].includes(key))) as Record<string, string>;
    try {
      const upstream = await fetch(`${targets[mode]()}${request.url}`, { method: request.method, headers, body: chunks.length ? Buffer.concat(chunks) : undefined, redirect: "manual" });
      const body = Buffer.from(await upstream.arrayBuffer());
      response.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
      response.end(body);
    } catch { response.writeHead(502); response.end(); }
  });
  return { server, set(next: Mode) { mode = next; } };
}

// One fresh Gateway process per check: separate memory, separate trust configuration.
function gatewayChild(env: Record<string, string>, subcommand: "inspect" | "run", artifactDir: string) {
  return new Promise<{ exitCode: number | null; stdout: any[]; stderr: any[]; failure?: string }>((resolve) => {
    const child = spawn(process.execPath, [gatewayEntry, subcommand, "--artifact", artifactDir, "--mode", "live"], { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let stdout = "", stderr = "", settled = false;
    const finish = (value: { exitCode: number | null; failure?: string }) => {
      if (settled) return; settled = true; clearTimeout(timer);
      resolve({ ...value, stdout: jsonLines(stdout), stderr: jsonLines(stderr) });
    };
    const timer = setTimeout(() => { child.kill("SIGKILL"); finish({ exitCode: null, failure: "GATEWAY_CHILD_TIMEOUT" }); }, CHILD_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", (error) => finish({ exitCode: null, failure: `GATEWAY_SPAWN_FAILED: ${error.message}`.slice(0, 120) }));
    child.once("close", (exitCode) => finish({ exitCode }));
  });
}

async function inspectInChild(env: Record<string, string>, artifactDir: string) {
  const result = await gatewayChild(env, "inspect", artifactDir);
  const decision = result.stdout.at(-1), failure = result.stderr.find((event) => event.event === "gateway_error");
  const path = result.stderr.find((event) => event.event === "admission_path");
  const message = result.failure ?? (failure ? String(failure.message ?? failure.name) : undefined);
  return { method: "GATEWAY_CHILD_PROCESS_INSPECT_NEVER_SPAWNS", exitCode: result.exitCode, decision: decision?.decision ?? "BLOCK",
    releaseStatus: decision?.releaseStatus ?? null, reasonCode: decision?.reasonCode ?? null, decisionSource: path?.decisionSource ?? null,
    gatewayError: message ? message.slice(0, 160) : null, gatewayErrorClass: failureClass(message) };
}

async function runInChild(env: Record<string, string>, artifactDir: string) {
  // `run` would spawn the artifact if admitted. Exit 3 + AdmissionBlockedError decision = refused before spawn (index.mjs main()).
  const result = await gatewayChild(env, "run", artifactDir);
  const blocked = [...result.stderr].reverse().find((event) => event.schemaVersion === "1.0.0" && event.decision === "BLOCK");
  return { method: "GATEWAY_CHILD_PROCESS_RUN", exitCode: result.exitCode, decision: blocked?.decision ?? (result.exitCode === 0 ? "ALLOW" : "UNKNOWN"),
    releaseStatus: blocked?.releaseStatus ?? null, reasonCode: blocked?.reasonCode ?? null,
    refusedBeforeSpawn: result.exitCode === 3 && Boolean(blocked), failure: result.failure ?? null };
}

async function mcpSession(command: string, args: string[], env: Record<string, string>, name: string): Promise<Session> {
  const transport = new StdioClientTransport({ command, args, env, stderr: "pipe" });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => { if (stderr.length < 1_000_000) stderr += chunk; });
  const client = new Client({ name, version: "1" });
  await client.connect(transport);
  return { client, stderr: () => stderr };
}

async function callOnce(session: Session, timeoutMs = CALL_TIMEOUT_MS): Promise<CallResult> {
  const startedAt = Date.now(), started = performance.now();
  let timer: NodeJS.Timeout | undefined;
  try {
    const result: any = await Promise.race([session.client.callTool({ name: "list_messages", arguments: {} }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("CALL_TIMEOUT")), timeoutMs); })]);
    const ok = result?.isError !== true && JSON.parse(result.content[0].text).messages[0].subject === "Welcome";
    return { ok, startedAt, at: Date.now(), ms: performance.now() - started, ...(ok ? {} : { error: "TOOL_ERROR_RESULT" }) };
  } catch (error: any) {
    const at = Date.now(), ms = performance.now() - started;
    await pause(100); // the Gateway writes its refusal to stderr before it closes the session
    const events = jsonLines(session.stderr());
    const blocked = events.filter((event) => event.event === "gateway_runtime_blocked").at(-1);
    const admission = events.filter((event) => event.event === "admission" && event.phase === "CALL").at(-1);
    return { ok: false, startedAt, at, ms, error: String(error?.message ?? error).slice(0, 120),
      gatewayBlocked: blocked ? String(blocked.error).slice(0, 160) : null,
      lastAdmission: admission ? { status: admission.status, reasonCode: admission.reasonCode } : null };
  } finally { clearTimeout(timer); }
}

export async function runConsortiumScene(options: SceneOptions = {}) {
  const samples = options.latencySamples ?? 10, pollIntervalMs = options.pollIntervalMs ?? 50, propagationTimeoutMs = options.propagationTimeoutMs ?? 20_000;
  const say = options.log ?? (() => {});
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  const owned: { apps: any[]; stores: ControlStore[]; sessions: Session[]; dir?: string; relayer?: V2Relayer; endpoint?: ReturnType<typeof operatorEndpoint>; miner?: NodeJS.Timeout } = { apps: [], stores: [], sessions: [] };
  let primaryFailure: unknown;
  const mine = () => chain.provider.request({ method: "evm_mine", params: [] });
  // ALLOW needs a head younger than 30 s, but a block landing mid-read of a NEGATIVE status makes the reader
  // fail closed (v2-chain-reader.mjs: only VERIFIED gets a fresh-view retry). So idle mining runs only while
  // the scene reads VERIFIED releases; negative-status phases start from one explicit fresh block instead.
  const idleMining = (on: boolean) => {
    clearInterval(owned.miner); owned.miner = undefined;
    if (on) owned.miner = setInterval(() => { mine().catch(() => {}); }, 5000);
  };
  try {
    await chain.listen(0, "127.0.0.1");
    const rpc = `http://127.0.0.1:${chain.address().port}`;
    const accounts = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
    const validators = accounts.slice(1, 4).map((account) => new Wallet(account.secretKey));
    const deployment = await deployV2(rpc, accounts[0].secretKey, validators.map((wallet) => wallet.address), CHAIN_ID);
    const registryAddress = deployment.releaseRegistry.address;
    const relayer = owned.relayer = new V2Relayer(rpc, registryAddress, CHAIN_ID, accounts[0].secretKey);
    const dir = owned.dir = await mkdtemp(join(tmpdir(), "mcpshield-consortium-"));
    const policyHash = hash(defaultPolicy);
    const reader = () => v2ChainReader({ rpcUrls: [rpc], registryContract: registryAddress, chainId: CHAIN_ID, confirmations: 1, timeoutMs: READER_BUDGET_MS });
    const reportFixture: ControlOptions["scanArtifact"] = async ({ artifactDir }) => {
      // Explicit REPORT FIXTURE test double, byte-for-byte the tests/api/v2-fullcycle.test.ts bundle. Policy only issues PASS
      // for a complete DOCKER-mode sandbox record, so this double claims one; no container runs. Trust plane and Gateways are real.
      const manifest = await loadManifest(artifactDir), malicious = manifest.version === "1.0.1";
      const findings = malicious ? [{ code: "CANARY_EXFILTRATION", deterministic: true, severity: "CRITICAL", stage: "SANDBOX", evidence: {}, message: "Synthetic report fixture" }] : [];
      const result = { scanStatus: malicious ? "FAILED" : "PASSED", artifactDigest: await artifactDigest(artifactDir), toolSurfaceHash: toolSurfaceHash(manifest.tools), findings };
      return { result, bundle: createEvidenceBundle({ "report.json": { ...result, scope: "STATIC_AI_SANDBOX" },
        "sandbox/events.json": { mode: "DOCKER", complete: true }, "sandbox/mcp.json": { complete: true }, "static/findings.json": [], "semantic/model-output.json": { findings: [] } }) };
    };
    const company = async (label: string, tenantId: string, extra: Partial<ControlOptions>,
      reuse: { signingKey?: ReturnType<typeof generateKeyPairSync>; keyId?: string; token?: string } = {}) => {
      const signingKey = reuse.signingKey ?? generateKeyPairSync("ed25519"), keyId = reuse.keyId ?? `${label}-admission`;
      const token = reuse.token ?? `synthetic-${label}-token`;
      const store = await ControlStore.open(join(dir, `${label}.sqlite`));
      const control: ControlOptions = { store, credentials: [{ token, tenantId, role: "admin" }], artifactPath: join(dir, `${label}-artifacts`),
        evidencePath: join(dir, `${label}-evidence`), evidenceKey: "9".repeat(64), signingKey: signingKey.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
        signingKeyId: keyId, ...extra, chainDecision: extra.chainDecision ?? reader() };
      let app;
      try { app = await buildApp({ adminApiToken: `unused-${label}-legacy-admin`, scannerApiToken: `unused-${label}-legacy-scan`, controlPlane: control }); }
      catch (error) {
        // buildApp owns store/reader only after it returns.
        await Promise.allSettled([Promise.resolve().then(() => store.close()), Promise.resolve().then(() => (control.chainDecision as any)?.close?.())]);
        throw error;
      }
      owned.apps.push(app);
      await app.listen({ host: "127.0.0.1", port: 0 });
      const url = `http://127.0.0.1:${(app.server!.address() as any).port}`;
      const post = async (path: string, payload: any = {}, headers: Record<string, string> = {}) => {
        const response = await app.inject({ method: "POST", url: path, headers: { authorization: `Bearer ${token}`, ...headers }, payload });
        if (response.statusCode >= 300) throw new Error(`${label} ${path}: ${response.statusCode} ${response.body.slice(0, 200)}`);
        return response.json();
      };
      const resolve = async (version: string) => (await post("/v1/releases/resolve", { sourceType: "fixture", locator: `mail-mcp-${version}` })).release;
      const artifactDir = async (releaseId: string) => (await store.get(tenantId, "release", releaseId))!.artifactDir as string;
      return { label, tenantId, token, url, app, store, control, post, resolve, artifactDir,
        publicKey: signingKey.publicKey.export({ type: "spki", format: "pem" }).toString(), keyId, signingKey };
    };
    let compromised: Awaited<ReturnType<typeof company>> | undefined;

    say("setup: local EVM, ReleaseRegistryV2, operator stack (company A tenant), company B stack");
    const operator = await company("operator", "company-a", { v2Relayer: relayer, scanArtifact: reportFixture });
    const companyB = await company("company-b", "company-b", {});
    const settle = async (actionId: string) => {
      for (let attempt = 0; attempt < 60; attempt++) {
        await mine();
        await runChainActionOnce(operator.store, relayer);
        const action = (await operator.app.inject({ url: `/v1/chain/actions/${actionId}`, headers: { authorization: `Bearer ${operator.token}` } })).json().action;
        if (action.status === "COMPLETED") return action;
        if (action.status === "FAILED") throw new Error(`chain action failed: ${JSON.stringify(action).slice(0, 200)}`);
        await pause(100);
      }
      throw new Error("chain action did not settle");
    };
    const vote = async (scanId: string, validator: Wallet, quarantine = false) => {
      // Test validators sign the operator's template without an independent rescan (SINGLE_INSTITUTION_DEMO).
      const kind = quarantine ? "quarantine" : "attestation";
      const template = (await operator.app.inject({ url: `/v1/scans/${scanId}/${kind}?validator=${validator.address}`, headers: { authorization: `Bearer ${operator.token}` } })).json();
      if (!template.payload) throw new Error(`no ${kind} template: ${JSON.stringify(template).slice(0, 200)}`);
      const signature = await validator.signTypedData(template.domain, template.types, template.payload);
      await settle((await operator.post(`/v1/validator/${quarantine ? "quarantines" : "attestations"}`, { scanId, payload: template.payload, signature })).action.actionId);
    };
    await settle((await operator.post(`/v1/policies/${policyHash}/publish`)).action.actionId);
    const prepare = async (version: string, verdict: "PASS" | "FAIL") => {
      const release = await operator.resolve(version);
      await settle((await operator.post(`/v1/releases/${release.releaseId}/register`)).action.actionId);
      const scan = (await operator.post("/v1/scans", { releaseId: release.releaseId, policyHash }, { "idempotency-key": `consortium-${version}` })).scan;
      await runControlWorkerOnce(operator.store, operator.control);
      const completed = await operator.store.scan(operator.tenantId, scan.scanId);
      if (completed?.result?.verdict !== verdict) throw new Error(`scan ${version} expected ${verdict}: ${completed?.status} ${JSON.stringify(completed?.lastError ?? null).slice(0, 200)}`);
      return { release, scan };
    };
    const independentIdentity = async (release: any) => {
      // Company B resolves the same bytes on its own; nothing is copied from the operator.
      const own = await companyB.resolve(release.version);
      return { releaseId: own.releaseId, matches: own.releaseId === release.releaseId && own.artifactDigest === release.artifactDigest && own.toolSurfaceHash === release.toolSurfaceHash };
    };
    const endpoint = owned.endpoint = operatorEndpoint({ HONEST: () => operator.url, COMPROMISED: () => compromised?.url ?? operator.url });
    await new Promise<void>((done) => endpoint.server.listen(0, "127.0.0.1", () => done()));
    const operatorUrl = `http://127.0.0.1:${(endpoint.server.address() as any).port}`;
    const gatewayEnv = (who: "A" | "B", release: any, extra: Record<string, string> = {}) => {
      const trust = who === "A" ? { url: operatorUrl, tenantId: operator.tenantId, token: operator.token, publicKey: operator.publicKey, keyId: operator.keyId }
        : { url: companyB.url, tenantId: companyB.tenantId, token: companyB.token, publicKey: companyB.publicKey, keyId: companyB.keyId };
      return { ...getDefaultEnvironment(), MCPSHIELD_MODE: "live", MCPSHIELD_API_URL: trust.url, MCPSHIELD_POLICY_HASH: policyHash,
        MCPSHIELD_CONTROL_RELEASE_ID: release.releaseId, MCPSHIELD_TENANT_ID: trust.tenantId, MCPSHIELD_CONTROL_TOKEN: trust.token,
        MCPSHIELD_CACHE_PUBLIC_KEY: trust.publicKey, MCPSHIELD_CACHE_KEY_ID: trust.keyId, MCPSHIELD_CHAIN_ID: String(CHAIN_ID),
        MCPSHIELD_REGISTRY_CONTRACT: registryAddress, MCPSHIELD_VALIDATOR_SET_VERSION: "1", MCPSHIELD_ADMISSION_MODE: "strict",
        MCPSHIELD_ADMISSION_TIMEOUT_MS: GATEWAY_ADMISSION_TIMEOUT_MS, MCPSHIELD_TELEMETRY_ENABLED: "false", ...extra } as Record<string, string>;
    };
    const dirs = async (release: any) => ({ A: await operator.artifactDir(release.releaseId), B: await companyB.artifactDir(release.releaseId) });
    const session = async (command: string, args: string[], env: Record<string, string>, name: string) => {
      const opened = await mcpSession(command, args, env, name); owned.sessions.push(opened); return opened;
    };
    const sessionPair = async (release: any) => {
      const own = await dirs(release);
      return { a: await session(process.execPath, [gatewayEntry, "stdio"], gatewayEnv("A", release, { MCPSHIELD_ARTIFACT_DIR: own.A }), "gateway-a"),
        b: await session(process.execPath, [gatewayEntry, "stdio"], gatewayEnv("B", release, { MCPSHIELD_ARTIFACT_DIR: own.B }), "gateway-b") };
    };

    // Scene 1 — approved release: both companies run it; measure the per-call cost.
    say("scene 1: safe mail-mcp@1.0.0 -> 2-of-3 PASS -> VERIFIED");
    const safe = await prepare("1.0.0", "PASS");
    const safeAtB = await independentIdentity(safe.release);
    for (const validator of validators.slice(0, 2)) await vote(safe.scan.scanId, validator);
    idleMining(true);
    const safeDirs = await dirs(safe.release);
    const safeInspect = { gatewayA: await inspectInChild(gatewayEnv("A", safe.release), safeDirs.A), gatewayB: await inspectInChild(gatewayEnv("B", safe.release), safeDirs.B) };
    const direct = await session(process.execPath, [join(safeDirs.A, "index.mjs")], getDefaultEnvironment(), "direct");
    const sessions = await sessionPair(safe.release);
    const firstCalls = { direct: await callOnce(direct), gatewayA: await callOnce(sessions.a), gatewayB: await callOnce(sessions.b) };
    const latency: Record<string, number[]> = { direct: [], gatewayA: [], gatewayB: [] };
    const measured = Object.entries({ direct, gatewayA: sessions.a, gatewayB: sessions.b });
    let failedLatencyCalls = 0;
    for (let index = 0; index < samples + 3; index++) for (const [name, target] of measured) {
      // Interleave targets so chain/miner noise affects all three alike. The first three rounds are warm-up.
      const call = await callOnce(target);
      if (!call.ok) failedLatencyCalls++; else if (index >= 3) latency[name].push(call.ms);
    }

    // Scene 2 — operator outage: company A stops, company B continues. Read/write handling of the Gateway A library.
    say("scene 2: operator endpoint DOWN");
    const readCache = join(dir, "gateway-a-read-cache.json"), writeCache = join(dir, "gateway-a-write-cache.json");
    const inProcessA = (operationClass: string, admissionMode: string, extra: Record<string, unknown> = {}) => getAdmission({
      identity: { releaseId: safe.release.legacyReleaseId, artifactDigest: safe.release.artifactDigest, toolSurfaceHash: safe.release.toolSurfaceHash },
      mode: "live", apiBaseUrl: operatorUrl, timeoutMs: 3000, policyHash, controlReleaseId: safe.release.releaseId, tenantId: operator.tenantId,
      publicKey: operator.publicKey, keyId: operator.keyId, chainId: CHAIN_ID, registryContract: registryAddress, validatorSetVersion: 1,
      apiToken: operator.token, operationClass, admissionMode,
      // Pin every fallback explicitly so ambient MCPSHIELD_* variables of the harness process cannot change the rows.
      cacheFile: null, indexer: null, rpc: null, ...extra })
      .then((value: any) => ({ decision: value.decision, decisionSource: value.decisionSource ?? null, reasonCode: value.reasonCode, errorClass: null }))
      .catch((error: any) => ({ decision: "BLOCK", decisionSource: null, reasonCode: null, errorClass: failureClass(String(error?.message ?? error)), error: String(error?.message ?? error).slice(0, 120) }));
    const primed = { read: await inProcessA("READ_PRIVATE", "balanced", { cacheFile: readCache }), write: await inProcessA("WRITE_EXTERNAL", "balanced", { cacheFile: writeCache }) };
    endpoint.set("DOWN");
    const outageCalls = { gatewayA: await callOnce(sessions.a), gatewayB: await callOnce(sessions.b) };
    const readWrite = [
      { case: "strict + valid signed cache / READ", ...await inProcessA("READ_PRIVATE", "strict", { cacheFile: readCache }) },
      { case: "strict + valid signed cache / WRITE", ...await inProcessA("WRITE_EXTERNAL", "strict", { cacheFile: writeCache }) },
      { case: "balanced + valid signed cache / READ", ...await inProcessA("READ_PRIVATE", "balanced", { cacheFile: readCache }) },
      { case: "balanced + valid signed cache / WRITE", ...await inProcessA("WRITE_EXTERNAL", "balanced", { cacheFile: writeCache }) },
      { case: "balanced + expired cache (clock +31 s) / READ", ...await inProcessA("READ_PRIVATE", "balanced", { cacheFile: readCache, now: () => Date.now() + 31_000 }) },
    ].map((row) => ({ method: "IN_PROCESS_GATEWAY_LIBRARY_getAdmission", ...row }));
    endpoint.set("HONEST");
    for (const opened of [sessions.a, sessions.b, direct]) await opened.client.close().catch(() => {});

    // Scene 3 — malicious update: emergency quarantine then 2-of-3 FAIL -> REVOKED. Both refuse before spawn.
    say("scene 3: malicious mail-mcp@1.0.1 -> quarantine -> 2-of-3 FAIL -> REVOKED");
    idleMining(false);
    const bad = await prepare("1.0.1", "FAIL");
    const badAtB = await independentIdentity(bad.release);
    await vote(bad.scan.scanId, validators[0], true);
    await vote(bad.scan.scanId, validators[0]); await vote(bad.scan.scanId, validators[1]);
    const ground = new Contract(registryAddress, ["function revoked(bytes32) view returns (bool)", "function quarantine(bytes32,bytes32,bytes32,bytes32,uint64)"], relayer.provider);
    const revokedOnChain = await ground.revoked(bad.release.releaseId);
    const badDirs = await dirs(bad.release);
    const journalA = join(dir, "gateway-a-journal.json");
    await mine();
    const revokedRun = {
      // Gateway A keeps a private revocation journal from here on (MCPSHIELD_ADMISSION_CACHE_FILE).
      gatewayA: await runInChild(gatewayEnv("A", bad.release, { MCPSHIELD_ADMISSION_CACHE_FILE: journalA }), badDirs.A),
      gatewayB: await runInChild(gatewayEnv("B", bad.release), badDirs.B),
    };

    // Scene 4 — operator captured: an attacker answers with the operator's own signing key and a falsified chain view.
    say("scene 4: operator signing authority captured (forged VERIFIED for the revoked release)");
    const honestReader = reader();
    const lyingView = Object.assign(async (release: any, policy: any) => {
      const real: any = await honestReader(release, policy);
      if (release.releaseId !== bad.release.releaseId) return real;
      return { ...real, status: "VERIFIED", validFrom: new Date(Date.now() - 60_000).toISOString(), validUntil: new Date(Date.now() + 3_600_000).toISOString() };
    }, { close: () => honestReader.close() });
    // The attacker holds the operator's admission key, key ID and tenant credential; release identity is public.
    compromised = await company("compromised-operator", "company-a", { chainDecision: lyingView },
      { signingKey: operator.signingKey, keyId: operator.keyId, token: operator.token });
    await compromised.resolve("1.0.1");
    await mine();
    endpoint.set("COMPROMISED");
    const compromisedInspect = {
      gatewayAFirstSight: await inspectInChild(gatewayEnv("A", bad.release), badDirs.A),
      gatewayAWithJournal: await inspectInChild(gatewayEnv("A", bad.release, { MCPSHIELD_ADMISSION_CACHE_FILE: journalA }), badDirs.A),
      gatewayB: await inspectInChild(gatewayEnv("B", bad.release), badDirs.B),
    };
    endpoint.set("HONEST");
    const stillRevoked = await ground.revoked(bad.release.releaseId);

    // Scene 5 — a validator quarantines an approved release DIRECTLY on chain (no operator involved).
    // Measures how long until each Gateway refuses the next call of an already running session.
    say("scene 5: validator C sends emergency quarantine for the approved release straight to the chain");
    await mine();
    const live = await sessionPair(safe.release);
    const ready = { gatewayA: await callOnce(live.a), gatewayB: await callOnce(live.b) };
    const firstRefused: Record<string, CallResult | undefined> = {}, lastAllowed: Record<string, CallResult | undefined> = {};
    const unexpected: Record<string, number> = { gatewayA: 0, gatewayB: 0 };
    let sendStartedAt = Number.POSITIVE_INFINITY, includedAt = Number.POSITIVE_INFINITY, polling = true;
    const poll = async (name: string, target: Session) => {
      const deadline = Date.now() + propagationTimeoutMs;
      while (polling && Date.now() < deadline) {
        const call = await callOnce(target);
        if (call.ok) lastAllowed[name] = call;
        else if (call.at >= sendStartedAt) { firstRefused[name] = call; return; }
        else unexpected[name]++;
        await pause(pollIntervalMs);
      }
    };
    const pollers = Promise.all([poll("gatewayA", live.a), poll("gatewayB", live.b)]);
    let tx: any, receipt: any;
    const guard = new AbortController();
    try {
      await pause(500);
      const validatorC = ground.connect(new Wallet(accounts[3].secretKey, relayer.provider)) as any;
      const head = await relayer.provider.getBlock("latest");
      sendStartedAt = Date.now();
      tx = await validatorC.quarantine(safe.release.releaseId, policyHash, keccakText("synthetic-late-canary-evidence"), keccakText("CANARY_EXFILTRATION"), BigInt(head!.timestamp + 3600));
      receipt = await relayer.provider.getTransactionReceipt(tx.hash);
      for (let attempt = 0; !receipt && attempt < 200; attempt++) { await pause(10); receipt = await relayer.provider.getTransactionReceipt(tx.hash); }
      if (!receipt || receipt.status !== 1) throw new Error("quarantine transaction was not included");
      includedAt = Date.now();
      await Promise.race([pollers, pause(propagationTimeoutMs + 1000, undefined, { signal: guard.signal }).catch(() => {})]);
    } finally { guard.abort(); polling = false; await pollers; }
    const propagation = Object.fromEntries(["gatewayA", "gatewayB"].map((name) => {
      const refused = firstRefused[name];
      return [name, {
        refusedNextCall: Boolean(refused?.gatewayBlocked && /QUARANTINED/.test(refused.gatewayBlocked)),
        refusalReason: refused?.gatewayBlocked ?? refused?.error ?? null, refusalAdmission: refused?.lastAdmission ?? null,
        msFromInclusionToRefusal: refused ? refused.at - includedAt : null,
        msFromSendToRefusal: refused ? refused.at - sendStartedAt : null,
        // A call may legitimately be allowed after the send started (gas estimation precedes broadcast), never after inclusion.
        lastAllowedStartedBeforeInclusion: lastAllowed[name] ? lastAllowed[name]!.startedAt < includedAt : null,
        unexpectedFailuresBeforeSend: unexpected[name],
      }];
    }));

    return {
      schemaVersion: "mcpshield.consortium-scene.v1", status: "MEASURED",
      environment: { chain: "LOCAL_EVM_GANACHE", chainId: CHAIN_ID, contract: "ReleaseRegistryV2", scanner: "REPORT_FIXTURE_TEST_DOUBLE",
        validators: "SINGLE_INSTITUTION_DEMO", governance: deployment.governance, validatorVerification: "SIGNS_OPERATOR_TEMPLATE_NO_INDEPENDENT_RESCAN",
        rpc: "ONE_SHARED_LOCAL_RPC_FOR_BOTH_COMPANIES", topology: "Ganache, both Control APIs, the operator-endpoint switch and MCP clients share one Node process; Gateways run as child processes",
        node: process.version, platform: process.platform },
      limitations: [
        "Synthetic REPORT FIXTURE scan: the evidence bundle claims a DOCKER sandbox but no container ran",
        "Operator outage injected by a loopback switch that destroys sockets",
        "Operator compromise simulated by an attacker instance holding the operator signing key with an injected falsified chain view",
        "Validators are three deterministic Ganache keys in one harness signing operator templates (not independent organisations)",
        "Local instant mining: not Base Sepolia, no real block time or confirmation wait",
      ],
      trust: { gatewayA: "operator Control API (company-a tenant), pins the operator admission key; does not read the chain itself",
        gatewayB: "company B's own Control API, pins company B's admission key; that API reads the same chain itself and never contacts the operator" },
      identities: { safe: { releaseId: safe.release.releaseId, companyBIndependentMatch: safeAtB.matches }, malicious: { releaseId: bad.release.releaseId, companyBIndependentMatch: badAtB.matches } },
      scenes: {
        approved: { inspect: safeInspect, firstToolCall: { direct: firstCalls.direct.ok, gatewayA: firstCalls.gatewayA.ok, gatewayB: firstCalls.gatewayB.ok } },
        operatorOutage: { toolCallDuringOutage: outageCalls, primedSignedCaches: primed, readWrite },
        revoked: { chainRevoked: revokedOnChain, ...revokedRun },
        operatorCompromised: { simulation: "INJECTED_FALSIFIED_CHAIN_VIEW_WITH_OPERATOR_KEY", chainRevoked: stillRevoked, ...compromisedInspect },
        validatorQuarantine: { txHash: tx.hash, block: receipt.blockNumber, sessionsReady: { gatewayA: ready.gatewayA.ok, gatewayB: ready.gatewayB.ok }, pollIntervalMs, propagation },
      },
      measurements: {
        toolCallLatencyMs: { direct: summary(latency.direct), gatewayA: summary(latency.gatewayA), gatewayB: summary(latency.gatewayB), failedCalls: failedLatencyCalls,
          note: "list_messages tools/call round trip over stdio after warm-up, targets interleaved. Gateway paths include a signed admission check per call (API -> chain read -> Ed25519 sign -> Gateway verify). Gateway A additionally passes the local operator-endpoint switch." },
        quarantinePropagationMs: { gatewayA: propagation.gatewayA.msFromInclusionToRefusal, gatewayB: propagation.gatewayB.msFromInclusionToRefusal,
          note: "From receipt observed by the harness to the first refused call of a running session. Local instant-mining lower bound; resolution = poll interval + one call. On a testnet add block time; a negative status is read from the head block, only a new ALLOW waits for the configured confirmations." },
      },
    };
  } catch (error) { primaryFailure = error; throw error; }
  finally {
    idleMining(false);
    const cleanup: PromiseSettledResult<unknown>[] = await Promise.allSettled([
      ...owned.sessions.map((opened) => opened.client.close()),
      ...owned.apps.map((app) => app.close()),
      owned.endpoint ? new Promise<void>((done) => owned.endpoint!.server.close(() => done())) : Promise.resolve(),
    ]);
    // The operator app owns the relayer once built; close it directly only if setup failed earlier.
    cleanup.push(...await Promise.allSettled([Promise.resolve().then(() => { if (!owned.apps.length) owned.relayer?.close(); }), Promise.resolve().then(() => chain.close())]));
    if (owned.dir) cleanup.push(...await Promise.allSettled([rm(owned.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })]));
    const failures = cleanup.filter((item) => item.status === "rejected");
    if (failures.length) {
      console.error(JSON.stringify({ event: "consortium_scene_cleanup_failed", count: failures.length }));
      throw new AggregateError(failures.map((item: any) => item.reason), "CONSORTIUM_SCENE_CLEANUP_FAILED", { cause: primaryFailure });
    }
  }
}

// Single source of truth for what the scene must show; used by the test and before results are published.
export function assertConsortiumReport(report: Awaited<ReturnType<typeof runConsortiumScene>>, samples: number) {
  const { approved, operatorOutage, revoked, operatorCompromised, validatorQuarantine } = report.scenes;
  const show = (value: unknown) => JSON.stringify(value);
  // Company B computed the same exact release identities without copying them from the operator.
  assert.equal(report.identities.safe.companyBIndependentMatch, true);
  assert.equal(report.identities.malicious.companyBIndependentMatch, true);
  // 1. Approved release: both companies run it through separate Gateway processes.
  for (const gateway of [approved.inspect.gatewayA, approved.inspect.gatewayB]) assert.equal(gateway.decision, "ALLOW", show(gateway));
  assert.deepEqual(approved.firstToolCall, { direct: true, gatewayA: true, gatewayB: true });
  // 2. Operator outage: company A fails closed, company B continues. Only read calls may use a still-valid signed cache.
  const outageA = operatorOutage.toolCallDuringOutage.gatewayA;
  assert.equal(outageA.ok, false, show(outageA));
  assert.match(String(outageA.gatewayBlocked), /Admission unavailable|fail closed/, show(outageA));
  assert.equal(operatorOutage.toolCallDuringOutage.gatewayB.ok, true, show(operatorOutage.toolCallDuringOutage.gatewayB));
  assert.deepEqual([operatorOutage.primedSignedCaches.read.decision, operatorOutage.primedSignedCaches.write.decision], ["ALLOW", "ALLOW"]);
  assert.deepEqual(Object.fromEntries(operatorOutage.readWrite.map((row: any) => [row.case, `${row.decision}:${row.decisionSource}:${row.errorClass}`])), {
    "strict + valid signed cache / READ": "BLOCK:null:UNAVAILABLE_FAIL_CLOSED",
    "strict + valid signed cache / WRITE": "BLOCK:null:UNAVAILABLE_FAIL_CLOSED",
    "balanced + valid signed cache / READ": "ALLOW:CACHE:null",
    "balanced + valid signed cache / WRITE": "BLOCK:null:UNAVAILABLE_FAIL_CLOSED",
    "balanced + expired cache (clock +31 s) / READ": "BLOCK:null:SIGNED_CACHE_EXPIRED",
  });
  // 3. Malicious update revoked by 2-of-3 FAIL: both Gateways refuse it before spawning it.
  assert.equal(revoked.chainRevoked, true);
  for (const gateway of [revoked.gatewayA, revoked.gatewayB]) {
    assert.equal(gateway.releaseStatus, "REVOKED", show(gateway)); assert.equal(gateway.refusedBeforeSpawn, true, show(gateway));
  }
  // 4. Operator signing authority captured. The chain never changed. A first-sight operator-trusting Gateway is fooled
  // (control group); one that already journalled the revocation refuses; the Gateway that trusts only its own
  // chain-reading Control API still blocks.
  assert.equal(operatorCompromised.chainRevoked, true);
  assert.equal(operatorCompromised.gatewayAFirstSight.decision, "ALLOW", show(operatorCompromised.gatewayAFirstSight));
  assert.equal(operatorCompromised.gatewayAWithJournal.decision, "BLOCK", show(operatorCompromised.gatewayAWithJournal));
  assert.equal(operatorCompromised.gatewayAWithJournal.gatewayErrorClass, "LOCAL_REVOCATION_JOURNAL", show(operatorCompromised.gatewayAWithJournal));
  assert.equal(operatorCompromised.gatewayB.decision, "BLOCK", show(operatorCompromised.gatewayB));
  assert.equal(operatorCompromised.gatewayB.releaseStatus, "REVOKED", show(operatorCompromised.gatewayB));
  // 5. A validator quarantines an approved release directly on chain: running sessions refuse the next call for that reason.
  assert.deepEqual(validatorQuarantine.sessionsReady, { gatewayA: true, gatewayB: true });
  for (const name of ["gatewayA", "gatewayB"] as const) {
    const propagation = validatorQuarantine.propagation[name];
    assert.equal(propagation.refusedNextCall, true, `${name} ${show(propagation)}`);
    assert.equal(propagation.lastAllowedStartedBeforeInclusion, true, `${name} ${show(propagation)}`);
    assert.equal(propagation.unexpectedFailuresBeforeSend, 0, `${name} ${show(propagation)}`);
    assert.ok(Number.isFinite(propagation.msFromInclusionToRefusal), name);
  }
  // Measurement completeness only; absolute latency is environment-dependent and reported, not asserted.
  const latency = report.measurements.toolCallLatencyMs;
  assert.equal(latency.failedCalls, 0);
  for (const path of [latency.direct, latency.gatewayA, latency.gatewayB]) assert.equal(path.n, samples);
}
