import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash, generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as pause } from "node:timers/promises";
import ganache from "ganache";
import { Wallet } from "ethers";
import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { buildApp } from "../../apps/api/src/app.js";
import { hash, type ControlOptions } from "../../apps/api/src/control-plane.js";
import { preparedPolicy } from "../../apps/api/src/control-policy.js";
import { runPreparationWorkerOnce } from "../../apps/api/src/preparation-worker.js";
import { preparations } from "../../apps/api/src/preparation-store.js";
import { V2Relayer, runChainActionOnce } from "../../apps/api/src/chain-outbox.js";
import { v2ChainReader } from "../../apps/api/src/registry-v2-client.js";
import { indexV2 } from "../../apps/indexer/src/v2-indexer.js";
// @ts-expect-error Shared actual scanner implementation.
import { artifactDigest, toolSurfaceHash } from "../../services/scanner/src/scanner.mjs";
// @ts-expect-error Shared actual prepared scanner implementation.
import { prepareAndScanRuntime } from "../../services/scanner/src/prepared-scan.mjs";
// @ts-expect-error Shared actual Gateway implementation.
import { runArtifact } from "../../apps/gateway/src/index.mjs";

const preparedMailInput = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "prepared-fullcycle", version: "1" } } },
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", id: 2, method: "tools/list" },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_messages", arguments: {} } },
].map(message => JSON.stringify(message)).join("\n") + "\n";

function privateNode(script: string, config: Record<string, any>, timeoutMs = 30000): Promise<any> {
  const input = JSON.stringify(config); assert.ok(Buffer.byteLength(input) <= 32768);
  return new Promise((resolve, reject) => {
    const child = execFile(process.execPath, ["--input-type=module", "-e", script], {
      env: { ...getDefaultEnvironment(), MCPSHIELD_TELEMETRY_ENABLED: "false" }, windowsHide: true, timeout: timeoutMs, maxBuffer: 65536,
    }, (error, stdout, stderr) => {
      clearTimeout(force);
      if (config.apiToken && (stdout.includes(config.apiToken) || stderr.includes(config.apiToken))) { reject(Error("GATEWAY_CHILD_EXPOSED_PRIVATE_CONFIG")); return; }
      if (error) { reject(Error(error.killed ? "GATEWAY_CHILD_TIMEOUT_OR_OUTPUT_LIMIT" : "GATEWAY_CHILD_FAILED")); return; }
      try { resolve(JSON.parse(stdout.trim())); } catch { reject(Error("GATEWAY_CHILD_INVALID_OUTPUT")); }
    });
    // Let the real Gateway's SIGTERM handler remove its exact owned container;
    // force-stop only this child if graceful cleanup exceeds another five seconds.
    const force = setTimeout(() => child.kill("SIGKILL"), timeoutMs + 5000);
    child.stdin?.on("error", () => {}); child.stdin?.end(input);
  });
}

const deniedGatewayChild = `
  import { AdmissionBlockedError, runArtifact } from ${JSON.stringify(new URL("../../apps/gateway/src/index.mjs", import.meta.url).href)};
  try {
    let input = ''; for await (const chunk of process.stdin) { input += chunk; if (Buffer.byteLength(input) > 32768) throw Error('INPUT_LIMIT'); }
    const options = JSON.parse(input);
    try { await runArtifact({ ...options, executionTimeoutMs: 2000, capture: true }); throw Error('UNEXPECTED_EXECUTION'); }
    catch (error) {
      if (!(error instanceof AdmissionBlockedError)) throw error;
      const d = error.decision;
      process.stdout.write(JSON.stringify({ pid: process.pid, releaseId: d.releaseId, decision: d.decision, status: d.releaseStatus,
        reasonCode: d.reasonCode, source: d.source, cacheHit: d.cacheHit }));
    }
  } catch { process.stderr.write('PREPARED_GATEWAY_CHILD_FAILED\\n'); process.exitCode = 1; }
`;

async function dockerEvents(since: string) {
  const until = new Date().toISOString();
  const { stdout } = await promisify(execFile)("docker", ["events", "--since", since, "--until", until, "--format", "{{json .}}"],
    { windowsHide: true, timeout: 10000, maxBuffer: 262144 });
  const events = stdout.trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
  // Docker retains 256 historical events. Refuse a possibly truncated window;
  // this local acceptance check is not a durable production audit log.
  assert.ok(events.length < 256, "DOCKER_EVENT_WINDOW_POSSIBLY_TRUNCATED");
  return events.filter(event => event.Type === "container" && event.Actor?.Attributes?.["io.mcpshield.gateway.owner"]);
}

test("Gateway child configuration travels only through bounded stdin, with distinct processes and deadlines", async () => {
  const apiToken = "SYNTHETIC_PRIVATE_STDIN_ONLY";
  const read = `let value='';for await(const chunk of process.stdin)value+=chunk;const config=JSON.parse(value);console.log(JSON.stringify({pid:process.pid,tokenLength:config.apiToken.length,argvContainsToken:process.argv.some(arg=>arg.includes(config.apiToken)),envContainsToken:Object.values(process.env).some(value=>value.includes(config.apiToken))}));`;
  const children = await Promise.all([privateNode(read, { apiToken }), privateNode(read, { apiToken })]);
  assert.equal(new Set(children.map(child => child.pid)).size, 2);
  for (const child of children) { assert.notEqual(child.pid, process.pid); assert.equal(child.tokenLength, apiToken.length); assert.equal(child.argvContainsToken, false); assert.equal(child.envContainsToken, false); }
  await assert.rejects(privateNode(`for await(const chunk of process.stdin)process.stdout.write(chunk);`, { apiToken }), /EXPOSED_PRIVATE_CONFIG/);
  await assert.rejects(privateNode(`process.stdin.resume();setInterval(()=>{},1000);`, { apiToken }, 100), /TIMEOUT_OR_OUTPUT_LIMIT/);
});

test("prepared fullcycle supplies MCP framing before testing admission denial", async () => {
  assert.deepEqual(preparedMailInput.trim().split("\n").map(line => JSON.parse(line).method), ["initialize", "notifications/initialized", "tools/list", "tools/call"]);
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-prepared-input-"));
  try {
    const options = { mode: "live", policyHash: `0x${"1".repeat(64)}`, preparedIdentityPath: join(directory, "deliberately-missing.json") };
    await assert.rejects(runArtifact(options), /PREPARED_MCP_INPUT_REQUIRED/);
    // With framing present we reach actual identity validation, not the earlier
    // missing-input guard. This portable regression makes no Docker/chain claim.
    await assert.rejects(runArtifact({ ...options, input: preparedMailInput }), /PREPARED_IDENTITY_FILE_INVALID/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

// Actual Linux Docker + local EVM + signed admission. AI is a deterministic loopback
// contract stub, sources are local mail fixtures, validators belong to one institution.
// No production provider quality, public npm provenance or independent organization claim.
test("prepared source → actual Docker/AI-stub scans → independent validators → V2 quorum → real Gateway allow/revoke", {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== "1", timeout: 600000,
}, async (t) => {
  assert.equal(process.platform, "linux");
  assert.match(process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE ?? "", /^sha256:[a-f0-9]{64}$/);
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-prepared-fullcycle-")), cleanups: (() => Promise<void>)[] = [];
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  let app: Awaited<ReturnType<typeof buildApp>> | undefined, relayer: V2Relayer | undefined, store: ControlStore | undefined;
  const aiCounts = { analyzer: 0, critic: 0, probes: 0 };
  const ai = createServer(async (request, response) => {
    try {
      const chunks: Buffer[] = []; let bytes = 0;
      for await (const chunk of request) { bytes += chunk.length; if (bytes > 512 * 1024) throw Error("STUB_INPUT_LIMIT"); chunks.push(chunk); }
      const body = JSON.parse(Buffer.concat(chunks).toString()), plan = body.responseSchema?.properties?.scenarios !== undefined;
      assert.deepEqual(body.tools, []);
      const role = plan ? "probes" : body.prompt.includes("Act as an independent adversarial reviewer") ? "critic" : "analyzer";
      aiCounts[role]++;
      const result = plan ? { scenarios: ["NORMAL", "ADVERSARIAL"].map((kind) => ({ scenarioId: kind.toLowerCase(), kind,
        goal: "Exercise a bounded synthetic mail read.", toolName: "list_messages", argumentsJson: "{}" })) }
        : { riskClaims: [], semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false };
      response.writeHead(200, { "content-type": "application/json", connection: "close" }).end(JSON.stringify(result));
    } catch { response.writeHead(400, { connection: "close" }).end(); }
  });
  ai.requestTimeout = 10000; ai.headersTimeout = 10000;
  try {
    await new Promise<void>((done) => ai.listen(0, "127.0.0.1", done));
    await chain.listen(0, "127.0.0.1");
    const rpc = `http://127.0.0.1:${chain.address().port}`, aiUrl = `http://127.0.0.1:${(ai.address() as any).port}`;
    const accounts = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
    const deployment = await deployV2(rpc, accounts[0].secretKey, accounts.slice(1, 4).map(({ secretKey }) => new Wallet(secretKey).address), 1337);
    relayer = new V2Relayer(rpc, deployment.releaseRegistry.address, 1337, accounts[0].secretKey);
    store = await ControlStore.open(join(dir, "control.sqlite"));
    const keys = generateKeyPairSync("ed25519"), tenantId = "synthetic-prepared-fullcycle", token = "SYNTHETIC_PREPARED_ADMIN_ONLY";
    const config = { builderImageDigest: process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE!, platform: { os: "linux" as const, architecture: "amd64" as const } };
    const options: ControlOptions = { store, credentials: [{ tenantId, token, role: "admin" }], artifactPath: join(dir, "artifacts"), evidencePath: join(dir, "evidence"),
      evidenceKey: "9".repeat(64), signingKey: keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), signingKeyId: "prepared-integration",
      preparedRuntime: config, scannerOptions: { sandbox: "docker", allowRemoteAi: true, aiProvider: "custom", aiUrl, aiTimeoutMs: 5000 },
      v2Relayer: relayer, chainDecision: v2ChainReader({ rpcUrls: [rpc], registryContract: deployment.releaseRegistry.address, chainId: 1337, confirmations: 1 }),
      // Track only our actual images for cleanup. No scanner/proof/PASS test double is injected.
      prepareRuntime: async (input) => { const output = await prepareAndScanRuntime(input); if (output.cleanup) cleanups.push(output.cleanup); return output; } };
    app = await buildApp({ adminApiToken: "unused-legacy-admin", scannerApiToken: "unused-legacy-scan", controlPlane: options });
    await app.listen({ host: "127.0.0.1", port: 0 });
    const apiUrl = `http://127.0.0.1:${(app.server.address() as any).port}`, auth = { authorization: `Bearer ${token}` }, policyHash = hash(preparedPolicy);
    const post = async (url: string, payload: any = {}, extra = {}) => {
      const response = await app!.inject({ method: "POST", url, headers: { ...auth, ...extra }, payload });
      assert.ok(response.statusCode < 300, `${url}: ${response.body}`); return response.json();
    };
    const settle = async (actionId: string) => {
      for (let attempt = 0; attempt < 40; attempt++) {
        await chain.provider.request({ method: "evm_mine", params: [] }); await runChainActionOnce(store!, relayer!);
        const { action } = (await app!.inject({ url: `/v1/chain/actions/${actionId}`, headers: auth })).json();
        if (action.status === "COMPLETED") return;
        assert.notEqual(action.status, "FAILED", JSON.stringify(action)); await pause(100);
      }
      assert.fail("PREPARED_CHAIN_ACTION_TIMEOUT");
    };
    await settle((await post(`/v1/policies/${policyHash}/publish`)).action.actionId);
    const prepare = async (version: string) => {
      const root = join(dir, `source-${version}`); await mkdir(root);
      const fixture = fileURLToPath(new URL(`../../demo/fixtures/mail-mcp-${version}/`, import.meta.url));
      for (const file of ["index.mjs", "manifest.json", "package.json"]) await cp(join(fixture, file), join(root, file));
      const pkg = { ...JSON.parse(await readFile(join(root, "package.json"), "utf8")), bin: "index.mjs" };
      await writeFile(join(root, "package.json"), JSON.stringify(pkg));
      await writeFile(join(root, "package-lock.json"), JSON.stringify({ name: pkg.name, version, lockfileVersion: 3,
        packages: { "": { name: pkg.name, version, bin: pkg.bin } } }));
      const digest = await artifactDigest(root), manifestDigest = `sha256:${createHash("sha256").update(await readFile(join(root, "manifest.json"))).digest("hex")}`;
      const source = { ...exactReleaseIdentity({ toolId: "npm:mail-mcp", artifactDigest: digest, manifestDigest, toolSurfaceHash: toolSurfaceHash([]) }),
        artifactDigest: digest, manifestDigest, toolSurfaceHash: toolSurfaceHash([]), sourceType: "tarball", artifactDir: root,
        artifactUri: "synthetic-local-fixture:not-a-public-registry-download", legacyReleaseId: `mail-mcp@${version}`, version, status: "UNVERIFIED", metadata: { archiveDigest: digest } };
      await store!.put(tenantId, "release", source.releaseId, source);
      const { preparation } = await post(`/v1/releases/${source.releaseId}/prepare`, { policyHash }, { "idempotency-key": version });
      await runPreparationWorkerOnce(store!, options);
      const [completed] = await preparations(store!, tenantId, preparation.preparationId);
      assert.equal(completed.status, "COMPLETED", JSON.stringify(completed.lastError));
      assert.equal(completed.result?.outcome, "DERIVED_RELEASE_CREATED", JSON.stringify(completed.result));
      assert.equal(completed.result?.verdict, version === "1.0.0" ? "PASS" : "FAIL", JSON.stringify(completed.result));
      const release = (await store!.get(tenantId, "release", completed.result!.releaseId))!, scan = (await store!.scan(tenantId, completed.result!.scanId))!;
      assert.notEqual(release.releaseId, source.releaseId); assert.equal(release.status, "UNVERIFIED");
      assert.deepEqual(await store!.get(tenantId, "release", source.releaseId), source, "immutable source must not become the prepared release");
      assert.equal(scan.result?.scanResult.source, "LIVE"); assert.equal(scan.result?.state, "READY_FOR_VALIDATORS");
      if (version === "1.0.1") assert.ok(scan.result?.scanResult.findings.some((finding: any) => finding.code === "CANARY_EXFILTRATION" && finding.deterministic));
      await settle((await post(`/v1/releases/${release.releaseId}/register`)).action.actionId);
      const response = await app!.inject({ url: `/v1/releases/${release.releaseId}/gateway-config`, headers: auth }); assert.equal(response.statusCode, 200);
      const file = join(dir, `gateway-${version}.json`); await writeFile(file, response.body, { mode: 0o600 });
      return { release, scan, file, imageDigest: response.json().binding.finalImageDigest };
    };
    const admission = (release: any) => post("/v1/admission/check", { releaseId: release.releaseId, artifactDigest: release.artifactDigest,
      toolSurfaceHash: release.toolSurfaceHash, policyHash, mode: "strict", operationClass: "READ_PRIVATE" });
    const vote = async (scanId: string) => {
      let pumping = true;
      const pump = (async () => { while (pumping) { await chain.provider.request({ method: "evm_mine", params: [] }); await runChainActionOnce(store!, relayer!); await pause(100); } })();
      try {
        for (const { secretKey } of accounts.slice(1, 3)) {
          // Separate key-owning process; neither validator receives its peer's key or an injected scanner/proof callback.
          const { stdout, stderr } = await promisify(execFile)(process.execPath, ["--import", "tsx", fileURLToPath(new URL("../../apps/validator/src/v2.ts", import.meta.url))],
            { timeout: 240000, maxBuffer: 256 * 1024, windowsHide: true, env: { ...getDefaultEnvironment(), VALIDATOR_PRIVATE_KEY: secretKey,
              CONTROL_API_URL: apiUrl, CONTROL_API_TOKEN: token, CONTROL_SCAN_ID: scanId, CONTROL_V2_RPC_URLS: rpc,
              CONTROL_V2_CHAIN_ID: "1337", CONTROL_V2_REGISTRY_ADDRESS: deployment.releaseRegistry.address, CONTROL_VALIDATOR_POLICY_HASH: policyHash,
              VALIDATOR_PREPARED_BUILDER_DIGEST: config.builderImageDigest, VALIDATOR_PREPARED_ARCHITECTURE: "amd64",
              VALIDATOR_ALLOW_REMOTE_AI: "true", VALIDATOR_AI_PROVIDER: "custom", VALIDATOR_AI_URL: aiUrl, VALIDATOR_AI_TIMEOUT_MS: "5000",
              VALIDATOR_VERIFICATION_RECEIPTS_PATH: join(dir, "local-verifications.jsonl") } });
          assert.ok(!stdout.includes(secretKey) && !stderr.includes(secretKey) && !stdout.includes(token) && !stderr.includes(token));
          const outcome = JSON.parse(stdout.trim().split("\n").at(-1)!);
          assert.equal(outcome.mode, "SINGLE_VALIDATOR"); assert.equal(outcome.operations.length, 1);
        }
      } finally { pumping = false; await pump; }
      await indexV2(store!, relayer!, { deploymentBlock: deployment.releaseRegistry.blockNumber, confirmations: 1 });
    };
    const publicKey = keys.publicKey.export({ format: "pem", type: "spki" }).toString();
    const gatewayContext = { mode: "live", apiBaseUrl: apiUrl, timeoutMs: 5000, policyHash, tenantId, publicKey, keyId: "prepared-integration", chainId: 1337,
      registryContract: deployment.releaseRegistry.address, validatorSetVersion: 1, apiToken: token, operationClass: "READ_PRIVATE", admissionMode: "strict" };
    const safe = await prepare("1.0.0");
    assert.equal((await admission(safe.release)).decision, "BLOCK"); await vote(safe.scan.scanId);
    assert.equal((await admission(safe.release)).decision, "ALLOW");
    const safeGatewayEventsSince = new Date().toISOString();
    const client = new Client({ name: "prepared-fullcycle", version: "1" }), transport = new StdioClientTransport({ command: process.execPath,
      args: [fileURLToPath(new URL("../../apps/gateway/src/index.mjs", import.meta.url)), "stdio", "--prepared-identity", safe.file], stderr: "pipe",
      env: { ...getDefaultEnvironment(), MCPSHIELD_PREPARED_IDENTITY: safe.file, MCPSHIELD_MODE: "live", MCPSHIELD_API_URL: apiUrl,
        MCPSHIELD_POLICY_HASH: policyHash, MCPSHIELD_TENANT_ID: tenantId, MCPSHIELD_CONTROL_TOKEN: token, MCPSHIELD_CACHE_PUBLIC_KEY: publicKey,
        MCPSHIELD_CACHE_KEY_ID: "prepared-integration", MCPSHIELD_CHAIN_ID: "1337", MCPSHIELD_REGISTRY_CONTRACT: deployment.releaseRegistry.address,
        MCPSHIELD_VALIDATOR_SET_VERSION: "1", MCPSHIELD_ADMISSION_MODE: "strict" } });
    transport.stderr?.on("data", () => {});
    try {
      await client.connect(transport); assert.equal((await client.listTools()).tools[0].name, "list_messages");
      const result = await client.callTool({ name: "list_messages", arguments: {} }); assert.notEqual(result.isError, true);
      assert.equal(JSON.parse((result.content as any[])[0].text).messages[0].subject, "Welcome");
    } finally { await client.close(); }
    const safeEvents = await dockerEvents(safeGatewayEventsSince);
    for (const action of ["create", "start"]) assert.ok(safeEvents.some(event => event.Action === action && event.Actor.Attributes.image === safe.imageDigest), `Safe Gateway must positively demonstrate observable Docker ${action}`);
    const bad = await prepare("1.0.1"); await vote(bad.scan.scanId);
    const finalDenied = await admission(bad.release);
    assert.deepEqual({ decision: finalDenied.decision, status: finalDenied.status, reasonCode: finalDenied.reasonCode, snapshotStatus: finalDenied.snapshot?.status },
      { decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED", snapshotStatus: "REVOKED" });
    assert.equal((await store.get(tenantId, "release", bad.release.releaseId))?.status, "REVOKED");
    const containers = async () => (await promisify(execFile)("docker", ["container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "label=io.mcpshield.gateway.owner"],
      { windowsHide: true, timeout: 10000, maxBuffer: 65536 })).stdout.trim().split("\n").filter(Boolean).sort();
    const before = await containers(), deniedEventsSince = new Date().toISOString();
    // Each process has an empty private in-memory cache; Gateway-B cannot inherit
    // Gateway-A's terminal revocation journal or satisfy the assertion via it.
    const attempts = await Promise.allSettled(["Gateway-A", "Gateway-B"].map(agentId => privateNode(deniedGatewayChild,
      { ...gatewayContext, agentId, preparedIdentityPath: bad.file, input: preparedMailInput })));
    const gateways = attempts.map(attempt => { assert.equal(attempt.status, "fulfilled"); return (attempt as PromiseFulfilledResult<any>).value; });
    assert.equal(new Set(gateways.map(gateway => gateway.pid)).size, 2);
    for (const { pid, ...decision } of gateways) {
      assert.notEqual(pid, process.pid);
      assert.deepEqual(decision, { releaseId: bad.release.releaseId, decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED", source: "LIVE", cacheHit: false });
    }
    const deniedEvents = await dockerEvents(deniedEventsSince);
    assert.equal(deniedEvents.filter(event => event.Actor.Attributes.image === bad.imageDigest && ["create", "start"].includes(event.Action)).length, 0, "Revoked candidate must be blocked before Docker create/start");
    assert.deepEqual(await containers(), before, "No Gateway container may remain after either denied process");
    const receipts = (await readFile(join(dir, "local-verifications.jsonl"), "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(receipts.length, 4); assert.equal(new Set(receipts.map((receipt) => receipt.independentReportRoot)).size, 4);
    assert.ok(receipts.every((receipt) => receipt.originalReportRoot !== receipt.independentReportRoot && receipt.state === "LOCAL_VERIFICATION_ONLY"));
    assert.equal(receipts.filter((receipt) => receipt.verdict === "PASS").length, 2); assert.equal(receipts.filter((receipt) => receipt.verdict === "FAIL").length, 2);
    assert.ok(aiCounts.probes >= 6 && aiCounts.analyzer >= 6 && aiCounts.critic >= 6, "each worker/signer must perform its own paid-provider contract requests");
    t.diagnostic(JSON.stringify({ mode: "ACTUAL_LINUX_DOCKER_LOCAL_EVM_STUB_AI_SINGLE_INSTITUTION", independentScans: receipts.length, independentGatewayProcesses: gateways.length,
      deniedGatewayCreateOrStartEvents: 0, dockerEventEvidence: "BOUNDED_LOCAL_DAEMON_WINDOW_WITH_SAFE_POSITIVE_CONTROL", aiCounts }));
  } finally {
    if (app) await app.close(); else { relayer?.close(); await store?.close(); }
    await chain.close().catch(() => {}); ai.closeAllConnections(); await new Promise<void>((done) => ai.close(() => done()));
    for (const cleanup of cleanups.reverse()) await cleanup();
    await rm(dir, { recursive: true, force: true });
  }
});
