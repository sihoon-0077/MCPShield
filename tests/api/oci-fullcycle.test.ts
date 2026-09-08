import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
import { ociPolicy } from "../../apps/api/src/control-policy.js";
import { runPreparationWorkerOnce } from "../../apps/api/src/preparation-worker.js";
import { preparations } from "../../apps/api/src/preparation-store.js";
import { V2Relayer, runChainActionOnce } from "../../apps/api/src/chain-outbox.js";
import { v2ChainReader } from "../../apps/api/src/registry-v2-client.js";
import { indexV2 } from "../../apps/indexer/src/v2-indexer.js";
import { privateNode, deniedGatewayChild, dockerEvents } from "./runtime-fullcycle-helpers.js";
// @ts-expect-error Shared authored native SOURCE fixture, not an injected scanner.
import { createOciProfileFixture, OCI_PROFILE_PROBE_PLAN } from "../security/oci-profile-fixture.mjs";
// @ts-expect-error Actual operator-local immutable source resolver.
import { resolveOciArtifact } from "../../services/resolver/src/oci.mjs";
// @ts-expect-error Actual native worker scan; wrapper tracks only cleanup ownership.
import { prepareAndScanOciRuntime } from "../../services/scanner/src/oci-scan.mjs";
// @ts-expect-error Actual native base image authority, never inferred from a candidate.
import { readOciRuntimeCatalogue } from "../../services/scanner/src/oci-coverage.mjs";
// @ts-expect-error Actual bounded local Trivy DB identity.
import { readTrivyDatabaseIdentity } from "../../services/scanner/src/oci-trivy.mjs";

const ociMcpInput = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "oci-fullcycle", version: "1" } } },
  { jsonrpc: "2.0", method: "notifications/initialized" }, { jsonrpc: "2.0", id: 2, method: "tools/list" },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "read_context", arguments: {} } },
].map(message => JSON.stringify(message)).join("\n") + "\n";

test("OCI fullcycle uses genuine initialization and paginated fixture tools with private child configuration", async () => {
  assert.deepEqual(ociMcpInput.trim().split("\n").map(line => JSON.parse(line).method), ["initialize", "notifications/initialized", "tools/list", "tools/call"]);
  assert.deepEqual(OCI_PROFILE_PROBE_PLAN.scenarios.map((s: any) => s.toolName), ["read_messages", "read_context"]);
  await assert.rejects(privateNode("for await(const chunk of process.stdin)process.stdout.write(chunk)", { privateKeys: ["SYNTHETIC_PRIVATE_KEY_ONLY"] }), /EXPOSED_PRIVATE_CONFIG/);
});

// Real local Linux Docker, offline Trivy, immutable source resolver, V2 transactions
// and isolated key-owning CLI/Gateway processes. AI is a numeric-loopback contract
// stub and all validators belong to ONE institution; neither proves model quality.
test("OCI source → worker → independent single-key validators → V2 quorum → two Gateway pre-create blocks", {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== "1" || process.env.MCPSHIELD_OCI_PROFILE_TESTS !== "1", timeout: 1200000,
}, async t => {
  assert.equal(process.platform, "linux");
  const builder = process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE!, trivy = process.env.MCPSHIELD_TRIVY_IMAGE!, databaseDir = process.env.MCPSHIELD_TRIVY_DATABASE_DIR!;
  assert.match(builder ?? "", /^sha256:[a-f0-9]{64}$/); assert.match(trivy ?? "", /^sha256:[a-f0-9]{64}$/); assert.ok(databaseDir);
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-oci-fullcycle-")), cleanups: (() => Promise<void>)[] = [];
  const chain: any = ganache.server({ logging: { quiet: true }, miner: { blockTime: 1 }, wallet: { deterministic: true, totalAccounts: 5 } });
  let app: Awaited<ReturnType<typeof buildApp>> | undefined, relayer: V2Relayer | undefined, store: ControlStore | undefined, executionFailed = false;
  const aiCounts = { analyzer: 0, critic: 0, probes: 0 }, validatorPids: number[] = [], sourceMeasurements: Record<string, any>[] = [];
  const ai = createServer(async (request, response) => {
    try {
      const chunks: Buffer[] = []; let bytes = 0;
      for await (const chunk of request) { bytes += chunk.length; if (bytes > 512 * 1024) throw Error("STUB_INPUT_LIMIT"); chunks.push(chunk); }
      const body = JSON.parse(Buffer.concat(chunks).toString()), plan = body.responseSchema?.properties?.scenarios !== undefined;
      assert.deepEqual(body.tools, []);
      const role = plan ? "probes" : body.prompt.includes("Act as an independent adversarial reviewer") ? "critic" : "analyzer";
      aiCounts[role]++;
      response.writeHead(200, { "content-type": "application/json", connection: "close" }).end(JSON.stringify(plan ? OCI_PROFILE_PROBE_PLAN
        : { riskClaims: [], semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false }));
    } catch { response.writeHead(400, { connection: "close" }).end(); }
  });
  ai.requestTimeout = 10000; ai.headersTimeout = 10000;
  try {
    await new Promise<void>(done => ai.listen(0, "127.0.0.1", done)); await chain.listen(0, "127.0.0.1");
    const rpc = `http://127.0.0.1:${chain.address().port}`, aiUrl = `http://127.0.0.1:${(ai.address() as any).port}`;
    const platform = { os: "linux" as const, architecture: "amd64" as const };
    const catalogue = await readOciRuntimeCatalogue({ baseImageDigest: builder, platform, timeoutMs: 40000 }), database = await readTrivyDatabaseIdentity({ databaseDir });
    const config = { baseImageDigest: builder, baseCatalogueDigest: catalogue.catalogueDigest, trivyImageDigest: trivy,
      databaseDir, databaseDigest: database.databaseDigest, sinkImageDigest: builder, platform };
    const accounts = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
    const deployment = await deployV2(rpc, accounts[0].secretKey, accounts.slice(1, 4).map(({ secretKey }) => new Wallet(secretKey).address), 1337);
    relayer = new V2Relayer(rpc, deployment.releaseRegistry.address, 1337, accounts[0].secretKey); store = await ControlStore.open(join(dir, "control.sqlite"));
    const keys = generateKeyPairSync("ed25519"), tenantId = "synthetic-oci-fullcycle", token = "SYNTHETIC_OCI_ADMIN_ONLY", keyId = "oci-integration";
    const publicKey = keys.publicKey.export({ format: "pem", type: "spki" }).toString();
    const options: ControlOptions = { store, credentials: [{ tenantId, token, role: "admin" }], artifactPath: join(dir, "artifacts"), evidencePath: join(dir, "evidence"),
      evidenceKey: "9".repeat(64), signingKey: keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), signingKeyId: keyId,
      ociRuntime: config, scannerOptions: { sandbox: "docker", allowRemoteAi: true, aiProvider: "custom", aiDisclosurePolicy: "LOCAL_CONTRACT_TEST", aiUrl, aiTimeoutMs: 5000 },
      v2Relayer: relayer, chainDecision: v2ChainReader({ rpcUrls: [rpc], registryContract: deployment.releaseRegistry.address, chainId: 1337, confirmations: 1 }),
      prepareOciRuntime: async input => { const output = await prepareAndScanOciRuntime(input); if (output.cleanup) cleanups.push(output.cleanup); return output; } };
    app = await buildApp({ adminApiToken: "unused-legacy-admin", scannerApiToken: "unused-legacy-scan", controlPlane: options }); await app.listen({ host: "127.0.0.1", port: 0 });
    const apiUrl = `http://127.0.0.1:${(app.server.address() as any).port}`, auth = { authorization: `Bearer ${token}` }, policyHash = hash(ociPolicy);
    const post = async (url: string, payload: any = {}, extra = {}) => {
      const response = await app!.inject({ method: "POST", url, headers: { ...auth, ...extra }, payload });
      assert.ok(response.statusCode < 300, `${url}: HTTP_${response.statusCode}`); return response.json();
    };
    const settle = async (actionId: string) => {
      for (let i = 0; i < 40; i++) {
        await chain.provider.request({ method: "evm_mine", params: [] }); await runChainActionOnce(store!, relayer!);
        const { action } = (await app!.inject({ url: `/v1/chain/actions/${actionId}`, headers: auth })).json();
        if (action.status === "COMPLETED") return; assert.notEqual(action.status, "FAILED"); await pause(100);
      }
      assert.fail("OCI_CHAIN_ACTION_TIMEOUT");
    };
    await settle((await post(`/v1/policies/${policyHash}/publish`)).action.actionId);
    const prepare = async (variant: "safe" | "malicious") => {
      const fixture = await createOciProfileFixture({ builderImageDigest: builder, variant }); cleanups.push(fixture.cleanup);
      // Trusted test/operator-local ingestion, not a public API file-path parameter.
      const resolved = await resolveOciArtifact({ type: "oci-layout", path: join(fixture.root, "oci"), platform }); cleanups.push(resolved.cleanup);
      assert.equal(resolved.metadata.allLayerDigestsVerified, true); assert.equal(resolved.metadata.executionPerformed, false);
      const source = { ...exactReleaseIdentity(resolved), artifactDigest: resolved.artifactDigest, manifestDigest: resolved.manifestDigest, toolSurfaceHash: resolved.toolSurfaceHash,
        sourceType: "oci", artifactDir: resolved.artifactDir, artifactUri: "synthetic-local-layout:not-public-registry-provenance", legacyReleaseId: resolved.releaseId,
        version: resolved.version, metadata: resolved.metadata, status: "UNVERIFIED" };
      await store!.put(tenantId, "release", source.releaseId, source);
      const { preparation } = await post(`/v1/releases/${source.releaseId}/prepare`, { policyHash }, { "idempotency-key": variant });
      await runPreparationWorkerOnce(store!, options);
      const [completed] = await preparations(store!, tenantId, preparation.preparationId);
      assert.equal(completed.status, "COMPLETED", JSON.stringify(completed.lastError)); assert.equal(completed.result?.outcome, "DERIVED_RELEASE_CREATED");
      assert.equal(completed.result?.verdict, variant === "safe" ? "PASS" : "FAIL", JSON.stringify({ issues: completed.result?.issues }));
      assert.equal(completed.result?.semanticEvidenceMode, "LOCAL_CONTRACT_TEST");
      const release = (await store!.get(tenantId, "release", completed.result!.releaseId))!, scan = (await store!.scan(tenantId, completed.result!.scanId))!;
      assert.notEqual(release.releaseId, source.releaseId); assert.equal(release.status, "UNVERIFIED"); assert.equal(release.runtimeProfile, ociPolicy.profile);
      assert.equal(scan.result?.scanResult.source, "LIVE"); assert.equal(scan.result?.state, "READY_FOR_VALIDATORS");
      assert.deepEqual(await store!.get(tenantId, "release", source.releaseId), source);
      await settle((await post(`/v1/releases/${release.releaseId}/register`)).action.actionId);
      const exported = await app!.inject({ url: `/v1/releases/${release.releaseId}/gateway-config`, headers: auth }); assert.equal(exported.statusCode, 200);
      const { binding } = exported.json(), file = join(dir, `gateway-${variant}.json`); await writeFile(file, exported.body, { mode: 0o600 });
      assert.equal(binding.profile, "oci-container-v1"); assert.ok(binding.descriptor.sourceBytes <= ociPolicy.maxSourceBytes);
      assert.ok(binding.descriptor.layerArchiveBytes + binding.descriptor.exportArchiveBytes <= ociPolicy.maxExpandedBytes);
      sourceMeasurements.push({ variant, sourceBytes: binding.descriptor.sourceBytes, expandedBytes: binding.descriptor.layerArchiveBytes + binding.descriptor.exportArchiveBytes });
      return { release, scan, file, imageDigest: binding.finalImageDigest };
    };
    const vote = async (scanId: string) => {
      let pumping = true, pumpFailed = false;
      const pump = (async () => { try { while (pumping) { await chain.provider.request({ method: "evm_mine", params: [] }); await runChainActionOnce(store!, relayer!); await pause(100); } }
        catch { pumpFailed = true; pumping = false; } })();
      try {
        for (const { secretKey } of accounts.slice(1, 3)) {
          const pending = promisify(execFile)(process.execPath, ["--import", "tsx", fileURLToPath(new URL("../../apps/validator/src/v2.ts", import.meta.url))],
            { windowsHide: true, timeout: 420000, maxBuffer: 262144, env: { ...getDefaultEnvironment(), MCPSHIELD_TELEMETRY_ENABLED: "false", VALIDATOR_PRIVATE_KEY: secretKey,
              CONTROL_API_URL: apiUrl, CONTROL_API_TOKEN: token, CONTROL_SCAN_ID: scanId, CONTROL_V2_RPC_URLS: rpc, CONTROL_V2_CHAIN_ID: "1337",
              CONTROL_V2_REGISTRY_ADDRESS: deployment.releaseRegistry.address, CONTROL_VALIDATOR_POLICY_HASH: policyHash,
              VALIDATOR_OCI_ENABLED: "true", VALIDATOR_OCI_BASE_DIGEST: builder, VALIDATOR_OCI_BASE_CATALOGUE_DIGEST: config.baseCatalogueDigest,
              VALIDATOR_OCI_TRIVY_DIGEST: trivy, VALIDATOR_OCI_DATABASE_DIR: databaseDir, VALIDATOR_OCI_DATABASE_DIGEST: database.databaseDigest,
              VALIDATOR_OCI_SINK_DIGEST: builder, VALIDATOR_OCI_ARCHITECTURE: "amd64", VALIDATOR_ALLOW_REMOTE_AI: "true", VALIDATOR_AI_PROVIDER: "custom",
              VALIDATOR_AI_URL: aiUrl, VALIDATOR_AI_TIMEOUT_MS: "5000", MCPSHIELD_AI_DISCLOSURE_POLICY: "LOCAL_CONTRACT_TEST",
              VALIDATOR_VERIFICATION_RECEIPTS_PATH: join(dir, "local-verifications.jsonl") } });
          validatorPids.push(pending.child.pid!);
          let result;
          try { result = await pending; } catch { throw Error("OCI_VALIDATOR_CHILD_FAILED"); }
          assert.equal(pumpFailed, false, "OCI_CHAIN_PUMP_FAILED");
          assert.ok(!result.stdout.includes(secretKey) && !result.stderr.includes(secretKey) && !result.stdout.includes(token) && !result.stderr.includes(token));
          const outcome = JSON.parse(result.stdout.trim().split("\n").at(-1)!); assert.equal(outcome.mode, "SINGLE_VALIDATOR"); assert.equal(outcome.operations.length, 1);
        }
      } finally { pumping = false; await pump; }
      await indexV2(store!, relayer!, { deploymentBlock: deployment.releaseRegistry.blockNumber, confirmations: 1 });
    };
    const admission = (release: any) => post("/v1/admission/check", { releaseId: release.releaseId, artifactDigest: release.artifactDigest,
      toolSurfaceHash: release.toolSurfaceHash, policyHash, mode: "strict", operationClass: "READ_PRIVATE" });
    const safe = await prepare("safe"); assert.equal((await admission(safe.release)).decision, "BLOCK"); await vote(safe.scan.scanId);
    assert.equal((await admission(safe.release)).decision, "ALLOW");
    const safeSince = new Date().toISOString(), client = new Client({ name: "oci-fullcycle", version: "1" });
    const transport = new StdioClientTransport({ command: process.execPath, args: [fileURLToPath(new URL("../../apps/gateway/src/index.mjs", import.meta.url)), "stdio", "--prepared-identity", safe.file], stderr: "pipe",
      env: { ...getDefaultEnvironment(), MCPSHIELD_TELEMETRY_ENABLED: "false", MCPSHIELD_PREPARED_IDENTITY: safe.file, MCPSHIELD_MODE: "live", MCPSHIELD_API_URL: apiUrl,
        MCPSHIELD_POLICY_HASH: policyHash, MCPSHIELD_TENANT_ID: tenantId, MCPSHIELD_CONTROL_TOKEN: token, MCPSHIELD_CACHE_PUBLIC_KEY: publicKey, MCPSHIELD_CACHE_KEY_ID: keyId,
        MCPSHIELD_CHAIN_ID: "1337", MCPSHIELD_REGISTRY_CONTRACT: deployment.releaseRegistry.address, MCPSHIELD_VALIDATOR_SET_VERSION: "1", MCPSHIELD_ADMISSION_MODE: "strict" } });
    transport.stderr?.on("data", () => {});
    try {
      await client.connect(transport);
      const first = await client.listTools(); assert.equal(first.tools[0].name, "read_messages"); assert.equal(first.nextCursor, "next");
      assert.equal((await client.listTools({ cursor: first.nextCursor })).tools[0].name, "read_context");
      const result = await client.callTool({ name: "read_messages", arguments: {} }); assert.equal(result.isError, false);
      assert.match((result.content as any[])[0].text, /Packaged synthetic result/);
    } finally { await client.close(); }
    const safeEvents = await dockerEvents(safeSince);
    for (const action of ["create", "start"]) assert.ok(safeEvents.some(e => e.Action === action && e.Actor.Attributes.image === safe.imageDigest));
    const bad = await prepare("malicious"); await vote(bad.scan.scanId);
    const denied = await admission(bad.release);
    assert.deepEqual({ decision: denied.decision, status: denied.status, reasonCode: denied.reasonCode, snapshotStatus: denied.snapshot?.status },
      { decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED", snapshotStatus: "REVOKED" });
    assert.equal((await store.get(tenantId, "release", bad.release.releaseId))?.status, "REVOKED");
    const containers = async () => (await promisify(execFile)("docker", ["container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "label=io.mcpshield.gateway.owner"],
      { windowsHide: true, timeout: 10000, maxBuffer: 65536 })).stdout.trim().split("\n").filter(Boolean).sort();
    const before = await containers(), deniedSince = new Date().toISOString();
    const attempts = await Promise.allSettled(["Gateway-A", "Gateway-B"].map(agentId => privateNode(deniedGatewayChild, { mode: "live", apiBaseUrl: apiUrl, apiToken: token,
      timeoutMs: 5000, policyHash, tenantId, publicKey, keyId, chainId: 1337, registryContract: deployment.releaseRegistry.address, validatorSetVersion: 1,
      operationClass: "READ_PRIVATE", admissionMode: "strict", agentId, preparedIdentityPath: bad.file, input: ociMcpInput }, 60000)));
    const gateways = attempts.map(attempt => { assert.equal(attempt.status, "fulfilled"); return (attempt as PromiseFulfilledResult<any>).value; });
    assert.equal(new Set(gateways.map(g => g.pid)).size, 2);
    for (const { pid, ...decision } of gateways) { assert.notEqual(pid, process.pid); assert.deepEqual(decision, { releaseId: bad.release.releaseId,
      decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED", source: "LIVE", cacheHit: false }); }
    assert.equal((await dockerEvents(deniedSince)).filter(e => e.Actor.Attributes.image === bad.imageDigest && ["create", "start"].includes(e.Action)).length, 0);
    assert.deepEqual(await containers(), before);
    const receipts = (await readFile(join(dir, "local-verifications.jsonl"), "utf8")).trim().split("\n").map(line => JSON.parse(line));
    assert.equal(receipts.length, 4); assert.equal(new Set(validatorPids).size, 4); assert.ok(validatorPids.every(pid => pid !== process.pid));
    assert.equal(new Set(receipts.map(r => r.independentReportRoot)).size, 4);
    assert.ok(receipts.every(r => r.originalReportRoot !== r.independentReportRoot && r.state === "LOCAL_VERIFICATION_ONLY"
      && r.semanticEvidenceMode === "LOCAL_CONTRACT_TEST" && r.providerQuality === "PROVIDER_QUALITY_NOT_MEASURED"));
    assert.equal(receipts.filter(r => r.verdict === "PASS").length, 2); assert.equal(receipts.filter(r => r.verdict === "FAIL").length, 2);
    assert.ok(aiCounts.probes >= 6 && aiCounts.analyzer >= 6 && aiCounts.critic >= 6);
    t.diagnostic(JSON.stringify({ mode: "ACTUAL_LINUX_DOCKER_OFFLINE_TRIVY_LOCAL_EVM_LOCAL_CONTRACT_TEST_SINGLE_INSTITUTION",
      independentValidatorProcesses: 4, independentGatewayProcesses: 2, deniedGatewayCreateOrStartEvents: 0, sourceMeasurements, aiCounts }));
  } catch (error) { executionFailed = true; throw error;
  } finally {
    const failures = [];
    for (const cleanup of [async () => { if (app) await app.close(); else { relayer?.close(); await store?.close(); } }, async () => chain.close(),
      async () => { ai.closeAllConnections(); await new Promise<void>(done => ai.close(() => done())); }, ...cleanups.reverse(), async () => rm(dir, { recursive: true, force: true })]) {
      try { await cleanup(); } catch { failures.push("OCI_FULLCYCLE_CLEANUP_FAILED"); }
    }
    if (failures.length) t.diagnostic(JSON.stringify({ cleanupCode: "OCI_FULLCYCLE_CLEANUP_FAILED", count: failures.length }));
    if (!executionFailed) assert.equal(failures.length, 0, failures.join());
  }
});
