import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir, availableParallelism } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import ganache from "ganache";
import { Contract, JsonRpcProvider, NonceManager, Wallet, id } from "ethers";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { attestationV2Domain, attestationV2Types, bytes32, createReleaseRegistryV2, exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
import { boundedServiceRequest, v2RpcRequest } from "../../packages/contracts-sdk/src/transport.js";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { defaultPolicy, hash } from "../../apps/api/src/control-plane.js";
import { v2ChainReader } from "../../apps/api/src/registry-v2-client.js";
// @ts-expect-error Gateway is shared native ESM.
import { getSignedAdmission } from "../../apps/gateway/src/signed-admission.mjs";

export function latencySummary(samples: number[]) {
  assert.ok(samples.length && samples.every((n) => Number.isFinite(n) && n >= 0));
  const sorted = [...samples].sort((a, b) => a - b);
  const percentile = (p: number) => Number(sorted[Math.ceil(sorted.length * p) - 1].toFixed(3));
  return { samples: sorted.length, p50Ms: percentile(0.5), p95Ms: percentile(0.95), p99Ms: percentile(0.99), maxMs: percentile(1) };
}

const expectedFailures = {
  OFFLINE_STRICT_OR_WRITE: "Admission unavailable; strict or non-read-only calls fail closed",
  EXPIRED_CACHE: "Signed admission expired or has an invalid lifetime",
  EMPTY_CACHE: "Admission unavailable and no matching signed cache exists",
  // Only used after the injected RPC outage's actual HTTP response is independently checked below.
  RPC_UNAVAILABLE_UNSIGNED: "Invalid signed admission snapshot fields",
  FRESH_VIEW_UNAVAILABLE_UNSIGNED: "Invalid signed admission snapshot fields",
  SUPERSEDED_BY_DENIAL: "Admission superseded by a newer denial or invalid response",
} as const;
type ExpectedFailure = keyof typeof expectedFailures;
type MeasuredDecision = { outcome: "ALLOW" | "BLOCK" | "FAIL_CLOSED_ERROR"; cacheHit: boolean; releaseStatus?: string; reasonCode?: string; failureCode?: ExpectedFailure };

export async function measuredDecision(run: () => Promise<any>, expectedFailure?: ExpectedFailure | ExpectedFailure[]): Promise<MeasuredDecision> {
  try {
    const result = await run();
    assert.ok(["ALLOW", "BLOCK"].includes(result.decision), "Unexpected admission decision");
    return { outcome: result.decision, cacheHit: result.cacheHit, releaseStatus: result.releaseStatus, reasonCode: result.reasonCode };
  } catch (error) {
    const expected = Array.isArray(expectedFailure) ? expectedFailure : expectedFailure ? [expectedFailure] : [];
    const failureCode = error instanceof Error && error.name === "Error" ? expected.find(code => error.message === expectedFailures[code]) : undefined;
    if (!failureCode) throw error;
    return { outcome: "FAIL_CLOSED_ERROR", cacheHit: false, failureCode };
  }
}

export function admissionMatrixPlan({ requests = 40, concurrency = 4, identities = 64, fullMatrix = false } = {}) {
  assert.equal(typeof fullMatrix, "boolean");
  if (fullMatrix) assert.ok(identities === 10_000 && concurrency === 16, "FULL_MATRIX_REQUIRES_10000_KEYS_AND_CONCURRENCY_16");
  for (const [value, max] of [[requests, 10_000], [concurrency, 16], [identities, 10_000]]) assert.ok(Number.isInteger(value) && value >= 1 && value <= max, "bounded matrix options required");
  const requestsPerHotCell = fullMatrix ? 1000 : requests, requestsPerUniformCell = fullMatrix ? 10_000 : requests;
  return { profile: "MATRIX", fullMatrix, requestsPerHotCell, requestsPerUniformCell, concurrency, identities, cells: 18, measuredRequests: 9 * (requestsPerHotCell + requestsPerUniformCell),
    setupTransactions: 4 + 3 * identities, setupAttestationSignatures: 2 * identities, setupBatchIdentities: 16,
    warmupRequests: 9 * (1 + Math.min(1024, identities)), nativeCacheCapacity: 1024, nativeAllowTtlMs: 30_000,
    targetCacheAttemptRates: [95, 50, 0], rpcConditions: ["NORMAL", "DELAY_50MS", "HTTP_503"],
    distribution: "ONE_HOT_AND_UNIFORM_CYCLIC", setupBudgetMs: fullMatrix ? 900_000 : 120_000, totalBudgetMs: fullMatrix ? 3_600_000 : 180_000 };
}

// Deterministic spread, not IID sampling or an assertion about actual cache hits.
export const cacheAttemptAt = (index: number, rate: number) => Math.floor((index + 1) * rate / 100) > Math.floor(index * rate / 100);

export function assertUnavailableAdmission(body: any, releaseId: string, policyHash: string) {
  assert.deepEqual(Object.keys(body).sort(), ["checkedAt", "decision", "policyHash", "reasonCode", "releaseId", "source", "status", "traceId"]);
  assert.deepEqual({ decision: body.decision, status: body.status, reasonCode: body.reasonCode, source: body.source, releaseId: body.releaseId, policyHash: body.policyHash },
    { decision: "BLOCK", status: "UNVERIFIED", reasonCode: "STATUS_UNAVAILABLE", source: "EVM", releaseId, policyHash });
  assert.ok(typeof body.checkedAt === "string" && Number.isFinite(Date.parse(body.checkedAt)) && typeof body.traceId === "string" && /^[0-9a-f-]{32,36}$/i.test(body.traceId));
}

export function matrixProxyFailureCode(error: any) {
  if (error?.message === "SERVICE_TIMEOUT") return "SERVICE_TIMEOUT";
  if (["SERVICE_RESPONSE_TOO_LARGE", "BENCHMARK_PROXY_BODY_LIMIT"].includes(error?.message)) return "BODY_LIMIT";
  const code = error?.cause?.code ?? error?.code;
  if (["ECONNRESET", "ECONNREFUSED", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_SOCKET", "ABORT_ERR"].includes(code)) return code as string;
  return "UNCLASSIFIED_PROXY_FAULT";
}

// Never serialize error.message, raw assertion values, response bodies or absolute stack paths.
export function safeMatrixFailure(error: any, stage: string) {
  // Node AssertionError appends numeric details after the caller's fixed message.
  const firstLine = String(error?.message ?? "").split(/\r?\n/, 1)[0];
  const code = ["BENCHMARK_API_CACHE_ATTEMPT_COUNT", "BENCHMARK_API_REQUEST_COUNT", "BENCHMARK_UNSIGNED_RESPONSE_COUNT", "BENCHMARK_KEYSPACE_COVERAGE",
    "BENCHMARK_FULL_KEYSPACE_COVERAGE", "BENCHMARK_API_PROXY_FAULT_COUNT", "BENCHMARK_RPC_PROXY_FAULT_COUNT", "BENCHMARK_TOTAL_BUDGET_EXCEEDED",
    "BENCHMARK_SETUP_BUDGET_EXCEEDED"].includes(firstLine) ? firstLine : "BENCHMARK_UNCLASSIFIED_FAILURE";
  const frame = String(error?.stack ?? "").match(/(?:^|[\\/])(admission-measure\.ts):(\d+):(\d+)/m);
  return { code, stage: ["SETUP", "WARMUP", "REQUESTS", "INVARIANTS", "CLEANUP"].includes(stage) ? stage : "UNKNOWN",
    ...(frame ? { frame: `tests/integration/${frame[1]}:${frame[2]}:${frame[3]}` } : {}),
    ...(Number.isFinite(error?.actual) ? { actual: error.actual } : {}), ...(Number.isFinite(error?.expected) ? { expected: error.expected } : {}) };
}

/** Actual HTTP fault boundary, never a replacement chainDecision or fabricated proof. */
export async function benchmarkProxy(upstream: string, kind: "API" | "RPC", signal: AbortSignal) {
  const target = new URL(upstream);
  assert.ok(target.protocol === "http:" && target.hostname === "127.0.0.1" && !target.username && !target.password && target.pathname === "/" && !target.search && !target.hash);
  const state = { mode: "NORMAL" as "NORMAL" | "DELAY_50MS" | "HTTP_503", received: 0, forwarded: 0, rejected: 0, errors: 0, errorCodes: {} as Record<string, number> };
  const closing = new AbortController();
  const joinedSignal = AbortSignal.any([signal, closing.signal]);
  const server = createServer(async (request, response) => {
    try {
      if (request.method !== "POST" || request.url !== (kind === "API" ? "/v1/admission/check" : "/")) { response.writeHead(404).end(); return; }
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of request) { size += chunk.length; assert.ok(size <= 1024 * 1024, "BENCHMARK_PROXY_BODY_LIMIT"); chunks.push(Buffer.from(chunk)); }
      state.received++;
      if ((kind === "API" && request.headers["x-benchmark-cache-attempt"] === "1") || (kind === "RPC" && state.mode === "HTTP_503")) {
        state.rejected++; response.writeHead(503, { "content-type": "application/json" }).end('{"error":"SYNTHETIC_HTTP_OUTAGE"}'); return;
      }
      if (kind === "RPC" && state.mode === "DELAY_50MS") await delay(50, undefined, { signal: joinedSignal });
      state.forwarded++;
      const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json" };
      if (kind === "API" && request.headers.authorization) headers.authorization = request.headers.authorization;
      const result = await boundedServiceRequest(new URL(request.url, upstream).href, { method: "POST", headers, body: Buffer.concat(chunks), signal: joinedSignal }, { timeoutMs: 5000, maxBytes: 1024 * 1024 });
      response.writeHead(result.statusCode, { "content-type": "application/json" }).end(result.body);
    } catch (error) {
      // Unexpected proxy faults must fail the benchmark, not inflate the expected-outage count.
      if (!joinedSignal.aborted) { state.errors++; const code = matrixProxyFailureCode(error); state.errorCodes[code] = (state.errorCodes[code] ?? 0) + 1; }
      response.writeHead(502).end();
    }
  });
  server.requestTimeout = 5000; server.headersTimeout = 5000; server.setTimeout(5000, socket => socket.destroy());
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return { url: `http://127.0.0.1:${(server.address() as any).port}`, state,
    async close() { closing.abort(); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } };
}

/** Native JSON-RPC batches still execute every signed transaction on the unmodified EVM. */
export async function benchmarkRpcBatch(url: string, calls: { method: string; params: any[] }[], signal: AbortSignal) {
  assert.ok(calls.length > 0 && calls.length <= 128);
  const request = calls.map((call, index) => ({ jsonrpc: "2.0", id: index + 1, ...call }));
  const response = await boundedServiceRequest(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(request), signal }, { timeoutMs: 10_000, maxBytes: 8 * 1024 * 1024 });
  assert.equal(response.statusCode, 200);
  const values = JSON.parse(response.body.toString());
  assert.ok(Array.isArray(values) && values.length === calls.length && new Set(values.map(value => value.id)).size === calls.length);
  return request.map(call => {
    const value = values.find(item => item.id === call.id);
    assert.ok(value?.jsonrpc === "2.0" && !value.error && Object.hasOwn(value, "result"), `BENCHMARK_NATIVE_RPC_FAILED: ${call.method}`);
    return value.result;
  });
}

export async function measureAdmissionMatrix(options: Parameters<typeof admissionMatrixPlan>[0] = {}) {
  const plan = admissionMatrixPlan(options);
  assert.ok(plan.fullMatrix || plan.identities <= 64 && plan.requestsPerUniformCell <= 100, "PILOT_LIMIT: use explicit --full-matrix for the fixed 10,000-key / 99,000-request workload");
  const began = performance.now(), started = new Date().toISOString(), controller = new AbortController();
  // CLI parent also bounds synchronous compiler stalls using this profile's hard cap.
  const deadline = setTimeout(() => controller.abort(new Error("BENCHMARK_TOTAL_BUDGET_EXCEEDED")), plan.totalBudgetMs - 5000);
  const budget = (setup = false) => { controller.signal.throwIfAborted(); assert.ok(!setup || performance.now() - began < plan.setupBudgetMs, "BENCHMARK_SETUP_BUDGET_EXCEEDED"); };
  const resourceSamples: { benchmarkProgress: string; completed: number; total: number; elapsedMs: number; rssBytes: number; heapUsedBytes: number; cpuUserMicros: number; cpuSystemMicros: number }[] = [];
  const progress = (phase: string, completed: number, total: number) => {
    const memory = process.memoryUsage(), cpu = process.cpuUsage();
    const sample = { benchmarkProgress: phase, completed, total, elapsedMs: Math.round(performance.now() - began), rssBytes: memory.rss, heapUsedBytes: memory.heapUsed, cpuUserMicros: cpu.user, cpuSystemMicros: cpu.system };
    resourceSamples.push(sample); process.stderr.write(`${JSON.stringify(sample)}\n`);
  };
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 4 }, miner: { blockTime: 1 } });
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-admission-matrix-"));
  let provider: JsonRpcProvider | undefined, app: Awaited<ReturnType<typeof buildApp>> | undefined, store: ControlStore | undefined;
  let reader: ReturnType<typeof v2ChainReader> | undefined, rpcProxy: Awaited<ReturnType<typeof benchmarkProxy>> | undefined, apiProxy: Awaited<ReturnType<typeof benchmarkProxy>> | undefined;
  const gas: Record<string, number[]> = {}, cells: any[] = [];
  let stage = "SETUP", currentCell: Record<string, any> | undefined, partialCell: (() => Record<string, any>) | undefined;
  let setup: Record<string, any> = { status: "INCOMPLETE", confirmedTransactions: 0, registeredAndVerifiedOnChain: 0, validatorExecution: "EXPLICIT_TEST_ONLY_SIGNING" };
  let result: Record<string, any> | undefined;
  const parallel = async (count: number, run: (index: number) => Promise<void>) => {
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(plan.concurrency, count) }, async () => { while (next < count) { budget(); await run(next++); } }));
  };
  try {
    await chain.listen(0, "127.0.0.1");
    const rpc = `http://127.0.0.1:${chain.address().port}`;
    const batch = (calls: { method: string; params: any[] }[]) => { budget(true); return benchmarkRpcBatch(rpc, calls, controller.signal); };
    const keys = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
    const validators = keys.slice(1).map(key => new Wallet(key.secretKey)), owner = new Wallet(keys[0].secretKey);
    const deploymentStart = performance.now();
    const deployment = await deployV2(rpc, keys[0].secretKey, validators.map(wallet => wallet.address), 1337); budget(true);
    provider = new JsonRpcProvider(v2RpcRequest(rpc, { signal: controller.signal }), undefined, { batchMaxCount: 1 });
    const registry = createReleaseRegistryV2(deployment.releaseRegistry.address, provider), policyHash = hash(defaultPolicy);
    const policy = new Contract(deployment.policyRegistry.address, ["function publish(bytes32,bytes32)"], owner.connect(provider));
    const published = await (await policy.publish(policyHash, policyHash)).wait(); assert.equal(published.status, 1);
    gas.publishPolicy = [Number(published.gasUsed)];
    const deploymentMs = performance.now() - deploymentStart;
    setup = { ...setup, confirmedTransactions: 4, deploymentMs: Math.round(deploymentMs) };
    progress("DEPLOYMENT_CONFIRMED", 4, 4);
    const now = Number((await provider.getBlock("latest"))!.timestamp);
    let nonce = await provider.getTransactionCount(owner.address, "pending");
    const validatorNonces = await Promise.all(validators.slice(0, 2).map(async validator => Number(await registry.nonces(validator.address))));
    const releases: Record<string, any>[] = [], receiptHashes: string[] = [];
    store = await ControlStore.open(join(directory, "control.sqlite"));
    const registrationStart = performance.now(); let nextSetupProgress = 1000;
    await batch([{ method: "miner_stop", params: [] }]);
    for (let offset = 0; offset < plan.identities; offset += plan.setupBatchIdentities) {
      budget(true);
      const transactions: { raw: string; kind: string; releaseId: string }[] = [];
      const add = async (kind: string, releaseId: string, data: string) => transactions.push({ kind, releaseId, raw: await owner.signTransaction({ to: deployment.releaseRegistry.address, data, nonce: nonce++, chainId: 1337, type: 0, gasPrice: 2_000_000_000n, gasLimit: kind === "registerRelease" ? 250_000 : 700_000 }) });
      for (let index = offset; index < Math.min(offset + plan.setupBatchIdentities, plan.identities); index++) {
        const artifactDigest = `sha256:${id(`matrix-synthetic-artifact-${index}`).slice(2)}`, manifestDigest = id(`matrix-manifest-${index}`), toolSurfaceHash = id(`matrix-surface-${index}`);
        const release = { ...exactReleaseIdentity({ toolId: "benchmark:synthetic-matrix", artifactDigest, manifestDigest, toolSurfaceHash }), artifactDigest, manifestDigest, toolSurfaceHash, status: "UNVERIFIED" };
        await add("registerRelease", release.releaseId, registry.interface.encodeFunctionData("registerRelease", [release.toolId, bytes32(artifactDigest), manifestDigest, toolSurfaceHash]));
        for (let validator = 0; validator < 2; validator++) {
          const payload = { releaseId: release.releaseId, artifactDigest: bytes32(artifactDigest), manifestDigest, toolSurfaceDigest: toolSurfaceHash,
            policyHash, reportRoot: id(`SYNTHETIC_REPORT_NOT_SCANNER_${index}`), verdict: 0, validFrom: now - 1, validUntil: now + 86400, validatorSetVersion: 1, nonce: validatorNonces[validator]++, deadline: now + 86400 };
          const signature = await validators[validator].signTypedData(attestationV2Domain(1337, deployment.releaseRegistry.address), attestationV2Types, payload);
          await add("passAttestation", release.releaseId, registry.interface.encodeFunctionData("submitAttestation", [payload, signature]));
        }
        // SQL stores identity only; VERIFIED is obtained from the actual contract, never injected.
        await store.put("benchmark", "release", release.releaseId, release); releases.push(release);
      }
      const hashes = await batch(transactions.map(transaction => ({ method: "eth_sendRawTransaction", params: [transaction.raw] })));
      assert.ok(hashes.every(value => /^0x[0-9a-f]{64}$/.test(value)));
      let receipts: any[] = [];
      for (let attempt = 0; attempt < 4; attempt++) {
        await batch([{ method: "evm_mine", params: [] }]);
        receipts = await batch(hashes.map(transactionHash => ({ method: "eth_getTransactionReceipt", params: [transactionHash] })));
        if (receipts.every(Boolean)) break;
      }
      receipts.forEach((receipt, index) => {
        const transaction = transactions[index]; assert.ok(receipt && Number(receipt.status) === 1 && receipt.transactionHash === hashes[index], "ACTUAL_SETUP_TRANSACTION_NOT_CONFIRMED");
        const events = receipt.logs.map((log: any) => registry.interface.parseLog(log)).filter(Boolean);
        const eventName = transaction.kind === "registerRelease" ? "ReleaseRegistered" : "AttestationAccepted";
        assert.ok(events.some((event: any) => event.name === eventName && event.args.releaseId === transaction.releaseId), "ACTUAL_SETUP_EVENT_MISSING");
        (gas[transaction.kind] ??= []).push(Number(receipt.gasUsed)); receiptHashes.push(receipt.transactionHash);
      });
      const decisions = await batch(releases.slice(offset).map(release => ({ method: "eth_call", params: [{ to: deployment.releaseRegistry.address, data: registry.interface.encodeFunctionData("getDecision", [release.releaseId, policyHash]) }, "latest"] })));
      decisions.forEach(value => { const decision = registry.interface.decodeFunctionResult("getDecision", value)[0]; assert.equal(Number(decision.status), 1); assert.equal(Number(decision.approvals), 2); });
      setup = { ...setup, confirmedTransactions: 4 + receiptHashes.length, registeredAndVerifiedOnChain: releases.length };
      if (releases.length >= nextSetupProgress || releases.length === plan.identities) { progress("ACTUAL_CHAIN_SETUP", releases.length, plan.identities); nextSetupProgress += 1000; }
    }
    await batch([{ method: "miner_start", params: [1] }]);
    assert.equal(receiptHashes.length, plan.identities * 3);
    const registrationMs = performance.now() - registrationStart, setupMs = performance.now() - began;
    setup = { status: "COMPLETE", elapsedMs: Math.round(setupMs), deploymentMs: Math.round(deploymentMs), registrationsAndVotesMs: Math.round(registrationMs), confirmedTransactions: 4 + receiptHashes.length,
      receiptDigest: hash(receiptHashes), registeredAndVerifiedOnChain: releases.length, validatorExecution: "EXPLICIT_TEST_ONLY_SIGNING", wallClockUnmodified: true, attestationLifetimeSeconds: 86400 };
    rpcProxy = await benchmarkProxy(rpc, "RPC", controller.signal);
    reader = v2ChainReader({ rpcUrls: [rpcProxy.url], registryContract: deployment.releaseRegistry.address, chainId: 1337, confirmations: 1 });
    const key = generateKeyPairSync("ed25519"), token = randomUUID();
    app = await buildApp({ adminApiToken: randomUUID(), scannerApiToken: randomUUID(), controlPlane: { store, credentials: [{ token, tenantId: "benchmark", role: "reader" }],
      artifactPath: directory, evidencePath: directory, evidenceKey: "a".repeat(64), signingKey: key.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), signingKeyId: "benchmark-matrix", chainDecision: reader } });
    await app.listen({ host: "127.0.0.1", port: 0 });
    // Measure only this local API/native-cache tier; never inherit an operator's
    // organization-indexer or direct-RPC fallback URLs from the shell environment.
    const base = { timeoutMs: 5000, admissionMode: "balanced", cacheFile: null, indexer: null, rpc: null, publicKey: key.publicKey.export({ format: "pem", type: "spki" }).toString(), keyId: "benchmark-matrix",
      policyHash, chainId: 1337, registryContract: deployment.releaseRegistry.address, validatorSetVersion: 1, tenantId: "benchmark", apiToken: token, operationClass: "READ_PRIVATE" };
    for (const distribution of ["HOT", "UNIFORM_CYCLIC"] as const) for (const targetCacheAttemptRate of plan.targetCacheAttemptRates) for (const rpcCondition of plan.rpcConditions) {
      budget();
      // A fresh real loopback endpoint namespaces the native cache; no internal cache mutation.
      apiProxy = await benchmarkProxy(`http://127.0.0.1:${(app.server.address() as any).port}`, "API", controller.signal);
      const api = apiProxy, keyspace = distribution === "HOT" ? 1 : plan.identities, requests = distribution === "HOT" ? plan.requestsPerHotCell : plan.requestsPerUniformCell;
      currentCell = { distribution, keyspace, requests, targetCacheAttemptRate, rpcCondition }; partialCell = undefined; stage = "WARMUP";
      const proxy: Awaited<ReturnType<typeof benchmarkProxy>> = rpcProxy;
      let verifiedUnsignedResponses = 0;
      const check = async (index: number, cacheAttempt: boolean, fault: boolean) => {
        const release = releases[index % keyspace];
        let verifiedUnsigned = false;
        const fetchImpl: typeof fetch = async (input, init) => {
          const headers = new Headers(init?.headers); if (cacheAttempt) headers.set("x-benchmark-cache-attempt", "1");
          const response = await fetch(input, { ...init, headers, signal: init?.signal ? AbortSignal.any([init.signal, controller.signal]) : controller.signal });
          if (!cacheAttempt) {
            assert.equal(response.status, 200); const body = await response.clone().json();
            if (fault || body.reasonCode === "STATUS_UNAVAILABLE") {
              assertUnavailableAdmission(body, release.releaseId, policyHash); verifiedUnsigned = true; verifiedUnsignedResponses++;
            }
          }
          return response;
        };
        const expected: ExpectedFailure[] = cacheAttempt ? ["EMPTY_CACHE", "EXPIRED_CACHE", "SUPERSEDED_BY_DENIAL"] : [fault ? "RPC_UNAVAILABLE_UNSIGNED" : "FRESH_VIEW_UNAVAILABLE_UNSIGNED", "SUPERSEDED_BY_DENIAL"];
        const result = await measuredDecision(() => getSignedAdmission({ ...base, apiBaseUrl: api.url, fetchImpl, identity: release, controlReleaseId: release.releaseId }), expected);
        if (result.failureCode === "SUPERSEDED_BY_DENIAL") assert.ok(verifiedUnsignedResponses > 0, "Supersession must follow an independently checked unsigned unavailable response");
        else if (!cacheAttempt && result.outcome === "FAIL_CLOSED_ERROR") assert.ok(verifiedUnsigned, "An unknown signature/protocol failure is never an expected unavailable sample");
        if (!cacheAttempt && fault) assert.equal(result.outcome, "FAIL_CLOSED_ERROR");
        if (result.outcome === "ALLOW") assert.equal(result.cacheHit, cacheAttempt);
        assert.notEqual(result.outcome, "BLOCK", "Verified setup has no revocations; unexpected signed BLOCK is not an outage sample");
        return result;
      };
      proxy.state.mode = "NORMAL";
      const warmupStarted = performance.now(), warmupRequests = Math.min(1024, keyspace), warmupRpcStart = proxy.state.received;
      let warmupAllowed = 0;
      const warmupFailureCodes: Partial<Record<ExpectedFailure, number>> = {};
      await parallel(warmupRequests, async index => {
        const result = await check(index, false, false); warmupAllowed += Number(result.outcome === "ALLOW");
        if (result.failureCode) warmupFailureCodes[result.failureCode] = (warmupFailureCodes[result.failureCode] ?? 0) + 1;
      });
      const warmupMs = performance.now() - warmupStarted, warmupRpcRequests = proxy.state.received - warmupRpcStart;
      const warmupUnavailable = verifiedUnsignedResponses; verifiedUnsignedResponses = 0;
      proxy.state.mode = rpcCondition as typeof proxy.state.mode;
      const rpcStart = { received: proxy.state.received, forwarded: proxy.state.forwarded, rejected: proxy.state.rejected };
      const apiStart = { received: api.state.received, forwarded: api.state.forwarded, rejected: api.state.rejected };
      const latencies: number[] = [], failureCodes: Partial<Record<ExpectedFailure, number>> = {}; let allowed = 0, attempts = 0, cacheHits = 0, completed = 0;
      const visited = new Set<number>();
      const cellStart = performance.now();
      partialCell = () => ({ ...currentCell, completed, allowed, failClosedErrors: completed - allowed, failureCodes: { ...failureCodes }, cacheHits,
        actualCacheAttempts: attempts, uniqueKeysVisited: visited.size, verifiedUnsignedResponses,
        ...(latencies.length ? latencySummary(latencies) : {}), postCellInvariantsAccepted: false,
        warmup: { requests: warmupRequests, allowed: warmupAllowed, failClosedErrors: warmupRequests - warmupAllowed, failureCodes: { ...warmupFailureCodes }, elapsedMs: Math.round(warmupMs) },
        proxyFaults: { api: api.state.errors, apiCodes: { ...api.state.errorCodes }, rpc: proxy.state.errors, rpcCodes: { ...proxy.state.errorCodes } } });
      stage = "REQUESTS";
      await parallel(requests, async index => {
        visited.add(index % keyspace);
        const cacheAttempt = cacheAttemptAt(index, targetCacheAttemptRate); attempts += Number(cacheAttempt);
        const requestStart = performance.now(), result = await check(index, cacheAttempt, rpcCondition === "HTTP_503");
        latencies.push(performance.now() - requestStart); allowed += Number(result.outcome === "ALLOW"); cacheHits += Number(result.cacheHit);
        if (result.failureCode) failureCodes[result.failureCode] = (failureCodes[result.failureCode] ?? 0) + 1;
        completed++; if (completed % 1000 === 0) progress(`${distribution}:${targetCacheAttemptRate}:${rpcCondition}`, completed, requests);
      });
      stage = "INVARIANTS";
      assert.equal(api.state.rejected - apiStart.rejected, attempts, "BENCHMARK_API_CACHE_ATTEMPT_COUNT");
      assert.equal(api.state.received - apiStart.received, requests, "BENCHMARK_API_REQUEST_COUNT");
      assert.equal(verifiedUnsignedResponses, rpcCondition === "HTTP_503" ? requests - attempts : failureCodes.FRESH_VIEW_UNAVAILABLE_UNSIGNED ?? 0, "BENCHMARK_UNSIGNED_RESPONSE_COUNT");
      assert.equal(visited.size, Math.min(keyspace, requests), "BENCHMARK_KEYSPACE_COVERAGE");
      if (plan.fullMatrix && distribution === "UNIFORM_CYCLIC") assert.equal(visited.size, 10_000, "BENCHMARK_FULL_KEYSPACE_COVERAGE");
      assert.equal(api.state.errors, 0, "BENCHMARK_API_PROXY_FAULT_COUNT");
      assert.equal(proxy.state.errors, 0, "BENCHMARK_RPC_PROXY_FAULT_COUNT");
      const elapsedMs = performance.now() - cellStart;
      cells.push({ distribution, keyspace, uniqueKeysVisited: visited.size, keyspaceCoverage: visited.size / keyspace,
        targetCacheAttemptRate, actualCacheAttempts: attempts, actualCacheAttemptRate: 100 * attempts / requests, observedCacheHitRate: 100 * cacheHits / requests,
        rpcCondition, ...latencySummary(latencies), elapsedMs: Math.round(elapsedMs), throughputQps: Number((requests * 1000 / elapsedMs).toFixed(2)),
        allowed, failClosedErrors: requests - allowed, failClosedErrorRate: (requests - allowed) / requests, unexpectedErrors: 0, failureCodes, cacheHits,
        warmup: { requests: warmupRequests, allowed: warmupAllowed, failClosedErrors: warmupRequests - warmupAllowed, verifiedUnsignedResponses: warmupUnavailable, failureCodes: warmupFailureCodes,
          elapsedMs: Math.round(warmupMs), rpcRequests: warmupRpcRequests, rpcCondition: "NORMAL", includedInRequestLatencies: false },
        transport: { apiForwarded: api.state.forwarded - apiStart.forwarded, api503: api.state.rejected - apiStart.rejected,
          rpcRequests: proxy.state.received - rpcStart.received, rpcForwarded: proxy.state.forwarded - rpcStart.forwarded, rpc503: proxy.state.rejected - rpcStart.rejected, verifiedUnsignedResponses } });
      await api.close(); apiProxy = undefined;
      // Persist each completed aggregate in the captured stream before a later cell/fatal exit can lose it.
      process.stderr.write(`${JSON.stringify({ benchmarkCell: cells.at(-1) })}\n`);
      progress("CELLS_COMPLETED", cells.length, plan.cells);
    }
    result = { status: "MEASURED", profile: plan.fullMatrix ? "10000_KEY_OPT_IN_MATRIX" : "64_KEY_BOUNDED_PILOT", measuredAt: started, inputs: plan,
      environment: { hostClass: "SHARED_DEVELOPMENT_HOST", chain: "LOCAL_GANACHE_EVM", blockTimeSeconds: 1, setupMining: "NATIVE_MANUAL_BATCH_THEN_PERIODIC", database: "SQLITE_WAL", http: "LOOPBACK_ACTUAL_HTTP_PROXIES", node: process.version, platform: process.platform, logicalProcessors: availableParallelism() },
      setup,
      totalElapsedMs: Math.round(performance.now() - began), warmupElapsedMs: cells.reduce((sum, cell) => sum + cell.warmup.elapsedMs, 0), cells, resourceSamples,
      gas: Object.fromEntries(Object.entries(gas).map(([kind, values]) => [kind, { samples: values.length, min: Math.min(...values), max: Math.max(...values), mean: Math.round(values.reduce((a, b) => a + b, 0) / values.length) }])),
      limitations: ["Synthetic report roots are signed only by benchmark code; this does not run or bypass the production independent scanner/validator.",
        "Organization-indexer/direct-RPC fallback tiers are explicitly disabled; this experiment measures the local signed API and its native cache only.",
        "Gateway is network-first: targetCacheAttemptRate requests a real API HTTP 503, not a target or measured cache-hit percentage. All hits still pay one HTTP roundtrip.",
        "Native memory cache capacity 1024 and 30-second ALLOW TTL are unchanged; expiry, invalidation and eviction can lower observed hits. Empty-cache outcomes do not distinguish eviction from never-warmed keys.",
        "Each cell starts at a new real loopback URL and warms at most 1024 entries using normal RPC; warming time and traffic are disclosed, not included in request latency.",
        "Uniform means deterministic cyclic visits, not IID random requests. Keyspace coverage is reported; 40 pilot requests do not visit all 64 keys.",
        "RPC delay is an added 50ms per real HTTP request; HTTP 503 is immediate failure, not a TCP timeout or public-network outage.",
        "FRESH_VIEW_UNAVAILABLE_UNSIGNED records the actual unsigned STATUS_UNAVAILABLE response without injected RPC faults; the API does not expose whether canonical-head movement, RPC budget, or another fresh-reader rejection caused it. It is not relabeled as an injected outage.",
        "Warmup unavailability is counted without retrying until success; no clock freeze, cache TTL change, or forced hit rate is used.",
        "Shared development host, not an isolated idle lab; other local work may contend for CPU/memory. Resource samples are observations, not continuous peak-memory measurements.",
        "Local closed-loop samples are not production capacity or a production p99 SLO. Only the explicit full profile visits 10,000 keys; existing smoke separately measures fresh revocation."] };
  } catch (error) {
    result = { status: "PARTIAL_FAILED", profile: plan.fullMatrix ? "10000_KEY_OPT_IN_MATRIX" : "64_KEY_BOUNDED_PILOT", measuredAt: started, inputs: plan,
      environment: { hostClass: "SHARED_DEVELOPMENT_HOST", chain: "LOCAL_GANACHE_EVM", node: process.version, platform: process.platform },
      setup, cells: [...cells], partialCell: partialCell?.() ?? currentCell ?? null, failure: safeMatrixFailure(error, stage),
      totalElapsedMs: Math.round(performance.now() - began), resourceSamples,
      limitations: ["Failed partial attempt, not a complete benchmark or production SLO. Partial-cell counts and quantiles did not pass every post-cell invariant.",
        "Completed cell aggregates are also streamed before proceeding. Fatal process termination still requires recovery from captured output."] };
  } finally {
    clearTimeout(deadline); controller.abort(); reader?.close();
    const cleanups = [async () => { if (apiProxy) await apiProxy.close(); }, async () => { if (app) await app.close(); else if (store) await store.close(); },
      async () => { if (rpcProxy) await rpcProxy.close(); }, async () => { provider?.destroy(); await chain.close(); }, async () => { await rm(directory, { recursive: true, force: true }); }];
    for (const close of cleanups) try { await close(); } catch (error) {
      // Keep already collected evidence and attempt the remaining exact-resource cleanup.
      result = { ...result, status: "PARTIAL_FAILED", cleanupFailure: safeMatrixFailure(error, "CLEANUP") };
    }
  }
  return result!;
}

export function assertFreshRevocation(result: MeasuredDecision) {
  assert.deepEqual({ outcome: result.outcome, releaseStatus: result.releaseStatus, reasonCode: result.reasonCode, cacheHit: result.cacheHit },
    { outcome: "BLOCK", releaseStatus: "REVOKED", reasonCode: "RELEASE_REVOKED", cacheHit: false }, "A fresh signed revocation is required; any other error is not revocation propagation");
}

// Integration measurement, not a production SLO: actual local EVM, SQL, HTTP and
// signature checks; only the stated outage conditions and scan reports are synthetic.
export async function measureAdmission({ requests = 40, concurrency = 4, identities = 4 } = {}) {
  for (const [value, max] of [[requests, 1000], [concurrency, 16], [identities, 16]]) assert.ok(Number.isInteger(value) && value >= 1 && value <= max, "bounded benchmark options required");
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 4 } });
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-admission-measure-"));
  let provider: JsonRpcProvider | undefined, app: Awaited<ReturnType<typeof buildApp>> | undefined, store: ControlStore | undefined;
  let reader: ReturnType<typeof v2ChainReader> | undefined;
  const started = new Date().toISOString(), gas: Record<string, number[]> = {};
  try {
    await chain.listen(0, "127.0.0.1");
    const rpc = `http://127.0.0.1:${chain.address().port}`;
    const keys = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
    const validators = keys.slice(1).map((key) => new Wallet(key.secretKey));
    const deployment = await deployV2(rpc, keys[0].secretKey, validators.map((wallet) => wallet.address), 1337);
    provider = new JsonRpcProvider(v2RpcRequest(rpc), undefined, { batchMaxCount: 1 });
    const signer = new NonceManager(new Wallet(keys[0].secretKey, provider));
    const registry = createReleaseRegistryV2(deployment.releaseRegistry.address, signer), policyHash = hash(defaultPolicy);
    const policy = new Contract(deployment.policyRegistry.address, ["function publish(bytes32,bytes32)"], signer);
    const mined = async (kind: string, transaction: any) => {
      const receipt = await (await transaction).wait(); assert.equal(receipt.status, 1);
      (gas[kind] ??= []).push(Number(receipt.gasUsed)); return receipt;
    };
    await mined("publishPolicy", policy.publish(policyHash, policyHash));
    const releases: Record<string, any>[] = [], payloads: Record<string, any>[] = [];
    const now = Number((await provider.getBlock("latest"))!.timestamp);
    store = await ControlStore.open(join(directory, "control.sqlite"));
    for (let index = 0; index < identities; index++) {
      const artifactDigest = `sha256:${id(`synthetic-artifact-${index}`).slice(2)}`;
      const release = { ...exactReleaseIdentity({ toolId: "benchmark:synthetic", artifactDigest, manifestDigest: id(`manifest-${index}`), toolSurfaceHash: id(`surface-${index}`) }),
        artifactDigest, manifestDigest: id(`manifest-${index}`), toolSurfaceHash: id(`surface-${index}`), status: "UNVERIFIED" };
      await mined("registerRelease", registry.registerRelease(release.toolId, bytes32(artifactDigest), release.manifestDigest, release.toolSurfaceHash));
      const payload = { releaseId: release.releaseId, artifactDigest: bytes32(artifactDigest), manifestDigest: release.manifestDigest,
        toolSurfaceDigest: release.toolSurfaceHash, policyHash, reportRoot: id(`SYNTHETIC_REPORT_NOT_SCANNER_${index}`), verdict: 0,
        validFrom: now - 1, validUntil: now + 3600, validatorSetVersion: 1, nonce: 0, deadline: now + 1800 };
      for (const validator of validators.slice(0, 2)) {
        payload.nonce = Number(await registry.nonces(validator.address));
        const signature = await validator.signTypedData(attestationV2Domain(1337, deployment.releaseRegistry.address), attestationV2Types, payload);
        await mined("passAttestation", registry.submitAttestation(payload, signature));
      }
      await store.put("benchmark", "release", release.releaseId, release); releases.push(release); payloads.push({ ...payload });
    }
    const key = generateKeyPairSync("ed25519"), token = randomUUID();
    reader = v2ChainReader({ rpcUrls: [rpc], registryContract: deployment.releaseRegistry.address, chainId: 1337, confirmations: 1 });
    let rpcFault = false;
    app = await buildApp({ adminApiToken: randomUUID(), scannerApiToken: randomUUID(), controlPlane: {
      store, credentials: [{ token, tenantId: "benchmark", role: "reader" }], artifactPath: directory, evidencePath: directory,
      evidenceKey: "a".repeat(64), signingKey: key.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), signingKeyId: "benchmark",
      chainDecision: async (release, policyDocument) => { if (rpcFault) throw Error("INJECTED_RPC_OUTAGE"); return reader!(release, policyDocument); },
    } });
    await app.listen({ host: "127.0.0.1", port: 0 });
    const base = { apiBaseUrl: `http://127.0.0.1:${(app.server.address() as any).port}`, timeoutMs: 5000, fetchImpl: fetch, admissionMode: "strict", cacheFile: null, indexer: null, rpc: null,
      publicKey: key.publicKey.export({ type: "spki", format: "pem" }).toString(), keyId: "benchmark", policyHash, chainId: 1337,
      registryContract: deployment.releaseRegistry.address, validatorSetVersion: 1, tenantId: "benchmark", apiToken: token, operationClass: "READ_PRIVATE" };
    const phases: Array<ReturnType<typeof latencySummary> & { name: string; elapsedMs: number; throughputQps: number; allowed: number; blocked: number; failClosedErrors: number; deniedTotal: number; failureCodes: Partial<Record<ExpectedFailure, number>>; cacheHits: number }> = [];
    const measure = async (name: string, run: (index: number) => Promise<MeasuredDecision>, expectedOutcome: MeasuredDecision["outcome"]) => {
      const latencies: number[] = [], failureCodes: Partial<Record<ExpectedFailure, number>> = {}; let next = 0, allowed = 0, blocked = 0, failClosedErrors = 0, cacheHits = 0;
      const start = performance.now();
      await Promise.all(Array.from({ length: Math.min(concurrency, requests) }, async () => {
        while (next < requests) {
          const index = next++, begin = performance.now(), result = await run(index);
          latencies.push(performance.now() - begin); allowed += Number(result.outcome === "ALLOW"); blocked += Number(result.outcome === "BLOCK");
          failClosedErrors += Number(result.outcome === "FAIL_CLOSED_ERROR"); cacheHits += Number(result.cacheHit === true);
          if (result.failureCode) failureCodes[result.failureCode] = (failureCodes[result.failureCode] ?? 0) + 1;
          assert.equal(result.outcome, expectedOutcome, `${name} decision mismatch`);
        }
      }));
      const elapsedMs = performance.now() - start;
      phases.push({ name, ...latencySummary(latencies), elapsedMs: Number(elapsedMs.toFixed(3)), throughputQps: Number((requests * 1000 / elapsedMs).toFixed(2)), allowed, blocked, failClosedErrors, deniedTotal: blocked + failClosedErrors, failureCodes, cacheHits });
    };
    const check = (index: number, options: Record<string, any> = {}, expectedFailure?: ExpectedFailure | ExpectedFailure[]) =>
      measuredDecision(() => getSignedAdmission({ ...base, identity: releases[index % identities], controlReleaseId: releases[index % identities].releaseId, ...options }), expectedFailure);
    await measure("actual_http_evm_strict_hot_key", () => check(0), "ALLOW");
    await measure("actual_http_evm_strict_uniform_keys", (index) => check(index), "ALLOW");
    for (let index = 0; index < identities; index++) assert.equal((await check(index)).outcome, "ALLOW");
    // Explicit fast network-failure injection. Its latency is not a real TCP timeout measurement.
    const offline = async () => { throw new TypeError("INJECTED_API_OFFLINE"); };
    await measure("injected_api_offline_balanced_read_signed_cache", async (index) => { const result = await check(index, { admissionMode: "balanced", fetchImpl: offline }); assert.equal(result.cacheHit, true); return result; }, "ALLOW");
    await measure("injected_api_offline_strict_read", (index) => check(index, { fetchImpl: offline }, "OFFLINE_STRICT_OR_WRITE"), "FAIL_CLOSED_ERROR");
    await measure("injected_api_offline_balanced_write", (index) => check(index, { admissionMode: "balanced", operationClass: "WRITE_EXTERNAL", fetchImpl: offline }, "OFFLINE_STRICT_OR_WRITE"), "FAIL_CLOSED_ERROR");
    // The first expired proof is deleted. Later calls for that same identity
    // correctly find no cache; retain the two distinct counts, never relabel them.
    await measure("injected_api_offline_expired_signed_cache", (index) => check(index, { admissionMode: "balanced", fetchImpl: offline, now: () => Date.now() + 60000 }, ["EXPIRED_CACHE", "EMPTY_CACHE"]), "FAIL_CLOSED_ERROR");
    rpcFault = true;
    const rpcUnavailableFetch: typeof fetch = async (input, options) => {
      const response = await fetch(input, options); assert.equal(response.status, 200);
      const body = await response.clone().json();
      assert.deepEqual({ decision: body.decision, status: body.status, reasonCode: body.reasonCode, source: body.source, snapshot: body.snapshot, signature: body.signature },
        { decision: "BLOCK", status: "UNVERIFIED", reasonCode: "STATUS_UNAVAILABLE", source: "EVM", snapshot: undefined, signature: undefined }, "Injected RPC failure must produce the expected unsigned outage response");
      return response;
    };
    await measure("actual_http_injected_rpc_failure", (index) => check(index, { admissionMode: "balanced", fetchImpl: rpcUnavailableFetch }, "RPC_UNAVAILABLE_UNSIGNED"), "FAIL_CLOSED_ERROR");
    rpcFault = false;
    assert.equal((await check(0)).outcome, "ALLOW");
    // Existing approvals cannot be replaced mid-round. Quarantine first, then
    // attest a genuinely newer scan round, exactly as the incident flow requires.
    const incidentAt = Number((await provider.getBlock("latest"))!.timestamp);
    const quarantiner = createReleaseRegistryV2(deployment.releaseRegistry.address, validators[0].connect(provider));
    await mined("quarantine", quarantiner.quarantine(releases[0].releaseId, policyHash, id("SYNTHETIC_INCIDENT"), id("CANARY_EXFILTRATION"), incidentAt + 600));
    await chain.provider.request({ method: "evm_increaseTime", params: [2] });
    await chain.provider.request({ method: "evm_mine", params: [] });
    const freshTime = Number((await chain.provider.request({ method: "eth_getBlockByNumber", params: ["latest", false] })).timestamp);
    let receipt;
    for (const validator of validators.slice(0, 2)) {
      const payload = { ...payloads[0], reportRoot: id("SYNTHETIC_REVOKE_REPORT"), verdict: 1, validFrom: freshTime, validUntil: freshTime + 3600, nonce: Number(await registry.nonces(validator.address)) };
      const signature = await validator.signTypedData(attestationV2Domain(1337, deployment.releaseRegistry.address), attestationV2Types, payload);
      receipt = await mined("failAttestation", registry.submitAttestation(payload, signature));
    }
    const propagationStart = performance.now(), blocked = await check(0);
    assertFreshRevocation(blocked);
    const propagationMs = performance.now() - propagationStart;
    await measure("actual_http_evm_revoked_signed_block", async () => { const result = await check(0); assertFreshRevocation(result); return result; }, "BLOCK");
    const staleCache = await check(0, { admissionMode: "balanced", fetchImpl: offline }, "EMPTY_CACHE");
    assert.equal(staleCache.failureCode, "EMPTY_CACHE", "fresh revoke must invalidate older signed allow");
    return { status: "MEASURED", measuredAt: started, environment: { chain: "LOCAL_GANACHE_EVM", database: "SQLITE_WAL", http: "LOOPBACK", node: process.version, platform: process.platform, logicalProcessors: availableParallelism() },
      inputs: { requestsPerPhase: requests, concurrency, identities, confirmations: 1 }, phases,
      gas: Object.fromEntries(Object.entries(gas).map(([kind, values]) => [kind, { samples: values.length, min: Math.min(...values), max: Math.max(...values), mean: Math.round(values.reduce((a, b) => a + b, 0) / values.length) }])),
      revocation: { actualEvm: true, blockNumber: receipt!.blockNumber, receiptToNextCheckBlockedMs: Number(propagationMs.toFixed(3)), status: blocked.releaseStatus, reasonCode: blocked.reasonCode, cacheHit: blocked.cacheHit, staleCacheResurrection: false, subsequentOfflineFailure: staleCache.failureCode },
      limitations: ["Synthetic scan reports; this benchmark does not measure scanner detection.", "Local single-host closed-loop measurements are not production load capacity or a Base Sepolia SLO.",
        "API and RPC outages are explicitly injected; separate transport tests cover slow/stalled networks.", "No proactive notification latency claim: revocation is measured at the next admission check.", "p99 from small samples is a smoke measurement; use larger repeated trials for capacity planning."] };
  } finally {
    reader?.close(); if (app) await app.close(); else if (store) await store.close();
    provider?.destroy(); await chain.close(); await rm(directory, { recursive: true, force: true });
  }
}
