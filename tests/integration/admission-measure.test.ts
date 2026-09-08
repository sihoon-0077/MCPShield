import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createServer } from "node:http";
import { latencySummary, measureAdmission, measuredDecision, assertFreshRevocation, admissionMatrixPlan, cacheAttemptAt, benchmarkProxy, benchmarkRpcBatch, measureAdmissionMatrix, assertUnavailableAdmission } from "./admission-measure.js";
import { sourceSnapshot, withSourceProvenance } from "../../scripts/ops/evaluate-admission.js";
test("load report uses nearest-rank quantiles, all samples, and bounded opt-in inputs", async () => {
  assert.deepEqual(latencySummary([100, 1, 3, 2]), { samples: 4, p50Ms: 2, p95Ms: 100, p99Ms: 100, maxMs: 100 });
  assert.throws(() => latencySummary([])); assert.throws(() => latencySummary([NaN]));
  await assert.rejects(measureAdmission({ requests: 0 })); await assert.rejects(measureAdmission({ concurrency: 17 }));
});

test("matrix plans exact workload and native setup cost without claiming cache hits or running a 10,000-key chain", async () => {
  const pilot = admissionMatrixPlan();
  assert.equal(pilot.identities, 64); assert.equal(pilot.cells, 18); assert.equal(pilot.measuredRequests, 720);
  assert.equal(pilot.setupTransactions, 196); assert.equal(pilot.setupAttestationSignatures, 128); assert.equal(pilot.warmupRequests, 585);
  const full = admissionMatrixPlan({ identities: 10_000, requests: 10_000 });
  assert.equal(full.setupTransactions, 30_004); assert.equal(full.warmupRequests, 9 * 1025); assert.equal(full.measuredRequests, 180_000);
  const optedIn = admissionMatrixPlan({ fullMatrix: true, identities: 10_000, concurrency: 16 });
  assert.equal(optedIn.measuredRequests, 99_000); assert.equal(optedIn.requestsPerHotCell, 1000); assert.equal(optedIn.requestsPerUniformCell, 10_000);
  assert.equal(optedIn.setupAttestationSignatures, 20_000); assert.equal(optedIn.totalBudgetMs, 3_600_000); assert.equal(pilot.totalBudgetMs, 180_000);
  assert.equal(optedIn.setupBudgetMs, 900_000); assert.equal(pilot.setupBudgetMs, 120_000);
  for (const options of [{ fullMatrix: true }, { fullMatrix: true, identities: 10_000, concurrency: 4 }]) assert.throws(() => admissionMatrixPlan(options));
  for (const requests of [1, 7, 40, 10_000]) for (const rate of [0, 50, 95]) {
    assert.equal(Array.from({ length: requests }, (_, index) => Number(cacheAttemptAt(index, rate))).reduce((sum, value) => sum + value, 0), Math.floor(requests * rate / 100));
  }
  for (const options of [{ identities: 10_001 }, { requests: 0 }, { concurrency: 17 }, { identities: NaN }]) assert.throws(() => admissionMatrixPlan(options));
  await assert.rejects(measureAdmissionMatrix({ identities: 10_000 }), /PILOT_LIMIT/);
  await assert.rejects(measureAdmissionMatrix({ requests: 101 }), /PILOT_LIMIT/);
});

test("uninjected unavailable classification requires the exact unsigned API identity-bound response, not any malformed signature", async () => {
  const body = { decision: "BLOCK", status: "UNVERIFIED", reasonCode: "STATUS_UNAVAILABLE", source: "EVM", releaseId: "release", policyHash: "policy", traceId: "a".repeat(32), checkedAt: new Date().toISOString() };
  assertUnavailableAdmission(body, "release", "policy");
  for (const changed of [{ decision: "ALLOW" }, { status: "REVOKED" }, { snapshot: {} }, { signature: "bad" }, { extra: true }, { releaseId: "other" }, { policyHash: "other" }, { checkedAt: "invalid" }]) {
    assert.throws(() => assertUnavailableAdmission({ ...body, ...changed }, "release", "policy"));
  }
  const result = await measuredDecision(async () => { throw Error("Invalid signed admission snapshot fields"); }, "FRESH_VIEW_UNAVAILABLE_UNSIGNED");
  assert.equal(result.failureCode, "FRESH_VIEW_UNAVAILABLE_UNSIGNED");
  await assert.rejects(measuredDecision(async () => { throw Error("Signed admission signature is invalid"); }, "FRESH_VIEW_UNAVAILABLE_UNSIGNED"));
});

test("matrix uses actual bounded HTTP proxies for delayed RPC and outages, with no upstream request on injected 503", async () => {
  const controller = new AbortController(); let upstreamCalls = 0;
  const upstream = createServer(async (request, response) => {
    for await (const _ of request) { /* consume bounded fixture body */ }
    upstreamCalls++; response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ upstream: true, path: request.url, leakedMarker: request.headers["x-benchmark-cache-attempt"] ?? null }));
  });
  await new Promise<void>(resolve => upstream.listen(0, "127.0.0.1", resolve));
  let api: Awaited<ReturnType<typeof benchmarkProxy>> | undefined, rpc: typeof api;
  try {
    const url = `http://127.0.0.1:${(upstream.address() as any).port}`;
    await assert.rejects(benchmarkProxy("https://example.invalid", "RPC", controller.signal));
    api = await benchmarkProxy(url, "API", controller.signal); rpc = await benchmarkProxy(url, "RPC", controller.signal);
    const post = (target: string, headers = {}) => fetch(target, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: "{}", signal: AbortSignal.timeout(3000) });
    const live = await post(`${api.url}/v1/admission/check`); assert.equal(live.status, 200); assert.equal((await live.json()).leakedMarker, null); assert.equal(upstreamCalls, 1);
    const cached = await post(`${api.url}/v1/admission/check`, { "x-benchmark-cache-attempt": "1" }); assert.equal(cached.status, 503); await cached.body?.cancel(); assert.equal(upstreamCalls, 1);
    rpc.state.mode = "DELAY_50MS"; const began = performance.now();
    const delayed = await post(rpc.url); assert.equal(delayed.status, 200); await delayed.body?.cancel(); assert.ok(performance.now() - began >= 45); assert.equal(upstreamCalls, 2);
    rpc.state.mode = "HTTP_503"; const fault = await post(rpc.url); assert.equal(fault.status, 503); await fault.body?.cancel(); assert.equal(upstreamCalls, 2);
    assert.equal(api.state.rejected, 1); assert.equal(rpc.state.rejected, 1); assert.equal(rpc.state.forwarded, 1);
    assert.deepEqual(api.state.errors, []); assert.deepEqual(rpc.state.errors, []);
  } finally {
    controller.abort(); await api?.close(); await rpc?.close(); upstream.closeAllConnections(); await new Promise<void>(resolve => upstream.close(() => resolve()));
  }
});

test("native RPC batch matches out-of-order IDs and rejects missing, duplicate or error responses", async () => {
  let mode = "valid";
  const fixture = createServer(async (request, response) => {
    const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const input = JSON.parse(Buffer.concat(chunks).toString());
    let output = input.map((call: any) => ({ jsonrpc: "2.0", id: call.id, result: call.method })).reverse();
    if (mode === "missing") output.pop();
    if (mode === "duplicate") output[1] = output[0];
    if (mode === "error") output[0] = { ...output[0], error: { code: -32000 } };
    response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(output));
  });
  await new Promise<void>(resolve => fixture.listen(0, "127.0.0.1", resolve));
  try {
    const url = `http://127.0.0.1:${(fixture.address() as any).port}`;
    const calls = [{ method: "synthetic_A", params: [] }, { method: "synthetic_B", params: [] }];
    assert.deepEqual(await benchmarkRpcBatch(url, calls, AbortSignal.timeout(1000)), ["synthetic_A", "synthetic_B"]);
    for (mode of ["missing", "duplicate", "error"]) await assert.rejects(benchmarkRpcBatch(url, calls, AbortSignal.timeout(1000)));
  } finally { fixture.closeAllConnections(); await new Promise<void>(resolve => fixture.close(() => resolve())); }
});

test("measurement rejects unexpected errors and distinguishes signed BLOCK from explicitly expected fail-closed errors", async () => {
  for (const message of ["Invalid signed admission snapshot fields", "Signed admission signature is invalid", "Admission API returned 403", "unexpected failure"]) {
    const run = async () => { throw Error(message); };
    await assert.rejects(measuredDecision(run), { message });
    await assert.rejects(measuredDecision(run, "OFFLINE_STRICT_OR_WRITE"), { message });
  }
  const failClosed = await measuredDecision(async () => { throw Error("Admission unavailable; strict or non-read-only calls fail closed"); }, "OFFLINE_STRICT_OR_WRITE");
  assert.equal(failClosed.outcome, "FAIL_CLOSED_ERROR"); assert.equal(failClosed.failureCode, "OFFLINE_STRICT_OR_WRITE");
  const expiredThenDeleted: any[] = [];
  for (const message of ["Signed admission expired or has an invalid lifetime", "Admission unavailable and no matching signed cache exists"]) {
    expiredThenDeleted.push(await measuredDecision(async () => { throw Error(message); }, ["EXPIRED_CACHE", "EMPTY_CACHE"]));
  }
  assert.deepEqual(expiredThenDeleted.map(result => result.failureCode), ["EXPIRED_CACHE", "EMPTY_CACHE"]);
  await assert.rejects(measuredDecision(async () => { throw Error("Signed admission signature is invalid"); }, ["EXPIRED_CACHE", "EMPTY_CACHE"]), /signature is invalid/);
  assert.throws(() => assertFreshRevocation(failClosed));
  const revoked = await measuredDecision(async () => ({ decision: "BLOCK", releaseStatus: "REVOKED", reasonCode: "RELEASE_REVOKED", cacheHit: false }));
  assertFreshRevocation(revoked);
  for (const changed of [{ releaseStatus: "UNVERIFIED" }, { reasonCode: "STATUS_UNAVAILABLE" }, { cacheHit: true }, { outcome: "FAIL_CLOSED_ERROR" as const }]) assert.throws(() => assertFreshRevocation({ ...revoked, ...changed }));
});

test("source provenance compares HEAD, dirty state and actual tracked/untracked bytes at measurement boundaries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-provenance-test-"));
  assert.equal(dirname(directory), tmpdir());
  const git = (...args: string[]) => execFileSync("git", ["-c", "core.hooksPath=" + join(directory, "no-hooks"), "-c", "commit.gpgsign=false", "-c", "user.name=Synthetic Test", "-c", "user.email=synthetic@example.invalid", ...args], { cwd: directory, windowsHide: true, stdio: "pipe" });
  try {
    git("init", "-q"); await writeFile(join(directory, "source.txt"), "synthetic source v1"); git("add", "source.txt"); git("commit", "-qm", "synthetic initial source");
    const unchanged = await withSourceProvenance(async () => ({ status: "MEASURED" }), directory);
    assert.equal(unchanged.worktreeDirty, false); assert.deepEqual(unchanged.provenance.start, unchanged.provenance.end);
    await mkdir(join(directory, "nested")); assert.deepEqual(sourceSnapshot(directory), sourceSnapshot(join(directory, "nested")));
    await assert.rejects(withSourceProvenance(async () => { git("commit", "--allow-empty", "-qm", "synthetic HEAD change"); return {}; }, directory), { code: "NOT_COMPARABLE" });
    await assert.rejects(withSourceProvenance(async () => { await writeFile(join(directory, "source.txt"), "dirty source v2"); return {}; }, directory), { code: "NOT_COMPARABLE" });
    const before = sourceSnapshot(directory);
    await assert.rejects(withSourceProvenance(async () => { await writeFile(join(directory, "source.txt"), "dirty source v3"); return {}; }, directory), { code: "NOT_COMPARABLE" });
    const after = sourceSnapshot(directory);
    assert.equal(before.dirty, true); assert.equal(after.dirty, true); assert.equal(before.statusHash, after.statusHash); assert.notEqual(before.sourceHash, after.sourceHash);
    await writeFile(join(directory, "untracked.txt"), "synthetic untracked v1");
    await assert.rejects(withSourceProvenance(async () => { await writeFile(join(directory, "untracked.txt"), "synthetic untracked v2"); return {}; }, directory), { code: "NOT_COMPARABLE" });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
