import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { NextRequest } from "next/server";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { GET, POST } from "../app/api/control/[...path]/route";
import { PreparationConsole, PreparationDetail, PreparationRecords, canPrepare, canRetryPreparation, isPreparationPolicy } from "../components/preparation-console";
import { EvidenceView } from "../components/evidence-view";
import { baselineCandidates, baselineRequestFields } from "../components/baseline-selection";
import { ReleaseWorkflow } from "../components/release-workflow";
import { preparedDownload } from "../lib/prepared-download";
import { buildApp } from "../../api/src/app.js";
import { ControlStore } from "../../api/src/control-store.js";
import { hash, type ControlOptions } from "../../api/src/control-plane.js";
import { preparedPolicy, scopedPreparedPolicy, scopedBaselinePreparedPolicy } from "../../api/src/control-policy.js";
import { runPreparationWorkerOnce } from "../../api/src/preparation-worker.js";
import { runControlWorkerOnce } from "../../api/src/control-worker.js";
import { claimPreparation, failPreparation } from "../../api/src/preparation-store.js";
import { syntheticPreparedFixture } from "../../../tests/api/prepared-fixture.js";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2-identity.mjs";
// @ts-expect-error Shared pure binding constructor; no candidate execution.
import { createPreparedReleaseBinding, scopedPreparedExecutionPolicy } from "../../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared exact semantic policy constructor.
import { scopedReviewPolicy } from "../../../services/scanner/src/scoped-policy.mjs";
// @ts-expect-error Shared Merkle helper.
import { createEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";
// @ts-expect-error Actual bounded source acquisition without executing candidate code.
import { resolveArtifact } from "../../../services/resolver/src/resolver.mjs";
// @ts-expect-error Shared exact descriptor commitment.
import { hashPreparedRuntimeDescriptor } from "../../../services/resolver/src/runtime-descriptor.mjs";

const policy = { policyHash: hash(preparedPolicy), alias: "prepared-test", version: "1.0.0", document: preparedPolicy, deprecatedAt: null };

test("real preparation API/BFF keeps source identity, roles, evidence privacy and SSE resync separate from approval", { timeout: 20000 }, async () => {
  const fixture = await syntheticPreparedFixture();
  const source = { ...fixture.source, sourceType: "npm", artifactDir: "SYNTHETIC_PRIVATE_PATH_NOT_FOR_BROWSER",
    legacyReleaseId: fixture.result.releaseId, version: "1.0.0", status: "UNVERIFIED", policyHash: null, reportRoot: null, validUntil: null, chain: null };
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-console-preparation-"));
  const store = await ControlStore.open(join(directory, "control.sqlite"));
  const credentials = ["operator", "reader", "admin"].map(role => ({ tenantId: "prepared-console", token: `synthetic-prepared-${role}-token`, role: role as "operator" | "reader" | "admin" }));
  credentials.push({ tenantId: "foreign", token: "synthetic-foreign-operator-token", role: "operator" });
  const options: ControlOptions = { store, credentials, artifactPath: "unused", evidencePath: join(directory, "evidence"), evidenceKey: "1".repeat(64),
    scannerOptions: { sandbox: "docker", allowRemoteAi: false }, preparedRuntime: fixture.config,
    // Explicit test-only daemon double; the production inspector and strict policy are unchanged.
    inspectPreparedRuntime: async () => fixture.trusted };
  let noDiscovery = false;
  options.prepareRuntime = async input => {
    if (noDiscovery) return { binding: null, result: null, analysis: { issues: ["PREPARED_DISCOVERY_REQUIRED"] }, cleanup: async () => {} };
    const result = { ...fixture.result, scanId: input.scanId, releaseId: source.legacyReleaseId, scanStatus: "INCONCLUSIVE", source: "MOCK" };
    const analysis = { profile: preparedPolicy.profile, verdict: "ABSTAIN", issues: ["SYNTHETIC_CONTRACT_TEST_NOT_LIVE_DOCKER"] };
    const bundle = createEvidenceBundle({ ...fixture.documents, "report.json": { ...result, scope: "RESTRICTED_NODE_DOCKER_V1" },
      "prepared/policy-review.json": analysis, "prepared/private-test.json": { value: "SYNTHETIC_PRIVATE_METADATA", padding: "x".repeat(5 * 1024 * 1024) } });
    assert.ok(Buffer.byteLength(JSON.stringify(bundle)) > 4 * 1024 * 1024, "Exercise actual private evidence beyond the ordinary BFF response limit");
    return { binding: fixture.binding, result, analysis, cleanup: async () => {}, runtimeTag: `mcpshield-runtime-${randomUUID()}:local`, bundle };
  };
  const app = await buildApp({ adminApiToken: "synthetic-legacy-admin-token", scannerApiToken: "synthetic-legacy-scanner-token", controlPlane: options });
  await app.listen({ host: "127.0.0.1", port: 0 }); await store.put(credentials[0].tenantId, "release", source.releaseId, source);
  const names = ["MCPSHIELD_API_URL", "MCPSHIELD_PUBLIC_ORIGIN"], previous = names.map(name => process.env[name]);
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`; process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  const request = (path: string, cookie = "", body?: unknown, key = "synthetic-attempt", origin = "https://console.test") => (body === undefined ? GET : POST)(new NextRequest(`https://console.test/api/control/${path}`, {
    method: body === undefined ? "GET" : "POST", headers: { cookie, origin, "content-type": "application/json", "idempotency-key": key }, body: body === undefined ? undefined : JSON.stringify(body),
  }), { params: Promise.resolve({ path: path.split("/") }) });
  let streamReader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    const cookies: string[] = [];
    for (const credential of credentials) { const login = await request("session", "", { token: credential.token }); assert.equal(login.status, 200); cookies.push(login.headers.get("set-cookie")!.split(";")[0]); }
    const [operator, reader, admin, foreign] = cookies;
    const path = `releases/${source.releaseId}/prepare`, body = { policyHash: policy.policyHash };
    assert.equal((await request("events/stream")).status, 401);
    const stream = await request("events/stream", reader); assert.equal(stream.status, 200); streamReader = stream.body!.getReader();
    const initial = new TextDecoder().decode((await streamReader.read()).value); assert.match(initial, /retry: 3000|INITIAL/);
    // Read the fixed initial resync even if it is delivered in a separate stream chunk.
    if (!initial.includes("INITIAL")) assert.match(new TextDecoder().decode((await streamReader.read()).value), /INITIAL/);
    assert.equal((await request(path, reader, body)).status, 403); assert.equal((await request(path, foreign, body)).status, 404);
    assert.equal((await request(path, operator, body, "")).status, 400);
    assert.equal((await request(path, operator, body, "csrf", "https://attacker.invalid")).status, 403);
    for (const field of ["image", "root", "builderImageDigest", "privateKey", "apiToken", "arguments"]) assert.equal((await request(path, operator, { ...body, [field]: "synthetic-forbidden" })).status, 400);
    for (const baselineReleaseId of [null, source.releaseId]) assert.equal((await request(path, operator, { ...body, baselineReleaseId }, "legacy-baseline")).status, 400, "API must keep non-2.1 preparation bodies unchanged");
    const queuedResponse = await request(path, operator, body); assert.equal(queuedResponse.status, 202);
    const queued = (await queuedResponse.json()).preparation;
    assert.equal(queued.status, "QUEUED"); assert.equal(queued.result, undefined);
    const changed = new TextDecoder().decode((await streamReader.read()).value); assert.match(changed, /EVENTS_CHANGED/); assert.doesNotMatch(changed, /preparationId|sourceReleaseId|SYNTHETIC_PRIVATE|token/);
    await streamReader.cancel(); streamReader = undefined;
    assert.equal((await (await request(path, operator, body)).json()).preparation.preparationId, queued.preparationId);
    assert.equal((await request(`preparations/${queued.preparationId}/retry`, operator, {})).status, 409);
    assert.equal(await runPreparationWorkerOnce(store, options), true);
    const completed = (await (await request(`preparations/${queued.preparationId}`, reader)).json()).preparation;
    assert.equal(completed.status, "COMPLETED"); assert.equal(completed.result.outcome, "DERIVED_RELEASE_CREATED"); assert.equal(completed.result.verdict, "ABSTAIN");
    assert.notEqual(completed.result.releaseId, source.releaseId); assert.deepEqual(await store.get(credentials[0].tenantId, "release", source.releaseId), source);
    const releases = (await (await request("releases", reader)).json()).items, derived = releases.find((item: any) => item.releaseId === completed.result.releaseId);
    assert.equal(derived.status, "UNVERIFIED"); assert.equal(derived.sourceReleaseId, source.releaseId);
    for (const evidencePath of [`preparations/${queued.preparationId}/evidence`, `scans/${completed.result.scanId}/evidence`]) {
      assert.equal((await request(evidencePath, reader)).status, 403);
      const response = await request(evidencePath, operator); assert.equal(response.status, 200);
      const summary = await response.json(); assert.equal(summary.verification, "API_VERIFIED"); assert.equal(summary.root, completed.result.reportRoot);
      assert.deepEqual(Object.keys(summary).sort(), ["checkedAt", "leafCount", "root", "verification"]); assert.doesNotMatch(JSON.stringify(summary), /SYNTHETIC_PRIVATE|private_synthetic_tool|files|bundle|collectorDigest/);
      assert.match(renderToStaticMarkup(React.createElement(EvidenceView, { evidence: summary })), /API가 증거 루트를 검증함/);
    }
    const exportPath = `releases/${derived.releaseId}/gateway-config`;
    assert.equal((await request(exportPath, reader)).status, 403); assert.equal((await request(exportPath, foreign)).status, 404);
    const download = await request(exportPath, operator); assert.equal(download.status, 200); assert.match(download.headers.get("content-disposition")!, /^attachment; filename="mcpshield-0x[a-f0-9]{64}\.json"$/);
    assert.equal(download.headers.get("content-type"), "application/octet-stream"); assert.equal(download.headers.get("cache-control"), "no-store");
    const config = JSON.parse(await download.text()); assert.equal(config.releaseId, derived.releaseId); assert.deepEqual(config.tools, fixture.documents["runtime/tools.json"]);
    assert.doesNotMatch(JSON.stringify(config), /SYNTHETIC_PRIVATE_PATH_NOT_FOR_BROWSER|synthetic-prepared-operator-token|privateKey|apiToken/);
    for (const mutated of [{ ...config, privateKey: "forbidden" }, { ...config, releaseId: source.releaseId }, { ...config, binding: { ...config.binding, finalImageDigest: "image:latest" } }]) assert.throws(() => preparedDownload(mutated, derived.releaseId), /PREPARED_EXPORT_INVALID/);
    // Pure export-envelope regressions only: these synthetic commitments are not v2 API/worker approvals.
    for (const mode of ["LOCAL_CONTRACT_TEST", "PROVIDER_EXECUTION"]) {
      const { collectorDigest, observerDigest, egressAllowHosts } = config.binding.executionPolicy;
      const binding = createPreparedReleaseBinding({ sourceReleaseId: config.binding.sourceReleaseId, descriptor: config.binding.descriptor,
        executionPolicy: scopedPreparedExecutionPolicy({ collectorDigest, observerDigest, egressAllowHosts }, scopedReviewPolicy(mode)) });
      const scoped = { ...config, ...exactReleaseIdentity({ toolId: config.toolId, ...binding }), binding };
      assert.notEqual(scoped.releaseId, config.releaseId);
      assert.deepEqual(await preparedDownload(scoped, scoped.releaseId).json(), scoped);
      assert.throws(() => preparedDownload({ ...scoped, releaseId: config.releaseId }, config.releaseId), /PREPARED_EXPORT_INVALID/);
      const changed = structuredClone(scoped); changed.binding.executionPolicy.semantic.evidenceMode = mode === "LOCAL_CONTRACT_TEST" ? "PROVIDER_EXECUTION" : "LOCAL_CONTRACT_TEST";
      assert.throws(() => preparedDownload(changed, scoped.releaseId), /PREPARED_EXPORT_INVALID/);
      assert.throws(() => preparedDownload({ ...scoped, privateKey: "forbidden" }, scoped.releaseId), /PREPARED_EXPORT_INVALID/);
    }
    const html = renderToStaticMarkup(React.createElement(PreparationRecords, { jobs: [queued, completed], releases, operator: false }));
    assert.match(html, /COMPLETED ≠ VERIFIED/); assert.match(html, /UNVERIFIED/); assert.match(html, /ABSTAIN/); assert.doesNotMatch(html, /실패 작업 재시도|SYNTHETIC_PRIVATE/);
    const detailHtml = renderToStaticMarkup(React.createElement(PreparationDetail, { job: completed, operator: true, summary: null }));
    assert.match(detailHtml, /원본 exact release ID/); assert.match(detailHtml, /Gateway 구성 JSON 다운로드/); assert.match(detailHtml, /실행 허가가 아닙니다/);
    const readerHtml = renderToStaticMarkup(React.createElement(PreparationDetail, { job: completed, operator: false, summary: null }));
    assert.doesNotMatch(readerHtml, /href=.*gateway-config|type="password"|<input/);
    const formHtml = renderToStaticMarkup(React.createElement(PreparationConsole, { jobs: [], releases, policies: [policy], operator: true, onRefresh: async () => {}, onSelect: () => {} }));
    assert.match(formHtml, /이미지 준비 요청/); assert.doesNotMatch(formHtml, /type="password"|name="(?:image|root|apiToken|privateKey)"/);
    assert.equal(canPrepare(source), true); assert.equal(canPrepare(derived), false); assert.equal(isPreparationPolicy(policy), true);
    assert.equal(isPreparationPolicy({ ...policy, document: {} }), false);
    // Retryable failures are actual durable queue transitions, not a client status toggle.
    const retryId = (await (await request(path, admin, body, "retry-job")).json()).preparation.preparationId;
    for (let i = 0; i < 3; i++) { const job = (await claimPreparation(store, "synthetic-worker"))!; await failPreparation(store, job, "synthetic-worker", "WORKER_LOST", true, 0); }
    const dead = (await (await request(`preparations/${retryId}`, reader)).json()).preparation; assert.equal(canRetryPreparation(dead), true);
    assert.equal(canRetryPreparation({ ...dead, lastError: { code: "INVALID", retryable: false } }), false);
    assert.equal((await request(`preparations/${retryId}/retry`, reader, {})).status, 403);
    assert.equal((await request(`preparations/${retryId}/retry`, operator, { root: "forbidden" })).status, 400);
    assert.equal((await request(`preparations/${retryId}/retry`, operator, {})).status, 200);
    noDiscovery = true; await runPreparationWorkerOnce(store, options);
    const inconclusive = (await (await request(`preparations/${retryId}`, reader)).json()).preparation;
    assert.equal(inconclusive.result.outcome, "INCONCLUSIVE"); assert.equal(inconclusive.result.releaseId, undefined);
    assert.match(renderToStaticMarkup(React.createElement(PreparationRecords, { jobs: [inconclusive], releases, operator: true })), /판단 근거 부족/);
  } finally {
    await streamReader?.cancel(); names.forEach((name, index) => previous[index] === undefined ? delete process.env[name] : process.env[name] = previous[index]);
    await app.close(); await rm(directory, { recursive: true, force: true });
  }
});

test("BFF forwards exact optional baseline selection without converting omission/null/ID and rejects forged shapes", async context => {
  // Transport-boundary regression only, not evidence of a completed 2.1 worker or a browser interaction.
  const previous = process.env.MCPSHIELD_PUBLIC_ORIGIN; process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  const forwarded: unknown[] = [], sourceId = `0x${"a".repeat(64)}`, baselineId = `0x${"b".repeat(64)}`;
  context.mock.method(globalThis, "fetch", async (_url: unknown, options: RequestInit) => { forwarded.push(JSON.parse(String(options.body))); return Response.json({ accepted: true }, { status: 202 }); });
  const request = (body: unknown) => POST(new NextRequest(`https://console.test/api/control/releases/${sourceId}/prepare`, { method: "POST", headers: {
    origin: "https://console.test", cookie: "mcpshield_control=synthetic-private-token", "content-type": "application/json", "idempotency-key": "synthetic-baseline-request" }, body: JSON.stringify(body) }), { params: Promise.resolve({ path: ["releases", sourceId, "prepare"] }) });
  try {
    for (const body of [{ policyHash: policy.policyHash }, { policyHash: policy.policyHash, baselineReleaseId: null }, { baselineReleaseId: baselineId, policyHash: policy.policyHash }]) {
      assert.equal((await request(body)).status, 202); assert.deepEqual(forwarded.at(-1), body);
    }
    const count = forwarded.length;
    for (const baselineReleaseId of ["", "null", "0xABC", [baselineId], { releaseId: baselineId }, false, 0]) assert.equal((await request({ policyHash: policy.policyHash, baselineReleaseId })).status, 400);
    for (const body of [{ baselineReleaseId: null }, { policyHash: [policy.policyHash], baselineReleaseId: null }, { policyHash: policy.policyHash, baselineReleaseId: null, provenancePath: "SYNTHETIC_PRIVATE_PATH" },
      { policyHash: policy.policyHash, baselineReleaseId: null, baselines: { [sourceId]: baselineId } }]) assert.equal((await request(body)).status, 400);
    assert.equal(forwarded.length, count);
    for (const baselineReleaseId of [null, baselineId]) {
      const html = renderToStaticMarkup(React.createElement(PreparationDetail, { job: { preparationId: "synthetic-job", sourceReleaseId: sourceId, policyHash: policy.policyHash, baselineReleaseId,
        status: "QUEUED", attempts: 0, maxAttempts: 3, traceId: "synthetic-trace", createdAt: "2026-10-01T00:00:00Z", updatedAt: "2026-10-01T00:00:00Z" }, operator: false, summary: null }));
      assert.match(html, /이 준비 작업에 연결된 검사의 비교 대상/); assert.match(html, baselineReleaseId === null ? /비교하지 않음/ : new RegExp(baselineId));
      assert.match(html, /비교 선택은 해당 검사에만 적용/); assert.doesNotMatch(html, /SYNTHETIC_PRIVATE|type="password"/);
    }
  } finally { previous === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previous; }
});

test("2.1 UI payloads reach real tenant API/worker through BFF with scan-specific null/ID and immutable runtime evidence", { timeout: 20000 }, async t => {
  const resources: (() => Promise<void>)[] = [];
  t.after(async () => {
    const errors = []; for (const close of resources.reverse()) try { await close(); } catch (error) { errors.push(error); }
    if (errors.length) throw new AggregateError(errors, "BASELINE_CONSOLE_TEST_CLEANUP_FAILED");
  });
  const fixture = await syntheticPreparedFixture(), directory = await mkdtemp(join(tmpdir(), "mcpshield-console-baseline-"));
  resources.push(() => rm(directory, { recursive: true, force: true }));
  const snapshots = [];
  for (const version of ["1.0.0", "1.0.1"]) {
    const snapshot = await resolveArtifact({ sourceType: "local", locator: fileURLToPath(new URL(`../../../demo/fixtures/mail-mcp-${version}`, import.meta.url)) });
    resources.push(() => snapshot.cleanup()); snapshots.push(snapshot);
  }
  const sources = snapshots.map(snapshot => ({ ...exactReleaseIdentity(snapshot), artifactDigest: snapshot.artifactDigest, manifestDigest: snapshot.manifestDigest, toolSurfaceHash: snapshot.toolSurfaceHash,
    artifactDir: snapshot.artifactDir, sourceType: "npm", legacyReleaseId: snapshot.releaseId, version: snapshot.metadata.version, status: "UNVERIFIED", policyHash: null, reportRoot: null, validUntil: null, chain: null }));
  const tenant = "console-baseline", token = "synthetic-baseline-operator-token", filename = join(directory, "private-catalogue.json");
  await writeFile(filename, JSON.stringify({ schemaVersion: "mcpshield.scoped-provenance-catalogue.v1", artifacts: sources.map(source => ({
    schemaVersion: "mcpshield.operator-code-artifact.v1", authority: "OPERATOR_LOCAL_CATALOG", contentClass: "CODE_ARTIFACT_NO_CUSTOMER_DATA", sourceArtifactDigest: source.artifactDigest })) }));
  const store = await ControlStore.open();
  let app: Awaited<ReturnType<typeof buildApp>> | undefined;
  resources.push(async () => { if (app) await app.close(); else await store.close(); });
  const currentPolicy = scopedBaselinePreparedPolicy("LOCAL_CONTRACT_TEST"), currentHash = hash(currentPolicy), previousHash = hash(scopedPreparedPolicy("LOCAL_CONTRACT_TEST"));
  const options: ControlOptions = { store, credentials: [{ tenantId: tenant, token, role: "operator" }, { tenantId: "foreign", token: "synthetic-baseline-foreign-token", role: "operator" }], artifactPath: "unused", evidencePath: join(directory, "evidence"), evidenceKey: "1".repeat(64),
    scannerOptions: { sandbox: "docker", allowRemoteAi: false }, preparedRuntime: fixture.config,
    scopedPrepared: { provenancePaths: { [tenant]: filename }, ai: { allowRemoteAi: true, disclosurePolicy: "SCOPED_PROVIDER_REVIEW_V1", evidenceMode: "LOCAL_CONTRACT_TEST", provider: "custom", url: "http://127.0.0.1:9", timeoutMs: 1000 } },
    // Explicit synthetic runtime observations: real intake/storage/worker/BFF, no Docker or model execution.
    inspectPreparedRuntime: async ({ descriptor }) => ({ ...fixture.trusted, sourceDescriptorDigest: hashPreparedRuntimeDescriptor({ ...descriptor, stage: "PREFLIGHT", finalImageDigest: null, toolSurfaceHash: null }) }) };
  const output = async (input: any) => {
    const descriptor = input.descriptor ?? { ...fixture.binding.descriptor, sourceDigest: input.preparation.sourceTreeDigest, sourceTreeDigest: input.preparation.sourceTreeDigest };
    const binding = createPreparedReleaseBinding({ sourceReleaseId: input.sourceReleaseId, descriptor, executionPolicy: input.scopedReview.executionPolicy });
    const result = { ...fixture.result, scanId: input.scanId, releaseId: input.releaseId, artifactDigest: binding.artifactDigest, scanStatus: "INCONCLUSIVE", source: "MOCK" };
    return { binding, result, analysis: { profile: currentPolicy.profile, verdict: "ABSTAIN", issues: ["SYNTHETIC_CONTRACT_TEST_NOT_LIVE_DOCKER"] }, cleanup: async () => {}, runtimeTag: `mcpshield-runtime-${randomUUID()}:local`,
      bundle: createEvidenceBundle({ ...fixture.documents, "report.json": result, "prepared/binding.json": binding, "runtime/descriptor.json": descriptor, "runtime/execution-policy.json": binding.executionPolicy,
        "static/closure-report.json": { ...fixture.documents["static/closure-report.json"], sourceDescriptorDigest: hashPreparedRuntimeDescriptor({ ...descriptor, stage: "PREFLIGHT", finalImageDigest: null, toolSurfaceHash: null }) } }) };
  };
  options.prepareRuntime = output; options.scanPreparedRuntime = output;
  app = await buildApp({ adminApiToken: "synthetic-admin-token", scannerApiToken: "synthetic-scanner-token", controlPlane: options });
  await app.listen({ host: "127.0.0.1", port: 0 });
  for (const source of sources) await store.put(tenant, "release", source.releaseId, source);
  await store.put(tenant, "policy", currentHash, { policyHash: currentHash, alias: "baseline-local", version: currentPolicy.version, document: currentPolicy, deprecatedAt: null });
  const names = ["MCPSHIELD_API_URL", "MCPSHIELD_PUBLIC_ORIGIN"], previous = names.map(name => process.env[name]);
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`; process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  let cookie = "";
  const request = (path: string, body?: unknown, key = randomUUID()) => (body === undefined ? GET : POST)(new NextRequest(`https://console.test/api/control/${path}`, { method: body === undefined ? "GET" : "POST", headers: {
    origin: "https://console.test", cookie, "content-type": "application/json", "idempotency-key": key }, body: body === undefined ? undefined : JSON.stringify(body) }), { params: Promise.resolve({ path: path.split("/") }) });
  const read = async (path: string) => { const response = await request(path); assert.equal(response.status, 200); return response.json(); };
  const prepare = async (source: typeof sources[number], body: object) => {
    const response = await request(`releases/${source.releaseId}/prepare`, body); assert.equal(response.status, 202, await response.clone().text());
    const { preparation } = await response.json(); await runPreparationWorkerOnce(store, options);
    const completed = (await read(`preparations/${preparation.preparationId}`)).preparation;
    assert.equal(completed.status, "COMPLETED", JSON.stringify(completed)); assert.equal(completed.result.verdict, "ABSTAIN"); return completed;
  };
  try {
    const login = await request("session", { token }); assert.equal(login.status, 200); cookie = login.headers.get("set-cookie")!.split(";")[0];
    const old = await prepare(sources[0], { policyHash: previousHash }); assert.equal(Object.hasOwn(old, "baselineReleaseId"), false);
    const path = `releases/${sources[1].releaseId}/prepare`;
    const missing = await request(path, { policyHash: currentHash }); assert.equal(missing.status, 400); assert.equal((await missing.json()).error.code, "SCOPED_BASELINE_SELECTION_REQUIRED");
    const first = await prepare(sources[1], { policyHash: currentHash, baselineReleaseId: null }); assert.equal(first.baselineReleaseId, null);
    const inventory = (await read("releases")).items, current = inventory.find((release: any) => release.releaseId === first.result.releaseId);
    assert.deepEqual(baselineCandidates(inventory, current, currentPolicy).map(release => release.releaseId), [old.result.releaseId]);
    const pinned = baselineRequestFields(inventory, current, currentPolicy, old.result.releaseId);
    const original = await store.get(tenant, "release", current.releaseId);
    const compared = await prepare(sources[1], { policyHash: currentHash, ...pinned });
    assert.equal(compared.baselineReleaseId, old.result.releaseId); assert.equal(compared.result.releaseId, current.releaseId);
    assert.deepEqual(await store.get(tenant, "release", current.releaseId), original, "changing comparison cannot replace original runtime ownership/evidence");
    const body = { releaseId: current.releaseId, policyHash: currentHash, ...pinned };
    const queued = await request("scans", body, "pinned-scan"); assert.equal(queued.status, 202, await queued.clone().text()); const scan = (await queued.json()).scan;
    assert.equal(scan.baselineReleaseId, old.result.releaseId);
    assert.equal((await (await request("scans", body, "pinned-scan")).json()).scan.scanId, scan.scanId);
    assert.equal((await request("scans", { ...body, baselineReleaseId: null }, "pinned-scan")).status, 409);
    const noComparison = await request("scans", { ...body, ...baselineRequestFields(inventory, current, currentPolicy, "none") }); assert.equal(noComparison.status, 202);
    assert.equal((await noComparison.json()).scan.baselineReleaseId, null);
    const omitted = await request("scans", { releaseId: current.releaseId, policyHash: currentHash }); assert.equal(omitted.status, 400); assert.equal((await omitted.json()).error.code, "SCOPED_BASELINE_SELECTION_REQUIRED");
    for (const value of [[], {}, "null"]) assert.equal((await request("scans", { ...body, baselineReleaseId: value })).status, 400);
    const crossVersion = await request("scans", { ...body, releaseId: old.result.releaseId, baselineReleaseId: null }); assert.equal(crossVersion.status, 409); assert.equal((await crossVersion.json()).error.code, "SCOPED_EXECUTION_POLICY_MISMATCH");
    const crossMode = await request("scans", { ...body, policyHash: hash(scopedPreparedPolicy("PROVIDER_EXECUTION")) }); assert.equal(crossMode.status, 409); assert.equal((await crossMode.json()).error.code, "SCAN_SEMANTIC_MODE_MISMATCH");
    await runControlWorkerOnce(store, options); await runControlWorkerOnce(store, options);
    const projected = (await read(`scans/${scan.scanId}`)).scan;
    assert.equal(projected.status, "COMPLETED"); assert.equal(projected.result.verdict, "ABSTAIN"); assert.equal(projected.baselineReleaseId, old.result.releaseId);
    const html = renderToStaticMarkup(React.createElement(ReleaseWorkflow, { release: current, scans: [projected], policies: [], actions: [], manage: false, onRefresh: async () => {} }));
    assert.match(html, new RegExp(old.result.releaseId)); assert.match(html, /선택한 검사의 비교 대상/); assert.match(html, /ABSTAIN/);
    for (const endpoint of ["releases", "scans", "preparations"]) assert.doesNotMatch(JSON.stringify(await read(endpoint)), /private-catalogue|artifactDir|scopedConfigHash|preparedEvidenceKey|provenancePaths|127\.0\.0\.1:9/);
    cookie = (await request("session", { token: "synthetic-baseline-foreign-token" })).headers.get("set-cookie")!.split(";")[0];
    assert.equal((await request("scans", body)).status, 404); assert.equal((await request(path, { policyHash: currentHash, ...pinned })).status, 404);
  } finally {
    names.forEach((name, index) => previous[index] === undefined ? delete process.env[name] : process.env[name] = previous[index]);
  }
});
