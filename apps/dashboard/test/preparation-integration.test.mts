import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { NextRequest } from "next/server";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { GET, POST } from "../app/api/control/[...path]/route";
import { PreparationConsole, PreparationDetail, PreparationRecords, canPrepare, canRetryPreparation, isPreparationPolicy } from "../components/preparation-console";
import { EvidenceView } from "../components/evidence-view";
import { preparedDownload } from "../lib/prepared-download";
import { buildApp } from "../../api/src/app.js";
import { ControlStore } from "../../api/src/control-store.js";
import { hash, type ControlOptions } from "../../api/src/control-plane.js";
import { preparedPolicy } from "../../api/src/control-policy.js";
import { runPreparationWorkerOnce } from "../../api/src/preparation-worker.js";
import { claimPreparation, failPreparation } from "../../api/src/preparation-store.js";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared pure Security helper.
import { createPreparedReleaseBinding, preparedExecutionPolicy } from "../../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared Merkle helper.
import { createEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared canonical tool hash.
import { toolSurfaceHash } from "../../gateway/src/artifact.mjs";

const sha = (letter: string) => `sha256:${letter.repeat(64)}`;
const source = { ...exactReleaseIdentity({ toolId: "npm:console-prepared", artifactDigest: sha("a"), manifestDigest: sha("b"), toolSurfaceHash: `0x${"c".repeat(64)}` }),
  artifactDigest: sha("a"), manifestDigest: sha("b"), toolSurfaceHash: `0x${"c".repeat(64)}`, sourceType: "npm", artifactDir: "SYNTHETIC_PRIVATE_PATH_NOT_FOR_BROWSER",
  legacyReleaseId: "console-prepared@1.0.0", version: "1.0.0", status: "UNVERIFIED", policyHash: null, reportRoot: null, validUntil: null, chain: null };
const policy = { policyHash: hash(preparedPolicy), alias: "prepared-test", version: "1.0.0", document: preparedPolicy, deprecatedAt: null };

test("real preparation API/BFF keeps source identity, roles, evidence privacy and SSE resync separate from approval", { timeout: 20000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-console-preparation-"));
  const store = await ControlStore.open(join(directory, "control.sqlite"));
  const credentials = ["operator", "reader", "admin"].map(role => ({ tenantId: "prepared-console", token: `synthetic-prepared-${role}-token`, role: role as "operator" | "reader" | "admin" }));
  credentials.push({ tenantId: "foreign", token: "synthetic-foreign-operator-token", role: "operator" });
  const options: ControlOptions = { store, credentials, artifactPath: "unused", evidencePath: join(directory, "evidence"), evidenceKey: "1".repeat(64),
    scannerOptions: { sandbox: "docker", allowRemoteAi: false }, preparedRuntime: { builderImageDigest: sha("d"), platform: { os: "linux", architecture: "amd64" } } };
  let noDiscovery = false;
  options.prepareRuntime = async input => {
    if (noDiscovery) return { binding: null, result: null, analysis: { issues: ["PREPARED_DISCOVERY_REQUIRED"] }, cleanup: async () => {} };
    const tools = [{ name: "private_synthetic_tool", description: "SYNTHETIC_PRIVATE_METADATA", inputSchema: { type: "object" } }];
    const descriptor = { schemaVersion: "mcpshield.prepared-runtime.v1", stage: "CLOSURE_PREPARED", profile: "npm-closure-v1", sourceDigest: source.artifactDigest,
      sourceTreeDigest: source.artifactDigest, lockDigest: sha("2"), lockOrigin: "SUPPLIED", builderImageDigest: input.trusted.builderImageDigest, platform: input.preparation.platform,
      finalImageDigest: sha("e"), toolSurfaceHash: toolSurfaceHash(tools), entrypoint: { path: "server.mjs", digest: sha("f") }, argv: ["/usr/local/bin/node", "/app/server.mjs"],
      policy: { acquisitionNetwork: "REGISTRY_ONLY_SEPARATE", installNetwork: "NONE", installScripts: "DISABLED", executionNetwork: "INTERNAL_SYNTHETIC_PROXY", user: "NON_ROOT", rootFilesystem: "READ_ONLY" } };
    const binding = createPreparedReleaseBinding({ sourceReleaseId: source.releaseId, descriptor, executionPolicy: preparedExecutionPolicy({ collectorDigest: input.trusted.collectorDigest, observerDigest: input.trusted.observerDigest, egressAllowHosts: [] }) });
    const result = { schemaVersion: "1.0.0", scanId: input.scanId, releaseId: source.legacyReleaseId, artifactDigest: binding.artifactDigest, toolSurfaceHash: binding.toolSurfaceHash,
      scanStatus: "INCONCLUSIVE", findings: [], evidenceHash: `0x${"1".repeat(64)}`, source: "MOCK" };
    const analysis = { profile: preparedPolicy.profile, verdict: "ABSTAIN", issues: ["SYNTHETIC_CONTRACT_TEST_NOT_LIVE_DOCKER"] };
    return { binding, result, analysis, cleanup: async () => {}, runtimeTag: `mcpshield-runtime-${randomUUID()}:local`,
      bundle: createEvidenceBundle({ "report.json": { ...result, scope: "RESTRICTED_NODE_DOCKER_V1" }, "prepared/binding.json": binding, "runtime/tools.json": tools,
        "runtime/descriptor.json": descriptor, "runtime/execution-policy.json": binding.executionPolicy, "prepared/policy-review.json": analysis }) };
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
    const config = JSON.parse(await download.text()); assert.equal(config.releaseId, derived.releaseId); assert.equal(config.tools[0].description, "SYNTHETIC_PRIVATE_METADATA");
    assert.doesNotMatch(JSON.stringify(config), /SYNTHETIC_PRIVATE_PATH_NOT_FOR_BROWSER|synthetic-prepared-operator-token|privateKey|apiToken/);
    for (const mutated of [{ ...config, privateKey: "forbidden" }, { ...config, releaseId: source.releaseId }, { ...config, binding: { ...config.binding, finalImageDigest: "image:latest" } }]) assert.throws(() => preparedDownload(mutated, derived.releaseId), /PREPARED_EXPORT_INVALID/);
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
