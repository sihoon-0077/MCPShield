import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NextRequest } from "next/server";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { GET, POST } from "../app/api/control/[...path]/route";
import { PreparationConsole, PreparationDetail, PreparationRecords, canPrepare, preparationPolicyMatchesRelease } from "../components/preparation-console";
import { ReleaseWorkflow, SemanticEvidenceNotice } from "../components/release-workflow";
import { preparedDownload } from "../lib/prepared-download";
import { buildApp } from "../../api/src/app.js";
import { ControlStore } from "../../api/src/control-store.js";
import { hash, type ControlOptions } from "../../api/src/control-plane.js";
import { ociPolicy, preparedPolicy } from "../../api/src/control-policy.js";
import { ociTrust, type OciConfig } from "../../api/src/oci-config.js";
import { runPreparationWorkerOnce } from "../../api/src/preparation-worker.js";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared pure Security identity helpers; no image executes in this test.
import { ociExecutionPolicy, createOciReleaseBinding } from "../../../services/scanner/src/oci-binding.mjs";
// @ts-expect-error Shared fixed OCI descriptor contract.
import { OCI_SOURCE_BUDGET_PROFILE, OCI_OBSERVATION_POLICY } from "../../../services/resolver/src/oci-runtime-descriptor.mjs";
// @ts-expect-error Shared Merkle evidence contract.
import { createEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared full raw tool commitment.
import { toolSurfaceHash } from "../../../services/scanner/src/tool-surface.mjs";

test("OCI console uses actual API/BFF preparation, strict export and explicit synthetic AI scope without crossing npm policy or reader permissions", { timeout: 20000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-console-oci-")), digest = "sha256:" + "a".repeat(64);
  const config: OciConfig = { baseImageDigest: digest, baseCatalogueDigest: digest, trivyImageDigest: digest, databaseDigest: digest,
    databaseDir: join(directory, "SYNTHETIC_PRIVATE_DATABASE"), sinkImageDigest: digest, platform: { os: "linux", architecture: "amd64" } };
  const sourceIdentity = { ...exactReleaseIdentity({ toolId: "oci:synthetic-console", artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: toolSurfaceHash([]) }),
    artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: toolSurfaceHash([]) };
  const source = { ...sourceIdentity, sourceType: "oci", artifactDir: "SYNTHETIC_PRIVATE_SOURCE", legacyReleaseId: "oci-console@0.0.0", version: "0.0.0", status: "UNVERIFIED", policyHash: null, reportRoot: null, validUntil: null, chain: null };
  const tools = [{ name: "SYNTHETIC_PRIVATE_TOOL", description: "SYNTHETIC_PRIVATE_DESCRIPTION", inputSchema: { type: "object" } }];
  const { databaseDir: _databaseDir, platform: _platform, ...anchors } = await ociTrust(config);
  const descriptor = { schemaVersion: "mcpshield.oci-runtime.v1", profile: "oci-container-v1", stage: "OBSERVED", budgetProfile: OCI_SOURCE_BUDGET_PROFILE,
    sourceBytes: 1000, layerArchiveBytes: 2048, exportArchiveBytes: 2048, sourceTreeDigest: digest, sourceIndexDigest: digest, manifestDigest: digest, configDigest: digest,
    platform: config.platform, finalImageDigest: digest, imageDigestKind: "DOCKER_IMAGE_CONFIG_ID", rootfsDigest: digest,
    entrypoint: { requestedPath: "/bin/sh", resolvedPath: "/bin/busybox", contentDigest: digest, linkChainDigest: digest }, argv: ["/bin/sh", "/server.sh"],
    workingDirectory: "/", environmentDigest: digest, toolSurfaceHash: toolSurfaceHash(tools), policy: OCI_OBSERVATION_POLICY };
  const binding = createOciReleaseBinding({ sourceReleaseId: source.releaseId, descriptor, executionPolicy: ociExecutionPolicy(anchors) });
  const store = await ControlStore.open(join(directory, "control.sqlite"));
  const credentials = ["operator", "reader"].map(role => ({ tenantId: "oci-console", token: `synthetic-oci-${role}-token`, role: role as "operator" | "reader" }));
  credentials.push({ tenantId: "other", token: "synthetic-foreign-oci-token", role: "operator" });
  const options: ControlOptions = { store, credentials, artifactPath: directory, evidencePath: directory, evidenceKey: "1".repeat(64), ociRuntime: config,
    scannerOptions: { sandbox: "docker", allowRemoteAi: false }, inspectOciRuntime: async () => ({ anchors, platform: config.platform }),
    // Explicit local identity/daemon double. MOCK + ABSTAIN, not native/AI/quorum approval.
    prepareOciRuntime: async input => {
      const result = { schemaVersion: "1.0.0", scanId: input.scanId, releaseId: source.legacyReleaseId, artifactDigest: binding.artifactDigest,
        toolSurfaceHash: binding.toolSurfaceHash, scanStatus: "INCONCLUSIVE", findings: [], evidenceHash: "0x" + "1".repeat(64), source: "MOCK" };
      return { binding, result, analysis: { profile: ociPolicy.profile, verdict: "ABSTAIN", issues: ["SYNTHETIC_NOT_EXECUTED"] }, runtimeOwnership: "BORROWED", runtimeTag: null, cleanup: async () => {},
        bundle: createEvidenceBundle({ "oci/binding.json": binding, "prepared/source-identity.json": sourceIdentity, "runtime/tools.json": tools,
          "runtime/oci-descriptor.json": descriptor, "runtime/execution-policy.json": binding.executionPolicy, "report.json": result }) };
    } };
  const app = await buildApp({ adminApiToken: "synthetic-legacy-admin-token", scannerApiToken: "synthetic-legacy-scanner-token", controlPlane: options });
  await app.listen({ host: "127.0.0.1", port: 0 }); await store.put(credentials[0].tenantId, "release", source.releaseId, source);
  const names = ["MCPSHIELD_API_URL", "MCPSHIELD_PUBLIC_ORIGIN"], previous = names.map(name => process.env[name]);
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`; process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  const request = (path: string, cookie = "", body?: unknown) => (body === undefined ? GET : POST)(new NextRequest(`https://console.test/api/control/${path}`, {
    method: body === undefined ? "GET" : "POST", headers: { cookie, origin: "https://console.test", "content-type": "application/json", "idempotency-key": "oci-console-attempt" }, body: body === undefined ? undefined : JSON.stringify(body),
  }), { params: Promise.resolve({ path: path.split("/") }) });
  try {
    const cookies: string[] = [];
    for (const credential of credentials) { const login = await request("session", "", { token: credential.token }); assert.equal(login.status, 200); assert.match(login.headers.get("set-cookie")!, /HttpOnly/); cookies.push(login.headers.get("set-cookie")!.split(";")[0]); }
    const [operator, reader, foreign] = cookies, path = `releases/${source.releaseId}/prepare`;
    const policies = (await (await request("policies", reader)).json()).items;
    const policy = policies.find((item: any) => item.policyHash === hash(ociPolicy)), npm = policies.find((item: any) => item.policyHash === hash(preparedPolicy));
    assert.ok(policy && npm); assert.equal(canPrepare(source), true);
    assert.equal(preparationPolicyMatchesRelease(source, policy), true); assert.equal(preparationPolicyMatchesRelease(source, npm), false);
    assert.equal(preparationPolicyMatchesRelease({ ...source, sourceType: "npm" }, policy), false); assert.equal(preparationPolicyMatchesRelease({ ...source, sourceType: "tarball" }, npm), true);
    for (const invalid of [{ ...policy, deprecatedAt: "2026-01-01" }, { ...policy, document: { ...ociPolicy, semanticEvidenceMode: "PRODUCTION" } }]) assert.equal(preparationPolicyMatchesRelease(source, invalid), false);
    assert.equal((await request(path, operator, { policyHash: npm.policyHash })).status, 400);
    assert.equal((await request(path, reader, { policyHash: policy.policyHash })).status, 403); assert.equal((await request(path, foreign, { policyHash: policy.policyHash })).status, 404);
    assert.equal((await request(path, operator, { policyHash: policy.policyHash, semanticEvidenceMode: "PRODUCTION" })).status, 400);
    const queued = await request(path, operator, { policyHash: policy.policyHash }); assert.equal(queued.status, 202); const jobId = (await queued.json()).preparation.preparationId;
    await runPreparationWorkerOnce(store, options);
    const completed = (await (await request(`preparations/${jobId}`, reader)).json()).preparation;
    assert.equal(completed.status, "COMPLETED"); assert.equal(completed.result.verdict, "ABSTAIN"); assert.equal(completed.result.semanticEvidenceMode, "LOCAL_CONTRACT_TEST");
    assert.equal(completed.result.providerQuality, "PROVIDER_QUALITY_NOT_MEASURED");
    const releases = (await (await request("releases", reader)).json()).items, derived = releases.find((item: any) => item.releaseId === completed.result.releaseId);
    assert.equal(derived.status, "UNVERIFIED"); assert.equal(derived.sourceReleaseId, source.releaseId); assert.equal(canPrepare(derived), false);
    assert.deepEqual(await store.get(credentials[0].tenantId, "release", source.releaseId), source);
    for (const evidencePath of [`preparations/${jobId}/evidence`, `scans/${completed.result.scanId}/evidence`]) {
      assert.equal((await request(evidencePath, reader)).status, 403);
      const response = await request(evidencePath, operator); assert.equal(response.status, 200); const summary = await response.json();
      assert.equal(summary.verification, "API_VERIFIED"); assert.equal(summary.root, completed.result.reportRoot);
      assert.doesNotMatch(JSON.stringify(summary), /SYNTHETIC_PRIVATE|bundle|files|observerDigest|token/);
    }
    const exportPath = `releases/${derived.releaseId}/gateway-config`;
    assert.equal((await request(exportPath, reader)).status, 403); assert.equal((await request(exportPath, foreign)).status, 404);
    const download = await request(exportPath, operator); assert.equal(download.status, 200); assert.equal(download.headers.get("cache-control"), "no-store");
    assert.match(download.headers.get("content-disposition")!, /^attachment; filename="mcpshield-0x[a-f0-9]{64}\.json"$/);
    const envelope = JSON.parse(await download.text()); assert.deepEqual(envelope.binding, binding); assert.deepEqual(envelope.tools, tools);
    assert.doesNotMatch(JSON.stringify(envelope), /SYNTHETIC_PRIVATE_SOURCE|SYNTHETIC_PRIVATE_DATABASE|synthetic-oci-operator-token|apiToken|privateKey/);
    for (const edit of [v => v.ready = true, v => v.releaseId = source.releaseId, v => v.binding.profile = "npm-closure-v1", v => v.binding.descriptor.argv.push("/bad"),
      v => v.binding.executionPolicy.trust.databaseDigest = "sha256:" + "b".repeat(64), v => v.tools[0].description = "changed"]) {
      const changed = structuredClone(envelope); edit(changed); assert.throws(() => preparedDownload(changed, derived.releaseId), /PREPARED_EXPORT_INVALID/);
    }
    const scans = (await (await request("scans", reader)).json()).items;
    for (const html of [renderToStaticMarkup(React.createElement(PreparationRecords, { jobs: [completed], releases, operator: false })),
      renderToStaticMarkup(React.createElement(PreparationDetail, { job: completed, operator: true, summary: null })),
      renderToStaticMarkup(React.createElement(ReleaseWorkflow, { release: derived, scans, policies, actions: [], manage: false, onRefresh: async () => {} }))]) {
      assert.match(html, /LOCAL_CONTRACT_TEST/); assert.match(html, /PROVIDER_QUALITY_NOT_MEASURED/); assert.match(html, /상용 AI 모델의 탐지 품질을 측정하거나 승인한 결과가 아닙니다/);
      assert.doesNotMatch(html, /SYNTHETIC_PRIVATE|name="(?:privateKey|apiToken|arguments)"/);
    }
    const missing = renderToStaticMarkup(React.createElement(SemanticEvidenceNotice, { oci: true })); assert.match(missing, /미제공/); assert.doesNotMatch(missing, /LOCAL_CONTRACT_TEST/);
    const html = renderToStaticMarkup(React.createElement(PreparationConsole, { jobs: [], releases, policies, operator: true, onRefresh: async () => {}, onSelect: () => {} }));
    assert.match(html, /npm · OCI 실행 이미지 준비/); assert.match(html, /원본을 먼저 선택하세요/); assert.match(html, /button disabled=""/);
    assert.doesNotMatch(renderToStaticMarkup(React.createElement(PreparationDetail, { job: completed, operator: false, summary: null })), /href=.*gateway-config/);
  } finally {
    names.forEach((name, index) => previous[index] === undefined ? delete process.env[name] : process.env[name] = previous[index]);
    await app.close(); await rm(directory, { recursive: true, force: true });
  }
});
