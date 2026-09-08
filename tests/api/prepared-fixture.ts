import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { preparedTrust } from "../../apps/api/src/prepared-config.js";
import { exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared ESM closure helper.
import { closureManifest } from "../../services/resolver/src/closure-files.mjs";
// @ts-expect-error Shared ESM descriptor helper.
import { hashPreparedRuntimeDescriptor } from "../../services/resolver/src/runtime-descriptor.mjs";
// @ts-expect-error Shared ESM binding helper.
import { createPreparedReleaseBinding, preparedExecutionPolicy } from "../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared ESM semantic review helper.
import { inspectPreparedSources, reviewPreparedSemantics } from "../../services/scanner/src/prepared-review.mjs";
// @ts-expect-error Shared ESM evidence helper.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared ESM surface helper.
import { toolSurfaceHash } from "../../services/scanner/src/tool-surface.mjs";

export const sha = (value: string | Buffer) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
export const cleanAi = { riskClaims: [], semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false };
export async function syntheticPreparedFixture() {
  const server = createServer(async (request, response) => { for await (const _chunk of request) { /* trusted small test client only */ }
    response.writeHead(200, { "content-type": "application/json", connection: "close" }).end(JSON.stringify(cleanAi)); });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const files = { "package.json": JSON.stringify({ name: "prepared-test", version: "1.0.0", bin: "server.js" }),
      "server.js": "// synthetic pure contract fixture; no execution\nexport const value = 1;",
      "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "prepared-test", version: "1.0.0" } } }) };
    const contents = Object.entries(files).map(([path, text]) => ({ path, bytes: Buffer.from(text) }));
    const closure = { ...closureManifest(contents.map(({ path, bytes }) => ({ path, type: "File", mode: 0o444, digest: sha(bytes) }))),
      contents, bytes: contents.reduce((total, item) => total + item.bytes.length, 0), source: "LIVE_DOCKER_IMAGE_EXPORT" };
    const config = { builderImageDigest: sha("synthetic-builder"), platform: { os: "linux" as const, architecture: "amd64" as const } }, anchors = preparedTrust(config);
    const tools = [{ name: "list_messages", inputSchema: { type: "object", properties: {}, additionalProperties: false } }];
    const digest = sha("synthetic-source"), descriptor = { schemaVersion: "mcpshield.prepared-runtime.v1", stage: "CLOSURE_PREPARED", profile: "npm-closure-v1",
      sourceDigest: digest, sourceTreeDigest: digest, lockDigest: sha(files["package-lock.json"]), lockOrigin: "SUPPLIED", builderImageDigest: config.builderImageDigest,
      platform: config.platform, finalImageDigest: sha("synthetic-final-image-not-present"), toolSurfaceHash: toolSurfaceHash(tools),
      entrypoint: { path: "server.js", digest: sha(files["server.js"]) }, argv: ["/usr/local/bin/node", "/app/server.js"],
      policy: { acquisitionNetwork: "REGISTRY_ONLY_SEPARATE", installNetwork: "NONE", installScripts: "DISABLED", executionNetwork: "INTERNAL_SYNTHETIC_PROXY", user: "NON_ROOT", rootFilesystem: "READ_ONLY" } };
    const source = { ...exactReleaseIdentity({ toolId: "npm:prepared-test", artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: toolSurfaceHash([]) }),
      artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: toolSurfaceHash([]) };
    const binding = createPreparedReleaseBinding({ sourceReleaseId: source.releaseId, descriptor, executionPolicy: preparedExecutionPolicy({
      collectorDigest: anchors.collectorDigest, observerDigest: anchors.observerDigest, egressAllowHosts: [] }) });
    const identity = exactReleaseIdentity({ toolId: source.toolId, artifactDigest: binding.artifactDigest, manifestDigest: binding.manifestDigest, toolSurfaceHash: binding.toolSurfaceHash });
    const trusted = { ...anchors, finalImageDigest: descriptor.finalImageDigest, platform: descriptor.platform, closureDigest: closure.digest,
      entrypointDigest: descriptor.entrypoint.digest, sourceDescriptorDigest: hashPreparedRuntimeDescriptor({ ...descriptor, stage: "PREFLIGHT", finalImageDigest: null, toolSurfaceHash: null }) };
    const reviewed = inspectPreparedSources(closure), semantic = await reviewPreparedSemantics({ files: reviewed.files, tools, releaseId: "prepared-test@1.0.0",
      ai: { allowRemoteAi: true, provider: "custom", url: `http://127.0.0.1:${(server.address() as any).port}`, timeoutMs: 1000 } });
    const step = { protocolComplete: true, timedOut: false, exitCode: 0, failureCode: null, pages: 1, permissionProfile: "NODE_PERMISSION_READ_ONLY_V1",
      runtimeIdentity: { imageDigest: descriptor.finalImageDigest, platform: descriptor.platform, argv: descriptor.argv }, toolSurfaceHash: binding.toolSurfaceHash,
      egressEvents: [], canaryExfiltration: false, callResults: [{ name: "list_messages", isError: false, contentHash: "b".repeat(64) }] };
    const result = { schemaVersion: "1.0.0", scanId: randomUUID(), releaseId: "prepared-test@1.0.0", artifactDigest: binding.artifactDigest,
      toolSurfaceHash: binding.toolSurfaceHash, scanStatus: "PASSED", findings: [], evidenceHash: `0x${"c".repeat(64)}`, source: "LIVE" };
    const documents: Record<string, any> = { "report.json": { ...result, scope: "RESTRICTED_NODE_DOCKER_V1" }, "prepared/binding.json": binding, "prepared/source-identity.json": source,
      "runtime/descriptor.json": descriptor, "runtime/execution-policy.json": binding.executionPolicy, "runtime/tools.json": tools,
      "prepared/observation.json": { source: "LIVE_DOCKER", identity: { observedDescriptorDigest: binding.descriptorDigest, sourceArtifactDigest: binding.sourceArtifactDigest,
        executionPolicyDigest: binding.executionPolicyDigest, finalImageDigest: binding.finalImageDigest, preparationDescriptorDigest: hashPreparedRuntimeDescriptor({ ...descriptor, toolSurfaceHash: null }) },
        steps: { discovery: { ...step, callResults: [] }, normal: step, adversarial: step }, issues: [], scenarios: ["NORMAL", "ADVERSARIAL"].map((kind) => ({ kind, toolCall: { name: "list_messages" } })) },
      "static/closure-inventory.json": { ...reviewed.inventory, source: closure.source }, "static/closure-report.json": { ...closureManifest(closure.entries), bytes: closure.bytes,
        sourceDescriptorDigest: trusted.sourceDescriptorDigest, installScripts: false, installNetwork: "NONE" },
      "static/closure-source.json": { complete: true, files: contents.map(({ path, bytes }) => ({ path, base64: bytes.toString("base64") })) },
      "static/findings.json": [], "static/sbom.json": reviewed.sbom, "semantic/reviews.json": semantic };
    // All observations/proofs above are synthetic test data, even when testing rejection of forged LIVE labels.
    return { config, trusted, binding, identity, source, result, documents, bundle: createEvidenceBundle(documents),
      independent: () => { const second = { ...result, scanId: randomUUID() }; return { result: second,
        bundle: createEvidenceBundle({ ...documents, "report.json": { ...second, scope: "RESTRICTED_NODE_DOCKER_V1" } }) }; } };
  } finally { await new Promise<void>((done) => server.close(() => done())); }
}
