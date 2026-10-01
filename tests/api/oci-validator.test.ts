import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { id, Wallet, verifyTypedData } from "ethers";
import { compareOciScans, independentlyScanOci } from "../../apps/validator/src/oci-verification.js";
import { recordPreparedVerification } from "../../apps/validator/src/prepared-verification.js";
import { checkedValidatorPayload } from "../../apps/validator/src/v2.js";
import { ociPolicy, policyVerdict, preparedPolicy } from "../../apps/api/src/control-policy.js";
import { ociTrust, type OciConfig } from "../../apps/api/src/oci-config.js";
import { hash } from "../../apps/api/src/control-plane.js";
import { attestationV2Domain, attestationV2Types, bytes32, exactReleaseIdentity, quarantineV2Types } from "../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared ESM evidence helper.
import { createEvidenceBundle, canonicalJson } from "../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared pure OCI commitments.
import { createOciReleaseBinding, ociExecutionPolicy } from "../../services/scanner/src/oci-binding.mjs";
// @ts-expect-error Shared strict OCI effect reconstruction.
import { assessOciPolicy, ociSandboxFindings } from "../../services/scanner/src/oci-policy.mjs";
// @ts-expect-error Shared installed observer byte identity, no Docker execution.
import { readOciObservationPolicy } from "../../services/scanner/src/oci-observer.mjs";
// @ts-expect-error Shared OCI descriptor identity.
import { hashOciRuntimeDescriptor, ociHash, OCI_OBSERVATION_POLICY, OCI_SOURCE_BUDGET_PROFILE } from "../../services/resolver/src/oci-runtime-descriptor.mjs";
// @ts-expect-error Shared tool metadata identity.
import { toolSurfaceHash } from "../../services/scanner/src/tool-surface.mjs";

async function syntheticOciFailure() {
  const digest = ociHash("synthetic-not-an-actual-Docker-image"), platform = { os: "linux" as const, architecture: "amd64" as const };
  const config: OciConfig = { baseImageDigest: digest, baseCatalogueDigest: digest, trivyImageDigest: digest, databaseDigest: digest,
    databaseDir: resolve("unused-private-db"), sinkImageDigest: digest, platform };
  const { databaseDir: _directory, platform: _platform, ...anchors } = await ociTrust(config), observationPolicy = await readOciObservationPolicy(digest);
  const tools = [{ name: "synthetic_private_tool", inputSchema: { type: "object" } }];
  const source = { ...exactReleaseIdentity({ toolId: "oci:synthetic", artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: toolSurfaceHash([]) }),
    artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: toolSurfaceHash([]) };
  const descriptor = { schemaVersion: "mcpshield.oci-runtime.v1", profile: "oci-container-v1", stage: "OBSERVED", budgetProfile: OCI_SOURCE_BUDGET_PROFILE,
    sourceBytes: 1000, layerArchiveBytes: 2048, exportArchiveBytes: 2048, sourceTreeDigest: digest, sourceIndexDigest: digest, manifestDigest: digest, configDigest: digest,
    platform, finalImageDigest: digest, imageDigestKind: "DOCKER_IMAGE_CONFIG_ID", rootfsDigest: digest,
    entrypoint: { requestedPath: "/bin/sh", resolvedPath: "/bin/sh", contentDigest: digest, linkChainDigest: digest }, argv: ["/bin/sh", "/synthetic.sh"],
    workingDirectory: "/", environmentDigest: digest, toolSurfaceHash: toolSurfaceHash(tools), policy: OCI_OBSERVATION_POLICY };
  const binding = createOciReleaseBinding({ sourceReleaseId: source.releaseId, descriptor, executionPolicy: ociExecutionPolicy(anchors) });
  const identity = exactReleaseIdentity({ toolId: source.toolId, artifactDigest: binding.artifactDigest, manifestDigest: binding.manifestDigest, toolSurfaceHash: binding.toolSurfaceHash });
  const preparationDigest = hashOciRuntimeDescriptor({ ...descriptor, stage: "IMPORTED", toolSurfaceHash: null });
  // Entire native context and observations are synthetic contract inputs. Only the
  // real independentlyScanOci path may produce these within a signing process.
  const trusted = { anchors, descriptorDigest: binding.descriptorDigest, finalImageDigest: digest, rootfsDigest: digest, platform, observationPolicy };
  const sample = (canary = "a".repeat(64), count = 1, unavailable = false, egressOnly = false) => {
    const step = { source: "LIVE_DOCKER_EXTERNAL_MCP_CLIENT", runtimeDigest: unavailable ? ociHash("wrong") : preparationDigest,
      canaryHashes: egressOnly ? [] : [canary], undeclaredEgress: egressOnly, eventBodyLimit: false, eventCount: 1,
      mcp: { complete: true, toolSurfaceHash: binding.toolSurfaceHash } };
    const observation = { profile: "oci-container-v1", source: "LIVE_DOCKER_EXTERNAL_MCP_CLIENT", preparationDescriptorDigest: preparationDigest,
      observedDescriptorDigest: binding.descriptorDigest, executionPolicyDigest: ociHash(canonicalJson(observationPolicy)),
      steps: { discovery: { ...step, canaryHashes: [], undeclaredEgress: false, eventCount: 0 }, normal: step, ...(count > 1 ? { adversarial: structuredClone(step) } : {}) } };
    const findings = ociSandboxFindings(observation), result = { schemaVersion: "1.0.0", scanId: randomUUID(), releaseId: "synthetic@1.0.0", artifactDigest: binding.artifactDigest,
      toolSurfaceHash: binding.toolSurfaceHash, scanStatus: "FAILED", findings, evidenceHash: "0x" + ociHash(canonicalJson(findings)).slice(7), source: "LIVE" };
    const documents = { "oci/binding.json": binding, "prepared/source-identity.json": source, "runtime/tools.json": tools, "runtime/oci-descriptor.json": descriptor,
      "runtime/execution-policy.json": binding.executionPolicy, "runtime/observation-policy.json": observationPolicy, "oci/observation.json": observation,
      "report.json": { ...result, scope: "RESTRICTED_OCI_OFFLINE_V1" } };
    return { result, documents, bundle: createEvidenceBundle(documents) };
  };
  return { config, trusted, binding, identity, sample };
}

test("OCI independent contract compares exact binding and deterministic scope sets, never advertised checks or same-root replay", async () => {
  const f = await syntheticOciFailure(), original = f.sample(), independent = f.sample("b".repeat(64), 2);
  assert.equal(policyVerdict(original.bundle, original.result, ociPolicy, f.trusted), "FAIL");
  assert.equal(policyVerdict(independent.bundle, independent.result, ociPolicy, f.trusted), "FAIL", JSON.stringify(assessOciPolicy(independent.bundle, independent.result, f.binding, f.trusted)));
  const compared = compareOciScans(original, independent, ociPolicy, f.trusted);
  assert.equal(compared.verdict, "FAIL"); assert.notEqual(compared.originalReportRoot, compared.independentReportRoot);
  assert.equal(compared.semanticEvidenceMode, "LOCAL_CONTRACT_TEST"); assert.equal(compared.providerQuality, "PROVIDER_QUALITY_NOT_MEASURED");
  assert.throws(() => compareOciScans(original, original, ociPolicy, f.trusted), /IDENTITY_MISMATCH/);
  assert.throws(() => compareOciScans(original, independent, preparedPolicy, f.trusted), /OCI_POLICY_REQUIRED/);
  assert.throws(() => compareOciScans(original, independent, ociPolicy, { independentlyVerified: true }), /DID_NOT_CONFIRM/);
  assert.throws(() => compareOciScans(original, f.sample("b".repeat(64), 1, true), ociPolicy, f.trusted), /DID_NOT_CONFIRM/);
  assert.throws(() => compareOciScans(original, f.sample("b".repeat(64), 1, false, true), ociPolicy, f.trusted), /DID_NOT_CONFIRM/);
  const forged = { ...independent, bundle: createEvidenceBundle({ ...independent.documents, "oci/observation.json": { checks: { completed: true } } }) };
  assert.throws(() => compareOciScans(original, forged, ociPolicy, f.trusted), /DID_NOT_CONFIRM/);
});

test("OCI async signing guard pins every local authority/domain and requires fresh independent evidence (synthetic only)", async t => {
  const f = await syntheticOciFailure(), original = f.sample(), now = Math.floor(Date.now() / 1000), policyHash = hash(ociPolicy), registry = `0x${"a".repeat(40)}`;
  const identity = { ...f.identity, exists: true, artifactDigest: bytes32(f.binding.artifactDigest), manifestDigest: bytes32(f.binding.manifestDigest), toolSurfaceDigest: f.binding.toolSurfaceHash };
  const context = { chainId: 31337, registryAddress: registry, policyHash, policy: ociPolicy, validatorSetVersion: 1, nonce: 0, now, identity,
    scan: { status: "COMPLETED", releaseId: f.identity.releaseId, policyHash, result: { scanResult: original.result, reportRoot: original.bundle.manifest.root,
      validFrom: new Date(now * 1000).toISOString(), validUntil: new Date((now + 600) * 1000).toISOString() } }, evidence: { reportRoot: original.bundle.manifest.root, bundle: original.bundle },
    ociRuntime: f.config, ociRuntimeTrust: f.trusted, independentOciEvidence: f.sample("b".repeat(64)) };
  for (const quarantine of [false, true]) {
    const common = { releaseId: f.identity.releaseId, policyHash, validatorSetVersion: 1, nonce: 0, deadline: now + 300 };
    const template = { domain: attestationV2Domain(31337, registry), types: quarantine ? quarantineV2Types : attestationV2Types, verdict: "FAIL",
      payload: quarantine ? { ...common, evidenceHash: original.bundle.manifest.root, reasonCode: id("CANARY_EXFILTRATION"), expiresAt: now + 600 }
        : { ...common, artifactDigest: identity.artifactDigest, manifestDigest: identity.manifestDigest, toolSurfaceDigest: identity.toolSurfaceDigest,
          reportRoot: original.bundle.manifest.root, verdict: 1, validFrom: now, validUntil: now + 600 } };
    const checked = await checkedValidatorPayload(template, context, quarantine), wallet = Wallet.createRandom();
    const signature = await wallet.signTypedData(checked.domain, checked.types, checked.payload);
    assert.equal(verifyTypedData(checked.domain, checked.types, checked.payload, signature), wallet.address);
    for (const patch of [{ independentOciEvidence: undefined }, { ociRuntime: undefined }, { ociRuntimeTrust: { independentlyVerified: true } },
      { ociRuntime: { ...f.config, databaseDigest: `sha256:${"f".repeat(64)}` } },
      { independentOciEvidence: f.sample("b".repeat(64), 1, true) }]) {
      await assert.rejects(() => checkedValidatorPayload(template, { ...context, ...patch }, quarantine));
    }
    for (const patch of [{ domain: { ...template.domain, verifyingContract: `0x${"b".repeat(40)}` } },
      { types: { Permit: [] } }, { payload: { ...template.payload, nonce: 1 } }, { payload: { ...template.payload, deadline: now - 1 } }]) {
      await assert.rejects(() => checkedValidatorPayload({ ...template, ...patch }, context, quarantine), /BINDING_MISMATCH/);
    }
    // A production call cannot reuse an old pre-verification clock. The final
    // boundary is checked again even if the clock advances during reconstruction.
    let clockReads = 0;
    const clock = t.mock.method(Date, "now", () => (++clockReads === 1 ? now : now + 700) * 1000);
    try {
      await assert.rejects(() => checkedValidatorPayload(template, { ...context, now: undefined }, quarantine), /BINDING_MISMATCH/);
      assert.ok(clockReads >= 2);
    } finally { clock.mock.restore(); }
  }
});

test("OCI signer rejects missing local test authority or actual image; private receipts retain commitments and scope only", async () => {
  const f = await syntheticOciFailure(), original = f.sample(), ai = { allowRemoteAi: true as const, provider: "custom" as const,
    disclosurePolicy: "LOCAL_CONTRACT_TEST" as const, url: "http://127.0.0.1:9" };
  await assert.rejects(() => independentlyScanOci(original, ociPolicy, f.config), /EXPLICIT_AI_REQUIRED/);
  await assert.rejects(() => independentlyScanOci(original, ociPolicy, f.config, { ...ai, disclosurePolicy: undefined }), /LOCAL_CONTRACT_REQUIRED/);
  await assert.rejects(() => independentlyScanOci(original, ociPolicy, f.config, { ...ai, url: "https://remote.example" }), /LOCAL_CONTRACT_REQUIRED/);
  // This fake CID cannot exist: invoke the real native trust boundary with no test hook.
  await assert.rejects(() => independentlyScanOci(original, ociPolicy, f.config, ai));
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-oci-validator-")), path = join(dir, "receipts.jsonl");
  try {
    await recordPreparedVerification(path, { chainId: 31337, registryContract: `0x${"a".repeat(40)}`, validator: `0x${"b".repeat(40)}`,
      releaseId: f.identity.releaseId, policyHash: hash(ociPolicy) }, compareOciScans(original, f.sample("b".repeat(64)), ociPolicy, f.trusted));
    const text = await readFile(path, "utf8"), receipt = JSON.parse(text);
    assert.equal(receipt.state, "LOCAL_VERIFICATION_ONLY"); assert.equal(receipt.semanticEvidenceMode, "LOCAL_CONTRACT_TEST");
    assert.doesNotMatch(text, /synthetic_private_tool|runtimeTag|databaseDir|Bearer|privateKey|contentBase64|prompt|arguments/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
