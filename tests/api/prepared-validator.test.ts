import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { comparePreparedScans, independentlyScanPrepared, recordPreparedVerification, checkedPreparedValidatorAi } from "../../apps/validator/src/prepared-verification.js";
import { checkedValidatorPayload } from "../../apps/validator/src/v2.js";
import { preparedPolicy } from "../../apps/api/src/control-policy.js";
import { hash } from "../../apps/api/src/control-plane.js";
import { attestationV2Domain, attestationV2Types, bytes32 } from "../../packages/contracts-sdk/src/v2.js";
import { syntheticPreparedFixture } from "./prepared-fixture.js";
// @ts-expect-error Shared ESM evidence helper.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";

test("prepared signing requires independent evidence, not API PASS or a supplied runtime boolean (synthetic contract)", async () => {
  const f = await syntheticPreparedFixture(), independent = f.independent(), now = Math.floor(Date.now() / 1000);
  const policyHash = hash(preparedPolicy), registry = `0x${"a".repeat(40)}`;
  const scan = { scanId: f.result.scanId, releaseId: f.identity.releaseId, policyHash, status: "COMPLETED", result: { scanResult: f.result,
    reportRoot: f.bundle.manifest.root, validFrom: new Date(now * 1000).toISOString(), validUntil: new Date((now + 600) * 1000).toISOString() } };
  const identity = { ...f.identity, exists: true, artifactDigest: bytes32(f.binding.artifactDigest), manifestDigest: bytes32(f.binding.manifestDigest), toolSurfaceDigest: f.binding.toolSurfaceHash };
  const template = { domain: attestationV2Domain(31337, registry), types: attestationV2Types, verdict: "PASS", payload: { releaseId: f.identity.releaseId,
    artifactDigest: identity.artifactDigest, manifestDigest: identity.manifestDigest, toolSurfaceDigest: identity.toolSurfaceDigest, policyHash,
    reportRoot: f.bundle.manifest.root, verdict: 0, validFrom: now, validUntil: now + 600, validatorSetVersion: 1, nonce: 0, deadline: now + 300 } };
  const context = { chainId: 31337, registryAddress: registry, policyHash, policy: preparedPolicy, scan,
    evidence: { bundle: f.bundle, reportRoot: f.bundle.manifest.root }, identity, validatorSetVersion: 1, nonce: 0, now,
    preparedRuntime: f.config, preparedRuntimeTrust: f.trusted, independentPreparedEvidence: independent };
  assert.equal(checkedValidatorPayload(template, context).verdict, "PASS");
  assert.throws(() => checkedValidatorPayload(template, { ...context, independentPreparedEvidence: undefined }), /BINDING_MISMATCH/);
  assert.throws(() => checkedValidatorPayload(template, { ...context, preparedRuntimeTrust: { independentlyVerified: true } }), /BINDING_MISMATCH/);
  assert.throws(() => checkedValidatorPayload(template, { ...context, preparedRuntime: { ...f.config, builderImageDigest: `sha256:${"0".repeat(64)}` } }), /BINDING_MISMATCH/);
  assert.throws(() => comparePreparedScans(f, f, preparedPolicy, f.trusted), /IDENTITY_MISMATCH/);
  const documents = structuredClone(f.documents); documents["semantic/reviews.json"].reviews[0].critic = undefined;
  delete documents["semantic/reviews.json"].reviews[0].critic;
  assert.throws(() => comparePreparedScans({ ...f, bundle: createEvidenceBundle(documents) }, independent, preparedPolicy, f.trusted), /DID_NOT_CONFIRM/);
  const different = structuredClone(independent.result); different.scanStatus = "FAILED";
  assert.throws(() => comparePreparedScans(f, { ...independent, result: different }, preparedPolicy, f.trusted), /DID_NOT_CONFIRM/);
});
test("local verification receipts contain only commitments; missing explicit AI or actual image cannot sign", async () => {
  const f = await syntheticPreparedFixture(), comparison = comparePreparedScans(f, f.independent(), preparedPolicy, f.trusted);
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-validator-receipt-")), path = join(dir, "receipts.jsonl");
  try {
    await recordPreparedVerification(path, { chainId: 31337, registryContract: `0x${"a".repeat(40)}`, validator: `0x${"b".repeat(40)}`,
      releaseId: f.identity.releaseId, policyHash: hash(preparedPolicy) }, comparison);
    const text = await readFile(path, "utf8"), receipt = JSON.parse(text);
    assert.equal(receipt.originalReportRoot, f.bundle.manifest.root); assert.notEqual(receipt.independentReportRoot, receipt.originalReportRoot);
    assert.equal(receipt.state, "LOCAL_VERIFICATION_ONLY"); assert.doesNotMatch(text, /list_messages|package\.json|semantic|Bearer|token|privateKey|apiKey|prompt|contents|base64/);
    assert.throws(() => checkedPreparedValidatorAi(), /EXPLICIT_AI_REQUIRED/);
    assert.throws(() => checkedPreparedValidatorAi({ allowRemoteAi: true, provider: "openai" }), /EXPLICIT_AI_REQUIRED/);
    assert.throws(() => checkedPreparedValidatorAi({ allowRemoteAi: true, provider: "custom", url: "http://untrusted.example/" }), /HTTPS/);
    await assert.rejects(independentlyScanPrepared(f, preparedPolicy, f.config), /EXPLICIT_AI_REQUIRED/);
    // Fake CID is deliberately absent: this invokes the real local image boundary, never an injected success boolean.
    await assert.rejects(independentlyScanPrepared(f, preparedPolicy, f.config, { allowRemoteAi: true, provider: "custom", url: "http://127.0.0.1:9" }));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("independent FAIL compares violation scopes, not random canaries or incidental occurrence counts (synthetic contract)", async () => {
  const f = await syntheticPreparedFixture();
  const failure = (count: number, canary: string, code = "CANARY_EXFILTRATION") => {
    const result = { ...f.independent().result, scanStatus: "FAILED", findings: Array.from({ length: count }, () => ({
      code, stage: "SANDBOX", severity: "CRITICAL", deterministic: true, message: "Synthetic scope comparison",
      evidence: { canaryHash: canary, observer: "LOCAL_PROXY" } })) };
    const documents = structuredClone(f.documents);
    documents["report.json"] = { ...result, scope: "RESTRICTED_NODE_DOCKER_V1" };
    documents["prepared/observation.json"].steps.normal.canaryExfiltration = true;
    documents["prepared/observation.json"].steps.normal.canaryHash = canary;
    documents["prepared/observation.json"].steps.normal.egressEvents = [{ type: "EGRESS_BLOCKED" }];
    return { result, bundle: createEvidenceBundle(documents) };
  };
  const original = failure(1, "a".repeat(64)), independent = failure(2, "b".repeat(64));
  assert.equal(comparePreparedScans(original, independent, preparedPolicy, f.trusted).verdict, "FAIL");
  assert.throws(() => comparePreparedScans(original, failure(1, "b".repeat(64), "UNDECLARED_EGRESS"), preparedPolicy, f.trusted), /DID_NOT_CONFIRM/);
});
