import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { comparePreparedScans, independentlyScanPrepared, recordPreparedVerification, checkedPreparedValidatorAi } from "../../apps/validator/src/prepared-verification.js";
import { checkedValidatorPayload, configuredValidatorKeys, configuredValidatorMode, runValidatorFanout } from "../../apps/validator/src/v2.js";
import { preparedPolicy } from "../../apps/api/src/control-policy.js";
import { hash } from "../../apps/api/src/control-plane.js";
import { attestationV2Domain, attestationV2Types, quarantineV2Types, bytes32 } from "../../packages/contracts-sdk/src/v2.js";
import { id } from "ethers";
import { syntheticPreparedFixture } from "./prepared-fixture.js";
import { controlConfig } from "../../apps/api/src/control-config.js";
import { preparedAi } from "../../apps/api/src/prepared-config.js";
// @ts-expect-error Shared ESM evidence helper.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";

test("prepared signing requires independent evidence, not API PASS or a supplied runtime boolean (synthetic contract)", async () => {
  const f = await syntheticPreparedFixture(), independent = f.independent(), now = Math.floor(Date.now() / 1000);
  assert.equal(f.documents["semantic/reviews.json"].disclosure.policy, "LOCAL_CONTRACT_TEST");
  for (const role of ["analyzer", "critic"]) assert.equal(f.documents["semantic/reviews.json"].reviews[0][role].execution.disclosure.providerQuality, "PROVIDER_QUALITY_NOT_MEASURED");
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
  assert.equal((await checkedValidatorPayload(template, context)).verdict, "PASS");
  await assert.rejects(() => checkedValidatorPayload(template, { ...context, independentPreparedEvidence: undefined }), /BINDING_MISMATCH/);
  await assert.rejects(() => checkedValidatorPayload(template, { ...context, preparedRuntimeTrust: { independentlyVerified: true } }), /BINDING_MISMATCH/);
  await assert.rejects(() => checkedValidatorPayload(template, { ...context, preparedRuntime: { ...f.config, builderImageDigest: `sha256:${"0".repeat(64)}` } }), /BINDING_MISMATCH/);
  assert.throws(() => comparePreparedScans(f, f, preparedPolicy, f.trusted), /IDENTITY_MISMATCH/);
  const documents = structuredClone(f.documents); documents["semantic/reviews.json"].reviews[0].critic = undefined;
  delete documents["semantic/reviews.json"].reviews[0].critic;
  assert.throws(() => comparePreparedScans({ ...f, bundle: createEvidenceBundle(documents) }, independent, preparedPolicy, f.trusted), /DID_NOT_CONFIRM/);
  const different = structuredClone(independent.result); different.scanStatus = "FAILED";
  assert.throws(() => comparePreparedScans(f, { ...independent, result: different }, preparedPolicy, f.trusted), /DID_NOT_CONFIRM/);
  const quarantine = { domain: template.domain, types: quarantineV2Types, payload: { releaseId: f.identity.releaseId, policyHash,
    evidenceHash: f.bundle.manifest.root, reasonCode: id("CANARY_EXFILTRATION"), expiresAt: now + 120, validatorSetVersion: 1, nonce: 0, deadline: now + 60 } };
  // An advertised API FAIL cannot turn independently confirmed PASS into emergency authority.
  for (const verdict of ["PASS", "FAIL", "ABSTAIN"]) await assert.rejects(checkedValidatorPayload(quarantine,
    { ...context, scan: { ...scan, result: { ...scan.result, verdict } } }, true), /BINDING_MISMATCH/);
  await assert.rejects(checkedValidatorPayload(quarantine, { ...context, independentPreparedEvidence: undefined }, true), /BINDING_MISMATCH/);
  const forged = structuredClone(f.bundle); forged.files["report.json"] = "{\"scanStatus\":\"FAILED\"}";
  await assert.rejects(checkedValidatorPayload(quarantine, { ...context, evidence: { ...context.evidence, bundle: forged } }, true), /BINDING_MISMATCH/);
  const incompleteDocs = structuredClone(f.documents); delete incompleteDocs["semantic/reviews.json"].reviews[0].critic;
  const incomplete = createEvidenceBundle(incompleteDocs), incompleteContext = { ...context, evidence: { bundle: incomplete, reportRoot: incomplete.manifest.root },
    scan: { ...scan, result: { ...scan.result, reportRoot: incomplete.manifest.root } } };
  await assert.rejects(checkedValidatorPayload({ ...quarantine, payload: { ...quarantine.payload, evidenceHash: incomplete.manifest.root } }, incompleteContext, true), /DID_NOT_CONFIRM/);
});

test("operator AI test disclosure is explicit, strictly numeric-loopback and preserved by API and validator configuration", () => {
  const env = { CONTROL_PLANE_ENABLED: "true", CONTROL_PLANE_CREDENTIALS: JSON.stringify([{ token: "synthetic-reader-token", tenantId: "synthetic", role: "reader" }]),
    CONTROL_EVIDENCE_KEY: "1".repeat(64), CONTROL_ALLOW_REMOTE_AI: "true", CONTROL_AI_PROVIDER: "custom", CONTROL_AI_URL: "http://127.0.0.1:9000" };
  assert.equal(preparedAi(controlConfig(env)!).disclosurePolicy, undefined);
  const configured = controlConfig({ ...env, MCPSHIELD_AI_DISCLOSURE_POLICY: "LOCAL_CONTRACT_TEST" })!;
  const ai = preparedAi(configured);
  assert.equal(ai.disclosurePolicy, "LOCAL_CONTRACT_TEST");
  assert.equal(checkedPreparedValidatorAi(ai as any).disclosurePolicy, "LOCAL_CONTRACT_TEST");
  for (const overrides of [{ MCPSHIELD_AI_DISCLOSURE_POLICY: "ALLOW_ALL" }, { CONTROL_AI_URL: "https://provider.example/model" },
    { CONTROL_AI_URL: "http://localhost:9000" }, { CONTROL_AI_URL: "http://user:password@127.0.0.1" }, { CONTROL_AI_PROVIDER: "openai" }])
    assert.throws(() => controlConfig({ ...env, MCPSHIELD_AI_DISCLOSURE_POLICY: "LOCAL_CONTRACT_TEST", ...overrides }), /DISCLOSURE/);
  for (const overrides of [{ disclosurePolicy: "ALLOW_ALL" }, { url: "https://provider.example/model" }, { url: "http://localhost:9000" }])
    assert.throws(() => checkedPreparedValidatorAi({ ...ai, ...overrides } as any), /DISCLOSURE/);
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

test("one institution can configure one key without sharing keys; CLI rejects ambiguous or malformed modes", () => {
  const key = `0x${"1".repeat(64)}`, second = `0x${"2".repeat(64)}`; // Public synthetic test keys only.
  assert.deepEqual(configuredValidatorKeys({ VALIDATOR_PRIVATE_KEY: key }), [key]);
  assert.deepEqual(configuredValidatorKeys({ VALIDATOR_PRIVATE_KEYS: JSON.stringify([key, second]) }), [key, second]);
  assert.throws(() => configuredValidatorKeys({ VALIDATOR_PRIVATE_KEY: key, VALIDATOR_PRIVATE_KEYS: "[]" }), /MODES_CONFLICT/);
  for (const env of [{}, { VALIDATOR_PRIVATE_KEY: "" }, { VALIDATOR_PRIVATE_KEYS: "not-json" }, { VALIDATOR_PRIVATE_KEYS: "{}" }, { VALIDATOR_PRIVATE_KEYS: "[]" }])
    assert.throws(() => configuredValidatorKeys(env), /CONFIG_INVALID/);
});

test("quarantine-only is explicit, single-key and cannot silently accept conflicting or malformed flags", async () => {
  assert.deepEqual(configuredValidatorMode([]), { quarantineFirst: false, quarantineOnly: false });
  assert.deepEqual(configuredValidatorMode(["--quarantine"]), { quarantineFirst: true, quarantineOnly: false });
  assert.deepEqual(configuredValidatorMode(["--quarantine-only"]), { quarantineFirst: false, quarantineOnly: true });
  for (const args of [["--quarantine", "--quarantine-only"], ["--quarantine-only", "--quarantine-only"], ["--quarantine-only=true"], ["--quarantine-only", "false"], ["--unknown"]])
    assert.throws(() => configuredValidatorMode(args), /QUARANTINE_MODE_INVALID/);
  const options = { apiUrl: "http://127.0.0.1:9", token: "synthetic-only", scanId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", privateKeys: [`0x${"1".repeat(64)}`],
    chainId: 1337, registryAddress: `0x${"a".repeat(40)}`, policyHash: `0x${"a".repeat(64)}`, rpcUrl: "http://127.0.0.1:9", quarantineOnly: true };
  for (const edit of [{ quarantineFirst: true }, { quarantineOnly: "true" }, { quarantineFirst: "false" }, { privateKeys: [] }, { privateKeys: [...options.privateKeys, `0x${"2".repeat(64)}`] }])
    await assert.rejects(runValidatorFanout({ ...options, ...edit } as any), /QUARANTINE_MODE_INVALID/);
});

test("quarantine-only always enters independent verification even when API advertises PASS/ABSTAIN (loopback contract, no Docker)", async () => {
  const f = await syntheticPreparedFixture(), policyHash = hash(preparedPolicy), scanId = f.result.scanId;
  let advertised = "PASS", forged = false, posts = 0;
  const server = createServer(async (request, response) => {
    let body: any;
    if (request.url === "/rpc") {
      let text = ""; for await (const chunk of request) text += chunk;
      const rpc = JSON.parse(text);
      assert.ok(["eth_chainId", "eth_call"].includes(rpc.method));
      body = { jsonrpc: "2.0", id: rpc.id, result: rpc.method === "eth_chainId" ? "0x539" : `0x${"0".repeat(24)}${"b".repeat(40)}` };
    } else {
      if (request.method === "POST") posts++;
      if (request.url === "/v1/policies") body = { items: [{ policyHash, document: preparedPolicy }] };
      else if (request.url?.endsWith("/evidence")) body = { reportRoot: f.bundle.manifest.root, bundle: forged ? { ...f.bundle, files: {} } : f.bundle };
      else body = { scan: { scanId, releaseId: f.identity.releaseId, policyHash, status: "COMPLETED", result: { scanResult: f.result, reportRoot: f.bundle.manifest.root, verdict: advertised } } };
    }
    response.writeHead(200, { "content-type": "application/json", connection: "close" }).end(JSON.stringify(body));
  });
  try {
    await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
    const apiUrl = `http://127.0.0.1:${(server.address() as any).port}`;
    const options = { apiUrl, token: "synthetic-local-only", scanId, privateKeys: [`0x${"1".repeat(64)}`], chainId: 1337,
      registryAddress: `0x${"a".repeat(40)}`, policyHash, rpcUrl: `${apiUrl}/rpc`, quarantineOnly: true };
    // No prepared-runtime authority is injected. All advertised verdicts must reach
    // the independent-runtime boundary and reject, never skip into success/no-op.
    for (advertised of ["PASS", "ABSTAIN", "FAIL"]) await assert.rejects(runValidatorFanout(options), /PREPARED_VALIDATOR_TRUST_REQUIRED/);
    forged = true; await assert.rejects(runValidatorFanout(options), /VALIDATOR_EVIDENCE_BINDING_MISMATCH/);
    assert.equal(posts, 0, "failed independent verification cannot submit an attestation or quarantine");
  } finally { server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); }
});
