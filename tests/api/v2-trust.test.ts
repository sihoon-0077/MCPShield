import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { Wallet, id, verifyTypedData } from "ethers";
import { checkedValidatorPayload } from "../../apps/validator/src/v2.js";
import { defaultPolicy, hash } from "../../apps/api/src/control-plane.js";
import { attestationV2Domain, attestationV2Types, exactReleaseIdentity, quarantineV2Types } from "../../packages/contracts-sdk/src/v2.js";
import { boundedServiceRequest, checkedServiceUrl, v2RpcRequest } from "../../packages/contracts-sdk/src/transport.js";
import { v2ChainReader } from "../../apps/api/src/registry-v2-client.js";
// @ts-expect-error Shared evidence implementation is ESM JavaScript.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";

function example(quarantine = false) {
  const now = Math.floor(Date.now() / 1000), digest = `0x${"a".repeat(64)}`, surface = `0x${"b".repeat(64)}`;
  const exact = exactReleaseIdentity({ toolId: "npm:mail-mcp", artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: surface });
  const report = { schemaVersion: "1.0.0", scanId: randomUUID(), releaseId: "mail-mcp@1.0.0", source: "LIVE", evidenceHash: `0x${"c".repeat(64)}`,
    artifactDigest: `sha256:${digest.slice(2)}`, toolSurfaceHash: surface, scanStatus: quarantine ? "FAILED" : "PASSED",
    findings: quarantine ? [{ code: "CANARY_EXFILTRATION", stage: "SANDBOX", severity: "CRITICAL", deterministic: true, message: "Synthetic trust contract", evidence: {} }] : [] };
  const documents = { "report.json": { ...report, scope: "STATIC_AI_SANDBOX" }, "static/findings.json": [], "static/package-diff.json": { hasBaseline: false }, "semantic/model-output.json": { findings: [] },
    "sandbox/events.json": { mode: "DOCKER", complete: true }, "sandbox/mcp.json": { complete: true } };
  const bundle = createEvidenceBundle(documents), independentResult = { ...report, scanId: randomUUID() };
  const policyHash = hash(defaultPolicy), registryAddress = `0x${"1".repeat(40)}`;
  const context = { chainId: 1337, registryAddress, policyHash, now, policy: defaultPolicy, validatorSetVersion: 1, nonce: 0,
    identity: { ...exact, exists: true, artifactDigest: digest, manifestDigest: digest, toolSurfaceDigest: surface }, evidence: { bundle, reportRoot: bundle.manifest.root },
    // Pure reconstruction test data, not an injected production scanner or evidence of actual Docker execution.
    independentSourceEvidence: { result: independentResult, bundle: createEvidenceBundle({ ...documents, "report.json": { ...independentResult, scope: "STATIC_AI_SANDBOX" } }),
      sourceIdentity: { ...exact, artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: surface }, baselineReleaseId: null },
    scan: { status: "COMPLETED", policyHash, releaseId: exact.releaseId, result: { reportRoot: bundle.manifest.root, scanResult: report,
      validFrom: new Date(now * 1000).toISOString(), validUntil: new Date((now + 3600) * 1000).toISOString() } } };
  const common = { releaseId: exact.releaseId, policyHash, validatorSetVersion: 1, nonce: 0, deadline: now + 300 };
  const template = { domain: attestationV2Domain(1337, registryAddress), types: quarantine ? quarantineV2Types : attestationV2Types, verdict: quarantine ? "FAIL" : "PASS",
    payload: quarantine ? { ...common, evidenceHash: bundle.manifest.root, reasonCode: id("CANARY_EXFILTRATION"), expiresAt: now + 600 }
      : { ...common, artifactDigest: digest, manifestDigest: digest, toolSurfaceDigest: surface, reportRoot: bundle.manifest.root, verdict: 0, validFrom: now, validUntil: now + 3600 } };
  return { context, template };
}

test("validator reconstructs local domain/types and rejects signing-oracle templates", async () => {
  for (const quarantine of [false, true]) {
    const { context, template } = example(quarantine), checked = await checkedValidatorPayload(template, context, quarantine), wallet = Wallet.createRandom();
    const signature = await wallet.signTypedData(checked.domain, checked.types, checked.payload);
    assert.equal(verifyTypedData(checked.domain, checked.types, checked.payload, signature), wallet.address);
    const corruptions = [
      (value: any) => { value.domain.verifyingContract = `0x${"2".repeat(40)}`; },
      (value: any) => { value.domain.chainId++; },
      (value: any) => { value.types = { Permit: [{ name: "spender", type: "address" }] }; },
      (value: any) => { value.payload.recipient = `0x${"3".repeat(40)}`; },
      (value: any) => { value.payload.nonce++; },
      (value: any) => { value.payload.validatorSetVersion++; },
      (value: any) => { value.payload.policyHash = `0x${"f".repeat(64)}`; },
      (value: any) => { value.payload.deadline = context.now + 86400; },
      (value: any) => { value.payload[quarantine ? "evidenceHash" : "manifestDigest"] = `0x${"f".repeat(64)}`; },
    ];
    for (const corrupt of corruptions) {
      const changed = structuredClone(template); corrupt(changed);
      await assert.rejects(() => checkedValidatorPayload(changed, context, quarantine));
    }
    await assert.rejects(() => checkedValidatorPayload(template, { ...context, policy: { ...defaultPolicy, validitySeconds: 120 } }, quarantine));
    await assert.rejects(() => checkedValidatorPayload(template, { ...context, identity: { ...context.identity, exists: false } }, quarantine));
    await assert.rejects(() => checkedValidatorPayload(template, { ...context, independentSourceEvidence: undefined }, quarantine));
  }
});

test("RPC URL policy rejects plaintext external, URL credentials and excessive fallback endpoints", () => {
  for (const url of ["http://public.example/rpc", "https://user:secret@example.test/rpc", "file:///tmp/rpc", "http://127.0.0.1.evil.test/"]) assert.throws(() => checkedServiceUrl(url));
  assert.throws(() => checkedServiceUrl("http://chain.railway.internal:8545"));
  assert.equal(checkedServiceUrl("http://chain.railway.internal:8545", ["chain.railway.internal"]).hostname, "chain.railway.internal");
  assert.throws(() => v2ChainReader({ rpcUrls: Array(4).fill("https://rpc.example"), registryContract: `0x${"1".repeat(40)}`, chainId: 1337, confirmations: 1 }));
});

test("RPC redirects, oversized bodies and total fallback budget fail closed", async () => {
  let redirected = 0;
  const server = createServer((request, response) => {
    if (request.url === "/redirect") { response.writeHead(307, { location: "/target" }); response.end(); }
    else if (request.url === "/target") { redirected++; response.end("{}"); }
    else if (request.url === "/large") { response.writeHead(200, { "content-length": "99999" }); response.end(); }
    else { response.writeHead(200, { "content-type": "application/json" }); response.write("{"); }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  try {
    const request = v2RpcRequest(`${base}/redirect`); request.method = "POST";
    await assert.rejects(request.send()); assert.equal(redirected, 0);
    await assert.rejects(boundedServiceRequest(`${base}/large`, {}, { maxBytes: 1024 }), /TOO_LARGE/);
    const reader = v2ChainReader({ rpcUrls: [base, base, base], registryContract: `0x${"1".repeat(40)}`, chainId: 1337, confirmations: 1, timeoutMs: 200 });
    const started = performance.now();
    try { await assert.rejects(reader({}, {}), /STATUS_UNAVAILABLE/); assert.ok(performance.now() - started < 1500); }
    finally { reader.close(); }
  } finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
});
