import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { admissionFetch, getSignedAdmission, verifyAdmissionSnapshot } from "../src/signed-admission.mjs";

const keys = generateKeyPairSync("ed25519");
const now = Date.now();
const context = {
  identity: { releaseId: `0x${"1".repeat(64)}`, artifactDigest: `sha256:${"a".repeat(64)}`, toolSurfaceHash: `0x${"b".repeat(64)}` },
  publicKey: keys.publicKey.export({ type: "spki", format: "pem" }), keyId: "cache-test-key",
  policyHash: `0x${"c".repeat(64)}`, chainId: 84532, registryContract: `0x${"d".repeat(40)}`, validatorSetVersion: 1,
  tenantId: "test-tenant", operationClass: "READ_PRIVATE", apiToken: "synthetic-test-credential-only",
};
const base = { schemaVersion: "1.0.0", keyId: context.keyId, ...context.identity, decision: "ALLOW", status: "VERIFIED",
  tenantId: context.tenantId, operationClass: context.operationClass, reasonCode: "RELEASE_VERIFIED", reportUrl: `/v1/releases/${context.identity.releaseId}`,
  policyHash: context.policyHash, chainId: context.chainId, registryContract: context.registryContract, validatorSetVersion: 1,
  observedBlock: 123, blockHash: `0x${"e".repeat(64)}`, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 30_000).toISOString() };
const signed = (snapshot) => ({ snapshot, signature: sign(null, Buffer.from(JSON.stringify(Object.fromEntries(Object.keys(snapshot).sort().map((key) => [key, snapshot[key]])))), keys.privateKey).toString("base64url") });
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });

test("admission timeout covers a stalled response body and bounds response size", async () => {
  await assert.rejects(admissionFetch("http://127.0.0.1", {}, async () => new Response(new ReadableStream({ start() {} })), 20), /timed out/);
  await assert.rejects(admissionFetch("http://127.0.0.1", {}, async () => new Response("x".repeat(65_537)), 100), /exceeds 65536/);
});

test("signed credentials cannot be sent to public HTTP or redirected endpoints", async () => {
  let called = false;
  await assert.rejects(getSignedAdmission({ ...context, apiBaseUrl: "http://public.example", timeoutMs: 100, fetchImpl: async () => { called = true; return json(signed(base)); } }), /requires HTTPS/);
  assert.equal(called, false);
  await admissionFetch("http://127.0.0.1", {}, async (_url, options) => { assert.equal(options.redirect, "error"); return json({}); }, 100);
});

test("signed admission binds every trust coordinate and rejects stale, tampered, unsigned proof", () => {
  const envelope = signed(base);
  assert.equal(verifyAdmissionSnapshot(envelope, { ...context, now }).decision, "ALLOW");
  for (const change of [
    { releaseId: "different@1.0.0" }, { artifactDigest: `sha256:${"f".repeat(64)}` }, { toolSurfaceHash: `0x${"f".repeat(64)}` },
    { policyHash: `0x${"f".repeat(64)}` }, { validatorSetVersion: 2 }, { chainId: 1 }, { registryContract: `0x${"f".repeat(40)}` },
    { keyId: "unknown" }, { status: "REVOKED" }, { expiresAt: new Date(now).toISOString() },
    { issuedAt: new Date(now + 10_000).toISOString() }, { expiresAt: new Date(now + 300_000).toISOString() },
    { blockHash: `0x${"0".repeat(64)}` }, { observedBlock: 0 }, { extra: "unsigned-extension" },
    { tenantId: "other-tenant" }, { operationClass: "READ_PUBLIC" }, { reportUrl: "https://attacker.invalid" },
  ]) assert.throws(() => verifyAdmissionSnapshot(signed({ ...base, ...change }), { ...context, now }));
  assert.throws(() => verifyAdmissionSnapshot({ ...envelope, snapshot: { ...base, observedBlock: 124 } }, { ...context, now }), /signature/);
  assert.throws(() => verifyAdmissionSnapshot({ snapshot: base }, { ...context, now }));
});

test("balanced fallback is read-only, short-lived, and cannot resurrect allow after a deny or malformed response", async () => {
  const options = { ...context, apiBaseUrl: "http://127.0.0.1:3101", timeoutMs: 100, now: () => now, operationClass: "READ_PRIVATE", admissionMode: "balanced" };
  const fresh = () => getSignedAdmission({ ...options, fetchImpl: async () => json(signed(base)) });
  const offline = async () => { throw new TypeError("fetch failed"); };
  assert.equal((await fresh()).cacheHit, false);
  assert.equal((await getSignedAdmission({ ...options, fetchImpl: offline })).cacheHit, true);
  assert.equal((await getSignedAdmission({ ...options, fetchImpl: async () => json({}, 503) })).cacheHit, true);
  await assert.rejects(getSignedAdmission({ ...options, apiToken: "different-test-credential", fetchImpl: offline }), /no matching signed cache/);
  await assert.rejects(getSignedAdmission({ ...options, operationClass: "READ_PUBLIC", fetchImpl: offline }), /no matching signed cache/);
  await assert.rejects(getSignedAdmission({ ...options, tenantId: "different-tenant", fetchImpl: offline }), /no matching signed cache/);
  await assert.rejects(getSignedAdmission({ ...options, admissionMode: "strict", fetchImpl: offline }), /fail closed/);
  await assert.rejects(getSignedAdmission({ ...options, operationClass: "FINANCIAL", fetchImpl: offline }), /fail closed/);
  await assert.rejects(getSignedAdmission({ ...options, now: () => now + 31_000, fetchImpl: offline }), /expired/);
  for (const response of [json({}, 403), json({}), new Response("x".repeat(65_537)), json(signed({ ...base, decision: "BLOCK", status: "REVOKED" }))]) {
    await fresh();
    await getSignedAdmission({ ...options, fetchImpl: async () => response }).catch(() => {});
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: offline }), /no matching signed cache/);
  }
});
