import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, open, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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
const isolated = (suffix) => ({ context: { ...context, tenantId: `test-${suffix}` }, base: { ...base, tenantId: `test-${suffix}` } });

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
  const { context, base } = isolated("fallback");
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

test("a concurrent late allow cannot return or repopulate cache after a newer denial or invalid response", async () => {
  const { context, base } = isolated("concurrent");
  const options = { ...context, apiBaseUrl: "http://127.0.0.1:3102", timeoutMs: 5000, now: () => now, cacheFile: null, admissionMode: "balanced" };
  const offline = async () => { throw new TypeError("synthetic offline"); };
  for (const response of [json(signed({ ...base, decision: "BLOCK", status: "QUARANTINED", reasonCode: "RELEASE_QUARANTINED" })), json({}), json({}, 403), new Response("not json"),
    new Response(new ReadableStream({ start(controller) { controller.error(new TypeError("synthetic body interruption")); } }), { status: 403 }),
    new Response(new ReadableStream({ start() {} }), { status: 403 })]) {
    let resume, started;
    const entered = new Promise(resolve => { started = resolve; });
    const late = getSignedAdmission({ ...options, fetchImpl: () => new Promise(resolve => { resume = () => resolve(json(signed(base))); started(); }) });
    await entered;
    await getSignedAdmission({ ...options, fetchImpl: async () => response }).catch(() => {});
    const rejected = assert.rejects(late, /superseded/); resume(); await rejected;
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: offline }), /no matching signed cache/);
  }
  const healthy = await Promise.all(Array.from({ length: 8 }, () => getSignedAdmission({ ...options, fetchImpl: async () => json(signed(base)) })));
  assert.ok(healthy.every(result => result.decision === "ALLOW" && !result.cacheHit), "Concurrent healthy reads must not invalidate each other");
});

test("4xx headers invalidate cached allow even when their body fails, stalls or exceeds the limit", async () => {
  const { context, base } = isolated("4xx");
  const options = { ...context, apiBaseUrl: "http://127.0.0.1:3104", timeoutMs: 20, now: () => now, cacheFile: null, admissionMode: "balanced" };
  const offline = async () => { throw new TypeError("synthetic offline"); };
  let cancelled = false;
  for (const body of [
    new ReadableStream({ start(controller) { controller.error(new TypeError("synthetic body interruption")); } }),
    new ReadableStream({ start() {}, cancel() { cancelled = true; } }),
    "x".repeat(65_537),
  ]) {
    await getSignedAdmission({ ...options, fetchImpl: async () => json(signed(base)) });
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => new Response(body, { status: 403 }) }), /returned 403/);
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: offline }), /no matching signed cache/);
  }
  assert.equal(cancelled, true);
  await getSignedAdmission({ ...options, fetchImpl: async () => json(signed(base)) });
  assert.equal((await getSignedAdmission({ ...options, fetchImpl: async () => new Response(new ReadableStream({ start() {} }), { status: 503 }) })).cacheHit, true);
});

test("persistent cache has one owner, never reclaims an unknown lock and respects another process's denial", async () => {
  const { context, base } = isolated("persistent");
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-signed-cache-test-"));
  assert.equal(dirname(directory), tmpdir());
  const cacheFile = join(directory, "admission.json");
  const options = { ...context, apiBaseUrl: "http://127.0.0.1:3103", timeoutMs: 5000, now: () => now, cacheFile, admissionMode: "balanced" };
  const offline = async () => { throw new TypeError("synthetic offline"); };
  try {
    let resume, started;
    const entered = new Promise(resolve => { started = resolve; });
    const first = getSignedAdmission({ ...options, fetchImpl: () => new Promise(resolve => { resume = () => resolve(json(signed(base))); started(); }) });
    await entered;
    let fetched = false;
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => { fetched = true; return json(signed(base)); } }), /cache is locked/);
    assert.equal(fetched, false); resume(); assert.equal((await first).decision, "ALLOW");
    assert.equal((await getSignedAdmission({ ...options, fetchImpl: offline })).cacheHit, true);
    const code = `import {readFileSync} from 'node:fs'; import {getSignedAdmission} from ${JSON.stringify(new URL('../src/signed-admission.mjs', import.meta.url).href)}; const x=JSON.parse(readFileSync(0,'utf8')); const result=await getSignedAdmission({...x.options,now:()=>x.now,fetchImpl:async()=>new Response(JSON.stringify(x.envelope))}); console.log(result.decision);`;
    const result = execFileSync(process.execPath, ["--input-type=module", "-e", code], { windowsHide: true, encoding: "utf8", timeout: 10000,
      input: JSON.stringify({ options: { ...options, now: undefined, publicKey: context.publicKey.toString() }, now,
        envelope: signed({ ...base, decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED" }) }) });
    assert.equal(result.trim(), "BLOCK"); assert.equal(await readFile(cacheFile, "utf8"), "null");
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: offline }), /no matching signed cache/);
    assert.equal(JSON.parse(await readFile(`${cacheFile}.revoked`, "utf8")).envelope.snapshot.status, "REVOKED");
    // The parent never observed the child's response. Its durable terminal record
    // must reject an otherwise valid old ALLOW, even on a later fresh HTTP request.
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => json(signed(base)) }), /previously revoked/);
    const later = now + 60_000, future = { ...base, issuedAt: new Date(later).toISOString(), expiresAt: new Date(later + 30_000).toISOString() };
    await assert.rejects(getSignedAdmission({ ...options, now: () => later, fetchImpl: async () => json(signed(future)) }), /previously revoked/);
    const orphan = await open(`${cacheFile}.lock`, "wx", 0o600); await orphan.close();
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: offline }), /cache is locked/);
    assert.equal(await readFile(`${cacheFile}.lock`, "utf8"), "", "A lock of unknown ownership must remain untouched");
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("terminal revocation rejects later re-signed allows across operation, credential and validator rotation", async () => {
  const { context, base } = isolated("terminal");
  const options = { ...context, apiBaseUrl: "http://127.0.0.1:3105", timeoutMs: 100, now: () => now, cacheFile: null };
  await getSignedAdmission({ ...options, fetchImpl: async () => json(signed(base)) });
  const denial = signed({ ...base, decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED" });
  assert.equal((await getSignedAdmission({ ...options, fetchImpl: async () => json(denial) })).decision, "BLOCK");
  for (const changed of [{}, { operationClass: "FINANCIAL" }, { apiToken: "rotated-test-credential" }, { validatorSetVersion: 2 }, { apiBaseUrl: "http://127.0.0.1:3106" }]) {
    const snapshot = { ...base, operationClass: changed.operationClass ?? base.operationClass, validatorSetVersion: changed.validatorSetVersion ?? base.validatorSetVersion };
    await assert.rejects(getSignedAdmission({ ...options, ...changed, fetchImpl: async () => json(signed(snapshot)) }), /previously revoked/);
  }
  // A different immutable policy is a different on-chain decision scope.
  const policyHash = `0x${"f".repeat(64)}`;
  assert.equal((await getSignedAdmission({ ...options, policyHash, fetchImpl: async () => json(signed({ ...base, policyHash })) })).decision, "ALLOW");
});

test("a failed cache invalidation retains its ownership lock instead of exposing the old allow", async () => {
  const { context, base } = isolated("persistence-failure");
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-cache-write-failure-"));
  assert.equal(dirname(directory), tmpdir());
  const cacheFile = join(directory, "invalid-directory-target"); await mkdir(cacheFile);
  const options = { ...context, apiBaseUrl: "http://127.0.0.1:3107", timeoutMs: 100, now: () => now, cacheFile };
  try {
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => json(signed(base)) }), /persistence failed/);
    assert.equal(await readFile(`${cacheFile}.lock`, "utf8"), "");
    let called = false;
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => { called = true; return json(signed(base)); } }), /cache is locked/);
    assert.equal(called, false);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
