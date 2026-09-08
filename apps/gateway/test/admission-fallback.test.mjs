import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { getSignedAdmission } from "../src/signed-admission.mjs";
import { createArtifactSnapshot } from "../src/artifact.mjs";
import { resolveArtifact } from "../../../services/resolver/src/resolver.mjs";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2-identity.mjs";
import { syntheticRpc, h } from "./fixtures/synthetic-rpc.mjs";

const primary = generateKeyPairSync("ed25519"), organization = generateKeyPairSync("ed25519"), time = Date.now();
const pem = keys => keys.publicKey.export({ type: "spki", format: "pem" }).toString();
const json = (body, status = 200) => new Response(JSON.stringify(body), { status });
const offline = async () => { throw new TypeError("synthetic offline"); };
function setup(name, rpc) {
  const identity = rpc?.identity ?? { releaseId: `0x${createHash("sha256").update(name).digest("hex")}`, artifactDigest: `sha256:${"a".repeat(64)}`, manifestDigest: `sha256:${"b".repeat(64)}`, toolSurfaceHash: h("c") };
  return { identity, publicKey: pem(primary), keyId: "primary-test-key", policyHash: h("d"), chainId: rpc?.chainId ?? 1337, registryContract: rpc?.registryContract ?? `0x${"1".repeat(40)}`,
    validatorSetVersion: 1, tenantId: "fallback-test", operationClass: "READ_PRIVATE", apiToken: "synthetic-primary-credential", apiBaseUrl: "https://primary.invalid",
    timeoutMs: 100, now: () => time, cacheFile: null, admissionMode: "balanced",
    indexer: { url: "https://organization.invalid", token: "synthetic-organization-credential", keyId: "org-test-key", publicKey: pem(organization) },
    rpc: rpc ? { rpcUrls: rpc.rpcUrls, confirmations: 2, timeoutMs: 500 } : null };
}
function signed(options, issuer = "API", changes = {}) {
  const snapshot = { schemaVersion: "1.0.0", keyId: issuer === "API" ? options.keyId : options.indexer.keyId,
    releaseId: options.identity.releaseId, artifactDigest: options.identity.artifactDigest, toolSurfaceHash: options.identity.toolSurfaceHash,
    decision: "ALLOW", status: "VERIFIED", reasonCode: "RELEASE_VERIFIED", reportUrl: `/v1/releases/${options.identity.releaseId}`,
    tenantId: options.tenantId, operationClass: options.operationClass, policyHash: options.policyHash, chainId: options.chainId,
    registryContract: options.registryContract, validatorSetVersion: options.validatorSetVersion, observedBlock: 2, blockHash: h("2"),
    issuedAt: new Date(time).toISOString(), expiresAt: new Date(time + 30_000).toISOString(), ...changes };
  const bytes = JSON.stringify(Object.fromEntries(Object.keys(snapshot).sort().map(key => [key, snapshot[key]])));
  return { snapshot, signature: sign(null, Buffer.from(bytes), (issuer === "API" ? primary : organization).privateKey).toString("base64url") };
}

test("fallback preserves cache-first order and separately pinned organization credentials and signatures", async () => {
  const options = setup("order"), calls = [];
  const fetchImpl = async (url, request) => {
    calls.push({ url, token: request.headers.authorization });
    return url.startsWith(options.apiBaseUrl) ? json({}, 503) : json(signed(options, "ORG_INDEXER"));
  };
  await getSignedAdmission({ ...options, fetchImpl: async () => json(signed(options)) });
  assert.equal((await getSignedAdmission({ ...options, fetchImpl })).decisionSource, "CACHE"); assert.equal(calls.length, 1);
  calls.length = 0;
  const result = await getSignedAdmission({ ...options, admissionMode: "strict", fetchImpl });
  assert.equal(result.decision, "ALLOW"); assert.equal(result.decisionSource, "ORG_INDEXER"); assert.equal(result.cacheHit, false);
  assert.deepEqual(calls.map(call => call.token), [`Bearer ${options.apiToken}`, `Bearer ${options.indexer.token}`]);
  assert.equal((await getSignedAdmission({ ...options, fetchImpl: offline })).decisionSource, "CACHE", "Org cache must authenticate with its own key");
  let fetched = false;
  await assert.rejects(getSignedAdmission({ ...options, indexer: { ...options.indexer, url: "http://public.invalid" }, fetchImpl: async () => { fetched = true; } }), /HTTPS/);
  assert.equal(fetched, false);
  await assert.rejects(getSignedAdmission({ ...options, indexer: { ...options.indexer, token: undefined }, fetchImpl: offline }), /INVALID_ORG_INDEXER_TRUST/);
});

test("explicit primary or indexer denials and malformed proofs never advance to another trust tier", async () => {
  const rpc = await syntheticRpc("no-bypass"), options = setup("no-bypass", rpc);
  try {
    for (const issuer of ["API", "ORG_INDEXER"]) {
      const valid = signed(options, issuer), forged = { ...valid, signature: "A".repeat(86) };
      for (const bad of [() => json({}, 403), () => json(null), () => json(false), () => json([]), () => json({}), () => json(forged),
        () => new Response("not-json"), () => new Response("x".repeat(65_537)), () => new Response(new ReadableStream({ start() {} }), { status: 403 })]) {
        let calls = 0;
        await assert.rejects(getSignedAdmission({ ...options, admissionMode: "strict", fetchImpl: async () => {
          calls++; return issuer === "ORG_INDEXER" && calls === 1 ? json({}, 503) : bad();
        } }));
        assert.equal(calls, issuer === "API" ? 1 : 2); assert.equal(rpc.requests.length, 0);
      }
      let calls = 0;
      const blocked = await getSignedAdmission({ ...options, admissionMode: "strict", fetchImpl: async () => {
        calls++; return issuer === "ORG_INDEXER" && calls === 1 ? json({}, 503) : json(signed(options, issuer, { decision: "BLOCK", status: "QUARANTINED", reasonCode: "RELEASE_QUARANTINED" }));
      } });
      assert.equal(blocked.decision, "BLOCK"); assert.equal(calls, issuer === "API" ? 1 : 2); assert.equal(rpc.requests.length, 0);
    }
  } finally { await rpc.close(); }
});

test("expired authentic cache advances tiers; an expired forgery still fails closed", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-fallback-expired-")); assert.equal(dirname(directory), tmpdir());
  try {
    for (const forged of [false, true]) {
      const options = { ...setup(`expiry-${forged}`), cacheFile: join(directory, `${forged}.json`) };
      await getSignedAdmission({ ...options, fetchImpl: async () => json(signed(options)) });
      if (forged) { const record = JSON.parse(await readFile(options.cacheFile, "utf8")); record.envelope.signature = "A".repeat(86); await writeFile(options.cacheFile, JSON.stringify(record)); }
      let calls = 0;
      const result = getSignedAdmission({ ...options, now: () => time + 31_000, fetchImpl: async () => {
        calls++; return calls === 1 ? json({}, 503) : json(signed(options, "ORG_INDEXER", { issuedAt: new Date(time + 31_000).toISOString(), expiresAt: new Date(time + 61_000).toISOString() }));
      } });
      if (forged) { await assert.rejects(result, /signature/); assert.equal(calls, 1); }
      else { assert.equal((await result).decisionSource, "ORG_INDEXER"); assert.equal(calls, 2); }
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

function assertRestartDenied(options, envelope) {
  const code = `import assert from 'node:assert/strict'; import{readFileSync}from'node:fs';import{getSignedAdmission}from ${JSON.stringify(new URL("../src/signed-admission.mjs", import.meta.url).href)};const x=JSON.parse(readFileSync(0,'utf8'));await assert.rejects(getSignedAdmission({...x.options,now:()=>x.time,fetchImpl:async()=>new Response(JSON.stringify(x.envelope))}),/previously revoked/);`;
  execFileSync(process.execPath, ["--input-type=module", "-e", code], { windowsHide: true, timeout: 10_000, encoding: "utf8", input: JSON.stringify({ options, envelope, time }) });
}

test("historical signed revocation in a cache is a terminal denial, not an expired allow miss", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-expired-revocation-")); assert.equal(dirname(directory), tmpdir());
  const options = { ...setup("expired-revocation"), cacheFile: join(directory, "admission.json") };
  try {
    await getSignedAdmission({ ...options, fetchImpl: async () => json(signed(options)) });
    const cached = JSON.parse(await readFile(options.cacheFile, "utf8"));
    cached.envelope = signed(options, "API", { decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED" });
    await writeFile(options.cacheFile, JSON.stringify(cached));
    let calls = 0;
    await assert.rejects(getSignedAdmission({ ...options, now: () => time + 31_000, fetchImpl: async () => { calls++; return json({}, 503); } }), /Cached admission does not allow/);
    assert.equal(calls, 1); assert.equal(JSON.parse(await readFile(`${options.cacheFile}.revoked`, "utf8")).envelope.snapshot.status, "REVOKED");
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => json(signed(options)) }), /previously revoked/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("organization revocation journal survives restart and cannot be replaced by a primary allow", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-indexer-revoked-")); assert.equal(dirname(directory), tmpdir());
  const options = { ...setup("org-revocation"), cacheFile: join(directory, "admission.json") };
  try {
    const blocked = await getSignedAdmission({ ...options, fetchImpl: async url => url.startsWith(options.apiBaseUrl) ? json({}, 503)
      : json(signed(options, "ORG_INDEXER", { decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED" })) });
    assert.equal(blocked.decision, "BLOCK"); assert.equal(blocked.decisionSource, "ORG_INDEXER");
    assert.equal(JSON.parse(await readFile(`${options.cacheFile}.revoked`, "utf8")).issuer, "ORG_INDEXER");
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => json(signed(options)) }), /previously revoked/);
    assertRestartDenied(options, signed(options));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("direct RPC is read-only, complete-identity only, never an allow cache and terminal on optimistic revocation", async () => {
  const rpc = await syntheticRpc("direct"), directory = await mkdtemp(join(tmpdir(), "mcpshield-rpc-revoked-")); assert.equal(dirname(directory), tmpdir());
  const options = { ...setup("direct", rpc), now: Date.now, cacheFile: join(directory, "admission.json"), fetchImpl: offline };
  try {
    let contextCalled = false;
    await assert.rejects(getSignedAdmission({ ...options, tenantId: undefined, fetchImpl: async () => { contextCalled = true; } }), /trust context/);
    assert.equal(contextCalled, false);
    for (const operationClass of ["WRITE_EXTERNAL", "DESTRUCTIVE", "FINANCIAL"]) await assert.rejects(getSignedAdmission({ ...options, operationClass }), /HIGH_RISK_NOT_APPROVED/);
    await assert.rejects(getSignedAdmission({ ...options, identity: { ...options.identity, manifestDigest: undefined } }), /COMPLETE_LOCAL_IDENTITY_REQUIRED/);
    assert.equal(rpc.requests.length, 0);
    const allowed = await getSignedAdmission(options);
    assert.equal(allowed.decision, "ALLOW"); assert.equal(allowed.decisionSource, "DIRECT_RPC"); assert.equal(allowed.source, "LIVE"); assert.equal(allowed.cacheHit, false);
    assert.equal(await readFile(options.cacheFile, "utf8"), "null");
    assert.ok(rpc.requests.every(request => request.authorization === undefined), "Admission tokens must never reach RPC");
    rpc.mode = "stale-head"; rpc.counts.clear(); await assert.rejects(getSignedAdmission(options), /STATUS_UNAVAILABLE/);
    rpc.mode = "revoked"; rpc.counts.clear(); const blocked = await getSignedAdmission(options);
    assert.equal(blocked.decision, "BLOCK"); assert.equal(blocked.releaseStatus, "REVOKED");
    const marker = JSON.parse(await readFile(`${options.cacheFile}.revoked`, "utf8"));
    assert.equal(marker.schemaVersion, "mcpshield.rpc-revocation.v1"); assert.equal(marker.observedBlock, 3);
    assert.equal(Object.hasOwn(marker, "signature"), false, "Local denial marker is not a signed chain proof");
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => json(signed(options)) }), /previously revoked/);
    assertRestartDenied(options, signed(options));
    await writeFile(`${options.cacheFile}.revoked`, JSON.stringify({ ...marker, blockHash: h("0") }));
    let fetched = false;
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => { fetched = true; return json(signed(options)); } }), /INVALID_LOCAL_RPC_REVOCATION/);
    assert.equal(fetched, false);
  } finally { await rpc.close(); await rm(directory, { recursive: true, force: true }); }
});

test("a cross-tenant indexer or RPC revocation wins against an already in-flight primary allow", async () => {
  for (const issuer of ["ORG_INDEXER", "DIRECT_RPC"]) {
    const rpc = await syntheticRpc(`race-${issuer}`), options = { ...setup(`race-${issuer}`, rpc), admissionMode: "strict", now: Date.now };
    let entered, resume;
    const reached = new Promise(resolve => { entered = resolve; });
    const late = getSignedAdmission({ ...options, fetchImpl: async () => { entered(); return new Promise(resolve => { resume = () => resolve(json(signed(options))); }); } })
      .then(value => ({ value }), error => ({ error }));
    try {
      await reached;
      const other = { ...options, tenantId: "another-tenant", policyHash: h("e") };
      rpc.mode = "revoked";
      const blocked = await getSignedAdmission({ ...other, indexer: issuer === "DIRECT_RPC" ? null : options.indexer,
        fetchImpl: async url => issuer === "DIRECT_RPC" || url.startsWith(options.apiBaseUrl) ? json({}, 503)
          : json(signed(other, "ORG_INDEXER", { decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED" })) });
      assert.equal(blocked.decision, "BLOCK"); assert.equal(blocked.decisionSource, issuer);
      resume(); const result = await late;
      assert.equal(result.value, undefined); assert.match(result.error?.message ?? "", /previously revoked|superseded/);
      await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => json(signed(options)) }), /previously revoked/);
    } finally { resume?.(); await late; await rpc.close(); }
  }
});

test("Gateway rejects explicit and environment RPC budgets above 1500ms before any request", async () => {
  const options = setup("rpc-budget"); let fetched = false;
  const fetchImpl = async () => { fetched = true; throw new TypeError("synthetic offline"); };
  for (const timeoutMs of [99, 1501, 5000]) await assert.rejects(getSignedAdmission({ ...options, fetchImpl,
    rpc: { rpcUrls: ["http://127.0.0.1:1"], timeoutMs } }), /DIRECT_RPC_TOTAL_BUDGET_INVALID/);
  const names = ["MCPSHIELD_RPC_URLS", "MCPSHIELD_RPC_TIMEOUT_MS"], previous = names.map(name => process.env[name]);
  try {
    process.env.MCPSHIELD_RPC_URLS = "http://127.0.0.1:1"; process.env.MCPSHIELD_RPC_TIMEOUT_MS = "1501";
    await assert.rejects(getSignedAdmission({ ...options, rpc: undefined, fetchImpl }), /DIRECT_RPC_TOTAL_BUDGET_INVALID/);
  } finally { names.forEach((name, index) => { if (previous[index] === undefined) delete process.env[name]; else process.env[name] = previous[index]; }); }
  assert.equal(fetched, false);
});

test("direct RPC alternatives share one total deadline and a fixed process quota", async t => {
  const rpc = await syntheticRpc("quota"), options = { ...setup("quota", rpc), admissionMode: "strict", indexer: null, fetchImpl: offline, now: Date.now };
  try {
    rpc.mode = "timeout";
    const start = performance.now();
    await assert.rejects(getSignedAdmission({ ...options, rpc: { rpcUrls: [1, 2, 3].map(number => `${rpc.rpcUrls[0]}/${number}`), confirmations: 2, timeoutMs: 100 } }), /STATUS_UNAVAILABLE/);
    assert.ok(performance.now() - start < 800, "Three providers must not each restart the total deadline");
    assert.ok(rpc.requests.length > 0 && rpc.requests.every(request => request.path === "/1"), "Deadline consumed by provider one must stop before providers two and three");
    rpc.mode = "valid";
    const frozen = performance.now() + 10000;
    t.mock.method(performance, "now", () => frozen); // Monotonic-clock double confined to this test process.
    for (let index = 0; index < 4; index++) { rpc.counts.clear(); assert.equal((await getSignedAdmission(options)).decisionSource, "DIRECT_RPC"); }
    const calls = rpc.requests.length;
    await assert.rejects(getSignedAdmission(options), /DIRECT_RPC_RATE_LIMITED/);
    assert.equal(rpc.requests.length, calls, "Quota exhaustion must stop before the transport");
  } finally { t.mock.restoreAll(); await rpc.close(); }
});

test("host fixture manifest digest matches Resolver exact source identity without trusting a remote digest", async () => {
  const path = fileURLToPath(new URL("../../../demo/fixtures/mail-mcp-1.0.0/", import.meta.url));
  const snapshot = await createArtifactSnapshot(path); let resolved;
  try {
    resolved = await resolveArtifact({ source: { type: "local", path } });
    for (const key of ["artifactDigest", "manifestDigest", "toolSurfaceHash"]) assert.equal(snapshot[key], resolved[key], key);
    assert.equal(exactReleaseIdentity({ toolId: resolved.toolId, ...snapshot }).releaseId, exactReleaseIdentity(resolved).releaseId);
  } finally { await snapshot.cleanup(); await resolved?.cleanup(); }
});

test("Gateway fallback executes the real V2 quorum and revocation on a local EVM", { timeout: 60_000 }, async () => {
  const { execFile } = await import("node:child_process"), { promisify } = await import("node:util");
  try {
    const result = await promisify(execFile)(process.execPath, ["--import", "tsx", fileURLToPath(new URL("./fixtures/fallback-evm.mts", import.meta.url))],
      { windowsHide: true, encoding: "utf8", timeout: 55_000, maxBuffer: 65536 });
    assert.match(result.stdout, /REAL_LOCAL_EVM_FALLBACK_PASS/);
  } catch (error) {
    assert.fail(String(error.stderr ?? "").match(/AssertionError[^:\n]*: ([^\r\n]+)/)?.[1] ?? `Local EVM fallback failed (exit ${error.code}, signal ${error.signal ?? "none"})`);
  }
});
