import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import { Wallet, type HDNodeWallet } from "ethers";
import { buildApp } from "../../apps/api/src/app.js";
import { loadConfig } from "../../apps/api/src/config.js";
import type { RegistryClient } from "../../apps/api/src/registry-client.js";
import { attestationDomain, attestationTypes, chainDecisions, releaseKey } from "../../packages/contracts-sdk/src/index.js";

const wallets = [Wallet.createRandom(), Wallet.createRandom(), Wallet.createRandom()];
const validators = wallets.map((wallet) => wallet.address);
const adminToken = "test-admin-token-secure";
const scannerToken = "test-scanner-token-secure";
const contract = "0x0000000000000000000000000000000000000042";
const digestA = `sha256:${"a".repeat(64)}`;
const toolHash = `0x${"b".repeat(64)}`;
const evidenceHash = `0x${"c".repeat(64)}`;

const options = {
  databasePath: ":memory:", validatorAddresses: validators, adminApiToken: adminToken,
  scannerApiToken: scannerToken,
  attestationChainId: 31337, attestationContract: contract,
};

test("startup configuration fails closed", () => {
  assert.throws(() => loadConfig({}));
  assert.throws(() => loadConfig({
    ADMIN_API_TOKEN: adminToken,
    SCANNER_API_TOKEN: scannerToken,
    CORS_ALLOWLIST: "http://localhost:3000",
    VALIDATOR_ADDRESSES: validators.join(","),
    ATTESTATION_CHAIN_ID: "31337",
    ATTESTATION_CONTRACT: contract,
    RPC_URL: "http://localhost:8545",
  }));
  assert.throws(() => loadConfig({
    ADMIN_API_TOKEN: "replace-with-admin-secret",
    SCANNER_API_TOKEN: scannerToken,
  }));
});

test("judge demo runs the fixed scanner, signed quorum, safe execution and pre-spawn block in an isolated session", async (t) => {
  const disabled = await buildApp(options); t.after(() => disabled.close());
  assert.equal((await disabled.inject({ method: "POST", url: "/api/demo/sessions" })).statusCode, 404);

  const app = await buildApp({ ...options, judgeDemo: true }); t.after(() => app.close());
  const first = await app.inject({ method: "POST", url: "/api/demo/sessions" });
  const second = await app.inject({ method: "POST", url: "/api/demo/sessions" });
  assert.equal(first.statusCode, 201);
  assert.equal(second.statusCode, 201);
  const sessionId = first.json().sessionId as string;
  assert.match(sessionId, /^[0-9a-f-]{36}$/);
  assert.notEqual(sessionId, second.json().sessionId);
  assert.equal((await app.inject({ method: "POST", url: `/api/demo/sessions/${sessionId}/actions`, payload: { action: "RUN_SAFE" } })).statusCode, 409);

  const actions = ["SCAN_SAFE", "VOTE_SAFE_A", "VOTE_SAFE_B", "RUN_SAFE", "SELECT_MALICIOUS", "SCAN_MALICIOUS", "VOTE_FAIL_A", "VOTE_FAIL_B", "RUN_MALICIOUS"];
  let state: any;
  for (const action of actions) {
    const response = await app.inject({ method: "POST", url: `/api/demo/sessions/${sessionId}/actions`, payload: { action } });
    assert.equal(response.statusCode, 200, response.body);
    state = response.json();
  }
  assert.equal(state.complete, true);
  assert.deepEqual(state.releases.map((release: any) => [release.scanStatus, release.status]), [["PASSED", "VERIFIED"], ["FAILED", "REVOKED"]]);
  assert.deepEqual(state.votes.map((vote: any) => vote.decision), ["PASS", "PASS", "FAIL", "FAIL"]);
  assert.equal(state.findings.some((finding: any) => finding.code === "CANARY_EXFILTRATION"), true);
  assert.equal(state.executions[0].decision, "ALLOW");
  assert.equal(state.executions[0].spawnAttempted, true);
  assert.deepEqual(state.executions[0].result, { ok: true, messages: [{ id: "demo-1", subject: "Welcome" }] });
  assert.deepEqual(state.executions[1], { releaseId: "mail-mcp@1.0.1", decision: "BLOCK", spawnAttempted: false, reasonCode: "RELEASE_REVOKED", at: state.executions[1].at });
  assert.equal((await app.inject({ method: "GET", url: `/api/demo/sessions/${second.json().sessionId}` })).json().step, 0);
  assert.equal((await app.inject({ method: "DELETE", url: `/api/demo/sessions/${sessionId}` })).statusCode, 204);
  assert.equal((await app.inject({ method: "GET", url: `/api/demo/sessions/${sessionId}` })).statusCode, 404);
});

async function register(app: Awaited<ReturnType<typeof buildApp>>, releaseId: string) {
  return app.inject({ method: "POST", url: "/api/releases",
    headers: { authorization: `Bearer ${adminToken}` },
    payload: { schemaVersion: "1.0.0", releaseId, artifactDigest: digestA, toolSurfaceHash: toolHash } });
}

async function scan(app: Awaited<ReturnType<typeof buildApp>>, releaseId: string) {
  const value = { schemaVersion: "1.0.0", scanId: randomUUID(), releaseId,
    artifactDigest: digestA, toolSurfaceHash: toolHash, scanStatus: "FAILED",
    findings: [], evidenceHash, source: "LIVE" };
  assert.equal((await app.inject({ method: "POST", url: "/api/scans",
    headers: { authorization: `Bearer ${scannerToken}` }, payload: value })).statusCode, 201);
  return value;
}

async function attestation(wallet: HDNodeWallet, releaseId: string, scanId: string, decision: "PASS" | "FAIL", nonce = 0, evidence = evidenceHash, deadline = Math.floor(Date.now() / 1000) + 300) {
  const signature = await wallet.signTypedData(attestationDomain(31337, contract), attestationTypes, {
    releaseKey: releaseKey(releaseId), decision: chainDecisions[decision], evidenceHash: evidence, nonce, deadline,
  });
  return { schemaVersion: "1.0.0", releaseId, scanId, decision, evidenceHash: evidence, nonce, deadline, signature };
}

test("protects release registration and validates canonical inputs", async (t) => {
  const app = await buildApp(options); t.after(() => app.close());
  const unauthorized = await app.inject({ method: "POST", url: "/api/releases", payload: {} });
  assert.equal(unauthorized.statusCode, 401);
  const malformed = await app.inject({ method: "POST", url: "/api/releases",
    headers: { authorization: `Bearer ${adminToken}` }, payload: {
      schemaVersion: "1.0.0", releaseId: "../bad@1.0.0", artifactDigest: digestA, toolSurfaceHash: toolHash,
    } });
  assert.equal(malformed.statusCode, 400);
  assert.equal((await register(app, "mail-mcp@1.0.0")).statusCode, 201);
});

test("concurrent registration retries have exactly one transaction sender", async () => {
  let sendCount = 0;
  let enter!: () => void;
  let release!: () => void;
  const entered = new Promise<void>((resolve) => { enter = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const fakeRegistry: RegistryClient = {
    async registerRelease() { sendCount += 1; enter(); await gate;
      return { hash: `0x${"9".repeat(64)}`, async wait() {} }; },
    async submitAttestation() { throw new Error("unused"); },
    async getRelease(releaseId) { return { releaseId, artifactDigest: digestA, toolSurfaceHash: toolHash, status: "UNVERIFIED" }; },
    async findRelease() { return undefined; }, async getValidatorNonce() { return 0; },
    async hasVoted() { return false; }, async getReceipt() { return "PENDING"; },
    async getValidatorVote() { return undefined; },
    async validateConnection() {},
  };
  const app = await buildApp({ ...options, registryClient: fakeRegistry });
  try {
    const request = { method: "POST" as const, url: "/api/releases",
      headers: { authorization: `Bearer ${adminToken}` }, payload: {
        schemaVersion: "1.0.0", releaseId: "mail-mcp@2.0.0",
        artifactDigest: digestA, toolSurfaceHash: toolHash } };
    const firstPromise = app.inject(request);
    await entered;
    const second = await app.inject(request);
    assert.equal(second.statusCode, 202);
    assert.equal(sendCount, 1);
    release();
    assert.equal((await firstPromise).statusCode, 201);
    const completedRetry = await app.inject(request);
    assert.equal(completedRetry.statusCode, 200);
    assert.equal(completedRetry.json().idempotent, true);
    assert.equal(sendCount, 1);
  } finally { await app.close(); }
});

test("concurrent attestation retries have exactly one relayer sender", async () => {
  let sendCount = 0;
  let enter!: () => void;
  let release!: () => void;
  const entered = new Promise<void>((resolve) => { enter = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const fakeRegistry: RegistryClient = {
    async registerRelease() { return { hash: `0x${"7".repeat(64)}`, async wait() {} }; },
    async submitAttestation() { sendCount += 1; enter(); await gate;
      return { hash: `0x${"8".repeat(64)}`, async wait() {} }; },
    async getRelease(releaseId) { return { releaseId, artifactDigest: digestA, toolSurfaceHash: toolHash, status: "QUARANTINED" }; },
    async findRelease(releaseId) { return this.getRelease(releaseId); },
    async getValidatorNonce() { return 1; }, async hasVoted() { return true; },
    async getValidatorVote() { return undefined; },
    async getReceipt() { return "PENDING"; }, async validateConnection() {},
  };
  const app = await buildApp({ ...options, registryClient: fakeRegistry });
  try {
    await register(app, "mail-mcp@2.1.0");
    const storedScan = await scan(app, "mail-mcp@2.1.0");
    const payload = await attestation(wallets[0], "mail-mcp@2.1.0", storedScan.scanId, "FAIL");
    const firstPromise = app.inject({ method: "POST", url: "/api/validators/vote", payload });
    await entered;
    const second = await app.inject({ method: "POST", url: "/api/validators/vote", payload });
    assert.equal(second.statusCode, 202);
    assert.equal(sendCount, 1);
    release();
    assert.equal((await firstPromise).statusCode, 201);
    const completedRetry = await app.inject({ method: "POST", url: "/api/validators/vote", payload });
    assert.equal(completedRetry.statusCode, 200);
    assert.equal(sendCount, 1);
  } finally { await app.close(); }
});

test("failed attestation retry rejects a different direct on-chain vote", async () => {
  const releaseId = "mail-mcp@2.3.0";
  let sendCount = 0;
  const fakeRegistry: RegistryClient = {
    async registerRelease() { return { hash: `0x${"5".repeat(64)}`, async wait() {} }; },
    async submitAttestation() { sendCount += 1; throw new Error("relay crashed"); },
    async getRelease(id) { return { releaseId: id, artifactDigest: digestA,
      toolSurfaceHash: toolHash, status: "UNVERIFIED" }; },
    async findRelease(id) { return this.getRelease(id); },
    async getValidatorNonce() { return 1; }, async hasVoted() { return true; },
    async getValidatorVote(id, validatorAddress) { return { releaseId: id,
      validatorAddress, decision: "PASS", evidenceHash: `0x${"d".repeat(64)}`, nonce: 0 }; },
    async getReceipt() { return "REVERTED"; }, async validateConnection() {},
  };
  const app = await buildApp({ ...options, registryClient: fakeRegistry });
  try {
    assert.equal((await register(app, releaseId)).statusCode, 201);
    const storedScan = await scan(app, releaseId);
    const payload = await attestation(wallets[0], releaseId, storedScan.scanId, "FAIL");
    assert.equal((await app.inject({ method: "POST", url: "/api/validators/vote", payload })).statusCode, 500);
    const retry = await app.inject({ method: "POST", url: "/api/validators/vote", payload });
    assert.equal(retry.statusCode, 409);
    assert.equal(retry.json().error.code, "CHAIN_VOTE_CONFLICT");
    assert.equal((await app.inject({ method: "POST", url: "/api/validators/vote", payload })).statusCode, 409);
    assert.equal(sendCount, 1);
  } finally {
    await app.close();
  }
});

test("scanner ingestion requires credentials, stamps LIVE, limits rate and body", async () => {
  const unauthorizedApp = await buildApp(options);
  try {
    const denied = await unauthorizedApp.inject({ method: "POST", url: "/api/scans", payload: {} });
    assert.equal(denied.statusCode, 401);
  } finally { await unauthorizedApp.close(); }

  const limitedApp = await buildApp({ ...options, scanRateLimit: 1 });
  try {
    await register(limitedApp, "mail-mcp@1.2.0");
    const value = { schemaVersion: "1.0.0", scanId: randomUUID(), releaseId: "mail-mcp@1.2.0",
      artifactDigest: digestA, toolSurfaceHash: toolHash, scanStatus: "PASSED",
      findings: [], evidenceHash, source: "REPLAY" };
    const accepted = await limitedApp.inject({ method: "POST", url: "/api/scans",
      headers: { authorization: `Bearer ${scannerToken}` }, payload: value });
    assert.equal(accepted.statusCode, 201);
    assert.equal(accepted.json().source, "LIVE");
    const throttled = await limitedApp.inject({ method: "POST", url: "/api/scans",
      headers: { authorization: `Bearer ${scannerToken}` }, payload: { ...value, scanId: randomUUID() } });
    assert.equal(throttled.statusCode, 429);
  } finally { await limitedApp.close(); }

  const boundedApp = await buildApp({ ...options, bodyLimit: 128 });
  try {
    const oversized = await boundedApp.inject({ method: "POST", url: "/api/scans",
      headers: { authorization: `Bearer ${scannerToken}`, "content-type": "application/json" },
      payload: JSON.stringify({ padding: "x".repeat(1000) }) });
    assert.equal(oversized.statusCode, 413);
  } finally { await boundedApp.close(); }
});

test("returns the latest scan for a release without a preconfigured scan ID", async (t) => {
  const app = await buildApp(options); t.after(() => app.close());
  const releaseId = "mail-mcp@1.2.1";
  await register(app, releaseId);
  assert.equal((await app.inject({ method: "GET",
    url: `/api/releases/${releaseId}/scans/latest` })).statusCode, 404);
  const first = await scan(app, releaseId);
  const second = { ...first, scanId: randomUUID(), scanStatus: "PASSED" as const };
  assert.equal((await app.inject({ method: "POST", url: "/api/scans",
    headers: { authorization: `Bearer ${scannerToken}` }, payload: second })).statusCode, 201);
  const latest = await app.inject({ method: "GET",
    url: `/api/releases/${releaseId}/scans/latest` });
  assert.equal(latest.statusCode, 200);
  assert.equal(latest.json().schemaVersion, "1.0.0");
  assert.equal(latest.json().scan.scanId, second.scanId);
  assert.equal((await app.inject({ method: "GET",
    url: "/api/releases/not-a-release/scans/latest" })).statusCode, 400);
});

test("accepts signed attestations, rejects impersonation/replay/evidence mismatch", async (t) => {
  const app = await buildApp(options); t.after(() => app.close());
  await register(app, "mail-mcp@1.0.1");
  const storedScan = await scan(app, "mail-mcp@1.0.1");

  const outsider = Wallet.createRandom();
  const forged = await app.inject({ method: "POST", url: "/api/validators/vote",
    payload: await attestation(outsider, "mail-mcp@1.0.1", storedScan.scanId, "FAIL") });
  assert.equal(forged.statusCode, 403);

  const wrongEvidence = `0x${"d".repeat(64)}`;
  const mismatch = await app.inject({ method: "POST", url: "/api/validators/vote",
    payload: await attestation(wallets[0], "mail-mcp@1.0.1", storedScan.scanId, "FAIL", 0, wrongEvidence) });
  assert.equal(mismatch.statusCode, 409);
  assert.equal(mismatch.json().error.code, "SCAN_EVIDENCE_MISMATCH");

  const firstPayload = await attestation(wallets[0], "mail-mcp@1.0.1", storedScan.scanId, "FAIL");
  const first = await app.inject({ method: "POST", url: "/api/validators/vote", payload: firstPayload });
  assert.equal(first.statusCode, 201); assert.equal(first.json().release.status, "QUARANTINED");
  const replay = await app.inject({ method: "POST", url: "/api/validators/vote", payload: firstPayload });
  assert.equal(replay.statusCode, 200);
  assert.equal(replay.json().idempotent, true);

  const second = await app.inject({ method: "POST", url: "/api/validators/vote",
    payload: await attestation(wallets[1], "mail-mcp@1.0.1", storedScan.scanId, "FAIL") });
  assert.equal(second.json().release.status, "REVOKED");
});

test("admission requires matching hashes and allows only verified releases", async (t) => {
  const app = await buildApp(options); t.after(() => app.close());
  await register(app, "mail-mcp@1.0.0");
  const storedScan = await scan(app, "mail-mcp@1.0.0");
  for (let index = 0; index < 2; index++) {
    const response = await app.inject({ method: "POST", url: "/api/validators/vote",
      payload: await attestation(wallets[index], "mail-mcp@1.0.0", storedScan.scanId, "PASS") });
    assert.equal(response.statusCode, 201);
  }
  const allowed = await app.inject({ method: "POST", url: "/api/admission/check", payload: {
    schemaVersion: "1.0.0", releaseId: "mail-mcp@1.0.0", artifactDigest: digestA, toolSurfaceHash: toolHash,
  } });
  assert.equal(allowed.json().decision, "ALLOW");
  for (const identity of [
    { artifactDigest: `sha256:${"f".repeat(64)}`, toolSurfaceHash: toolHash },
    { artifactDigest: digestA, toolSurfaceHash: `0x${"f".repeat(64)}` },
  ]) {
    const mismatch = await app.inject({ method: "POST", url: "/api/admission/check", payload: {
      schemaVersion: "1.0.0", releaseId: "mail-mcp@1.0.0", ...identity,
    } });
    assert.equal(mismatch.json().decision, "BLOCK");
    assert.equal(mismatch.json().reasonCode, "DIGEST_MISMATCH");
  }

  await register(app, "mail-mcp@1.0.1");
  const revokedScan = await scan(app, "mail-mcp@1.0.1");
  for (let index = 0; index < 2; index++) {
    await app.inject({ method: "POST", url: "/api/validators/vote",
      payload: await attestation(wallets[index], "mail-mcp@1.0.1", revokedScan.scanId, "FAIL", 1) });
  }
  const revoked = await app.inject({ method: "POST", url: "/api/admission/check", payload: {
    schemaVersion: "1.0.0", releaseId: "mail-mcp@1.0.1", artifactDigest: digestA, toolSurfaceHash: toolHash,
  } });
  assert.equal(revoked.json().decision, "BLOCK");
  assert.equal(revoked.json().reasonCode, "RELEASE_REVOKED");
});

test("admission fails closed when chain truth is unavailable", async (t) => {
  let unavailable = false;
  const registryClient: RegistryClient = {
    async registerRelease() { return { hash: `0x${"9".repeat(64)}`, async wait() {} }; },
    async getRelease(releaseId: string) {
      if (unavailable) throw new Error("RPC_TIMEOUT:getRelease");
      return { releaseId, artifactDigest: digestA, toolSurfaceHash: toolHash, status: "VERIFIED" as const };
    },
    async submitAttestation() { throw new Error("unused"); },
    async findRelease() { return undefined; },
    async getValidatorNonce() { return 0; },
    async hasVoted() { return false; },
    async getValidatorVote() { return undefined; },
    async getReceipt() { return "REVERTED"; },
    async validateConnection() {},
  };
  const app = await buildApp({ ...options, registryClient }); t.after(() => app.close());
  assert.equal((await register(app, "mail-mcp@1.0.2")).statusCode, 201);
  const allowed = await app.inject({ method: "POST", url: "/api/admission/check", payload: {
    schemaVersion: "1.0.0", releaseId: "mail-mcp@1.0.2", artifactDigest: digestA, toolSurfaceHash: toolHash,
  } });
  assert.equal(allowed.json().decision, "ALLOW");
  unavailable = true;

  const blocked = await app.inject({ method: "POST", url: "/api/admission/check", payload: {
    schemaVersion: "1.0.0", releaseId: "mail-mcp@1.0.2", artifactDigest: digestA, toolSurfaceHash: toolHash,
  } });
  assert.equal(blocked.json().decision, "BLOCK");
  assert.equal(blocked.json().reasonCode, "STATUS_UNAVAILABLE");
});
