import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import { Wallet, type HDNodeWallet } from "ethers";
import { buildApp } from "../../apps/api/src/app.js";
import { loadConfig } from "../../apps/api/src/config.js";
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
  assert.equal(replay.statusCode, 409);

  const second = await app.inject({ method: "POST", url: "/api/validators/vote",
    payload: await attestation(wallets[1], "mail-mcp@1.0.1", storedScan.scanId, "FAIL") });
  assert.equal(second.json().release.status, "REVOKED");
});

test("admission requires both hashes and allows only verified releases", async (t) => {
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
  const mismatch = await app.inject({ method: "POST", url: "/api/admission/check", payload: {
    schemaVersion: "1.0.0", releaseId: "mail-mcp@1.0.0", artifactDigest: digestA, toolSurfaceHash: `0x${"f".repeat(64)}`,
  } });
  assert.equal(mismatch.json().reasonCode, "DIGEST_MISMATCH");
});
