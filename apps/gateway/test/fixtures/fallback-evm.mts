import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Contract, JsonRpcProvider, NonceManager, Wallet } from "ethers";
import ganache from "ganache";
import { deployV2 } from "../../../../contracts/scripts/deploy-v2.ts";
import { attestationV2Domain, attestationV2Types, bytes32, createReleaseRegistryV2, exactReleaseIdentity } from "../../../../packages/contracts-sdk/src/v2.ts";
import { createArtifactSnapshot } from "../../src/artifact.mjs";
import { getSignedAdmission } from "../../src/signed-admission.mjs";

// Actual contracts and signatures, but ephemeral local Ganache accounts; not independent institutions.
const chain = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
await chain.listen(0, "127.0.0.1");
const directory = await mkdtemp(join(tmpdir(), "mcpshield-fallback-evm-")); assert.equal(dirname(directory), tmpdir());
const url = `http://127.0.0.1:${chain.address().port}`, provider = new JsonRpcProvider(url, undefined, { batchMaxCount: 1, cacheTimeout: -1 });
provider.pollingInterval = 20;
let snapshot;
try {
  const accounts = Object.values(chain.provider.getInitialAccounts()), voters = accounts.slice(1, 4).map(account => new Wallet(account.secretKey));
  const deployment = await deployV2(url, accounts[0].secretKey, voters.map(voter => voter.address), 1337);
  const owner = new NonceManager(new Wallet(accounts[0].secretKey, provider));
  const registry = createReleaseRegistryV2(deployment.releaseRegistry.address, owner);
  const policyRegistry = new Contract(deployment.policyRegistry.address, ["function publish(bytes32,bytes32)"], owner);
  const policyHash = `0x${"a".repeat(64)}`, alternatePolicy = `0x${"b".repeat(64)}`;
  for (const hash of [policyHash, alternatePolicy]) await (await policyRegistry.publish(hash, hash)).wait();
  snapshot = await createArtifactSnapshot(fileURLToPath(new URL("../../../../demo/fixtures/mail-mcp-1.0.0/", import.meta.url)));
  const identity = exactReleaseIdentity({ toolId: "npm:mail-mcp", ...snapshot });
  await (await registry.registerRelease(identity.toolId, bytes32(snapshot.artifactDigest), bytes32(snapshot.manifestDigest), bytes32(snapshot.toolSurfaceHash))).wait();
  const now = Math.floor(Date.now() / 1000), domain = attestationV2Domain(1337, deployment.releaseRegistry.address);
  const vote = async (policy: string, verdict: number, nonce: number) => {
    const payload = { releaseId: identity.releaseId, artifactDigest: bytes32(snapshot.artifactDigest), manifestDigest: bytes32(snapshot.manifestDigest),
      toolSurfaceDigest: bytes32(snapshot.toolSurfaceHash), policyHash: policy, reportRoot: policy, verdict, validFrom: now - 1, validUntil: now + 300,
      validatorSetVersion: 1, nonce, deadline: now + 300 };
    for (const voter of voters.slice(0, 2)) await (await registry.submitAttestation(payload, await voter.signTypedData(domain, attestationV2Types, payload))).wait();
  };
  await vote(policyHash, 0, 0);
  await chain.provider.request({ method: "evm_mine", params: [] });
  const keys = generateKeyPairSync("ed25519"), cacheFile = join(directory, "admission.json");
  const options = { identity: snapshot, controlReleaseId: identity.releaseId, policyHash, chainId: 1337, registryContract: deployment.releaseRegistry.address,
    validatorSetVersion: 1, tenantId: "local-evm-test", operationClass: "READ_PRIVATE", admissionMode: "strict", apiBaseUrl: "https://offline.invalid",
    timeoutMs: 100, apiToken: "synthetic-admission-test-only", publicKey: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), keyId: "synthetic-key",
    indexer: null, rpc: { rpcUrls: [url], confirmations: 2, timeoutMs: 1500 }, cacheFile,
    fetchImpl: async () => { throw new TypeError("synthetic API outage"); } };
  const allowed = await getSignedAdmission(options);
  assert.equal(allowed.decision, "ALLOW"); assert.equal(allowed.decisionSource, "DIRECT_RPC"); assert.equal(allowed.cacheHit, false);
  assert.equal(await readFile(cacheFile, "utf8"), "null");
  // Two FAIL votes under another policy globally revoke the same exact release.
  await vote(alternatePolicy, 1, 1);
  const blocked = await getSignedAdmission(options);
  assert.equal(blocked.decision, "BLOCK"); assert.equal(blocked.releaseStatus, "REVOKED"); assert.equal(blocked.decisionSource, "DIRECT_RPC");
  const marker = JSON.parse(await readFile(`${cacheFile}.revoked`, "utf8"));
  assert.equal(marker.schemaVersion, "mcpshield.rpc-revocation.v1"); assert.equal(marker.releaseId, identity.releaseId);
  console.log("REAL_LOCAL_EVM_FALLBACK_PASS");
} finally { await snapshot?.cleanup(); provider.destroy(); await chain.close(); await rm(directory, { recursive: true, force: true }); }
