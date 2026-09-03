import assert from "node:assert/strict";
import { test } from "node:test";
import ganache from "ganache";
import { JsonRpcProvider, Wallet } from "ethers";
import { buildApp } from "../../apps/api/src/app.js";
import { EvmRegistryClient } from "../../apps/api/src/registry-client.js";
import { Repository } from "../../apps/api/src/repository.js";
import { ChainIndexer } from "../../apps/indexer/src/indexer.js";
import { deployRegistry } from "../../contracts/scripts/deploy.js";
import { attestationDomain, attestationTypes, chainDecisions,
  createReleaseRegistry, releaseKey } from "../../packages/contracts-sdk/src/index.js";

test("EVM smoke survives indexer projection winning the API receipt race", async () => {
  const port = 32_000 + (process.pid % 1_000);
  const rpcUrl = `http://127.0.0.1:${port}`;
  const server = ganache.server({ logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 5 }, chain: { chainId: 31337 } });
  await server.listen(port);
  const accounts = Object.entries(server.provider.getInitialAccounts());
  const ownerKey = accounts[0][1].secretKey;
  const validatorAccounts = accounts.slice(1, 4);
  const validators = validatorAccounts.map(([address]) => address) as [string, string, string];
  const registry = await deployRegistry(rpcUrl, ownerKey, validators);
  const registryAddress = await registry.getAddress();
  const deploymentBlock = (await registry.deploymentTransaction()!.wait())!.blockNumber;
  const client = new EvmRegistryClient(rpcUrl, registryAddress, ownerKey, 10_000);
  const projection = new Repository(":memory:");
  const indexProvider = new JsonRpcProvider(rpcUrl);
  const indexer = new ChainIndexer(indexProvider,
    createReleaseRegistry(registryAddress, indexProvider), projection,
    registryAddress, deploymentBlock, 0, 2);
  let preprojectedRegistrations = 0;
  let preprojectedVotes = 0;
  const registerRelease = client.registerRelease.bind(client);
  client.registerRelease = async (...args) => {
    const tx = await registerRelease(...args);
    return { hash: tx.hash, wait: async () => {
      await tx.wait();
      await indexer.syncOnce();
      preprojectedRegistrations += 1;
    } };
  };
  const submitAttestation = client.submitAttestation.bind(client);
  client.submitAttestation = async (attestation) => {
    const tx = await submitAttestation(attestation);
    return { hash: tx.hash, wait: async () => {
      await tx.wait();
      await indexer.syncOnce();
      preprojectedVotes += 1;
    } };
  };
  const app = await buildApp({ repository: projection, validatorAddresses: validators,
    adminApiToken: "smoke_admin_token_32_characters", scannerApiToken: "smoke_scanner_token_32_chars",
    corsAllowlist: ["http://localhost:3000"], attestationChainId: 31337,
    attestationContract: registryAddress, registryClient: client });
  try {
    const releaseId = "smoke-mcp@1.0.0";
    const artifactDigest = `sha256:${"a".repeat(64)}`;
    const toolSurfaceHash = `0x${"b".repeat(64)}`;
    const evidenceHash = `0x${"c".repeat(64)}`;
    const scanId = "00000000-0000-4000-8000-000000000999";
    assert.equal((await app.inject({ method: "POST", url: "/api/releases",
      headers: { authorization: "Bearer smoke_admin_token_32_characters" },
      payload: { schemaVersion: "1.0.0", releaseId, artifactDigest, toolSurfaceHash } })).statusCode, 201);
    assert.equal((await app.inject({ method: "POST", url: "/api/scans",
      headers: { authorization: "Bearer smoke_scanner_token_32_chars" },
      payload: { schemaVersion: "1.0.0", scanId, releaseId, artifactDigest,
        toolSurfaceHash, scanStatus: "PASSED", findings: [], evidenceHash, source: "LIVE" } })).statusCode, 201);

    const deadline = Math.floor(Date.now() / 1000) + 300;
    for (const [, account] of validatorAccounts.slice(0, 2)) {
      const wallet = new Wallet(account.secretKey);
      const signature = await wallet.signTypedData(
        attestationDomain(31337, registryAddress), attestationTypes,
        { releaseKey: releaseKey(releaseId), decision: chainDecisions.PASS,
          evidenceHash, nonce: 0, deadline },
      );
      const response = await app.inject({ method: "POST", url: "/api/validators/vote",
        payload: { schemaVersion: "1.0.0", releaseId, scanId, decision: "PASS",
          evidenceHash, nonce: 0, deadline, signature } });
      assert.equal(response.statusCode, 201, response.body);
    }
    const admission = await app.inject({ method: "POST", url: "/api/admission/check",
      payload: { schemaVersion: "1.0.0", releaseId, artifactDigest, toolSurfaceHash } });
    assert.equal(admission.json().decision, "ALLOW");

    const maliciousId = "smoke-mcp@1.0.1";
    const maliciousScanId = "00000000-0000-4000-8000-000000001000";
    const maliciousEvidence = `0x${"d".repeat(64)}`;
    assert.equal((await app.inject({ method: "POST", url: "/api/releases",
      headers: { authorization: "Bearer smoke_admin_token_32_characters" },
      payload: { schemaVersion: "1.0.0", releaseId: maliciousId,
        artifactDigest, toolSurfaceHash } })).statusCode, 201);
    assert.equal((await app.inject({ method: "POST", url: "/api/scans",
      headers: { authorization: "Bearer smoke_scanner_token_32_chars" },
      payload: { schemaVersion: "1.0.0", scanId: maliciousScanId, releaseId: maliciousId,
        artifactDigest, toolSurfaceHash, scanStatus: "FAILED", findings: [],
        evidenceHash: maliciousEvidence, source: "LIVE" } })).statusCode, 201);
    for (const [, account] of validatorAccounts.slice(0, 2)) {
      const signature = await new Wallet(account.secretKey).signTypedData(
        attestationDomain(31337, registryAddress), attestationTypes,
        { releaseKey: releaseKey(maliciousId), decision: chainDecisions.FAIL,
          evidenceHash: maliciousEvidence, nonce: 1, deadline },
      );
      const response = await app.inject({ method: "POST", url: "/api/validators/vote",
        payload: { schemaVersion: "1.0.0", releaseId: maliciousId,
          scanId: maliciousScanId, decision: "FAIL", evidenceHash: maliciousEvidence,
          nonce: 1, deadline, signature } });
      assert.equal(response.statusCode, 201, response.body);
    }
    const blocked = await app.inject({ method: "POST", url: "/api/admission/check",
      payload: { schemaVersion: "1.0.0", releaseId: maliciousId,
        artifactDigest, toolSurfaceHash } });
    assert.equal(blocked.json().decision, "BLOCK");
    assert.equal(blocked.json().releaseStatus, "REVOKED");

    assert.equal(preprojectedRegistrations, 2);
    assert.equal(preprojectedVotes, 4);
    const events = projection.listEvents(releaseId);
    assert.equal(events.filter((event) => event.eventName === "ReleaseRegistered").length, 1);
    assert.equal(events.filter((event) => event.eventName === "VoteSubmitted").length, 2);
    assert.equal(events.some((event) => event.eventName === "StatusChanged" && event.status === "VERIFIED"), true);
    const maliciousEvents = projection.listEvents(maliciousId);
    assert.equal(maliciousEvents.filter((event) => event.eventName === "VoteSubmitted").length, 2);
    assert.equal(maliciousEvents.some((event) =>
      event.eventName === "StatusChanged" && event.status === "REVOKED"), true);
  } finally {
    await app.close();
    indexProvider.destroy();
    await server.close();
  }
});
