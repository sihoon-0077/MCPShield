import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import { reconcileSubmittedOperations } from "../../apps/api/src/reconcile.js";
import type { RegistryClient } from "../../apps/api/src/registry-client.js";
import { Repository } from "../../apps/api/src/repository.js";

const digest = `sha256:${"a".repeat(64)}`;
const toolHash = `0x${"b".repeat(64)}`;
const evidenceHash = `0x${"c".repeat(64)}`;
const validator = "0x0000000000000000000000000000000000000001";

function fakeRegistry(receipt: "PENDING" | "SUCCESS" | "REVERTED"): RegistryClient {
  const chainRelease = async (releaseId: string) => ({ releaseId, artifactDigest: digest, toolSurfaceHash: toolHash, status: "REVOKED" as const });
  return { async getReceipt() { return receipt; },
    getRelease: chainRelease, findRelease: chainRelease,
    async getValidatorNonce() { return 1; }, async validateConnection() {},
    async hasVoted() { return true; },
    async getValidatorVote(releaseId, validatorAddress) { return { releaseId,
      validatorAddress, decision: "FAIL", evidenceHash, nonce: 0 }; },
    async registerRelease() { throw new Error("unused"); },
    async submitAttestation() { throw new Error("unused"); } };
}

test("reconciles confirmed registration and attestation idempotently", async () => {
  const repository = new Repository(":memory:");
  try {
    repository.createPendingOperation("register:test", "REGISTER_RELEASE", { releaseId: "mail-mcp@1.0.1" });
    repository.updatePendingOperation("register:test", "SUBMITTED", `0x${"1".repeat(64)}`);
    assert.deepEqual((await reconcileSubmittedOperations(repository, fakeRegistry("SUCCESS"))).completed, ["register:test"]);
    const scanId = randomUUID();
    repository.saveScan({ schemaVersion: "1.0.0", scanId, releaseId: "mail-mcp@1.0.1",
      artifactDigest: digest, toolSurfaceHash: toolHash, scanStatus: "FAILED", findings: [], evidenceHash, source: "LIVE" });
    repository.createPendingOperation("vote:test", "SUBMIT_ATTESTATION", { releaseId: "mail-mcp@1.0.1",
      validatorAddress: validator, scanId, decision: "FAIL", evidenceHash, nonce: 0,
      signature: `0x${"2".repeat(130)}` });
    repository.updatePendingOperation("vote:test", "SUBMITTED", `0x${"3".repeat(64)}`);
    assert.deepEqual((await reconcileSubmittedOperations(repository, fakeRegistry("SUCCESS"))).completed, ["vote:test"]);
    assert.equal(repository.hasVote("mail-mcp@1.0.1", validator), true);
    assert.equal(repository.getValidatorNonce(validator), 1);
    assert.deepEqual((await reconcileSubmittedOperations(repository, fakeRegistry("SUCCESS"))).completed, []);
  } finally { repository.close(); }
});

test("receipt pending and timeout preserve SUBMITTED state", async () => {
  const repository = new Repository(":memory:");
  try {
    repository.createPendingOperation("pending:test", "REGISTER_RELEASE", { releaseId: "mail-mcp@1.0.0" });
    repository.updatePendingOperation("pending:test", "SUBMITTED", `0x${"4".repeat(64)}`);
    assert.equal(repository.updatePendingOperation("pending:test", "FAILED", undefined, "late failure"), false);
    assert.equal(repository.getPendingOperation("pending:test")?.status, "SUBMITTED");
    assert.deepEqual((await reconcileSubmittedOperations(repository, fakeRegistry("PENDING"))).pending, ["pending:test"]);
    const timeout = fakeRegistry("SUCCESS");
    timeout.getReceipt = async () => { throw new Error("RPC_TIMEOUT:receipt"); };
    assert.deepEqual((await reconcileSubmittedOperations(repository, timeout)).pending, ["pending:test"]);
    assert.equal(repository.getPendingOperation("pending:test")?.status, "SUBMITTED");
  } finally { repository.close(); }
});

test("a stale crash claim has exactly one concurrent reclaimer and sender", async () => {
  const repository = new Repository(":memory:");
  try {
    repository.claimOperation("stale:test", "REGISTER_RELEASE", { releaseId: "mail-mcp@2.2.0" }, 1);
    await new Promise((resolve) => setTimeout(resolve, 5));
    let sendCount = 0;
    await Promise.all(Array.from({ length: 8 }, async () => {
      if (repository.reclaimStalePending("stale:test", 30_000)) sendCount += 1;
    }));
    assert.equal(sendCount, 1);
    assert.equal(repository.getPendingOperation("stale:test")?.stale, false);
  } finally { repository.close(); }
});
