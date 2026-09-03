import type { ValidatorDecision } from "../../../packages/protocol/api/types.js";
import type { RegistryClient } from "./registry-client.js";
import { Repository } from "./repository.js";

export interface ReconcileSummary {
  completed: string[];
  failed: string[];
  pending: string[];
}

export async function reconcileSubmittedOperations(
  repository: Repository,
  registry: RegistryClient,
): Promise<ReconcileSummary> {
  const summary: ReconcileSummary = { completed: [], failed: [], pending: [] };
  for (const operation of repository.listSubmittedOperations()) {
    let receipt: "PENDING" | "SUCCESS" | "REVERTED";
    try {
      receipt = await registry.getReceipt(operation.txHash);
    } catch (error) {
      if (String(error).includes("RPC_TIMEOUT")) {
        summary.pending.push(operation.operationId);
        continue;
      }
      throw error;
    }
    if (receipt === "PENDING") {
      summary.pending.push(operation.operationId);
      continue;
    }
    if (receipt === "REVERTED") {
      repository.updatePendingOperation(operation.operationId, "FAILED", operation.txHash, "TX_REVERTED");
      summary.failed.push(operation.operationId);
      continue;
    }

    const payload = operation.payload;
    const releaseId = String(payload.releaseId);
    const chainRelease = await registry.getRelease(releaseId);
    if (operation.operationType === "REGISTER_RELEASE") {
      repository.upsertReleaseFromChain(chainRelease);
    } else if (operation.operationType === "SUBMIT_ATTESTATION") {
      const validatorAddress = String(payload.validatorAddress).toLowerCase();
      const chainNonce = await registry.getValidatorNonce(validatorAddress);
      repository.reconcileVoteFromChain({
        releaseId,
        validatorAddress,
        decision: payload.decision as ValidatorDecision,
        evidenceHash: String(payload.evidenceHash),
        scanId: String(payload.scanId),
        nonce: Number(payload.nonce),
        signature: String(payload.signature),
        txHash: operation.txHash,
      }, chainRelease.status, chainNonce);
    } else {
      repository.updatePendingOperation(operation.operationId, "FAILED", operation.txHash, "UNKNOWN_OPERATION");
      summary.failed.push(operation.operationId);
      continue;
    }
    repository.updatePendingOperation(operation.operationId, "COMPLETED", operation.txHash);
    summary.completed.push(operation.operationId);
  }
  return summary;
}
