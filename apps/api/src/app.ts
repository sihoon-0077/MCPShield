import { timingSafeEqual } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import { id, verifyTypedData } from "ethers";
import {
  attestationDomain,
  attestationTypes,
  chainDecisions,
  releaseKey,
} from "../../../packages/contracts-sdk/src/index.js";
import {
  SCHEMA_VERSION,
  type AdmissionDecision,
  type ValidatorDecision,
} from "../../../packages/protocol/api/types.js";
import { Repository } from "./repository.js";
import { patterns, validateScanResult } from "./validation.js";
import type { RegistryClient } from "./registry-client.js";

const defaultValidators = [
  "0x0000000000000000000000000000000000000001",
  "0x0000000000000000000000000000000000000002",
  "0x0000000000000000000000000000000000000003",
];

export interface AppOptions {
  adminApiToken: string;
  scannerApiToken: string;
  databasePath?: string;
  validatorAddresses?: string[];
  logger?: boolean;
  registryClient?: RegistryClient;
  corsAllowlist?: string[];
  attestationChainId?: number;
  attestationContract?: string;
  bodyLimit?: number;
  scanRateLimit?: number;
  operationLeaseMs?: number;
  repository?: Repository;
}

function errorBody(code: string, message: string, details?: unknown) {
  return { schemaVersion: SCHEMA_VERSION, error: { code, message, details } };
}

function tokenMatches(header: string | undefined, expected: string) {
  const provided = header?.startsWith("Bearer ") ? header.slice(7) : "";
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function buildApp(options: AppOptions): Promise<FastifyInstance> {
  const app = Fastify({
    logger: options.logger ?? false,
    bodyLimit: options.bodyLimit ?? 262_144,
  });
  const allowlist = new Set(options.corsAllowlist ?? ["http://localhost:3000"]);
  await app.register(cors, {
    origin(origin, callback) {
      callback(null, !origin || allowlist.has(origin));
    },
  });
  await app.register(rateLimit, { global: false });
  const repository = options.repository ?? new Repository(options.databasePath ?? ":memory:");
  const validators = new Set(
    (options.validatorAddresses ?? defaultValidators).map((address) => address.toLowerCase()),
  );
  const adminToken = options.adminApiToken;
  const operationLeaseMs = options.operationLeaseMs ?? 30_000;
  const domain = attestationDomain(
    options.attestationChainId ?? 31337,
    options.attestationContract ?? "0x0000000000000000000000000000000000000001",
  );

  app.addHook("onClose", async () => repository.close());

  app.get("/health", async () => ({
    schemaVersion: SCHEMA_VERSION,
    status: "ok",
    ledgerMode: options.registryClient ? "EVM" : "LOCAL_DEMO",
  }));

  app.post("/api/releases", async (request, reply) => {
    if (!tokenMatches(request.headers.authorization, adminToken)) {
      return reply.code(401).send(errorBody("UNAUTHORIZED", "Admin bearer token required"));
    }
    const body = request.body as Record<string, unknown> | null;
    if (
      !body || body.schemaVersion !== SCHEMA_VERSION ||
      typeof body.releaseId !== "string" || !patterns.releaseId.test(body.releaseId) ||
      typeof body.artifactDigest !== "string" || !patterns.artifactDigest.test(body.artifactDigest) ||
      typeof body.toolSurfaceHash !== "string" || !patterns.bytes32.test(body.toolSurfaceHash)
    ) {
      return reply.code(400).send(errorBody("INVALID_RELEASE", "Release payload does not match contract v1"));
    }
    const operationId = `register:${body.releaseId}`;
    let claim = repository.claimOperation(operationId, "REGISTER_RELEASE", body, operationLeaseMs);
    if (!claim.claimed) {
      const existing = claim.operation;
      if (
        existing.payload.artifactDigest !== body.artifactDigest ||
        existing.payload.toolSurfaceHash !== body.toolSurfaceHash
      ) return reply.code(409).send(errorBody("IDEMPOTENCY_CONFLICT", "Release retry payload changed"));
      if (existing.status === "COMPLETED") {
        return reply.code(200).send({ schemaVersion: SCHEMA_VERSION,
          release: repository.getRelease(body.releaseId), txHash: existing.txHash, idempotent: true });
      }
      if (existing.status === "SUBMITTED" || (existing.status === "PENDING" && !existing.stale)) {
        return reply.code(202).send({ schemaVersion: SCHEMA_VERSION,
          operation: { operationId, status: existing.status, txHash: existing.txHash } });
      }
      if (!options.registryClient) {
        return reply.code(409).send(errorBody("CHAIN_TRUTH_UNAVAILABLE", "Cannot retry failed operation without chain truth"));
      }
      try {
        if (existing.status === "PENDING") {
          const chainRelease = await options.registryClient.findRelease(body.releaseId);
          if (chainRelease) {
            repository.upsertReleaseFromChain(chainRelease);
            repository.updatePendingOperation(operationId, "COMPLETED");
            return reply.code(200).send({ schemaVersion: SCHEMA_VERSION,
              release: repository.getRelease(body.releaseId), idempotent: true });
          }
          if (!repository.reclaimStalePending(operationId, operationLeaseMs)) {
            return reply.code(202).send({ schemaVersion: SCHEMA_VERSION,
              operation: repository.getPendingOperation(operationId) });
          }
          claim = { claimed: true, operation: repository.getPendingOperation(operationId)! };
        } else {
          const receipt = existing.txHash
            ? await options.registryClient.getReceipt(existing.txHash)
            : "REVERTED";
          if (receipt === "PENDING") return reply.code(202).send({ schemaVersion: SCHEMA_VERSION,
            operation: { operationId, status: "SUBMITTED", txHash: existing.txHash } });
          let chainRelease = await options.registryClient.findRelease(body.releaseId);
          if (receipt === "SUCCESS" || chainRelease) {
            if (!chainRelease) chainRelease = await options.registryClient.getRelease(body.releaseId);
            repository.upsertReleaseFromChain(chainRelease);
            repository.completeFailedOperation(operationId, existing.txHash);
            return reply.code(200).send({ schemaVersion: SCHEMA_VERSION,
              release: repository.getRelease(body.releaseId), txHash: existing.txHash, idempotent: true });
          }
          if (!repository.retryFailedOperation(operationId, operationLeaseMs)) {
            return reply.code(202).send({ schemaVersion: SCHEMA_VERSION,
              operation: repository.getPendingOperation(operationId) });
          }
          claim = { claimed: true, operation: repository.getPendingOperation(operationId)! };
        }
      } catch (error) {
        return reply.code(503).send(errorBody("CHAIN_TRUTH_UNAVAILABLE", "Failed operation was not retried", String(error)));
      }
    }
    if (repository.getRelease(body.releaseId)) {
      repository.updatePendingOperation(operationId, "COMPLETED");
      return reply.code(200).send({ schemaVersion: SCHEMA_VERSION,
        release: repository.getRelease(body.releaseId), idempotent: true });
    }
    let submittedTxHash: string | undefined;
    try {
      const tx = await options.registryClient?.registerRelease(
        body.releaseId, body.artifactDigest, body.toolSurfaceHash,
      );
      if (tx) {
        submittedTxHash = tx.hash;
        repository.updatePendingOperation(operationId, "SUBMITTED", tx.hash);
        await tx.wait();
      }
      let release;
      if (tx && options.registryClient) {
        const chainRelease = await options.registryClient.getRelease(body.releaseId);
        repository.upsertReleaseFromChain({ ...chainRelease, registrationTxHash: tx.hash });
        release = repository.getRelease(body.releaseId)!;
      } else {
        release = repository.createRelease({
          releaseId: body.releaseId,
          artifactDigest: body.artifactDigest,
          toolSurfaceHash: body.toolSurfaceHash,
        });
      }
      repository.updatePendingOperation(operationId, "COMPLETED", tx?.hash);
      return reply.code(201).send({ schemaVersion: SCHEMA_VERSION, release, txHash: tx?.hash });
    } catch (error) {
      if (!String(error).includes("RPC_TIMEOUT:registerReleaseReceipt")) {
        repository.updatePendingOperation(operationId, "FAILED", submittedTxHash, String(error));
      }
      throw error;
    }
  });

  app.get("/api/releases/:releaseId", async (request, reply) => {
    const { releaseId } = request.params as { releaseId: string };
    if (!patterns.releaseId.test(releaseId)) {
      return reply.code(400).send(errorBody("INVALID_RELEASE_ID", "Release ID is not canonical"));
    }
    const release = repository.getRelease(releaseId);
    return release
      ? { schemaVersion: SCHEMA_VERSION, release }
      : reply.code(404).send(errorBody("RELEASE_NOT_FOUND", "Release was not found"));
  });

  app.post("/api/scans", {
    config: { rateLimit: { max: options.scanRateLimit ?? 30, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    if (!tokenMatches(request.headers.authorization, options.scannerApiToken)) {
      return reply.code(401).send(errorBody("UNAUTHORIZED_SCANNER", "Scanner credential required"));
    }
    const trustedInput = {
      ...(request.body as Record<string, unknown>),
      source: "LIVE",
    };
    const validation = validateScanResult(trustedInput);
    if (!validation.valid || !patterns.releaseId.test((request.body as any)?.releaseId ?? "")) {
      return reply.code(400).send(errorBody(
        "INVALID_SCAN_RESULT", "Scan result failed schema validation",
        validation.valid ? [{ message: "releaseId is not canonical" }] : validation.errors,
      ));
    }
    try {
      repository.saveScan(validation.value);
      return reply.code(201).send(validation.value);
    } catch (error) {
      const code = error instanceof Error ? error.message : "SCAN_STORE_FAILED";
      if (code === "RELEASE_NOT_FOUND") return reply.code(404).send(errorBody(code, "Register the release before its scan"));
      if (code === "RELEASE_HASH_MISMATCH") return reply.code(409).send(errorBody(code, "Scan hashes do not match the release"));
      if (String(error).includes("UNIQUE constraint failed")) return reply.code(409).send(errorBody("SCAN_EXISTS", "Scan ID already exists"));
      throw error;
    }
  });

  app.get("/api/scans/:scanId", async (request, reply) => {
    const { scanId } = request.params as { scanId: string };
    const scan = repository.getScan(scanId);
    return scan ?? reply.code(404).send(errorBody("SCAN_NOT_FOUND", "Scan was not found"));
  });

  app.get("/api/releases/:releaseId/scans/latest", async (request, reply) => {
    const { releaseId } = request.params as { releaseId: string };
    if (!patterns.releaseId.test(releaseId)) {
      return reply.code(400).send(errorBody("INVALID_RELEASE_ID", "Release ID is not canonical"));
    }
    const scan = repository.getLatestScan(releaseId);
    return scan
      ? { schemaVersion: SCHEMA_VERSION, scan }
      : reply.code(404).send(errorBody("SCAN_NOT_FOUND", "No scan was found for this release"));
  });

  app.post("/api/validators/vote", async (request, reply) => {
    const body = request.body as Record<string, unknown> | null;
    const decision = body?.decision as ValidatorDecision;
    if (
      !body || body.schemaVersion !== SCHEMA_VERSION ||
      typeof body.releaseId !== "string" || !patterns.releaseId.test(body.releaseId) ||
      typeof body.scanId !== "string" || !patterns.uuid.test(body.scanId) ||
      !["PASS", "FAIL", "ABSTAIN"].includes(decision) ||
      typeof body.evidenceHash !== "string" || !patterns.bytes32.test(body.evidenceHash) ||
      !Number.isSafeInteger(body.nonce) || (body.nonce as number) < 0 ||
      !Number.isSafeInteger(body.deadline) || (body.deadline as number) < 0 ||
      typeof body.signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(body.signature)
    ) {
      return reply.code(400).send(errorBody("INVALID_ATTESTATION", "Signed attestation is invalid or expired"));
    }

    let validatorAddress: string;
    try {
      validatorAddress = verifyTypedData(domain, attestationTypes, {
        releaseKey: releaseKey(body.releaseId),
        decision: chainDecisions[decision],
        evidenceHash: body.evidenceHash,
        nonce: body.nonce,
        deadline: body.deadline,
      }, body.signature).toLowerCase();
    } catch {
      return reply.code(400).send(errorBody("INVALID_SIGNATURE", "Attestation signature cannot be recovered"));
    }
    if (!validators.has(validatorAddress)) {
      return reply.code(403).send(errorBody("NOT_VALIDATOR", "Recovered signer is not a validator"));
    }
    const operationId = `attestation:${id(body.signature)}`;
    const operationPayload = { ...body, validatorAddress };
    const claim = repository.claimOperation(
      operationId, "SUBMIT_ATTESTATION", operationPayload, operationLeaseMs,
    );
    if (!claim.claimed) {
      const existing = claim.operation;
      if (existing.status === "COMPLETED") {
        return reply.code(200).send({ schemaVersion: SCHEMA_VERSION,
          release: repository.getRelease(body.releaseId), validatorAddress,
          txHash: existing.txHash, idempotent: true });
      }
      if (existing.status === "SUBMITTED" || (existing.status === "PENDING" && !existing.stale)) {
        return reply.code(202).send({ schemaVersion: SCHEMA_VERSION,
          operation: { operationId, status: existing.status, txHash: existing.txHash } });
      }
      if (!options.registryClient) {
        return reply.code(409).send(errorBody("CHAIN_TRUTH_UNAVAILABLE", "Cannot retry failed operation without chain truth"));
      }
      try {
        const receipt = existing.status === "FAILED" && existing.txHash
          ? await options.registryClient.getReceipt(existing.txHash)
          : "REVERTED";
        if (receipt === "PENDING") return reply.code(202).send({ schemaVersion: SCHEMA_VERSION,
          operation: { operationId, status: "SUBMITTED", txHash: existing.txHash } });
        const chainVote = await options.registryClient.getValidatorVote(body.releaseId, validatorAddress);
        if (chainVote) {
          const chainRelease = await options.registryClient.getRelease(body.releaseId);
          const chainNonce = await options.registryClient.getValidatorNonce(validatorAddress);
          const matches = chainVote.releaseId === body.releaseId &&
            chainVote.validatorAddress.toLowerCase() === validatorAddress &&
            chainVote.decision === decision &&
            chainVote.evidenceHash.toLowerCase() === body.evidenceHash.toLowerCase() &&
            chainVote.nonce === body.nonce;
          if (matches) {
            repository.reconcileVoteFromChain({ releaseId: body.releaseId, validatorAddress,
              decision, evidenceHash: body.evidenceHash, scanId: body.scanId,
              nonce: body.nonce as number, signature: body.signature, txHash: existing.txHash },
            chainRelease.status, chainNonce);
            if (existing.status === "FAILED") repository.completeFailedOperation(operationId, existing.txHash);
            else repository.updatePendingOperation(operationId, "COMPLETED", existing.txHash);
            return reply.code(200).send({ schemaVersion: SCHEMA_VERSION,
              release: repository.getRelease(body.releaseId), validatorAddress,
              txHash: existing.txHash, idempotent: true });
          }
          repository.reconcileObservedVoteFromChain({ ...chainVote, txHash: existing.txHash },
            chainRelease.status, chainNonce);
          repository.failOperationAsConflict(operationId, "CHAIN_VOTE_CONFLICT");
          return reply.code(409).send(errorBody(
            "CHAIN_VOTE_CONFLICT", "On-chain validator vote differs from this attestation",
            { chainVote },
          ));
        }
        if (receipt === "SUCCESS") {
          return reply.code(503).send(errorBody(
            "CHAIN_TRUTH_UNAVAILABLE", "Confirmed transaction has no queryable validator vote",
          ));
        }
        const reclaimed = existing.status === "PENDING"
          ? repository.reclaimStalePending(operationId, operationLeaseMs)
          : repository.retryFailedOperation(operationId, operationLeaseMs);
        if (!reclaimed) {
          return reply.code(202).send({ schemaVersion: SCHEMA_VERSION,
            operation: repository.getPendingOperation(operationId) });
        }
      } catch (error) {
        return reply.code(503).send(errorBody("CHAIN_TRUTH_UNAVAILABLE", "Failed operation was not retried", String(error)));
      }
    }
    if ((body.deadline as number) <= Math.floor(Date.now() / 1000)) {
      repository.updatePendingOperation(operationId, "FAILED", undefined, "ATTESTATION_EXPIRED");
      return reply.code(400).send(errorBody("ATTESTATION_EXPIRED", "Attestation deadline has passed"));
    }
    if (repository.hasVote(body.releaseId, validatorAddress)) {
      repository.updatePendingOperation(operationId, "FAILED", undefined, "DUPLICATE_VOTE");
      return reply.code(409).send(errorBody("DUPLICATE_VOTE", "Validator already voted"));
    }
    try {
      repository.validateVote({
        releaseId: body.releaseId,
        validatorAddress,
        scanId: body.scanId,
        evidenceHash: body.evidenceHash,
        nonce: body.nonce as number,
      });
    } catch (error) {
      const code = error instanceof Error ? error.message : "ATTESTATION_FAILED";
      repository.updatePendingOperation(operationId, "FAILED", undefined, code);
      return reply.code(409).send(errorBody(code, "Attestation does not match current release state"));
    }

    let submittedTxHash: string | undefined;
    try {
      const attestation = {
        releaseId: body.releaseId,
        decision,
        evidenceHash: body.evidenceHash,
        nonce: body.nonce as number,
        deadline: body.deadline as number,
        signature: body.signature,
      };
      const tx = await options.registryClient?.submitAttestation(attestation);
      if (tx) {
        submittedTxHash = tx.hash;
        repository.updatePendingOperation(operationId, "SUBMITTED", tx.hash);
        await tx.wait();
      }
      let release;
      if (tx && options.registryClient) {
        const [chainRelease, chainNonce] = await Promise.all([
          options.registryClient.getRelease(body.releaseId),
          options.registryClient.getValidatorNonce(validatorAddress),
        ]);
        repository.reconcileVoteFromChain({ ...attestation, scanId: body.scanId,
          validatorAddress, txHash: tx.hash }, chainRelease.status, chainNonce);
        release = repository.getRelease(body.releaseId)!;
      } else {
        release = repository.recordVote({ ...attestation, scanId: body.scanId,
          validatorAddress });
      }
      repository.updatePendingOperation(operationId, "COMPLETED", tx?.hash);
      return reply.code(201).send({ schemaVersion: SCHEMA_VERSION, release, validatorAddress, txHash: tx?.hash });
    } catch (error) {
      if (!String(error).includes("RPC_TIMEOUT:attestationReceipt")) {
        repository.updatePendingOperation(operationId, "FAILED", submittedTxHash, String(error));
      }
      const code = error instanceof Error ? error.message : "ATTESTATION_FAILED";
      if (["RELEASE_NOT_FOUND", "SCAN_EVIDENCE_MISMATCH"].includes(code)) return reply.code(409).send(errorBody(code, "Attestation does not match a stored release scan"));
      if (code === "INVALID_NONCE") return reply.code(409).send(errorBody(code, "Attestation nonce is stale or skipped"));
      if (code === "RELEASE_REVOKED") return reply.code(409).send(errorBody(code, "Revocation is terminal"));
      throw error;
    }
  });

  app.post("/api/admission/check", async (request, reply) => {
    const body = request.body as Record<string, unknown> | null;
    if (
      !body || body.schemaVersion !== SCHEMA_VERSION ||
      typeof body.releaseId !== "string" || !patterns.releaseId.test(body.releaseId) ||
      typeof body.artifactDigest !== "string" || !patterns.artifactDigest.test(body.artifactDigest) ||
      typeof body.toolSurfaceHash !== "string" || !patterns.bytes32.test(body.toolSurfaceHash)
    ) return reply.code(400).send(errorBody("INVALID_ADMISSION_REQUEST", "Request is not canonical"));

    let release = repository.getRelease(body.releaseId);
    let chainAvailable = true;
    let chainMismatch = false;
    if (release && options.registryClient) {
      try {
        const chain = await options.registryClient.getRelease(body.releaseId);
        chainMismatch =
          chain.releaseId !== release.releaseId ||
          chain.artifactDigest !== release.artifactDigest ||
          chain.toolSurfaceHash !== release.toolSurfaceHash ||
          chain.artifactDigest !== body.artifactDigest ||
          chain.toolSurfaceHash !== body.toolSurfaceHash;
        repository.setProjectedStatus(body.releaseId, chain.status);
        release = repository.getRelease(body.releaseId);
      } catch {
        chainAvailable = false;
      }
    }

    let decision: AdmissionDecision;
    if (!release || !chainAvailable) {
      decision = { schemaVersion: SCHEMA_VERSION, releaseId: body.releaseId, decision: "BLOCK", releaseStatus: release?.status ?? "UNVERIFIED", reasonCode: "STATUS_UNAVAILABLE", checkedAt: new Date().toISOString(), source: "LIVE" };
    } else if (
      chainMismatch || release.artifactDigest !== body.artifactDigest ||
      release.toolSurfaceHash !== body.toolSurfaceHash
    ) {
      decision = { schemaVersion: SCHEMA_VERSION, releaseId: body.releaseId, decision: "BLOCK", releaseStatus: release.status, reasonCode: "DIGEST_MISMATCH", checkedAt: new Date().toISOString(), source: "LIVE" };
    } else {
      const allow = release.status === "VERIFIED";
      decision = { schemaVersion: SCHEMA_VERSION, releaseId: body.releaseId, decision: allow ? "ALLOW" : "BLOCK", releaseStatus: release.status, reasonCode: `RELEASE_${release.status}` as AdmissionDecision["reasonCode"], checkedAt: new Date().toISOString(), source: "LIVE" };
    }
    return decision;
  });

  app.get("/api/events", async (request) => {
    const { releaseId } = request.query as { releaseId?: string };
    return { schemaVersion: SCHEMA_VERSION, events: repository.listEvents(releaseId) };
  });

  return app;
}
