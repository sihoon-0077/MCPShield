import Fastify, { type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
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
  databasePath?: string;
  validatorAddresses?: string[];
  logger?: boolean;
  registryClient?: RegistryClient;
}

function errorBody(code: string, message: string, details?: unknown) {
  return { schemaVersion: SCHEMA_VERSION, error: { code, message, details } };
}

export async function buildApp(options: AppOptions = {}): Promise<FastifyInstance> {
  const app = Fastify({ logger: options.logger ?? false });
  await app.register(cors, { origin: true });
  const repository = new Repository(options.databasePath ?? ":memory:");
  const validators = new Set(
    (options.validatorAddresses ?? defaultValidators).map((address) => address.toLowerCase()),
  );

  app.addHook("onClose", async () => repository.close());

  app.get("/health", async () => ({
    schemaVersion: SCHEMA_VERSION,
    status: "ok",
    ledgerMode: options.registryClient ? "EVM" : "LOCAL_DEMO",
  }));

  app.post("/api/releases", async (request, reply) => {
    const body = request.body as Record<string, unknown> | null;
    if (
      !body ||
      body.schemaVersion !== SCHEMA_VERSION ||
      typeof body.releaseId !== "string" ||
      !patterns.releaseId.test(body.releaseId) ||
      typeof body.artifactDigest !== "string" ||
      !patterns.artifactDigest.test(body.artifactDigest) ||
      typeof body.toolSurfaceHash !== "string" ||
      !patterns.bytes32.test(body.toolSurfaceHash)
    ) {
      return reply
        .code(400)
        .send(errorBody("INVALID_RELEASE", "Release payload does not match contract v1"));
    }
    try {
      if (repository.getRelease(body.releaseId)) {
        return reply
          .code(409)
          .send(errorBody("RELEASE_EXISTS", "Release ID is already registered"));
      }
      const txHash = await options.registryClient?.registerRelease(
        body.releaseId,
        body.artifactDigest,
        body.toolSurfaceHash,
      );
      const release = repository.createRelease({
        releaseId: body.releaseId,
        artifactDigest: body.artifactDigest,
        toolSurfaceHash: body.toolSurfaceHash,
      });
      return reply.code(201).send({ schemaVersion: SCHEMA_VERSION, release, txHash });
    } catch (error) {
      if (String(error).includes("UNIQUE constraint failed")) {
        return reply
          .code(409)
          .send(errorBody("RELEASE_EXISTS", "Release ID is already registered"));
      }
      throw error;
    }
  });

  app.get("/api/releases/:releaseId", async (request, reply) => {
    const { releaseId } = request.params as { releaseId: string };
    const release = repository.getRelease(releaseId);
    return release
      ? { schemaVersion: SCHEMA_VERSION, release }
      : reply.code(404).send(errorBody("RELEASE_NOT_FOUND", "Release was not found"));
  });

  app.post("/api/scans", async (request, reply) => {
    const validation = validateScanResult(request.body);
    if (!validation.valid) {
      return reply
        .code(400)
        .send(errorBody("INVALID_SCAN_RESULT", "Scan result failed schema validation", validation.errors));
    }
    try {
      repository.saveScan(validation.value);
      return reply.code(201).send(validation.value);
    } catch (error) {
      const code = error instanceof Error ? error.message : "SCAN_STORE_FAILED";
      if (code === "RELEASE_NOT_FOUND") {
        return reply.code(404).send(errorBody(code, "Register the release before its scan"));
      }
      if (code === "RELEASE_HASH_MISMATCH") {
        return reply.code(409).send(errorBody(code, "Scan hashes do not match the release"));
      }
      if (String(error).includes("UNIQUE constraint failed")) {
        return reply.code(409).send(errorBody("SCAN_EXISTS", "Scan ID already exists"));
      }
      throw error;
    }
  });

  app.get("/api/scans/:scanId", async (request, reply) => {
    const { scanId } = request.params as { scanId: string };
    const scan = repository.getScan(scanId);
    return scan ?? reply.code(404).send(errorBody("SCAN_NOT_FOUND", "Scan was not found"));
  });

  app.post("/api/validators/vote", async (request, reply) => {
    const body = request.body as Record<string, unknown> | null;
    const decision = body?.decision as ValidatorDecision;
    const validatorAddress =
      typeof body?.validatorAddress === "string" ? body.validatorAddress.toLowerCase() : "";
    if (
      !body ||
      body.schemaVersion !== SCHEMA_VERSION ||
      typeof body.releaseId !== "string" ||
      !patterns.releaseId.test(body.releaseId) ||
      !patterns.address.test(validatorAddress) ||
      !["PASS", "FAIL", "ABSTAIN"].includes(decision) ||
      typeof body.evidenceHash !== "string" ||
      !patterns.bytes32.test(body.evidenceHash)
    ) {
      return reply.code(400).send(errorBody("INVALID_VOTE", "Vote payload is invalid"));
    }
    if (!validators.has(validatorAddress)) {
      return reply
        .code(403)
        .send(errorBody("NOT_VALIDATOR", "Address is not in the validator set"));
    }
    if (repository.hasVote(body.releaseId as string, validatorAddress)) {
      return reply.code(409).send(errorBody("DUPLICATE_VOTE", "Validator already voted"));
    }
    try {
      const txHash = await options.registryClient?.submitVote(
        body.releaseId,
        validatorAddress,
        decision,
        body.evidenceHash,
      );
      const release = repository.recordVote({
        releaseId: body.releaseId,
        validatorAddress,
        decision,
        evidenceHash: body.evidenceHash,
        txHash,
      });
      return reply.code(201).send({ schemaVersion: SCHEMA_VERSION, release, txHash });
    } catch (error) {
      const message = error instanceof Error ? error.message : "VOTE_FAILED";
      if (String(error).includes("UNIQUE constraint failed")) {
        return reply.code(409).send(errorBody("DUPLICATE_VOTE", "Validator already voted"));
      }
      if (message === "RELEASE_NOT_FOUND") {
        return reply.code(404).send(errorBody(message, "Release was not found"));
      }
      if (message === "RELEASE_REVOKED") {
        return reply.code(409).send(errorBody(message, "Revocation is terminal"));
      }
      throw error;
    }
  });

  app.post("/api/admission/check", async (request, reply) => {
    const body = request.body as Record<string, unknown> | null;
    if (
      !body ||
      body.schemaVersion !== SCHEMA_VERSION ||
      typeof body.releaseId !== "string" ||
      typeof body.artifactDigest !== "string" ||
      !patterns.artifactDigest.test(body.artifactDigest)
    ) {
      return reply.code(400).send(errorBody("INVALID_ADMISSION_REQUEST", "Request is invalid"));
    }
    let release = repository.getRelease(body.releaseId);
    let chainAvailable = true;
    if (release && options.registryClient) {
      try {
        const chainStatus = await options.registryClient.getStatus(body.releaseId);
        repository.setProjectedStatus(body.releaseId, chainStatus);
        release = repository.getRelease(body.releaseId);
      } catch {
        chainAvailable = false;
      }
    }
    let decision: AdmissionDecision;
    if (!release || !chainAvailable) {
      decision = {
        schemaVersion: SCHEMA_VERSION,
        releaseId: body.releaseId,
        decision: "BLOCK",
        releaseStatus: release?.status ?? "UNVERIFIED",
        reasonCode: "STATUS_UNAVAILABLE",
        checkedAt: new Date().toISOString(),
        source: "LIVE",
      };
    } else if (release.artifactDigest !== body.artifactDigest) {
      decision = {
        schemaVersion: SCHEMA_VERSION,
        releaseId: body.releaseId,
        decision: "BLOCK",
        releaseStatus: release.status,
        reasonCode: "DIGEST_MISMATCH",
        checkedAt: new Date().toISOString(),
        source: "LIVE",
      };
    } else {
      const allow = release.status === "VERIFIED";
      decision = {
        schemaVersion: SCHEMA_VERSION,
        releaseId: body.releaseId,
        decision: allow ? "ALLOW" : "BLOCK",
        releaseStatus: release.status,
        reasonCode: `RELEASE_${release.status}` as AdmissionDecision["reasonCode"],
        checkedAt: new Date().toISOString(),
        source: "LIVE",
      };
    }
    return decision;
  });

  app.get("/api/events", async (request) => {
    const { releaseId } = request.query as { releaseId?: string };
    return {
      schemaVersion: SCHEMA_VERSION,
      events: repository.listEvents(releaseId),
    };
  });

  return app;
}
