import { timingSafeEqual } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
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
  databasePath?: string;
  validatorAddresses?: string[];
  logger?: boolean;
  registryClient?: RegistryClient;
  adminApiToken?: string;
  corsAllowlist?: string[];
  attestationChainId?: number;
  attestationContract?: string;
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

export async function buildApp(options: AppOptions = {}): Promise<FastifyInstance> {
  const app = Fastify({ logger: options.logger ?? false });
  const allowlist = new Set(options.corsAllowlist ?? ["http://localhost:3000"]);
  await app.register(cors, {
    origin(origin, callback) {
      callback(null, !origin || allowlist.has(origin));
    },
  });
  const repository = new Repository(options.databasePath ?? ":memory:");
  const validators = new Set(
    (options.validatorAddresses ?? defaultValidators).map((address) => address.toLowerCase()),
  );
  const adminToken = options.adminApiToken ?? "local-demo-admin-token";
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
    if (repository.getRelease(body.releaseId)) {
      return reply.code(409).send(errorBody("RELEASE_EXISTS", "Release ID is already registered"));
    }
    const operationId = `register:${body.releaseId}`;
    repository.createPendingOperation(operationId, "REGISTER_RELEASE", body);
    try {
      const tx = await options.registryClient?.registerRelease(
        body.releaseId, body.artifactDigest, body.toolSurfaceHash,
      );
      if (tx) {
        repository.updatePendingOperation(operationId, "SUBMITTED", tx.hash);
        await tx.wait();
      }
      const release = repository.createRelease({
        releaseId: body.releaseId,
        artifactDigest: body.artifactDigest,
        toolSurfaceHash: body.toolSurfaceHash,
      });
      repository.updatePendingOperation(operationId, "COMPLETED", tx?.hash);
      return reply.code(201).send({ schemaVersion: SCHEMA_VERSION, release, txHash: tx?.hash });
    } catch (error) {
      repository.updatePendingOperation(operationId, "FAILED", undefined, String(error));
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

  app.post("/api/scans", async (request, reply) => {
    const validation = validateScanResult(request.body);
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
      !Number.isSafeInteger(body.deadline) || (body.deadline as number) <= Math.floor(Date.now() / 1000) ||
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
    if (repository.hasVote(body.releaseId, validatorAddress)) {
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
      return reply.code(409).send(errorBody(code, "Attestation does not match current release state"));
    }

    const operationId = `attestation:${id(body.signature)}`;
    repository.createPendingOperation(operationId, "SUBMIT_ATTESTATION", body);
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
        repository.updatePendingOperation(operationId, "SUBMITTED", tx.hash);
        await tx.wait();
      }
      const release = repository.recordVote({
        ...attestation,
        scanId: body.scanId,
        validatorAddress,
        txHash: tx?.hash,
      });
      repository.updatePendingOperation(operationId, "COMPLETED", tx?.hash);
      return reply.code(201).send({ schemaVersion: SCHEMA_VERSION, release, validatorAddress, txHash: tx?.hash });
    } catch (error) {
      repository.updatePendingOperation(operationId, "FAILED", undefined, String(error));
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
