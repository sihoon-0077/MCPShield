import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { ControlOptions, Credential } from "./control-plane.js";
import type { ControlStore } from "./control-store.js";
import { preparedPolicy, validPolicy } from "./control-policy.js";
import { preparedTrust } from "./prepared-config.js";
import { enqueuePreparation, preparations, publicPreparation, retryPreparation } from "./preparation-store.js";
import { currentTraceId, traceHeaders, withSpan } from "../../../packages/telemetry/index.mjs";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2.js";

const failure = (message: string, statusCode = 400) => Object.assign(new Error(message), { statusCode });
export function sourceIdentity(source: Record<string, any>) {
  const identity = Object.fromEntries(["releaseId", "toolId", "artifactDigest", "manifestDigest", "toolSurfaceHash"].map((key) => [key, source[key]]));
  if (exactReleaseIdentity(identity as any).releaseId !== source.releaseId) throw failure("SOURCE_IDENTITY_MISMATCH", 409);
  return identity;
}
export function registerPreparationRoutes(api: FastifyInstance, store: ControlStore, options: ControlOptions,
  authenticate: (header: string | undefined) => Credential, authorize: (identity: Credential, role: "operator" | "admin") => void) {
  const enabled = () => {
    if (!options.preparedRuntime || options.scannerOptions?.sandbox !== "docker") throw failure("PREPARATION_NOT_CONFIGURED", 503);
    return preparedTrust(options.preparedRuntime);
  };
  api.post("/releases/:sourceReleaseId/prepare", async (request, reply) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const body = request.body as any, sourceReleaseId = (request.params as any).sourceReleaseId;
    if (!body || Object.keys(body).join() !== "policyHash" || !/^0x[a-f0-9]{64}$/.test(body.policyHash) || !/^0x[a-f0-9]{64}$/.test(sourceReleaseId)) throw failure("INVALID_PREPARATION_REQUEST");
    const key = request.headers["idempotency-key"];
    if (typeof key !== "string" || !key.trim() || key.length > 256) throw failure("IDEMPOTENCY_KEY_REQUIRED");
    const source = await store.get(user.tenantId, "release", sourceReleaseId);
    if (!source) throw failure("RELEASE_NOT_FOUND", 404);
    if (!["npm", "tarball"].includes(source.sourceType) || source.runtimeProfile) throw failure("PREPARATION_SOURCE_UNSUPPORTED");
    const policy = await store.get(user.tenantId, "policy", body.policyHash);
    if (!policy || !validPolicy(policy.document) || policy.document.profile !== preparedPolicy.profile) throw failure("PREPARATION_POLICY_REQUIRED");
    if (policy.deprecatedAt) throw failure("POLICY_DEPRECATED", 409);
    const input = { sourceReleaseId, policyHash: body.policyHash, sourceIdentity: sourceIdentity(source), trustedConfig: enabled() };
    const result = await withSpan("preparation.accept", {}, () => enqueuePreparation(store, user.tenantId,
      { ...input, traceparent: traceHeaders().traceparent }, key, currentTraceId() ?? randomUUID()),
      { traceparent: typeof request.headers.traceparent === "string" ? request.headers.traceparent : undefined });
    return reply.code(202).send({ ...result, preparation: publicPreparation(result.preparation), links: { self: `/v1/preparations/${result.preparation.preparationId}` } });
  });
  api.get("/preparations", async (request) => ({ items: (await preparations(store, authenticate(request.headers.authorization).tenantId)).map(publicPreparation) }));
  api.get("/preparations/:preparationId", async (request) => {
    const [job] = await preparations(store, authenticate(request.headers.authorization).tenantId, (request.params as any).preparationId);
    if (!job) throw failure("PREPARATION_NOT_FOUND", 404); return { preparation: publicPreparation(job) };
  });
  api.post("/preparations/:preparationId/retry", async (request) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    if (request.body !== undefined && (!request.body || Array.isArray(request.body) || Object.keys(request.body as any).length)) throw failure("INVALID_PREPARATION_REQUEST");
    return { preparation: publicPreparation(await retryPreparation(store, user.tenantId, (request.params as any).preparationId, enabled())) };
  });
}
