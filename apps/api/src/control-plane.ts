import { createCipheriv, createDecipheriv, createHash, createPrivateKey, randomBytes, randomUUID, sign, timingSafeEqual } from "node:crypto";
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { FastifyInstance } from "fastify";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2.js";
import { ControlStore, type ScanJob } from "./control-store.js";
import { currentTraceId, traceHeaders, withSpan, recordAdmission } from "../../../packages/telemetry/index.mjs";

export type Credential = { token: string; tenantId: string; role: "reader" | "operator" | "admin" };
export interface ControlOptions {
  databaseUrl?: string; credentials: Credential[]; artifactPath: string; evidencePath: string; evidenceKey: string;
  signingKey?: string; signingKeyId?: string;
  resolveArtifact?: (input: Record<string, any>) => Promise<Record<string, any>>;
  scanArtifact?: (input: Record<string, any>) => Promise<Record<string, any>>;
  verifyEvidence?: (bundle: Record<string, any>, expectedRoot: string) => boolean;
  chainDecision?: (release: Record<string, any>, policy: Record<string, any>) => Promise<Record<string, any>>;
  store?: ControlStore;
}
export const canonical = (value: any): string => Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
  : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
export const hash = (value: any) => `0x${createHash("sha256").update(canonical(value)).digest("hex")}`;
const bytes32 = /^0x[0-9a-f]{64}$/;
const safeToken = (provided: string, expected: string) => Buffer.byteLength(provided) === Buffer.byteLength(expected) && timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
const err = (code: string, statusCode = 400) => Object.assign(new Error(code), { statusCode });
export const defaultPolicy = {
  version: "1.0.0", validitySeconds: 86400, requiredTiers: ["static", "semantic", "sandbox"],
  failClosed: true, maxArtifactBytes: 16777216, maxDailyScans: 100, maxQueuedScans: 20,
  deterministicRevocationRequired: true,
};

export async function registerControlPlane(app: FastifyInstance, options: ControlOptions) {
  if (!/^[0-9a-f]{64}$/.test(options.evidenceKey)) throw new Error("CONTROL_EVIDENCE_KEY must be 32-byte hex");
  if (!options.credentials.length || options.credentials.some((c) => !c.token || c.token.length < 16 || !/^[a-zA-Z0-9_-]{1,64}$/.test(c.tenantId) || !["reader", "operator", "admin"].includes(c.role))) throw new Error("Invalid control-plane credentials");
  if (new Set(options.credentials.map((c) => c.token)).size !== options.credentials.length) throw new Error("Duplicate control-plane token");
  const store = options.store ?? await ControlStore.open(options.databaseUrl);
  const signingKey = options.signingKey ? createPrivateKey(options.signingKey) : undefined;
  if (signingKey && (signingKey.asymmetricKeyType !== "ed25519" || !options.signingKeyId)) throw new Error("Ed25519 signing key and key ID required");
  app.addHook("onClose", () => store.close());
  for (const tenant of new Set(options.credentials.map((c) => c.tenantId))) {
    await store.put(tenant, "policy", hash(defaultPolicy), { policyHash: hash(defaultPolicy), alias: "mvp-default-v1", version: "1.0.0", document: defaultPolicy, createdAt: new Date().toISOString(), deprecatedAt: null });
  }
  const authenticate = (header: string | undefined) => {
    const supplied = header?.startsWith("Bearer ") ? header.slice(7) : "";
    const match = options.credentials.find((c) => safeToken(supplied, c.token));
    if (!match) throw err("UNAUTHORIZED", 401);
    return match;
  };
  const authorize = (identity: Credential, role: "operator" | "admin") => {
    if (identity.role === "reader" || (role === "admin" && identity.role !== "admin")) throw err("FORBIDDEN", 403);
  };
  const get = async (tenant: string, kind: string, id: string) => {
    const record = await store.get(tenant, kind, id); if (!record) throw err(`${kind.toUpperCase()}_NOT_FOUND`, 404); return record;
  };
  await app.register(async (api) => {
    api.addHook("onRequest", async (request) => { authenticate(request.headers.authorization); });
    api.setErrorHandler((error: Error & {statusCode?: number}, _request, reply) => {
      const code = /^[A-Z][A-Z0-9_]+$/.test(error.message) ? error.message : "CONTROL_PLANE_FAILED";
      reply.code(error.statusCode ?? (code === "CONTROL_PLANE_FAILED" ? 500 : 400)).send({ error: { code, message: code } });
    });
    api.get("/session", async (request) => {
      const { tenantId, role } = authenticate(request.headers.authorization);
      return { tenantId, role, capabilities: { read: true, scan: role !== "reader", evidence: role !== "reader", manage: role === "admin" } };
    });
    api.get("/policies", async (request) => ({ items: await store.list(authenticate(request.headers.authorization).tenantId, "policy") }));
    api.post("/policies", async (request, reply) => {
      const user = authenticate(request.headers.authorization); authorize(user, "admin");
      const body = request.body as any;
      if (!body || !/^[a-zA-Z0-9_-]{1,80}$/.test(body.alias) || !body.document || Array.isArray(body.document)
        || !Number.isInteger(body.document.validitySeconds) || body.document.validitySeconds < 60 || body.document.validitySeconds > 2592000
        || body.document.failClosed !== true || body.document.deterministicRevocationRequired !== true) throw err("INVALID_POLICY");
      const document = body.document;
      const policy = { policyHash: hash(document), alias: body.alias, version: String(document.version ?? "1"), document, createdAt: new Date().toISOString(), deprecatedAt: null };
      await store.put(user.tenantId, "policy", policy.policyHash, policy);
      await store.event(user.tenantId, null, "policy.published", { policyHash: policy.policyHash });
      return reply.code(201).send({ policy });
    });
    api.post("/policies/:policyHash/deprecate", async (request) => {
      const user = authenticate(request.headers.authorization); authorize(user, "admin");
      const policy = await get(user.tenantId, "policy", (request.params as any).policyHash);
      policy.deprecatedAt = new Date().toISOString(); await store.put(user.tenantId, "policy", policy.policyHash, policy, true);
      await store.event(user.tenantId, null, "policy.deprecated", { policyHash: policy.policyHash }); return { policy };
    });
    api.post("/releases/resolve", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (request, reply) => {
      const user = authenticate(request.headers.authorization); authorize(user, "operator");
      const body = request.body as any;
      if (!body || !["npm", "tarball", "fixture"].includes(body.sourceType) || typeof body.locator !== "string" || body.locator.length > 2048) throw err("UNSUPPORTED_SOURCE");
      // API clients can select shipped fixtures, never arbitrary server filesystem paths.
      const input = body.sourceType === "fixture" ? { sourceType: "local", locator: resolve("demo/fixtures", body.locator) } : { sourceType: body.sourceType, locator: body.locator };
      if (body.sourceType === "fixture" && !["mail-mcp-1.0.0", "mail-mcp-1.0.1"].includes(body.locator)) throw err("UNKNOWN_FIXTURE");
      // @ts-expect-error Scanner/resolver runtime is shared ESM JavaScript.
      const resolver = options.resolveArtifact ?? (await import("../../../services/resolver/src/resolver.mjs")).resolveArtifact;
      const resolved = await resolver(input);
      try {
        const exact = exactReleaseIdentity(resolved as any);
        const artifactDir = resolve(options.artifactPath, createHash("sha256").update(user.tenantId).digest("hex"), resolved.artifactDigest.slice(7));
        await mkdir(artifactDir, { recursive: true });
        await cp(resolved.artifactDir, artifactDir, { recursive: true, force: false, errorOnExist: false });
        const release = { releaseId: exact.releaseId, legacyReleaseId: resolved.releaseId, toolId: exact.toolId,
          version: resolved.version, artifactUri: resolved.artifactUri, artifactDigest: resolved.artifactDigest,
          manifestDigest: resolved.manifestDigest, toolSurfaceHash: resolved.toolSurfaceHash,
          artifactDir, sourceType: body.sourceType, status: "UNVERIFIED", policyHash: null, reportRoot: null, validUntil: null,
          createdAt: new Date().toISOString(), chain: null, metadata: resolved.metadata };
        await store.put(user.tenantId, "release", release.releaseId, release);
        await store.event(user.tenantId, release.releaseId, "release.resolved", { artifactDigest: release.artifactDigest });
        const saved = await get(user.tenantId, "release", release.releaseId);
        return reply.code(201).send({ release: publicRelease(saved) });
      } finally { await resolved.cleanup?.(); }
    });
    api.get("/releases", async (request) => ({ items: (await store.list(authenticate(request.headers.authorization).tenantId, "release")).map(publicRelease) }));
    api.get("/releases/:releaseId", async (request) => ({ release: publicRelease(await get(authenticate(request.headers.authorization).tenantId, "release", (request.params as any).releaseId)) }));
    api.get("/releases/:releaseId/history", async (request) => {
      const user = authenticate(request.headers.authorization), releaseId = (request.params as any).releaseId;
      await get(user.tenantId, "release", releaseId); return { items: await store.events(user.tenantId, releaseId) };
    });
    api.get("/events", async (request) => ({ items: await store.events(authenticate(request.headers.authorization).tenantId) }));
    api.post("/scans", async (request, reply) => {
      const user = authenticate(request.headers.authorization); authorize(user, "operator");
      const body = request.body as any;
      if (!body || !bytes32.test(body.releaseId) || !bytes32.test(body.policyHash) || Object.keys(body).some((key) => !["releaseId", "policyHash", "requestedTiers", "baselineReleaseId"].includes(key))) throw err("INVALID_SCAN_REQUEST");
      const release = await get(user.tenantId, "release", body.releaseId);
      const policy = await get(user.tenantId, "policy", body.policyHash);
      if (policy.deprecatedAt) throw err("POLICY_DEPRECATED", 409);
      if (body.baselineReleaseId) await get(user.tenantId, "release", body.baselineReleaseId);
      const idempotencyKey = request.headers["idempotency-key"];
      if (typeof idempotencyKey !== "string" || !idempotencyKey.trim() || idempotencyKey.length > 256) throw err("IDEMPOTENCY_KEY_REQUIRED");
      const previous = await store.scans(user.tenantId);
      const today = new Date().toISOString().slice(0, 10);
      if (previous.filter((scan) => scan.createdAt.startsWith(today)).length >= (policy.document.maxDailyScans ?? 100)
        || previous.filter((scan) => ["QUEUED", "RUNNING"].includes(scan.status)).length >= (policy.document.maxQueuedScans ?? 20)) throw err("SCAN_QUOTA_EXCEEDED", 429);
      const input = { ...body, artifactDigest: release.artifactDigest };
      const result = await withSpan("scan.accept", { "mcpshield.release_id": body.releaseId }, async () =>
        store.enqueue(user.tenantId, { ...input, traceparent: traceHeaders().traceparent }, idempotencyKey, hash(input), currentTraceId() ?? randomUUID()),
      { traceparent: typeof request.headers.traceparent === "string" ? request.headers.traceparent : undefined });
      if (!result.deduplicated) await store.event(user.tenantId, body.releaseId, "scan.queued", { scanId: result.scan.scanId }, result.scan.traceId);
      return reply.code(202).send({ ...result, scan: publicScan(result.scan), links: { self: `/v1/scans/${result.scan.scanId}` } });
    });
    api.get("/scans", async (request) => ({ items: (await store.scans(authenticate(request.headers.authorization).tenantId)).map(publicScan) }));
    api.get("/scans/:scanId", async (request) => {
      const scan = await store.scan(authenticate(request.headers.authorization).tenantId, (request.params as any).scanId);
      if (!scan) throw err("SCAN_NOT_FOUND", 404); return { scan: publicScan(scan) };
    });
    api.post("/scans/:scanId/retry", async (request) => {
      const user = authenticate(request.headers.authorization); authorize(user, "operator");
      const scan = await store.scan(user.tenantId, (request.params as any).scanId); if (!scan) throw err("SCAN_NOT_FOUND", 404);
      if (!scan.lastError?.retryable) throw err("SCAN_NOT_RETRYABLE", 409);
      if (!await store.retry(user.tenantId, scan.scanId)) throw err("SCAN_NOT_IN_DLQ", 409);
      await store.event(user.tenantId, scan.releaseId, "scan.retried", { scanId: scan.scanId }, scan.traceId);
      return { scan: publicScan((await store.scan(user.tenantId, scan.scanId))!) };
    });
    api.get("/scans/:scanId/evidence", async (request) => {
      const user = authenticate(request.headers.authorization); authorize(user, "operator");
      const scan = await store.scan(user.tenantId, (request.params as any).scanId); if (!scan) throw err("SCAN_NOT_FOUND", 404);
      if (!scan.result?.evidenceKey) throw err("EVIDENCE_NOT_READY", 409);
      await store.event(user.tenantId, scan.releaseId, "evidence.accessed", { scanId: scan.scanId, role: user.role }, scan.traceId);
      const bundle = await loadEvidence(options, user.tenantId, scan.result.evidenceKey, scan.result.reportRoot);
      return { bundle, reportRoot: scan.result.reportRoot };
    });
    api.post("/releases/:releaseId/appeals", async (request, reply) => {
      const user = authenticate(request.headers.authorization); authorize(user, "operator");
      const releaseId = (request.params as any).releaseId; await get(user.tenantId, "release", releaseId);
      const body = request.body as any;
      if (!body || typeof body.reason !== "string" || body.reason.trim().length < 8 || body.reason.length > 2000) throw err("INVALID_APPEAL");
      if (body.scanId && (await store.scan(user.tenantId, body.scanId))?.releaseId !== releaseId) throw err("SCAN_NOT_FOUND", 404);
      const appeal = { appealId: randomUUID(), releaseId, reason: body.reason, status: "OPEN", createdAt: new Date().toISOString(), scanId: body.scanId ?? null };
      await store.put(user.tenantId, "appeal", appeal.appealId, appeal);
      await store.event(user.tenantId, releaseId, "appeal.opened", { appealId: appeal.appealId });
      return reply.code(201).send({ appeal });
    });
    api.get("/releases/:releaseId/appeals", async (request) => {
      const user = authenticate(request.headers.authorization), releaseId = (request.params as any).releaseId;
      await get(user.tenantId, "release", releaseId);
      return { items: (await store.list(user.tenantId, "appeal")).filter((item) => item.releaseId === releaseId) };
    });
    api.post("/appeals/:appealId/resolve", async (request) => {
      const user = authenticate(request.headers.authorization); authorize(user, "admin");
      const appeal = await get(user.tenantId, "appeal", (request.params as any).appealId);
      const body = request.body as any; if (!body || typeof body.resolution !== "string" || body.resolution.length < 8 || body.resolution.length > 2000) throw err("INVALID_RESOLUTION");
      appeal.status = "RESOLVED"; appeal.resolution = body.resolution; appeal.resolvedAt = new Date().toISOString();
      await store.put(user.tenantId, "appeal", appeal.appealId, appeal, true);
      await store.event(user.tenantId, appeal.releaseId, "appeal.resolved", { appealId: appeal.appealId }); return { appeal };
    });
    api.post("/admission/check", async (request) => {
      const user = authenticate(request.headers.authorization), body = request.body as any;
      if (!body || !bytes32.test(body.releaseId) || !bytes32.test(body.policyHash) || !/^sha256:[0-9a-f]{64}$/.test(body.artifactDigest)
        || !bytes32.test(body.toolSurfaceHash) || !["strict", "balanced"].includes(body.mode)
        || !["READ_PUBLIC", "READ_PRIVATE", "WRITE_EXTERNAL", "DESTRUCTIVE", "FINANCIAL"].includes(body.operationClass)) throw err("INVALID_ADMISSION_REQUEST");
      const release = await get(user.tenantId, "release", body.releaseId), policy = await get(user.tenantId, "policy", body.policyHash);
      const checkedAt = new Date().toISOString(), traceId = currentTraceId() ?? randomUUID(), start = performance.now();
      let state: any = { status: "UNVERIFIED", source: "LOCAL_DEMO" };
      try { if (options.chainDecision) state = await options.chainDecision(release, policy); } catch { state = { status: "UNVERIFIED", source: "EVM", unavailable: true }; }
      let reasonCode = state.unavailable ? "STATUS_UNAVAILABLE" : `RELEASE_${state.status}`;
      if (body.artifactDigest !== release.artifactDigest || body.toolSurfaceHash !== release.toolSurfaceHash) reasonCode = "DIGEST_MISMATCH";
      else if (policy.deprecatedAt || state.policyHash && state.policyHash !== body.policyHash) reasonCode = "POLICY_MISMATCH";
      else if (state.status === "VERIFIED" && (!state.validUntil || Date.parse(state.validUntil) <= Date.now())) reasonCode = "ATTESTATION_EXPIRED";
      const decision = state.status === "VERIFIED" && reasonCode === "RELEASE_VERIFIED" && state.source === "EVM" ? "ALLOW" : "BLOCK";
      const response: any = { decision, status: state.status, reasonCode, releaseId: body.releaseId, policyHash: body.policyHash, traceId, checkedAt, source: state.source };
      if (signingKey && state.source === "EVM" && !state.unavailable && Number.isSafeInteger(state.observedBlock) && state.observedBlock > 0
        && bytes32.test(state.blockHash) && state.blockHash !== `0x${"0".repeat(64)}` && Number.isSafeInteger(state.chainId) && state.chainId > 0
        && Number.isSafeInteger(state.validatorSetVersion) && state.validatorSetVersion > 0 && /^0x[0-9a-fA-F]{40}$/.test(state.registryContract)) {
        const expiresAt = new Date(Math.min(Date.now() + 30000, decision === "ALLOW" ? Date.parse(state.validUntil) : Date.now() + 30000)).toISOString();
        const snapshot = { schemaVersion: "1.0.0", keyId: options.signingKeyId, decision, releaseId: body.releaseId,
          artifactDigest: body.artifactDigest, toolSurfaceHash: body.toolSurfaceHash, policyHash: body.policyHash,
          validatorSetVersion: state.validatorSetVersion, chainId: state.chainId, registryContract: state.registryContract,
          observedBlock: state.observedBlock, blockHash: state.blockHash, issuedAt: checkedAt, expiresAt, status: state.status,
          operationClass: body.operationClass, tenantId: user.tenantId, reasonCode,
          reportUrl: `/v1/releases/${body.releaseId}` };
        response.snapshot = snapshot; response.signature = sign(null, Buffer.from(canonical(snapshot)), signingKey).toString("base64url");
      }
      await store.event(user.tenantId, body.releaseId, "admission.decided", { decision, reasonCode, policyHash: body.policyHash, operationClass: body.operationClass }, traceId);
      recordAdmission({ decision, riskTier: body.operationClass, source: state.source, durationSeconds: (performance.now() - start) / 1000 });
      return response;
    });
    api.get("/operations", async (request) => {
      const user = authenticate(request.headers.authorization), scans = await store.scans(user.tenantId);
      return { driver: store.driver, counts: Object.fromEntries(["QUEUED", "RUNNING", "COMPLETED", "DEAD_LETTER"].map((status) => [status, scans.filter((item) => item.status === status).length])), total: scans.length };
    });
  }, { prefix: "/v1" });
  return store;
}

function publicRelease({ artifactDir: _path, metadata: _metadata, ...release }: Record<string, any>) { return release; }
function publicScan({ tenantId: _tenant, leaseOwner: _owner, request: _request, result, ...scan }: ScanJob) {
  if (!result) return scan;
  const { evidenceKey: _key, ...safeResult } = result; return { ...scan, result: safeResult };
}
export async function saveEvidence(options: ControlOptions, tenantId: string, bundle: Record<string, any>) {
  const content = Buffer.from(canonical(bundle));
  const key = createHash("sha256").update(tenantId).update(content).digest("hex");
  const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", Buffer.from(options.evidenceKey, "hex"), nonce);
  cipher.setAAD(Buffer.from(`${tenantId}:${key}`));
  const ciphertext = Buffer.concat([cipher.update(content), cipher.final()]);
  await mkdir(options.evidencePath, { recursive: true });
  try { await writeFile(resolve(options.evidencePath, `${key}.bin`), Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]), { flag: "wx", mode: 0o600 }); }
  catch (error: any) { if (error.code !== "EEXIST") throw error; }
  return key;
}
export async function loadEvidence(options: ControlOptions, tenantId: string, key: string, expectedRoot?: string) {
  if (!/^[0-9a-f]{64}$/.test(key)) throw err("INVALID_EVIDENCE_KEY");
  try {
    const bytes = await readFile(resolve(options.evidencePath, `${key}.bin`));
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(options.evidenceKey, "hex"), bytes.subarray(0, 12));
    decipher.setAuthTag(bytes.subarray(12, 28)); decipher.setAAD(Buffer.from(`${tenantId}:${key}`));
    const content = Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]);
    if (createHash("sha256").update(tenantId).update(content).digest("hex") !== key) throw err("EVIDENCE_INTEGRITY_MISMATCH");
    const bundle = JSON.parse(content.toString());
    if (expectedRoot) {
      // @ts-expect-error Scanner evidence is shared ESM JavaScript.
      const verify = options.verifyEvidence ?? (await import("../../../services/scanner/src/evidence.mjs")).verifyEvidenceBundle;
      if (!verify(bundle, expectedRoot)) throw err("EVIDENCE_INTEGRITY_MISMATCH");
    }
    return bundle;
  } catch { throw err("EVIDENCE_INTEGRITY_MISMATCH", 409); }
}
