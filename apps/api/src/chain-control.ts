import { id } from "ethers";
import type { FastifyInstance } from "fastify";
import { attestationV2Types, bytes32, quarantineV2Types } from "../../../packages/contracts-sdk/src/v2.js";
import { chainActions, enqueueChainAction, type V2Relayer } from "./chain-outbox.js";
import { ControlStore } from "./control-store.js";
import { hash, loadEvidence, type ControlOptions, type Credential } from "./control-plane.js";
import { policyVerdict } from "./control-policy.js";

const failure = (message: string, statusCode = 400) => Object.assign(new Error(message), { statusCode });
export async function registerChainRoutes(api: FastifyInstance, store: ControlStore, options: ControlOptions,
  authenticate: (header: string | undefined) => Credential, authorize: (identity: Credential, role: "operator" | "admin") => void) {
  const relayer = options.v2Relayer;
  const enabled = (): V2Relayer => { if (!relayer) throw failure("V2_RELAYER_NOT_CONFIGURED", 503); return relayer; };
  const prepare = async (tenantId: string, scanId: string, validator: string) => {
    const client = enabled(), scan = await store.scan(tenantId, scanId);
    if (!scan?.result || scan.status !== "COMPLETED") throw failure("SCAN_NOT_READY", 409);
    const [release, policy] = await Promise.all([store.get(tenantId, "release", scan.releaseId), store.get(tenantId, "policy", scan.policyHash)]);
    if (!release || !policy || policy.deprecatedAt) throw failure("POLICY_OR_RELEASE_UNAVAILABLE", 409);
    const bundle = await loadEvidence(options, tenantId, scan.result.evidenceKey, scan.result.reportRoot);
    const verdict = policyVerdict(bundle, scan.result.scanResult);
    const context = await client.context(validator);
    const now = Math.floor(Date.now() / 1000), validFrom = Math.floor(Date.parse(scan.result.validFrom) / 1000), validUntil = Math.floor(Date.parse(scan.result.validUntil) / 1000);
    if (validUntil <= now || validFrom > now) throw failure("SCAN_VALIDITY_EXPIRED", 409);
    return { scan, release, bundle, verdict, payload: { releaseId: scan.releaseId, artifactDigest: bytes32(release.artifactDigest),
      manifestDigest: bytes32(release.manifestDigest), toolSurfaceDigest: release.toolSurfaceHash, policyHash: scan.policyHash,
      reportRoot: scan.result.reportRoot, verdict: { PASS: 0, FAIL: 1, ABSTAIN: 2 }[verdict], validFrom, validUntil,
      validatorSetVersion: context.validatorSetVersion, nonce: context.nonce, deadline: Math.min(now + 600, validUntil) } };
  };
  api.get("/chain/actions", async (request) => ({ items: await chainActions(store, authenticate(request.headers.authorization).tenantId) }));
  api.get("/chain/actions/:actionId", async (request) => {
    const items = await chainActions(store, authenticate(request.headers.authorization).tenantId, (request.params as any).actionId);
    if (!items[0]) throw failure("CHAIN_ACTION_NOT_FOUND", 404); return { action: items[0] };
  });
  api.post("/releases/:releaseId/register", async (request, reply) => {
    const user = authenticate(request.headers.authorization); authorize(user, "admin");
    const release = await store.get(user.tenantId, "release", (request.params as any).releaseId);
    if (!release) throw failure("RELEASE_NOT_FOUND", 404);
    const payload = Object.fromEntries(["releaseId", "toolId", "artifactDigest", "manifestDigest", "toolSurfaceHash"].map((key) => [key, release[key]]));
    return reply.code(202).send({ action: await enqueueChainAction(store, enabled(), user.tenantId, "REGISTER_RELEASE", payload) });
  });
  api.post("/policies/:policyHash/publish", async (request, reply) => {
    const user = authenticate(request.headers.authorization); authorize(user, "admin");
    const policy = await store.get(user.tenantId, "policy", (request.params as any).policyHash);
    if (!policy || policy.deprecatedAt) throw failure("POLICY_UNAVAILABLE", 404);
    return reply.code(202).send({ action: await enqueueChainAction(store, enabled(), user.tenantId, "PUBLISH_POLICY", { policyHash: policy.policyHash }) });
  });
  api.get("/scans/:scanId/attestation", async (request) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const validator = (request.query as any).validator;
    if (typeof validator !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(validator)) throw failure("VALIDATOR_ADDRESS_REQUIRED");
    const prepared = await prepare(user.tenantId, (request.params as any).scanId, validator);
    await store.event(user.tenantId, prepared.scan.releaseId, "validator.evidence.checked", { scanId: prepared.scan.scanId, validator, verdict: prepared.verdict });
    return { domain: enabled().domain, types: attestationV2Types, payload: prepared.payload, verdict: prepared.verdict,
      evidenceUrl: `/v1/scans/${prepared.scan.scanId}/evidence` };
  });
  api.post("/validator/attestations", async (request, reply) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const body = request.body as any, client = enabled();
    if (!body || typeof body.scanId !== "string" || !body.payload || typeof body.signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(body.signature)) throw failure("INVALID_ATTESTATION");
    const actionPayload = { attestation: body.payload, signature: body.signature };
    const previous = await chainActions(store, user.tenantId, hash({ tenantId: user.tenantId, kind: "ATTEST", payload: actionPayload }));
    if (previous[0]) return reply.code(202).send({ action: previous[0], idempotent: true });
    const validator = await client.validateSignature(body.payload, body.signature);
    const prepared = await prepare(user.tenantId, body.scanId, validator);
    const { deadline: _generatedDeadline, ...expected } = prepared.payload;
    const { deadline, ...received } = body.payload;
    if (hash(expected) !== hash(received) || !Number.isSafeInteger(deadline) || deadline < Math.floor(Date.now() / 1000) || deadline > prepared.payload.validUntil
      || deadline > Math.floor(Date.now() / 1000) + 3600) throw failure("ATTESTATION_BINDING_MISMATCH");
    return reply.code(202).send({ action: await enqueueChainAction(store, client, user.tenantId, "ATTEST", actionPayload, prepared.scan.request.traceparent) });
  });
  api.get("/scans/:scanId/quarantine", async (request) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const validator = (request.query as any).validator;
    if (typeof validator !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(validator)) throw failure("VALIDATOR_ADDRESS_REQUIRED");
    const prepared = await prepare(user.tenantId, (request.params as any).scanId, validator);
    const evidence = prepared.scan.result!.scanResult.findings.find((finding: any) => finding.deterministic === true && finding.severity === "CRITICAL"
      && ["CANARY_EXFILTRATION", "HOST_ESCAPE_ATTEMPT", "DIGEST_MISMATCH"].includes(finding.code));
    if (!evidence) throw failure("DETERMINISTIC_CRITICAL_EVIDENCE_REQUIRED", 409);
    const now = Math.floor(Date.now() / 1000);
    return { domain: enabled().domain, types: quarantineV2Types, payload: { releaseId: prepared.scan.releaseId, policyHash: prepared.scan.policyHash,
      evidenceHash: prepared.scan.result!.reportRoot, reasonCode: id(evidence.code), expiresAt: now + 3600,
      validatorSetVersion: prepared.payload.validatorSetVersion, nonce: prepared.payload.nonce, deadline: now + 600 } };
  });
  api.post("/validator/quarantines", async (request, reply) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const body = request.body as any, client = enabled();
    if (!body?.payload || typeof body.scanId !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(body.signature ?? "")) throw failure("INVALID_QUARANTINE");
    if (Object.keys(body.payload).sort().join() !== quarantineV2Types.Quarantine.map((field) => field.name).sort().join()) throw failure("INVALID_QUARANTINE");
    const actionPayload = { quarantine: body.payload, signature: body.signature };
    const previous = await chainActions(store, user.tenantId, hash({ tenantId: user.tenantId, kind: "QUARANTINE", payload: actionPayload }));
    if (previous[0]) return reply.code(202).send({ action: previous[0], idempotent: true });
    const validator = await client.validateSignature(body.payload, body.signature, true), prepared = await prepare(user.tenantId, body.scanId, validator);
    const q = body.payload, now = Math.floor(Date.now() / 1000);
    const allowed = prepared.scan.result!.scanResult.findings.some((finding: any) => finding.deterministic === true && finding.severity === "CRITICAL"
      && ["CANARY_EXFILTRATION", "HOST_ESCAPE_ATTEMPT", "DIGEST_MISMATCH"].includes(finding.code) && id(finding.code) === q.reasonCode);
    if (!allowed || q.releaseId !== prepared.scan.releaseId || q.policyHash !== prepared.scan.policyHash || q.evidenceHash !== prepared.scan.result!.reportRoot
      || !Number.isSafeInteger(q.expiresAt) || q.expiresAt <= now || q.expiresAt > now + 86400 || !Number.isSafeInteger(q.deadline) || q.deadline < now || q.deadline > now + 3600) throw failure("QUARANTINE_BINDING_MISMATCH");
    return reply.code(202).send({ action: await enqueueChainAction(store, client, user.tenantId, "QUARANTINE", actionPayload, prepared.scan.request.traceparent) });
  });
}
