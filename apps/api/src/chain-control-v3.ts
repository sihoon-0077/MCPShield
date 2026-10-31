import { AbiCoder, Contract, ZeroHash, id, keccak256 } from "ethers";
import type { FastifyInstance } from "fastify";
import { QUARANTINE_REASONS, ROUND_OUTCOMES, VERDICTS, attestationV3Types, bytes32, checkedVoteEvidence, quarantineReason, quarantineV3Types } from "../../../packages/contracts-sdk/src/v3.js";
import { chainActionId, chainActions, type V2Relayer } from "./chain-outbox.js";
import { ControlStore } from "./control-store.js";
import { hash, type Credential } from "./control-plane.js";
import { validPolicy } from "./control-policy.js";

const STATUSES = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"];
const REASON_NAMES: Record<string, string> = Object.fromEntries(QUARANTINE_REASONS.map((name) => [id(name), name]));
const failure = (message: string, statusCode = 400) => Object.assign(new Error(message), { statusCode });
const isBytes32 = (value: unknown) => typeof value === "string" && /^0x[0-9a-f]{64}$/.test(value);
const isAddress = (value: unknown) => typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
const seconds = (iso: string) => Math.floor(Date.parse(iso) / 1000);
/** Same key as ReleaseRegistryV3.roundIdOf: a round never includes a report, so independent scans share it. */
export const roundIdOf = (round: { releaseId: string; policyHash: string; validFrom: number; validUntil: number; validatorSetVersion: number }) =>
  keccak256(AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "uint64", "uint64", "uint32"],
    [round.releaseId, round.policyHash, round.validFrom, round.validUntil, round.validatorSetVersion]));
const checkedEvidence = (file: unknown, expected: Parameters<typeof checkedVoteEvidence>[1]) => {
  try { return checkedVoteEvidence(file, expected); }
  catch (error: any) { throw failure(/^[A-Z_]+$/.test(error?.message ?? "") ? error.message : "VALIDATOR_EVIDENCE_INVALID"); }
};
const findingSummary = (report: any) => (Array.isArray(report?.findings) ? report.findings : []).slice(0, 32)
  .map((f: any) => ({ code: String(f.code), severity: String(f.severity), stage: String(f.stage), deterministic: f.deterministic === true }));

type SignedAction = (tenantId: string, kind: "ATTEST" | "QUARANTINE", payload: any, scan: any, incoming: unknown) => Promise<any>;

/**
 * ADR-008 vote relay for ReleaseRegistryV3. The operator announces a round (its scan's validity window) and pays gas
 * for signed votes, but never decides them: each validator signs its own verdict and its own evidenceHash, and a vote
 * that disagrees with the operator's scan is relayed like any other. The same signature also works sent directly.
 */
export function registerV3VoteRoutes(api: FastifyInstance, store: ControlStore, relayer: () => V2Relayer,
  authenticate: (header: string | undefined) => Credential, authorize: (identity: Credential, role: "operator" | "admin") => void, signedAction: SignedAction) {
  const announce = async (tenantId: string, scanId: string, validator: string) => {
    const client = relayer(), scan = await store.scan(tenantId, scanId);
    if (!scan?.result || scan.status !== "COMPLETED") throw failure("SCAN_NOT_READY", 409);
    const [release, policy] = await Promise.all([store.get(tenantId, "release", scan.releaseId), store.get(tenantId, "policy", scan.policyHash)]);
    if (!release || !policy || policy.deprecatedAt || !validPolicy(policy.document) || hash(policy.document) !== scan.policyHash) throw failure("POLICY_OR_RELEASE_UNAVAILABLE", 409);
    // V3 validators re-scan local source themselves (apps/validator/src/v3.ts); prepared and OCI profiles stay on V2.
    if (policy.document.profile !== undefined) throw failure("V3_POLICY_PROFILE_UNSUPPORTED", 409);
    const context = await client.context(validator);
    const now = Math.floor(Date.now() / 1000), validFrom = seconds(scan.result.validFrom), validUntil = seconds(scan.result.validUntil);
    if (validUntil <= now || validFrom > now) throw failure("SCAN_VALIDITY_EXPIRED", 409);
    const identity = { releaseId: scan.releaseId, artifactDigest: bytes32(release.artifactDigest), manifestDigest: bytes32(release.manifestDigest), toolSurfaceDigest: release.toolSurfaceHash };
    const round = { releaseId: scan.releaseId, policyHash: scan.policyHash, validFrom, validUntil, validatorSetVersion: context.validatorSetVersion };
    return { scan, identity, round, roundId: roundIdOf(round), nonce: context.nonce, now, operatorVerdict: (scan.result.verdict ?? null) as string | null };
  };
  const validatorQuery = (request: any) => {
    const validator = request.query?.validator;
    if (!isAddress(validator)) throw failure("VALIDATOR_ADDRESS_REQUIRED");
    return validator as string;
  };

  api.get("/scans/:scanId/attestation", async (request) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const validator = validatorQuery(request), a = await announce(user.tenantId, (request.params as any).scanId, validator);
    await store.event(user.tenantId, a.scan.releaseId, "validator.round.announced", { scanId: a.scan.scanId, validator, roundId: a.roundId });
    // No evidenceHash and no verdict: the validator fills both from its own scan and signs only the payload it built itself.
    return { registryVersion: 3, domain: relayer().domain, types: attestationV3Types, roundId: a.roundId, round: a.round, operatorVerdict: a.operatorVerdict,
      payload: { ...a.identity, policyHash: a.round.policyHash, validFrom: a.round.validFrom, validUntil: a.round.validUntil,
        validatorSetVersion: a.round.validatorSetVersion, nonce: a.nonce, deadline: Math.min(a.now + 600, a.round.validUntil) },
      evidenceUrl: `/v1/scans/${a.scan.scanId}/evidence` };
  });
  api.post("/validator/attestations", async (request, reply) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const body = request.body as any, client = relayer();
    if (!body || typeof body.scanId !== "string" || !body.payload || typeof body.payload !== "object"
      || Object.keys(body.payload).sort().join() !== attestationV3Types.Attestation.map((field) => field.name).sort().join()
      || typeof body.signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(body.signature)) throw failure("INVALID_ATTESTATION");
    const actionPayload = { attestation: body.payload, signature: body.signature };
    const previous = await chainActions(store, user.tenantId, chainActionId(client, user.tenantId, "ATTEST", actionPayload));
    if (previous[0]) return reply.code(202).send({ action: previous[0], idempotent: true });
    const validator = await client.validateSignature(body.payload, body.signature);
    const a = await announce(user.tenantId, body.scanId, validator);
    const { deadline, evidenceHash, verdict, ...bound } = body.payload;
    const expected = { ...a.identity, policyHash: a.round.policyHash, validFrom: a.round.validFrom, validUntil: a.round.validUntil,
      validatorSetVersion: a.round.validatorSetVersion, nonce: a.nonce };
    // Identity, round and nonce are bound; the verdict and the evidence are the validator's own and are never compared to the operator's.
    if (hash(expected) !== hash(bound) || ![0, 1, 2].includes(verdict) || !isBytes32(evidenceHash) || evidenceHash === ZeroHash
      || !Number.isSafeInteger(deadline) || deadline < a.now || deadline > a.round.validUntil || deadline > a.now + 3600) throw failure("ATTESTATION_BINDING_MISMATCH");
    const checked = body.evidence === undefined ? undefined : checkedEvidence(body.evidence, { evidenceHash, validator, release: a.identity, verdict });
    const record = { roundId: a.roundId, scanId: a.scan.scanId, releaseId: a.round.releaseId, policyHash: a.round.policyHash, validator, verdict: VERDICTS[verdict], evidenceHash,
      operatorVerdict: a.operatorVerdict, agreesWithOperator: a.operatorVerdict === VERDICTS[verdict], receivedAt: new Date().toISOString(),
      evidence: checked ? { consistent: checked.consistent, derivedVerdict: checked.derived.verdict, basis: checked.document.basis,
        findings: findingSummary(checked.document.report), file: body.evidence } : null };
    await store.put(user.tenantId, "validator-vote", `${a.roundId}:${validator.toLowerCase()}`, record, true);
    await store.event(user.tenantId, a.round.releaseId, "validator.vote.received", { scanId: a.scan.scanId, validator, roundId: a.roundId, verdict: record.verdict,
      evidenceHash, agreesWithOperator: record.agreesWithOperator, evidenceConsistent: checked?.consistent ?? null });
    return reply.code(202).send({ action: await signedAction(user.tenantId, "ATTEST", actionPayload, a.scan, request.headers.traceparent) });
  });
  api.get("/scans/:scanId/quarantine", async (request) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const validator = validatorQuery(request), a = await announce(user.tenantId, (request.params as any).scanId, validator);
    // evidenceHash and reasonCode come from the validator's own evidence file, which the relay request must include.
    return { registryVersion: 3, domain: relayer().domain, types: quarantineV3Types, payload: { releaseId: a.round.releaseId, policyHash: a.round.policyHash,
      expiresAt: a.now + 3600, validatorSetVersion: a.round.validatorSetVersion, nonce: a.nonce, deadline: a.now + 600 } };
  });
  api.post("/validator/quarantines", async (request, reply) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const body = request.body as any, client = relayer();
    if (!body?.payload || typeof body.payload !== "object" || typeof body.scanId !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(body.signature ?? "")
      || Object.keys(body.payload).sort().join() !== quarantineV3Types.Quarantine.map((field) => field.name).sort().join()) throw failure("INVALID_QUARANTINE");
    const actionPayload = { quarantine: body.payload, signature: body.signature };
    const previous = await chainActions(store, user.tenantId, chainActionId(client, user.tenantId, "QUARANTINE", actionPayload));
    if (previous[0]) return reply.code(202).send({ action: previous[0], idempotent: true });
    const validator = await client.validateSignature(body.payload, body.signature, true), a = await announce(user.tenantId, body.scanId, validator), q = body.payload;
    const { document } = checkedEvidence(body.evidence, { evidenceHash: q.evidenceHash, validator, release: a.identity });
    const reason = quarantineReason(document.report);
    if (!reason || id(reason) !== q.reasonCode || q.releaseId !== a.round.releaseId || q.policyHash !== a.round.policyHash
      || !Number.isSafeInteger(q.expiresAt) || q.expiresAt <= a.now || q.expiresAt > a.now + 86400
      || !Number.isSafeInteger(q.deadline) || q.deadline < a.now || q.deadline > a.now + 3600) throw failure("QUARANTINE_BINDING_MISMATCH");
    await store.event(user.tenantId, a.round.releaseId, "validator.quarantine.received", { scanId: a.scan.scanId, validator, reason, evidenceHash: q.evidenceHash });
    return reply.code(202).send({ action: await signedAction(user.tenantId, "QUARANTINE", actionPayload, a.scan, request.headers.traceparent) });
  });

  // Chain view of every round this release has: one per completed operator scan, plus the live and the revoking round
  // (a validator may open those directly). Votes are read from the registry; relayed evidence is attached when its hash matches.
  api.get("/releases/:releaseId/votes", async (request) => {
    const user = authenticate(request.headers.authorization), client = relayer(), registry: any = client.registry;
    const releaseId = (request.params as any).releaseId, query = request.query as any;
    if (!isBytes32(releaseId)) throw failure("RELEASE_ID_INVALID");
    if (!await store.get(user.tenantId, "release", releaseId)) throw failure("RELEASE_NOT_FOUND", 404);
    const scans = (await store.scans(user.tenantId)).filter((scan) => scan.releaseId === releaseId && scan.status === "COMPLETED" && scan.result);
    const policyHash = query.policyHash ?? scans[0]?.policyHash ?? null;
    if (policyHash !== null && !isBytes32(policyHash)) throw failure("POLICY_HASH_INVALID");
    const registered = (await registry.releases(releaseId)).exists;
    // Before registration or before any completed scan there is no round to show; that is not an error and not an approval.
    if (!registered || policyHash === null) return { registryVersion: 3, releaseId, policyHash, registered, rounds: [], quarantines: [] };
    const validatorRegistry = new Contract(await registry.validators(), ["function version() view returns(uint32)", "function validators(uint256) view returns(address)"], client.provider);
    const [version, ...members] = await Promise.all([validatorRegistry.version(), ...[0, 1, 2].map((index) => validatorRegistry.validators(index))]) as [bigint, ...string[]];
    const [decision, needsReview, live, revokedRound, quarantineUntil] = await Promise.all([registry.getDecision(releaseId, policyHash), registry.needsReview(releaseId, policyHash),
      registry.currentRound(releaseId, policyHash), registry.revokedRound(releaseId), registry.quarantineUntil(releaseId)]);
    const rounds = new Map<string, string | null>();
    for (const scan of scans.filter((scan) => scan.policyHash === policyHash)) rounds.set(roundIdOf({ releaseId, policyHash, validFrom: seconds(scan.result!.validFrom),
      validUntil: seconds(scan.result!.validUntil), validatorSetVersion: Number(version) }), scan.scanId);
    for (const extra of [live, revokedRound]) if (extra !== ZeroHash && !rounds.has(extra)) rounds.set(extra, null);
    const indexed = new Map((await store.query(`SELECT payload,transaction_hash FROM cp_v2_events WHERE chain_id = ? AND registry_address = ? AND release_id = ? AND event_name = 'VoteRecorded'`,
      [client.chainId, client.registryAddress.toLowerCase(), releaseId])).map((row) => {
      const event = JSON.parse(row.payload);
      return [`${event.roundId}:${String(event.validator).toLowerCase()}`, { afterDecision: event.afterDecision === true, txHash: row.transaction_hash }];
    }));
    const views = [];
    for (const [roundId, scanId] of rounds) {
      const round = await registry.getRound(roundId);
      if (Number(round.validUntil) === 0) continue;
      const votes = await Promise.all(members.map(async (validator) => {
        const vote = await registry.getVote(roundId, validator), key = `${roundId}:${validator.toLowerCase()}`;
        const stored = vote.cast ? await store.get(user.tenantId, "validator-vote", key) : undefined;
        const relayed = stored !== undefined && stored.evidenceHash === vote.evidenceHash ? stored : undefined;
        const evidence = relayed?.evidence ? (({ file: _file, ...summary }) => summary)(relayed.evidence) : null;
        return { validator, cast: vote.cast, verdict: vote.cast ? VERDICTS[Number(vote.verdict)] : null, evidenceHash: vote.cast ? vote.evidenceHash : null,
          agreesWithOperator: relayed ? relayed.agreesWithOperator : null, evidence,
          afterDecision: indexed.get(key)?.afterDecision ?? null, txHash: indexed.get(key)?.txHash ?? null };
      }));
      views.push({ roundId, scanId, live: roundId === live, validFrom: Number(round.validFrom), validUntil: Number(round.validUntil), validatorSetVersion: Number(round.validatorSetVersion),
        outcome: ROUND_OUTCOMES[Number(round.outcome)], approvals: Number(round.approvals), rejections: Number(round.rejections), abstentions: Number(round.abstentions),
        openedAt: Number(round.openedAt), decidedAt: Number(round.decidedAt) || null, votes });
    }
    views.sort((x, y) => y.openedAt - x.openedAt);
    // Emergency quarantines are a validator's own direct transaction (one per validator per release), indexed from ReleaseQuarantined.
    const quarantines = (await store.query(`SELECT payload,transaction_hash FROM cp_v2_events WHERE chain_id = ? AND registry_address = ? AND release_id = ? AND event_name = 'ReleaseQuarantined' ORDER BY block_number,log_index`,
      [client.chainId, client.registryAddress.toLowerCase(), releaseId])).map((row) => {
      const event = JSON.parse(row.payload);
      return { validator: event.validator, reason: REASON_NAMES[event.reasonCode] ?? null, evidenceHash: event.evidenceHash, expiresAt: Number(event.expiresAt), txHash: row.transaction_hash };
    });
    return { registryVersion: 3, releaseId, policyHash, registered: true, status: STATUSES[Number(decision.status)], decisionRound: decision.reportRoot === ZeroHash ? null : decision.reportRoot,
      needsReview, quarantineUntil: Number(quarantineUntil) || null, validatorSetVersion: Number(version), validators: members, rounds: views, quarantines };
  });
  // The exact bytes behind a relayed evidenceHash, so anyone can re-hash them.
  api.get("/releases/:releaseId/votes/:roundId/:validator/evidence", async (request, reply) => {
    const user = authenticate(request.headers.authorization), { releaseId, roundId, validator } = request.params as any;
    if (!isBytes32(releaseId) || !isBytes32(roundId) || !isAddress(validator)) throw failure("VALIDATOR_EVIDENCE_NOT_FOUND", 404);
    const record = await store.get(user.tenantId, "validator-vote", `${roundId}:${validator.toLowerCase()}`);
    if (!record?.evidence?.file || record.releaseId !== releaseId) throw failure("VALIDATOR_EVIDENCE_NOT_FOUND", 404);
    return reply.type("application/json").send(record.evidence.file);
  });
}
