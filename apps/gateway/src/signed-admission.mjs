import { createHash, createPublicKey, verify } from "node:crypto";
import { open, rename, unlink, writeFile } from "node:fs/promises";
import { traceHeaders } from "../../../packages/telemetry/index.mjs";

const FIELDS = ["schemaVersion", "keyId", "decision", "releaseId", "artifactDigest", "toolSurfaceHash", "policyHash", "validatorSetVersion", "chainId", "registryContract", "observedBlock", "blockHash", "issuedAt", "expiresAt", "status", "operationClass", "tenantId", "reasonCode", "reportUrl"].sort();
const STATUSES = new Set(["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"]);
const memory = new Map();
const pending = new Map();
const revoked = new Set();
let revocationCapacityExceeded = false;
const canonical = (value) => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]])));
const revocationKey = (value) => canonical(Object.fromEntries(["tenantId", "releaseId", "artifactDigest", "toolSurfaceHash", "policyHash", "chainId", "registryContract"].map(key => [key, typeof value[key] === "string" && key !== "tenantId" ? value[key].toLowerCase() : value[key]])));

async function readCacheJson(path, optional = false) {
  let file;
  try {
    file = await open(path, "r");
    const bytes = Buffer.alloc(32_769); let length = 0;
    while (length < bytes.length) { const result = await file.read(bytes, length, bytes.length - length); if (!result.bytesRead) break; length += result.bytesRead; }
    if (length > 32_768) throw new Error("Signed cache file is oversized");
    return JSON.parse(bytes.subarray(0, length).toString("utf8"));
  } catch (error) { if (optional && error.code === "ENOENT") return undefined; throw error; }
  finally { await file?.close(); }
}

async function persistCache(write) {
  try { await write(); }
  catch { throw Object.assign(new Error("Signed cache persistence failed; ownership lock retained"), { cacheWriteFailed: true }); }
}

export async function admissionFetch(url, options, fetchImpl, timeoutMs) {
  const controller = new AbortController();
  let reader;
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => { const error = new DOMException("Admission request timed out", "TimeoutError"); controller.abort(error); reject(error); }, timeoutMs);
  });
  const receive = async () => {
    const response = await fetchImpl(url, { ...options, headers: { ...options.headers, ...traceHeaders() }, signal: controller.signal, redirect: "error" });
    // The status already decides non-2xx handling. A broken/stalled 4xx body
    // must not disguise an explicit denial as an offline-cache opportunity.
    if (!response.ok) {
      void response.body?.cancel().catch(() => {});
      return new Response(null, { status: response.status, statusText: response.statusText, headers: response.headers });
    }
    controller.signal.throwIfAborted();
    if (!response.body) return response;
    reader = response.body.getReader();
    const chunks = [];
    let bytes = 0;
    while (true) {
      const { done, value } = await Promise.race([reader.read(), timeout]);
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 65_536) throw new Error("Admission response exceeds 65536 bytes");
      chunks.push(Buffer.from(value));
    }
    return new Response(Buffer.concat(chunks), { status: response.status, statusText: response.statusText, headers: response.headers });
  };
  try { return await Promise.race([receive(), timeout]); }
  finally { clearTimeout(timer); void reader?.cancel().catch(() => {}); }
}

export function verifyAdmissionSnapshot(envelope, { identity, publicKey, keyId, policyHash, chainId, registryContract, validatorSetVersion, tenantId, operationClass, now = Date.now(), maxTtlMs = 60_000 }) {
  const value = envelope?.snapshot;
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join() !== FIELDS.join()) throw new Error("Invalid signed admission snapshot fields");
  if (!publicKey || !keyId || !/^0x[0-9a-f]{64}$/i.test(policyHash ?? "") || !Number.isSafeInteger(chainId) || chainId < 1 ||
    !/^0x[0-9a-f]{40}$/i.test(registryContract ?? "") || !Number.isSafeInteger(validatorSetVersion) || validatorSetVersion < 1 ||
    typeof tenantId !== "string" || !tenantId || !["READ_PUBLIC", "READ_PRIVATE", "WRITE_EXTERNAL", "DESTRUCTIVE", "FINANCIAL"].includes(operationClass)) throw new Error("Signed admission trust context is not configured");
  if (value.schemaVersion !== "1.0.0" || value.keyId !== keyId || value.releaseId !== identity.releaseId ||
    value.artifactDigest !== identity.artifactDigest || value.toolSurfaceHash !== identity.toolSurfaceHash || value.policyHash !== policyHash ||
    value.chainId !== chainId || typeof value.registryContract !== "string" || value.registryContract.toLowerCase() !== registryContract.toLowerCase() || value.validatorSetVersion !== validatorSetVersion ||
    value.tenantId !== tenantId || value.operationClass !== operationClass) throw new Error("Signed admission identity or policy mismatch");
  if (!STATUSES.has(value.status) || !["ALLOW", "BLOCK"].includes(value.decision) ||
    (value.decision === "ALLOW" && (value.status !== "VERIFIED" || value.reasonCode !== "RELEASE_VERIFIED")) || !Number.isSafeInteger(value.observedBlock) || value.observedBlock < 1 ||
    !/^0x[0-9a-f]{64}$/i.test(value.blockHash) || /^0x0+$/.test(value.blockHash) || typeof envelope.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature) ||
    typeof value.reasonCode !== "string" || !/^[A-Z][A-Z0-9_]{1,79}$/.test(value.reasonCode) || value.reportUrl !== `/v1/releases/${identity.releaseId}` ||
    typeof value.issuedAt !== "string" || typeof value.expiresAt !== "string") throw new Error("Signed admission contains invalid proof metadata");
  const issued = Date.parse(value.issuedAt);
  const expires = Date.parse(value.expiresAt);
  if (!Number.isSafeInteger(maxTtlMs) || maxTtlMs < 1 || maxTtlMs > 300_000 || !Number.isFinite(issued) || !Number.isFinite(expires) ||
    issued > now + 5_000 || expires <= now || expires <= issued || expires - issued > maxTtlMs) throw new Error("Signed admission expired or has an invalid lifetime");
  const key = createPublicKey(publicKey);
  if (key.asymmetricKeyType !== "ed25519" || !verify(null, Buffer.from(canonical(value)), key, Buffer.from(envelope.signature, "base64url"))) throw new Error("Signed admission signature is invalid");
  return value;
}

export async function getSignedAdmission(options) {
  const cacheFile = options.cacheFile === undefined ? process.env.MCPSHIELD_ADMISSION_CACHE_FILE : options.cacheFile;
  let lock, retainLock = false;
  // A persisted cache belongs to one wrapper. Never race another process's
  // deny/rename or silently reclaim a lock whose owner may still be running.
  if (cacheFile) {
    try { lock = await open(`${cacheFile}.lock`, "wx", 0o600); }
    catch { throw new Error("Signed cache is locked or unavailable; admission fails closed"); }
  }
  try { return await signedAdmission({ ...options, cacheFile }); }
  catch (error) { retainLock = error.cacheWriteFailed === true; throw error; }
  finally { if (lock) { try { await lock.close(); } finally { if (!retainLock) await unlink(`${cacheFile}.lock`); } } }
}

async function signedAdmission({ identity, apiBaseUrl, timeoutMs, fetchImpl, admissionMode = process.env.MCPSHIELD_ADMISSION_MODE ?? "strict",
  publicKey = process.env.MCPSHIELD_CACHE_PUBLIC_KEY, keyId = process.env.MCPSHIELD_CACHE_KEY_ID,
  policyHash = process.env.MCPSHIELD_POLICY_HASH, chainId = Number(process.env.MCPSHIELD_CHAIN_ID),
  registryContract = process.env.MCPSHIELD_REGISTRY_CONTRACT, validatorSetVersion = Number(process.env.MCPSHIELD_VALIDATOR_SET_VERSION),
  operationClass = "WRITE_EXTERNAL", cacheFile = process.env.MCPSHIELD_ADMISSION_CACHE_FILE, now = Date.now,
  apiToken = process.env.MCPSHIELD_CONTROL_TOKEN, tenantId = process.env.MCPSHIELD_TENANT_ID, controlReleaseId = process.env.MCPSHIELD_CONTROL_RELEASE_ID }) {
  if (!["strict", "balanced"].includes(admissionMode)) throw new Error("Admission mode must be strict or balanced");
  const endpoint = new URL(apiBaseUrl);
  const allowedHttp = new Set(["127.0.0.1", "localhost", "[::1]", ...(process.env.MCPSHIELD_API_HTTP_HOSTS ?? "").split(",").map((host) => host.trim()).filter(Boolean)]);
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== "/" ||
    (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && allowedHttp.has(endpoint.hostname)))) throw new Error("Signed admission requires HTTPS or an explicitly trusted private HTTP hostname");
  if (!["READ_PUBLIC", "READ_PRIVATE", "WRITE_EXTERNAL", "DESTRUCTIVE", "FINANCIAL"].includes(operationClass)) throw new Error("Invalid operation class");
  identity = { ...identity, releaseId: controlReleaseId ?? identity.releaseId };
  if (!/^0x[0-9a-f]{64}$/i.test(identity.releaseId)) throw new Error("MCPSHIELD_CONTROL_RELEASE_ID must pin the exact /v1 release ID");
  const context = { identity, publicKey, keyId, policyHash, chainId, registryContract, validatorSetVersion, tenantId, operationClass };
  const terminalKey = revocationKey({ ...identity, policyHash, chainId, registryContract, tenantId });
  let storedRevocation;
  if (cacheFile) {
    storedRevocation = await readCacheJson(`${cacheFile}.revoked`, true);
    if (storedRevocation !== undefined) {
      const value = storedRevocation?.envelope?.snapshot;
      if (storedRevocation?.schemaVersion !== "mcpshield.revocation.v1" || revocationKey(value ?? {}) !== terminalKey || value.decision !== "BLOCK" || value.status !== "REVOKED") throw new Error("Signed revocation journal does not match this wrapper");
      // Terminal chain revocation outlives the short ALLOW TTL and validator-set
      // rotation. Authenticate the old proof at issuance; never reuse it to allow.
      verifyAdmissionSnapshot(storedRevocation.envelope, { ...context, operationClass: value.operationClass,
        validatorSetVersion: value.validatorSetVersion, now: Date.parse(value.issuedAt) + 1 });
    }
  }
  const credentialFingerprint = createHash("sha256").update(apiToken ?? "").digest("hex");
  const cacheKey = canonical({ apiBaseUrl, releaseId: identity.releaseId, artifactDigest: identity.artifactDigest, toolSurfaceHash: identity.toolSurfaceHash, policyHash, chainId, registryContract, validatorSetVersion, keyId, tenantId, operationClass, credentialFingerprint });
  const pendingKey = canonical({ releaseId: identity.releaseId, tenantId });
  if (!pending.has(pendingKey) && pending.size >= 1024) throw new Error("Too many concurrent admission identities");
  const state = pending.get(pendingKey) ?? { epoch: 0, active: 0 };
  pending.set(pendingKey, state); state.active++;
  const epoch = state.epoch;
  try {
  let envelope;
  let cacheHit = false;
  let response;
  const forget = async (invalidatePending = false) => {
    if (invalidatePending) state.epoch++;
    for (const [key, value] of memory) {
      if (value.snapshot.releaseId === identity.releaseId && value.snapshot.tenantId === tenantId) memory.delete(key);
    }
    if (cacheFile) await persistCache(() => writeFile(cacheFile, "null", { mode: 0o600 }));
  };
  try {
    response = await admissionFetch(`${apiBaseUrl.replace(/\/$/, "")}/v1/admission/check`, {
      method: "POST", headers: { "content-type": "application/json", accept: "application/json", ...(apiToken ? { authorization: `Bearer ${apiToken}` } : {}) },
      body: JSON.stringify({ releaseId: identity.releaseId, artifactDigest: identity.artifactDigest, toolSurfaceHash: identity.toolSurfaceHash, policyHash, mode: admissionMode, operationClass }),
    }, fetchImpl, timeoutMs);
  } catch (error) {
    if (!error || !["TypeError", "TimeoutError", "AbortError"].includes(error.name)) { await forget(true); throw error; }
  }
  if (!response || response.status >= 500) {
    if (admissionMode !== "balanced" || !["READ_PUBLIC", "READ_PRIVATE"].includes(operationClass)) throw new Error("Admission unavailable; strict or non-read-only calls fail closed");
    // The locked file is authoritative across processes. A process-local copy
    // must not resurrect an allow after another wrapper persisted a denial.
    envelope = cacheFile ? undefined : memory.get(cacheKey);
    if (!envelope && cacheFile) {
      const saved = await readCacheJson(cacheFile);
      if (saved?.cacheKey === cacheKey) envelope = saved.envelope;
    }
    if (!envelope) throw new Error("Admission unavailable and no matching signed cache exists");
    cacheHit = true;
  } else {
    if (!response.ok) { await forget(true); throw new Error(`Admission API returned ${response.status}`); }
    // Remove the previous allow before parsing: an invalid/new deny response must never resurrect it.
    await forget();
    try { envelope = await response.json(); }
    catch (error) { await forget(true); throw error; }
  }
  let snapshot;
  try { snapshot = verifyAdmissionSnapshot(envelope, { ...context, now: now() }); }
  catch (error) { await forget(true); throw error; }
  if (snapshot.decision === "ALLOW" && (storedRevocation || revoked.has(terminalKey) || revocationCapacityExceeded)) {
    await forget(true); throw new Error("Release was previously revoked or terminal journal is full; admission fails closed");
  }
  if (cacheHit && snapshot.decision !== "ALLOW") throw new Error("Cached admission does not allow execution");
  if (snapshot.decision === "BLOCK" && snapshot.status === "REVOKED") {
    // ponytail: 4096 terminal identities per process. Never evict a revocation
    // to gain capacity; use separate wrappers/private journals at larger scale.
    if (revoked.size >= 4096 && !revoked.has(terminalKey)) revocationCapacityExceeded = true;
    else revoked.add(terminalKey);
    if (cacheFile && !storedRevocation) await persistCache(() => writeFile(`${cacheFile}.revoked`,
      JSON.stringify({ schemaVersion: "mcpshield.revocation.v1", envelope }), { mode: 0o600, flag: "wx" }));
  }
  if (snapshot.decision === "BLOCK") await forget(true);
  const superseded = () => snapshot.decision === "ALLOW" && state.epoch !== epoch;
  if (superseded()) { await forget(); throw new Error("Admission superseded by a newer denial or invalid response"); }
  if (!cacheHit && snapshot.decision === "ALLOW") {
    // ponytail: bounded process cache; persistent single-release snapshots cover one wrapper per MCP.
    if (memory.size >= 1_024) memory.delete(memory.keys().next().value);
    if (!cacheFile) memory.set(cacheKey, envelope);
    if (cacheFile) {
      const temporary = `${cacheFile}.${process.pid}.tmp`;
      await persistCache(async () => {
        await writeFile(temporary, JSON.stringify({ cacheKey, envelope }), { mode: 0o600 });
        await rename(temporary, cacheFile);
      });
    }
  }
  // No await on the successful path after this final fence and before returning ALLOW.
  if (superseded()) { await forget(); throw new Error("Admission superseded by a newer denial or invalid response"); }
  return { schemaVersion: "1.0.0", releaseId: snapshot.releaseId, decision: snapshot.decision, releaseStatus: snapshot.status,
    reasonCode: snapshot.reasonCode, reportUrl: snapshot.reportUrl,
    checkedAt: snapshot.issuedAt, source: "LIVE", cacheHit, expiresAt: snapshot.expiresAt, policyHash: snapshot.policyHash };
  } finally {
    state.active--; if (!state.active) pending.delete(pendingKey);
  }
}
