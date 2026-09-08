import { createHash, createPublicKey, verify } from "node:crypto";
import { unlinkSync } from "node:fs";
import { open, rename, writeFile } from "node:fs/promises";
import { traceHeaders } from "../../../packages/telemetry/index.mjs";
import { fallbackConfiguration, directRpcAdmission, rpcRevocationRecord, validateRpcRevocation } from "./admission-fallback.mjs";

const FIELDS = ["schemaVersion", "keyId", "decision", "releaseId", "artifactDigest", "toolSurfaceHash", "policyHash", "validatorSetVersion", "chainId", "registryContract", "observedBlock", "blockHash", "issuedAt", "expiresAt", "status", "operationClass", "tenantId", "reasonCode", "reportUrl"].sort();
const STATUSES = new Set(["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"]);
const memory = new Map();
const pending = new Map();
const revoked = new Map();
const requestDeadlines = new WeakSet();
export class AdmissionTransportUnavailableError extends Error {
  constructor(message) { super(message); this.name = "AdmissionTransportUnavailableError"; }
}
let revocationCapacityExceeded = false;
const canonical = (value) => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]])));
// ReleaseRegistryV2.revoked[releaseId] is global across policies and tenants.
const revocationKey = (value) => canonical(Object.fromEntries(["releaseId", "artifactDigest", "toolSurfaceHash", "chainId", "registryContract"].map(key => [key, typeof value[key] === "string" ? value[key].toLowerCase() : value[key]])));
function rememberRevocation(key, envelope) {
  if (revoked.size >= 4096 && !revoked.has(key)) revocationCapacityExceeded = true;
  else revoked.set(key, envelope);
}

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
    timer = setTimeout(() => { const error = new DOMException("Admission request timed out", "TimeoutError"); requestDeadlines.add(error); controller.abort(error); reject(error); }, timeoutMs);
  });
  const receive = async () => {
    const response = await fetchImpl(url, { ...options, headers: { ...options.headers, ...traceHeaders() }, signal: controller.signal, redirect: "manual" });
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

function assertTrustContext({ publicKey, keyId, policyHash, chainId, registryContract, validatorSetVersion, tenantId, operationClass }) {
  if (!publicKey || !keyId || !/^0x[0-9a-f]{64}$/i.test(policyHash ?? "") || !Number.isSafeInteger(chainId) || chainId < 1 ||
    !/^0x[0-9a-f]{40}$/i.test(registryContract ?? "") || !Number.isSafeInteger(validatorSetVersion) || validatorSetVersion < 1 ||
    typeof tenantId !== "string" || !tenantId || !["READ_PUBLIC", "READ_PRIVATE", "WRITE_EXTERNAL", "DESTRUCTIVE", "FINANCIAL"].includes(operationClass)) throw new Error("Signed admission trust context is not configured");
}

export function verifyAdmissionSnapshot(envelope, { identity, publicKey, keyId, policyHash, chainId, registryContract, validatorSetVersion, tenantId, operationClass, now = Date.now(), maxTtlMs = 60_000 }) {
  const value = envelope?.snapshot;
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join() !== FIELDS.join()) throw new Error("Invalid signed admission snapshot fields");
  assertTrustContext({ publicKey, keyId, policyHash, chainId, registryContract, validatorSetVersion, tenantId, operationClass });
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

export function getSignedAdmission(options) {
  const cacheFile = options.cacheFile === undefined ? process.env.MCPSHIELD_ADMISSION_CACHE_FILE : options.cacheFile;
  return signedAdmission({ ...options, cacheFile });
}

async function signedAdmission({ identity, apiBaseUrl, timeoutMs, fetchImpl, admissionMode = process.env.MCPSHIELD_ADMISSION_MODE ?? "strict",
  publicKey = process.env.MCPSHIELD_CACHE_PUBLIC_KEY, keyId = process.env.MCPSHIELD_CACHE_KEY_ID,
  policyHash = process.env.MCPSHIELD_POLICY_HASH, chainId = Number(process.env.MCPSHIELD_CHAIN_ID),
  registryContract = process.env.MCPSHIELD_REGISTRY_CONTRACT, validatorSetVersion = Number(process.env.MCPSHIELD_VALIDATOR_SET_VERSION),
  operationClass = "WRITE_EXTERNAL", cacheFile = process.env.MCPSHIELD_ADMISSION_CACHE_FILE, now = Date.now,
  apiToken = process.env.MCPSHIELD_CONTROL_TOKEN, tenantId = process.env.MCPSHIELD_TENANT_ID, controlReleaseId = process.env.MCPSHIELD_CONTROL_RELEASE_ID, indexer, rpc }) {
  let lock, lockClosed = false, retainLock = false;
  // The pathname retains exclusive ownership even after its descriptor closes.
  // Unknown owners are never reclaimed, including after process crashes.
  if (cacheFile) {
    try { lock = await open(`${cacheFile}.lock`, "wx", 0o600); }
    catch { throw new Error("Signed cache is locked or unavailable; admission fails closed"); }
  }
  try {
  if (!["strict", "balanced"].includes(admissionMode)) throw new Error("Admission mode must be strict or balanced");
  const endpoint = new URL(apiBaseUrl);
  const allowedHttp = new Set(["127.0.0.1", "localhost", "[::1]", ...(process.env.MCPSHIELD_API_HTTP_HOSTS ?? "").split(",").map((host) => host.trim()).filter(Boolean)]);
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== "/" ||
    (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && allowedHttp.has(endpoint.hostname)))) throw new Error("Signed admission requires HTTPS or an explicitly trusted private HTTP hostname");
  if (!["READ_PUBLIC", "READ_PRIVATE", "WRITE_EXTERNAL", "DESTRUCTIVE", "FINANCIAL"].includes(operationClass)) throw new Error("Invalid operation class");
  identity = { ...identity, releaseId: controlReleaseId ?? identity.releaseId };
  if (!/^0x[0-9a-f]{64}$/i.test(identity.releaseId)) throw new Error("MCPSHIELD_CONTROL_RELEASE_ID must pin the exact /v1 release ID");
  const context = { identity, publicKey, keyId, policyHash, chainId, registryContract, validatorSetVersion, tenantId, operationClass };
  assertTrustContext(context);
  if (createPublicKey(publicKey).asymmetricKeyType !== "ed25519") throw new Error("Signed admission key must be Ed25519");
  const fallback = fallbackConfiguration({ indexer, rpc }, context);
  const issuerContext = (issuer = "API") => {
    if (issuer === "API") return context;
    if (issuer !== "ORG_INDEXER" || !fallback.indexer) throw new Error("Signed cache issuer is not locally trusted");
    return { ...context, publicKey: fallback.indexer.publicKey, keyId: fallback.indexer.keyId };
  };
  const terminalKey = revocationKey({ ...identity, policyHash, chainId, registryContract, tenantId });
  let storedRevocation;
  if (cacheFile) {
    storedRevocation = await readCacheJson(`${cacheFile}.revoked`, true);
    if (storedRevocation !== undefined) {
      if (storedRevocation?.schemaVersion === "mcpshield.rpc-revocation.v1") validateRpcRevocation(storedRevocation, context);
      else {
        const value = storedRevocation?.envelope?.snapshot;
        if (storedRevocation?.schemaVersion !== "mcpshield.revocation.v1" || revocationKey(value ?? {}) !== terminalKey || value.decision !== "BLOCK" || value.status !== "REVOKED") throw new Error("Signed revocation journal does not match this wrapper");
        // Historical proof is authenticated only to retain a denial, never to allow.
        verifyAdmissionSnapshot(storedRevocation.envelope, { ...issuerContext(storedRevocation.issuer), tenantId: value.tenantId, policyHash: value.policyHash, operationClass: value.operationClass,
          validatorSetVersion: value.validatorSetVersion, now: Date.parse(value.issuedAt) + 1 });
      }
      rememberRevocation(terminalKey, storedRevocation);
    }
  }
  const credentialFingerprint = createHash("sha256").update(apiToken ?? "").digest("hex");
  const cacheKey = canonical({ apiBaseUrl, releaseId: identity.releaseId, artifactDigest: identity.artifactDigest, toolSurfaceHash: identity.toolSurfaceHash, policyHash, chainId, registryContract, validatorSetVersion, keyId, tenantId, operationClass, credentialFingerprint, fallbackFingerprint: fallback.fingerprint });
  const pendingKey = canonical({ releaseId: identity.releaseId, tenantId });
  if (!pending.has(pendingKey) && pending.size >= 1024) throw new Error("Too many concurrent admission identities");
  const state = pending.get(pendingKey) ?? { epoch: 0, active: 0 };
  pending.set(pendingKey, state); state.active++;
  const epoch = state.epoch;
  try {
  let envelope, snapshot, rpcState, expiredCache;
  let definiteTransportOutage = true;
  let issuer = "API", decisionSource = "API";
  let cacheHit = false;
  const forget = async (invalidatePending = false) => {
    if (invalidatePending) state.epoch++;
    for (const [key, value] of memory) {
      if (value.envelope.snapshot.releaseId === identity.releaseId && value.envelope.snapshot.tenantId === tenantId) memory.delete(key);
    }
    if (cacheFile) await persistCache(() => writeFile(cacheFile, "null", { mode: 0o600 }));
  };
  const persistRevocation = async (proof = revoked.get(terminalKey)) => {
    if (cacheFile && !storedRevocation && proof) {
      await persistCache(() => writeFile(`${cacheFile}.revoked`, JSON.stringify(proof), { mode: 0o600, flag: "wx" }));
      storedRevocation = proof;
    }
  };
  const remote = async (url, token) => {
    let response;
    try { response = await admissionFetch(`${url.replace(/\/$/, "")}/v1/admission/check`, {
      method: "POST", headers: { "content-type": "application/json", accept: "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ releaseId: identity.releaseId, artifactDigest: identity.artifactDigest, toolSurfaceHash: identity.toolSurfaceHash, policyHash, mode: admissionMode, operationClass }),
    }, fetchImpl, timeoutMs); }
    catch (error) {
      if (!error || !["TypeError", "TimeoutError", "AbortError"].includes(error.name)) { await forget(true); throw error; }
      // An arbitrary AbortError/TypeError is not emergency authorization evidence.
      definiteTransportOutage &&= requestDeadlines.has(error) || ["ECONNREFUSED", "ECONNRESET", "ENOTFOUND", "EAI_AGAIN", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_SOCKET"].includes(error.cause?.code);
    }
    if (!response || response.status >= 500) return undefined;
    if (!response.ok) { await forget(true); throw new Error(`Admission API returned ${response.status}`); }
    await forget();
    try {
      const value = await response.json();
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid signed admission response");
      return value;
    }
    catch (error) { await forget(true); throw error; }
  };
  envelope = await remote(apiBaseUrl, apiToken);
  if (!envelope) {
    if (admissionMode === "balanced" && ["READ_PUBLIC", "READ_PRIVATE"].includes(operationClass)) {
      const saved = cacheFile ? await readCacheJson(cacheFile, true) : memory.get(cacheKey);
      if (saved?.cacheKey === cacheKey && saved.envelope) {
        try { snapshot = verifyAdmissionSnapshot(saved.envelope, { ...issuerContext(saved.issuer), now: now() }); }
        catch (error) {
          // Only a genuinely expired, still-authentic old ALLOW is a miss.
          // A forged expired signature must not escape into another trust tier.
          if (Date.parse(saved.envelope.snapshot?.expiresAt) <= now()) {
            let historical;
            try { historical = verifyAdmissionSnapshot(saved.envelope, { ...issuerContext(saved.issuer), now: Date.parse(saved.envelope.snapshot.issuedAt) + 1 }); }
            catch (invalid) { await forget(true); throw invalid; }
            if (historical.decision === "BLOCK") snapshot = historical;
            else { await forget(); expiredCache = error; }
          } else { await forget(true); throw error; }
        }
        if (snapshot) { envelope = saved.envelope; issuer = saved.issuer ?? "API"; cacheHit = true; decisionSource = "CACHE"; }
      }
    }
    if (!envelope && fallback.indexer) {
      issuer = "ORG_INDEXER"; decisionSource = "ORG_INDEXER";
      envelope = await remote(fallback.indexer.url, fallback.indexer.token);
    }
    if (!envelope && fallback.rpc) {
      const result = await directRpcAdmission(identity, context, fallback.rpc, now);
      snapshot = result.snapshot; rpcState = result.state; decisionSource = "DIRECT_RPC";
      // Publish a validated RPC revocation to the shared fence before any disk await.
      if (snapshot.decision === "ALLOW") await forget();
    }
    if (!envelope && !rpcState) throw expiredCache ?? new (definiteTransportOutage ? AdmissionTransportUnavailableError : Error)(admissionMode !== "balanced" || !["READ_PUBLIC", "READ_PRIVATE"].includes(operationClass)
      ? "Admission unavailable; strict or non-read-only calls fail closed" : "Admission unavailable and no matching signed cache exists");
  }
  try { if (!snapshot) snapshot = verifyAdmissionSnapshot(envelope, { ...issuerContext(issuer), now: now() }); }
  catch (error) { await forget(true); throw error; }
  if (snapshot.decision === "ALLOW" && (storedRevocation || revoked.has(terminalKey) || revocationCapacityExceeded)) {
    await persistRevocation(); await forget(true);
    throw Object.assign(new Error("Release was previously revoked or terminal journal is full; admission fails closed"), { cacheWriteFailed: Boolean(cacheFile && revocationCapacityExceeded) });
  }
  if (snapshot.decision === "BLOCK" && snapshot.status === "REVOKED") {
    // ponytail: 4096 terminal identities per process. Never evict a revocation
    // to gain capacity; use separate wrappers/private journals at larger scale.
    const proof = rpcState ? rpcRevocationRecord(identity, rpcState, now()) : { schemaVersion: "mcpshield.revocation.v1", envelope, ...(issuer === "ORG_INDEXER" ? { issuer } : {}) };
    rememberRevocation(terminalKey, proof);
    await persistRevocation(proof);
  }
  if (snapshot.decision === "BLOCK") await forget(true);
  if (cacheHit && snapshot.decision !== "ALLOW") throw new Error("Cached admission does not allow execution");
  const superseded = () => snapshot.decision === "ALLOW" && (state.epoch !== epoch || storedRevocation || revoked.has(terminalKey) || revocationCapacityExceeded);
  const rejectSuperseded = async () => {
    await persistRevocation(); await forget();
    throw Object.assign(new Error("Admission superseded by a newer denial or invalid response"), { cacheWriteFailed: Boolean(cacheFile && revocationCapacityExceeded) });
  };
  if (superseded()) return await rejectSuperseded();
  if (!cacheHit && !rpcState && snapshot.decision === "ALLOW") {
    // ponytail: bounded process cache; persistent single-release snapshots cover one wrapper per MCP.
    if (memory.size >= 1_024) memory.delete(memory.keys().next().value);
    const saved = { cacheKey, envelope, ...(issuer === "ORG_INDEXER" ? { issuer } : {}) };
    if (!cacheFile) memory.set(cacheKey, saved);
    if (cacheFile) {
      const temporary = `${cacheFile}.${process.pid}.tmp`;
      await persistCache(async () => {
        await writeFile(temporary, JSON.stringify(saved), { mode: 0o600 });
        await rename(temporary, cacheFile);
      });
    }
  }
  if (lock) { await persistCache(() => lock.close()); lockClosed = true; }
  if (snapshot.decision === "ALLOW") {
    try {
      if (rpcState) { if (Date.parse(snapshot.expiresAt) <= now()) throw new Error("Direct RPC admission expired"); }
      else verifyAdmissionSnapshot(envelope, { ...issuerContext(issuer), now: now() });
    }
    catch (error) { await forget(true); throw error; }
  }
  // Closing the handle can race a denial too. Keep pathname ownership through
  // this fence, then release it synchronously with no remaining successful await.
  if (superseded()) return await rejectSuperseded();
  return { schemaVersion: "1.0.0", releaseId: snapshot.releaseId, decision: snapshot.decision, releaseStatus: snapshot.status,
    reasonCode: snapshot.reasonCode, reportUrl: snapshot.reportUrl,
    checkedAt: snapshot.issuedAt, source: "LIVE", decisionSource, cacheHit, expiresAt: snapshot.expiresAt, policyHash: snapshot.policyHash };
  } finally {
    state.active--; if (!state.active) pending.delete(pendingKey);
  }
  } catch (error) { retainLock = error?.cacheWriteFailed === true; throw error; }
  finally {
    if (lock) {
      if (!lockClosed) await lock.close();
      if (!retainLock) unlinkSync(`${cacheFile}.lock`);
    }
  }
}
