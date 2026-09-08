import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";
import { traceHeaders } from "../../../packages/telemetry/index.mjs";

const FIELDS = ["schemaVersion", "keyId", "decision", "releaseId", "artifactDigest", "toolSurfaceHash", "policyHash", "validatorSetVersion", "chainId", "registryContract", "observedBlock", "blockHash", "issuedAt", "expiresAt", "status", "operationClass", "tenantId", "reasonCode", "reportUrl"].sort();
const STATUSES = new Set(["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"]);
const memory = new Map();
const canonical = (value) => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]])));

export async function admissionFetch(url, options, fetchImpl, timeoutMs) {
  const controller = new AbortController();
  let reader;
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => { const error = new DOMException("Admission request timed out", "TimeoutError"); controller.abort(error); reject(error); }, timeoutMs);
  });
  const receive = async () => {
    const response = await fetchImpl(url, { ...options, headers: { ...options.headers, ...traceHeaders() }, signal: controller.signal, redirect: "error" });
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

export async function getSignedAdmission({ identity, apiBaseUrl, timeoutMs, fetchImpl, admissionMode = process.env.MCPSHIELD_ADMISSION_MODE ?? "strict",
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
  const credentialFingerprint = createHash("sha256").update(apiToken ?? "").digest("hex");
  const cacheKey = canonical({ apiBaseUrl, releaseId: identity.releaseId, artifactDigest: identity.artifactDigest, toolSurfaceHash: identity.toolSurfaceHash, policyHash, chainId, registryContract, validatorSetVersion, keyId, tenantId, operationClass, credentialFingerprint });
  let envelope;
  let cacheHit = false;
  let response;
  const forget = async () => {
    for (const [key, value] of memory) {
      if (value.snapshot.releaseId === identity.releaseId && value.snapshot.tenantId === tenantId) memory.delete(key);
    }
    if (cacheFile) await writeFile(cacheFile, "null", { mode: 0o600 });
  };
  try {
    response = await admissionFetch(`${apiBaseUrl.replace(/\/$/, "")}/v1/admission/check`, {
      method: "POST", headers: { "content-type": "application/json", accept: "application/json", ...(apiToken ? { authorization: `Bearer ${apiToken}` } : {}) },
      body: JSON.stringify({ releaseId: identity.releaseId, artifactDigest: identity.artifactDigest, toolSurfaceHash: identity.toolSurfaceHash, policyHash, mode: admissionMode, operationClass }),
    }, fetchImpl, timeoutMs);
  } catch (error) {
    if (!error || !["TypeError", "TimeoutError", "AbortError"].includes(error.name)) { await forget(); throw error; }
  }
  if (!response || response.status >= 500) {
    if (admissionMode !== "balanced" || !["READ_PUBLIC", "READ_PRIVATE"].includes(operationClass)) throw new Error("Admission unavailable; strict or non-read-only calls fail closed");
    envelope = memory.get(cacheKey);
    if (!envelope && cacheFile) {
      const file = await readFile(cacheFile, "utf8");
      if (Buffer.byteLength(file) > 32_768) throw new Error("Signed cache file is oversized");
      const saved = JSON.parse(file);
      if (saved?.cacheKey === cacheKey) envelope = saved.envelope;
    }
    if (!envelope) throw new Error("Admission unavailable and no matching signed cache exists");
    cacheHit = true;
  } else {
    if (!response.ok) { await forget(); throw new Error(`Admission API returned ${response.status}`); }
    // Remove the previous allow before parsing: an invalid/new deny response must never resurrect it.
    await forget();
    envelope = await response.json();
  }
  const snapshot = verifyAdmissionSnapshot(envelope, { ...context, now: now() });
  if (cacheHit && snapshot.decision !== "ALLOW") throw new Error("Cached admission does not allow execution");
  if (!cacheHit && snapshot.decision === "ALLOW") {
    // ponytail: bounded process cache; persistent single-release snapshots cover one wrapper per MCP.
    if (memory.size >= 1_024) memory.delete(memory.keys().next().value);
    memory.set(cacheKey, envelope);
    if (cacheFile) {
      const temporary = `${cacheFile}.${process.pid}.tmp`;
      await writeFile(temporary, JSON.stringify({ cacheKey, envelope }), { mode: 0o600 });
      await rename(temporary, cacheFile);
    }
  }
  return { schemaVersion: "1.0.0", releaseId: snapshot.releaseId, decision: snapshot.decision, releaseStatus: snapshot.status,
    reasonCode: snapshot.reasonCode, reportUrl: snapshot.reportUrl,
    checkedAt: snapshot.issuedAt, source: "LIVE", cacheHit, expiresAt: snapshot.expiresAt, policyHash: snapshot.policyHash };
}
