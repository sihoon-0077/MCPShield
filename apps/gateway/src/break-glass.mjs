import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID, sign, verify } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { canonicalJson } from "./artifact.mjs";

const SCHEMA = "mcpshield.break-glass-grant.v1", ZERO = `sha256:${"0".repeat(64)}`;
const ID = /^0x[a-f0-9]{64}$/, HASH = /^sha256:[a-f0-9]{64}$/, UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const NAME = /^[A-Za-z0-9_.:-]{1,128}$/;
const named = value => typeof value === "string" && NAME.test(value);
const CONTEXT = ["releaseId", "artifactDigest", "manifestDigest", "toolSurfaceHash", "chainId", "registryContract", "policyHash", "tenantId"];
const FIELDS = ["schemaVersion", "keyId", "grantId", "actorId", "reasonText", "issuedAt", "expiresAt", ...CONTEXT, "toolName", "operationClass", "argumentsDigest"];
const fail = (code) => { throw new Error(`BREAK_GLASS_${code}`); };
const fields = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join() === [...keys].sort().join();
export const breakGlassDigest = (value) => `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;

function privateFile(path, maxBytes) {
  let file;
  try {
    const info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (process.platform !== "win32" && (info.mode & 0o077))) fail("PRIVATE_FILE_REQUIRED");
    file = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const actual = fstatSync(file);
    if (actual.dev !== info.dev || actual.ino !== info.ino || actual.size > maxBytes) fail("PRIVATE_FILE_INVALID");
    const data = Buffer.alloc(maxBytes + 1); let size = 0;
    while (size < data.length) { const n = readSync(file, data, size, data.length - size); if (!n) break; size += n; }
    if (size > maxBytes) fail("PRIVATE_FILE_OVERSIZED");
    return data.subarray(0, size).toString("utf8");
  } catch { fail("PRIVATE_FILE_INVALID"); }
  finally { if (file !== undefined) closeSync(file); }
}

function grantShape(grant) {
  if (!fields(grant, FIELDS) || grant.schemaVersion !== SCHEMA || !named(grant.keyId) || !UUID.test(grant.grantId) || !named(grant.actorId)
    || typeof grant.reasonText !== "string" || !grant.reasonText.trim() || Buffer.byteLength(grant.reasonText) > 512 || /[\u0000-\u001f\u007f]/u.test(grant.reasonText)
    || !ID.test(grant.releaseId) || !HASH.test(grant.artifactDigest) || !HASH.test(grant.manifestDigest) || !ID.test(grant.toolSurfaceHash)
    || !ID.test(grant.policyHash) || !Number.isSafeInteger(grant.chainId) || grant.chainId < 1 || !/^0x[a-f0-9]{40}$/.test(grant.registryContract)
    || !named(grant.tenantId) || !named(grant.toolName) || !["READ_PUBLIC", "READ_PRIVATE"].includes(grant.operationClass) || !HASH.test(grant.argumentsDigest)
    || !Number.isSafeInteger(grant.issuedAt) || !Number.isSafeInteger(grant.expiresAt) || grant.expiresAt <= grant.issuedAt || grant.expiresAt - grant.issuedAt > 60_000) fail("GRANT_INVALID");
}

export function signBreakGlassGrant(grant, privateKey) {
  grantShape(grant);
  const key = createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== "ed25519") fail("KEY_INVALID");
  return { grant, signature: sign(null, Buffer.from(canonicalJson(grant)), key).toString("base64url") };
}

function authenticate(envelope, config) {
  if (!fields(envelope, ["grant", "signature"]) || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature)) fail("SIGNATURE_INVALID");
  grantShape(envelope.grant);
  const key = createPublicKey(config.publicKey);
  if (key.asymmetricKeyType !== "ed25519" || envelope.grant.keyId !== config.keyId || !verify(null, Buffer.from(canonicalJson(envelope.grant)), key, Buffer.from(envelope.signature, "base64url"))) fail("SIGNATURE_INVALID");
}

function configuration(configPath) {
  let config;
  try { config = JSON.parse(privateFile(configPath, 65_536)); } catch { fail("CONFIG_INVALID"); }
  if (!fields(config, ["schemaVersion", "keyId", "publicKey", "clientInfo", "auditFile", "auditKeyFile", "allowedCalls"]) || config.schemaVersion !== "mcpshield.break-glass-config.v1"
    || !fields(config.clientInfo, ["name", "version"]) || !named(config.clientInfo.name) || !named(config.clientInfo.version)
    || !named(config.keyId) || typeof config.publicKey !== "string" || typeof config.auditFile !== "string" || !config.auditFile || typeof config.auditKeyFile !== "string" || !config.auditKeyFile || !Array.isArray(config.allowedCalls)
    || !config.allowedCalls.length || config.allowedCalls.length > 128 || config.allowedCalls.some(call => !fields(call, ["releaseId", "toolName", "operationClass"])
      || !ID.test(call.releaseId) || !named(call.toolName) || !["READ_PUBLIC", "READ_PRIVATE"].includes(call.operationClass))) fail("CONFIG_INVALID");
  const base = dirname(resolve(configPath));
  config.auditFile = resolve(base, config.auditFile); config.auditKeyFile = resolve(base, config.auditKeyFile);
  const key = privateFile(config.auditKeyFile, 65).trim();
  if (!/^[a-f0-9]{64}$/.test(key)) fail("AUDIT_KEY_INVALID");
  return { config, key: Buffer.from(key, "hex") };
}

// Separate from FR407: grants/reasons are private encrypted emergency audit data.
function auditLedger(config, key) {
  let database;
  try {
    mkdirSync(dirname(config.auditFile), { recursive: true, mode: 0o700 });
    try { closeSync(openSync(config.auditFile, "ax", 0o600)); } catch (error) { if (error.code !== "EEXIST") throw error; }
    const info = lstatSync(config.auditFile);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (process.platform !== "win32" && (info.mode & 0o077))) fail("PRIVATE_FILE_INVALID");
    database = new DatabaseSync(config.auditFile, { allowExtension: false });
    database.exec(`PRAGMA busy_timeout=1000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS emergency_audit (sequence INTEGER PRIMARY KEY, grant_id TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('ADMISSION','CALL')), session_id TEXT NOT NULL, encrypted TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, UNIQUE(grant_id,phase));
      CREATE TRIGGER IF NOT EXISTS emergency_no_update BEFORE UPDATE ON emergency_audit BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS emergency_no_delete BEFORE DELETE ON emergency_audit BEGIN SELECT RAISE(ABORT,'APPEND_ONLY'); END;`);
  } catch { database?.close(); fail("AUDIT_UNAVAILABLE"); }
  const decode = row => {
    if (typeof row.encrypted !== "string" || row.encrypted.length > 32_768 || !HASH.test(row.digest) || !UUID.test(row.grant_id) || !UUID.test(row.session_id)) fail("AUDIT_INTEGRITY");
    const blob = JSON.parse(row.encrypted);
    if (!fields(blob, ["iv", "tag", "data"]) || !/^[A-Za-z0-9_-]{16}$/.test(blob.iv) || !/^[A-Za-z0-9_-]{22}$/.test(blob.tag) || typeof blob.data !== "string" || !/^[A-Za-z0-9_-]{1,30000}$/.test(blob.data)) fail("AUDIT_INTEGRITY");
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(blob.iv, "base64url"));
    decipher.setAAD(Buffer.from(canonicalJson({ sequence: row.sequence, grantId: row.grant_id, phase: row.phase, sessionId: row.session_id })));
    decipher.setAuthTag(Buffer.from(blob.tag, "base64url"));
    const event = JSON.parse(Buffer.concat([decipher.update(Buffer.from(blob.data, "base64url")), decipher.final()]).toString());
    if (breakGlassDigest(event) !== row.digest || event.sequence !== row.sequence || event.envelope.grant.grantId !== row.grant_id || event.phase !== row.phase || event.sessionId !== row.session_id) fail("AUDIT_INTEGRITY");
    authenticate(event.envelope, config);
    return event;
  };
  const verifyLedger = () => {
    let count = 0, tip = ZERO;
    for (const row of database.prepare("SELECT * FROM emergency_audit ORDER BY sequence").iterate()) {
      if (count >= 10_000) fail("AUDIT_FULL");
      const event = decode(row);
      if (event.sequence !== ++count || event.previousHash !== tip) fail("AUDIT_INTEGRITY");
      tip = row.digest;
    }
    return { count, tip };
  };
  try { verifyLedger(); } catch { database.close(); fail("AUDIT_INTEGRITY"); }
  return {
    append(envelope, sessionId, phase, normalDecision) {
      let transaction = false;
      try {
        database.exec("BEGIN IMMEDIATE");
        transaction = true;
        const { count, tip } = verifyLedger();
        // ponytail: bounded local emergency ledger; archive plus a new trust key
        // after 10k events. Never discard claims while their signing key is active.
        if (count >= 10_000) fail("AUDIT_FULL");
        if (phase === "CALL") {
          const claim = database.prepare("SELECT * FROM emergency_audit WHERE grant_id=? AND phase='ADMISSION'").get(envelope.grant.grantId);
          if (!claim || claim.session_id !== sessionId || breakGlassDigest(decode(claim).envelope) !== breakGlassDigest(envelope)) fail("CLAIM_MISMATCH");
        }
        const event = { schemaVersion: "mcpshield.break-glass-audit.v1", sequence: count + 1, previousHash: tip, sessionId, phase,
          authorization: "BREAK_GLASS_OVERRIDE", eventKind: "AUTHORIZED_ATTEMPT_NOT_EXECUTION_PROOF", timestamp: Date.now(), envelope,
          normalDecision: { decision: normalDecision.decision, releaseStatus: normalDecision.releaseStatus, reasonCode: normalDecision.reasonCode } };
        const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv);
        cipher.setAAD(Buffer.from(canonicalJson({ sequence: event.sequence, grantId: envelope.grant.grantId, phase, sessionId })));
        const data = Buffer.concat([cipher.update(canonicalJson(event)), cipher.final()]);
        database.prepare("INSERT INTO emergency_audit(sequence,grant_id,phase,session_id,encrypted,digest) VALUES(?,?,?,?,?,?)").run(event.sequence,
          envelope.grant.grantId, phase, sessionId, JSON.stringify({ iv: iv.toString("base64url"), tag: cipher.getAuthTag().toString("base64url"), data: data.toString("base64url") }), breakGlassDigest(event));
        database.exec("COMMIT");
      } catch { if (transaction) database.exec("ROLLBACK"); fail("AUDIT_OR_REPLAY_REJECTED"); }
    },
    verify: verifyLedger,
    close() { database.close(); key.fill(0); },
  };
}

export function openBreakGlassSession({ configPath, grantPath }, context, tools) {
  const { config, key } = configuration(configPath);
  let envelope;
  try { envelope = JSON.parse(privateFile(grantPath, 16_384)); authenticate(envelope, config); } catch { key.fill(0); fail("GRANT_AUTHENTICATION"); }
  const grant = envelope.grant;
  if (CONTEXT.some(field => grant[field] !== context[field])) { key.fill(0); fail("IDENTITY_MISMATCH"); }
  const tool = tools.find(tool => tool.name === grant.toolName);
  // Candidate annotations are not authority: a separately pinned local operator
  // allowlist must also name this exact release and operation.
  if (!tool || tool.annotations?.readOnlyHint !== true || tool.annotations?.destructiveHint !== false || !config.allowedCalls.some(call =>
    call.releaseId === grant.releaseId && call.toolName === grant.toolName && call.operationClass === grant.operationClass)) { key.fill(0); fail("READ_ONLY_POLICY_REQUIRED"); }
  const now = Date.now(), monotonicEnd = performance.now() + (grant.expiresAt - now);
  let claimed = false, consumed = false, closed = false;
  const assertCurrent = () => {
    if (closed || Date.now() < grant.issuedAt || Date.now() >= grant.expiresAt || performance.now() >= monotonicEnd) fail("EXPIRED");
  };
  try { assertCurrent(); } catch (error) { key.fill(0); throw error; }
  const ledger = auditLedger(config, key), sessionId = randomUUID();
  const inspectRequest = message => {
    assertCurrent();
    if (!fields(message, ["jsonrpc", "method", ...(Object.hasOwn(message, "id") ? ["id"] : []), ...(Object.hasOwn(message, "params") ? ["params"] : [])])) fail("CALL_METADATA_SCOPE");
    const params = message.params;
    const permitted = {
      initialize: ["protocolVersion", "clientInfo", "capabilities"],
      "notifications/initialized": [], ping: ["_meta"], "server/discover": ["_meta"],
      "tools/list": ["cursor", "_meta"], "tools/call": ["name", "arguments", "_meta"],
    }[message.method];
    if (!permitted || Object.hasOwn(message, "params") && (!params || typeof params !== "object" || Array.isArray(params)
      || Object.keys(params).some(key => !permitted.includes(key)))) fail("CALL_METADATA_SCOPE");
    if (params?._meta !== undefined) {
      const meta = params._meta;
      if (!fields(meta, ["io.modelcontextprotocol/protocolVersion", "io.modelcontextprotocol/clientInfo", "io.modelcontextprotocol/clientCapabilities"])
        || meta["io.modelcontextprotocol/protocolVersion"] !== "2026-07-28"
        || canonicalJson(meta["io.modelcontextprotocol/clientInfo"]) !== canonicalJson(config.clientInfo)
        || !fields(meta["io.modelcontextprotocol/clientCapabilities"], [])) fail("CALL_METADATA_SCOPE");
    }
    if (message.method === "initialize" && (!fields(params, ["protocolVersion", "clientInfo", "capabilities"])
      || canonicalJson(params.clientInfo) !== canonicalJson(config.clientInfo) || !fields(params.capabilities, []))) fail("CALL_METADATA_SCOPE");
    if (message.method === "tools/call" && (!params
      || Object.hasOwn(params, "arguments") && (!params.arguments || typeof params.arguments !== "object" || Array.isArray(params.arguments)))) fail("CALL_METADATA_SCOPE");
  };
  return {
    operationClass: grant.operationClass,
    grantId: grant.grantId,
    remainingMs: () => Math.max(0, Math.min(grant.expiresAt - Date.now(), monotonicEnd - performance.now())),
    assertCurrent,
    inspectRequest,
    claim(decision) {
      assertCurrent(); if (claimed) fail("ALREADY_CLAIMED");
      ledger.append(envelope, sessionId, "ADMISSION", decision); claimed = true; assertCurrent();
    },
    call(message, decision) {
      inspectRequest(message);
      if (!claimed || consumed || message.params?.name !== grant.toolName || breakGlassDigest(message.params?.arguments ?? {}) !== grant.argumentsDigest) fail("CALL_SCOPE_OR_REPLAY");
      ledger.append(envelope, sessionId, "CALL", decision); consumed = true; assertCurrent();
    },
    close() { if (!closed) { closed = true; ledger.close(); } },
  };
}

export function verifyBreakGlassAudit(configPath) {
  const { config, key } = configuration(configPath), ledger = auditLedger(config, key);
  try { return { ...ledger.verify(), assurance: "LOCAL_ENCRYPTED_UNANCHORED" }; }
  finally { ledger.close(); }
}

// Local issuance only; no signing key or reason text belongs in process argv.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: { template: { type: "string" }, arguments: { type: "string" }, key: { type: "string" }, out: { type: "string" } } });
    if (Object.values(values).length !== 4 || !values.template || !values.arguments || !values.key || !values.out) fail("CLI_ARGUMENTS");
    const template = JSON.parse(privateFile(values.template, 16_384)), args = JSON.parse(privateFile(values.arguments, 1_048_576));
    if (!fields(template, FIELDS.filter(field => !["schemaVersion", "grantId", "issuedAt", "expiresAt", "argumentsDigest"].includes(field)).concat("ttlMs"))
      || !Number.isSafeInteger(template.ttlMs) || template.ttlMs < 1 || template.ttlMs > 60_000 || !args || typeof args !== "object" || Array.isArray(args)) fail("TEMPLATE_INVALID");
    const { ttlMs, ...input } = template, issuedAt = Date.now();
    const envelope = signBreakGlassGrant({ ...input, schemaVersion: SCHEMA, grantId: randomUUID(), issuedAt, expiresAt: issuedAt + ttlMs, argumentsDigest: breakGlassDigest(args) }, privateFile(values.key, 8_192));
    writeFileSync(values.out, canonicalJson(envelope), { flag: "wx", mode: 0o600 });
    process.stdout.write(`${JSON.stringify({ grantId: envelope.grant.grantId, expiresAt: envelope.grant.expiresAt, scope: "ONE_SESSION_ONE_CALL" })}\n`);
  } catch { process.stderr.write("BREAK_GLASS_ISSUANCE_FAILED\n"); process.exitCode = 1; }
}
