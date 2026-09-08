import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createDecipheriv, createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createServer } from "node:http";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalJson, createArtifactSnapshot } from "../src/artifact.mjs";
import { breakGlassDigest, openBreakGlassSession, signBreakGlassGrant, verifyBreakGlassAudit } from "../src/break-glass.mjs";
import { createGatewayHttpServer, createRemoteMcpServer, runArtifact } from "../src/index.mjs";
import { getSignedAdmission, AdmissionTransportUnavailableError } from "../src/signed-admission.mjs";
import { runtimeSurfaceGuards } from "../src/protocol-guard.mjs";

const fixture = fileURLToPath(new URL("../../../demo/fixtures/mail-mcp-1.0.0", import.meta.url));
const moduleUrl = new URL("../src/break-glass.mjs", import.meta.url).href;
const operator = generateKeyPairSync("ed25519"), issuer = generateKeyPairSync("ed25519");
const privatePem = operator.privateKey.export({ type: "pkcs8", format: "pem" });
const call = (args = {}, id = 3) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "list_messages", arguments: args } });
const input = (calls = [call()]) => [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "emergency-test", version: "1" } } },
  { jsonrpc: "2.0", method: "notifications/initialized" }, ...calls,
].map(JSON.stringify).join("\n") + "\n";
const denial = { decision: "BLOCK", releaseStatus: "REVOKED", reasonCode: "RELEASE_REVOKED" };

async function setup({ ttlMs = 10_000, args = {} } = {}) {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-emergency-test-"));
  const identity = await createArtifactSnapshot(fixture);
  await identity.cleanup();
  const context = { releaseId: `0x${createHash("sha256").update(randomUUID()).digest("hex")}`, artifactDigest: identity.artifactDigest,
    manifestDigest: identity.manifestDigest, toolSurfaceHash: identity.toolSurfaceHash, policyHash: `0x${"c".repeat(64)}`,
    chainId: 84532, registryContract: `0x${"d".repeat(40)}`, tenantId: "synthetic-tenant" };
  const paths = { configPath: join(directory, "config.json"), grantPath: join(directory, "grant.json") };
  const key = randomBytes(32), now = Date.now();
  const grant = { schemaVersion: "mcpshield.break-glass-grant.v1", keyId: "synthetic-operator", grantId: randomUUID(), actorId: "private-synthetic-actor",
    reasonText: "Synthetic emergency reason never public", issuedAt: now, expiresAt: now + ttlMs, ...context,
    toolName: "list_messages", operationClass: "READ_PRIVATE", argumentsDigest: breakGlassDigest(args) };
  const config = { schemaVersion: "mcpshield.break-glass-config.v1", keyId: grant.keyId, publicKey: operator.publicKey.export({ type: "spki", format: "pem" }),
    clientInfo: { name: "emergency-test", version: "1" },
    auditFile: join(directory, "audit.sqlite"), auditKeyFile: join(directory, "audit.key"), allowedCalls: [{ releaseId: grant.releaseId, toolName: grant.toolName, operationClass: grant.operationClass }] };
  const saveGrant = async (value = grant) => writeFile(paths.grantPath, JSON.stringify(signBreakGlassGrant(value, privatePem)), { mode: 0o600 });
  await writeFile(config.auditKeyFile, key.toString("hex"), { mode: 0o600 });
  await writeFile(paths.configPath, JSON.stringify(config), { mode: 0o600 }); await saveGrant();
  const options = { ...context, identity: { ...identity, releaseId: context.releaseId }, controlReleaseId: context.releaseId,
    publicKey: issuer.publicKey.export({ type: "spki", format: "pem" }), keyId: "synthetic-issuer", validatorSetVersion: 1,
    operationClass: "READ_PRIVATE", apiBaseUrl: "http://127.0.0.1:3199", timeoutMs: 100, cacheFile: null, indexer: null, rpc: null };
  const response = (state = "REVOKED") => {
    const snapshot = { schemaVersion: "1.0.0", keyId: options.keyId, releaseId: context.releaseId, artifactDigest: context.artifactDigest,
      toolSurfaceHash: context.toolSurfaceHash, policyHash: context.policyHash, chainId: context.chainId, registryContract: context.registryContract,
      validatorSetVersion: 1, tenantId: context.tenantId, operationClass: "READ_PRIVATE", decision: state === "VERIFIED" ? "ALLOW" : "BLOCK", status: state,
      reasonCode: `RELEASE_${state}`, reportUrl: `/v1/releases/${context.releaseId}`, observedBlock: 2, blockHash: `0x${"e".repeat(64)}`,
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 30_000).toISOString() };
    const signature = sign(null, Buffer.from(JSON.stringify(Object.fromEntries(Object.keys(snapshot).sort().map(key => [key, snapshot[key]])))), issuer.privateKey).toString("base64url");
    return new Response(JSON.stringify({ snapshot, signature }));
  };
  return { directory, identity, context, paths, key, grant, config, options, response, saveGrant,
    open: () => openBreakGlassSession(paths, context, identity.tools),
    run: (change = {}) => runArtifact({ ...options, breakGlass: paths, artifactDir: fixture, mode: "live", input: input(), capture: true, fetchImpl: async () => response(), ...change }),
    cleanup: () => rm(directory, { recursive: true, force: true }),
  };
}

test("one signed grant claims one process and one exact call; encrypted audit retains private reason and normal BLOCK", async () => {
  const x = await setup({ args: { token: "raw-synthetic-argument-must-not-persist", count: 1 } });
  let a, b;
  try {
    a = x.open(); b = x.open(); a.claim(denial);
    for (const method of ["notifications/initialized", "ping", "tools/list", "server/discover", "notifications/progress", "notifications/cancelled"]) {
      assert.throws(() => a.inspectRequest({ jsonrpc: "2.0", id: 12, method, params: { tenant: "unbound" } }), /CALL_METADATA_SCOPE/);
    }
    assert.throws(() => b.claim(denial), /AUDIT_OR_REPLAY_REJECTED/);
    assert.throws(() => a.call(call({ token: "changed" }), denial), /CALL_SCOPE/);
    const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": x.config.clientInfo, "io.modelcontextprotocol/clientCapabilities": {} };
    for (const params of [{ ...call().params, extraTenant: "other" }, { ...call().params, _meta: { tenant: "other" } },
      { ...call().params, _meta: { ...meta, tenant: "other" } }, { ...call().params, _meta: { ...meta, "io.modelcontextprotocol/clientInfo": { name: "other-client", version: "1" } } },
      { ...call().params, _meta: { ...meta, "io.modelcontextprotocol/clientCapabilities": { sampling: {} } } }]) {
      assert.throws(() => a.call({ ...call(), params }, denial), /CALL_METADATA_SCOPE/);
    }
    a.call(call({ count: 1, token: "raw-synthetic-argument-must-not-persist" }), denial);
    assert.throws(() => a.call(call({ count: 1, token: "raw-synthetic-argument-must-not-persist" }), denial), /CALL_SCOPE/);
    a.close(); b.close(); a = b = undefined;
    assert.equal(verifyBreakGlassAudit(x.paths.configPath).count, 2);
    const db = new DatabaseSync(x.config.auditFile);
    try {
      const rows = db.prepare("SELECT * FROM emergency_audit ORDER BY sequence").all();
      assert.doesNotMatch(JSON.stringify(rows), /Synthetic emergency reason|private-synthetic-actor|raw-synthetic-argument/);
      const events = rows.map(row => {
        const blob = JSON.parse(row.encrypted), decrypt = createDecipheriv("aes-256-gcm", x.key, Buffer.from(blob.iv, "base64url"));
        decrypt.setAAD(Buffer.from(canonicalJson({ sequence: row.sequence, grantId: row.grant_id, phase: row.phase, sessionId: row.session_id })));
        decrypt.setAuthTag(Buffer.from(blob.tag, "base64url"));
        return JSON.parse(Buffer.concat([decrypt.update(Buffer.from(blob.data, "base64url")), decrypt.final()]).toString());
      });
      assert.deepEqual(events.map(event => event.phase), ["ADMISSION", "CALL"]);
      assert.ok(events.every(event => event.envelope.grant.reasonText === x.grant.reasonText && event.envelope.grant.actorId === x.grant.actorId && event.normalDecision.decision === "BLOCK"));
      assert.doesNotMatch(JSON.stringify(events), /raw-synthetic-argument/);
      assert.throws(() => db.exec("DELETE FROM emergency_audit"), /APPEND_ONLY/);
      db.exec("DROP TRIGGER emergency_no_update; UPDATE emergency_audit SET encrypted='{}' WHERE sequence=2");
    } finally { db.close(); }
    assert.throws(() => verifyBreakGlassAudit(x.paths.configPath), /AUDIT_INTEGRITY/);
  } finally { a?.close(); b?.close(); await x.cleanup(); }
});

test("private grant requires exact identity, separately pinned read-only policy, valid signature and <=60 second lifetime", async () => {
  const x = await setup();
  try {
    for (const field of ["releaseId", "artifactDigest", "manifestDigest", "toolSurfaceHash", "policyHash", "chainId", "registryContract", "tenantId"]) {
      assert.throws(() => openBreakGlassSession(x.paths, { ...x.context, [field]: field === "chainId" ? 1 : "mismatch" }, x.identity.tools), /IDENTITY_MISMATCH/);
    }
    for (const change of [{ operationClass: "WRITE_EXTERNAL" }, { expiresAt: x.grant.issuedAt + 60_001 }, { reasonText: "" }, { actorId: "invalid actor" }, { rawArguments: {} }]) {
      assert.throws(() => signBreakGlassGrant({ ...x.grant, ...change }, privatePem));
    }
    await writeFile(x.paths.configPath, JSON.stringify({ ...x.config, allowedCalls: [{ ...x.config.allowedCalls[0], releaseId: `0x${"f".repeat(64)}` }] }));
    assert.throws(x.open, /READ_ONLY_POLICY/);
    await writeFile(x.paths.configPath, JSON.stringify(x.config));
    assert.throws(() => openBreakGlassSession(x.paths, x.context, [{ ...x.identity.tools[0], annotations: { readOnlyHint: false } }]), /READ_ONLY_POLICY/);
    const envelope = JSON.parse(await readFile(x.paths.grantPath, "utf8")); envelope.grant.reasonText = "tampered";
    await writeFile(x.paths.grantPath, JSON.stringify(envelope)); assert.throws(x.open, /GRANT_AUTHENTICATION/);
    await x.saveGrant({ ...x.grant, issuedAt: Date.now() + 1000, expiresAt: Date.now() + 2000 }); assert.throws(x.open, /EXPIRED/);
  } finally { await x.cleanup(); }
});

test("two live OS processes cannot claim the same grant and restart does not reset consumption", { timeout: 15_000 }, async () => {
  const x = await setup();
  const code = `import {openBreakGlassSession} from ${JSON.stringify(moduleUrl)};let session;process.on('message',m=>{try{if(m.open){session=openBreakGlassSession(m.paths,m.context,m.tools);process.send('ready');}else{session.claim(m.decision);session.close();process.send('claimed');process.disconnect();}}catch{session?.close();process.send('rejected');process.disconnect();}});`;
  const children = [];
  try {
    // Initialize SQLite schema before the intentionally concurrent claims.
    const first = x.open(); first.close();
    const completed = [0, 1].map(() => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", code], { stdio: ["ignore", "ignore", "ignore", "ipc"], windowsHide: true }); children.push(child);
      return new Promise((resolve, reject) => {
        child.once("error", reject); let result;
        child.on("message", message => { if (message === "ready") child.send({ decision: denial }); else result = message; });
        child.once("close", () => resolve(result));
        child.send({ open: true, paths: x.paths, context: x.context, tools: x.identity.tools });
      });
    });
    assert.deepEqual((await Promise.all(completed)).sort(), ["claimed", "rejected"]);
    const restarted = x.open();
    try { assert.throws(() => restarted.claim(denial), /AUDIT_OR_REPLAY_REJECTED/); } finally { restarted.close(); }
    assert.equal(verifyBreakGlassAudit(x.paths.configPath).count, 1);
  } finally { for (const child of children) if (child.exitCode === null) child.kill(); await x.cleanup(); }
});

test("monotonic deadline prevents a wall-clock rollback from extending an active grant", async () => {
  const x = await setup();
  try {
    const code = `import {openBreakGlassSession} from ${JSON.stringify(moduleUrl)};const x=JSON.parse(process.argv[1]);const real=Date.now;Date.now=()=>x.issuedAt+9990;const s=openBreakGlassSession(x.paths,x.context,x.tools);Date.now=()=>x.issuedAt+1;await new Promise(r=>setTimeout(r,30));try{s.assertCurrent();process.exitCode=1;}catch(e){if(e.message!=='BREAK_GLASS_EXPIRED')throw e;}finally{s.close();Date.now=real;}`;
    execFileSync(process.execPath, ["--input-type=module", "-e", code, JSON.stringify({ paths: x.paths, context: x.context, tools: x.identity.tools, issuedAt: x.grant.issuedAt })], { windowsHide: true, timeout: 5000, stdio: ["ignore", "pipe", "pipe"] });
  } finally { await x.cleanup(); }
});

test("real protected MCP call overrides execution explicitly without changing normal REVOKED or allowing a second call", async () => {
  const x = await setup();
  try {
    const result = await x.run();
    assert.equal(result.code, 0); assert.equal(result.executionAuthorization, "BREAK_GLASS_OVERRIDE");
    assert.equal(result.decision.decision, "BLOCK"); assert.equal(result.decision.releaseStatus, "REVOKED");
    assert.match(result.stdout, /Welcome/);
    assert.equal(verifyBreakGlassAudit(x.paths.configPath).count, 2);
    await assert.rejects(x.run(), /AUDIT_OR_REPLAY_REJECTED/);
    await assert.rejects(getSignedAdmission({ ...x.options, fetchImpl: async () => x.response("VERIFIED") }), /previously revoked/);
    await x.saveGrant({ ...x.grant, grantId: randomUUID() });
    await assert.rejects(x.run({ input: input([call(), call({}, 4)]) }), /CALL_SCOPE/);
  } finally { await x.cleanup(); }
});

test("grant cannot bypass protocol, arguments, public HTTP, replay, unsigned or rejected admission", async () => {
  const x = await setup();
  try {
    assert.throws(() => createRemoteMcpServer({ breakGlass: x.paths }), /LOCAL_STDIO_ONLY/);
    assert.throws(() => createGatewayHttpServer({ breakGlass: x.paths }), /LOCAL_STDIO_ONLY/);
    for (const change of [{ input: undefined }, { mode: "replay" }, { fetchImpl: async () => new Response("{}", { status: 403 }) },
      { fetchImpl: async () => new Response("{}") }, { fetchImpl: async () => new Response(null, { status: 302, headers: { location: "https://invalid.example" } }) }]) {
      await assert.rejects(x.run(change));
    }
    await assert.rejects(x.run({ input: JSON.stringify(call()) + "\n" }), /initialization|initialize|protocol/i);
    await x.saveGrant({ ...x.grant, grantId: randomUUID() });
    await assert.rejects(x.run({ input: input([call({ changed: true })]) }), /CALL_SCOPE/);
    assert.equal(verifyBreakGlassAudit(x.paths.configPath).count, 2, "Protocol/argument failure burns admission but never appends CALL");
  } finally { await x.cleanup(); }
});

test("emergency modern protocol accepts only the operator-pinned identity and strips no unbound metadata", async () => {
  const x = await setup();
  try {
    const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": x.config.clientInfo, "io.modelcontextprotocol/clientCapabilities": {} };
    const message = { ...call(), params: { ...call().params, _meta: meta } };
    const result = await x.run({ input: JSON.stringify(message) + "\n" }); assert.equal(result.code, 0); assert.match(result.stdout, /Welcome/);
    await x.saveGrant({ ...x.grant, grantId: randomUUID() });
    const initialize = JSON.parse(input().split("\n")[0]); initialize.params.clientInfo.name = "unbound-client";
    await assert.rejects(x.run({ input: JSON.stringify(initialize) + "\n" }), /CALL_METADATA_SCOPE/);
    assert.equal(verifyBreakGlassAudit(x.paths.configPath).count, 3, "Changed client rejected before private discovery/CALL");
  } finally { await x.cleanup(); }
});

test("only a definite transport outage is emergency eligible; arbitrary errors and invalid RPC stay closed", async () => {
  const x = await setup();
  try {
    for (const response of [async () => new Response(null, { status: 503 }), async () => { throw new TypeError("fetch failed", { cause: { code: "ECONNREFUSED" } }); }]) {
      await assert.rejects(getSignedAdmission({ ...x.options, fetchImpl: response }), AdmissionTransportUnavailableError);
    }
    for (const error of [new TypeError("unknown failure"), new DOMException("policy cancellation", "AbortError")]) {
      await assert.rejects(getSignedAdmission({ ...x.options, fetchImpl: async () => { throw error; } }), error => !(error instanceof AdmissionTransportUnavailableError));
    }
    const result = await x.run({ fetchImpl: async () => new Response(null, { status: 503 }) });
    assert.equal(result.code, 0); assert.equal(result.decision.decision, "BLOCK"); assert.equal(result.decision.reasonCode, "STATUS_UNAVAILABLE");
  } finally { await x.cleanup(); }
});

test("final synchronous protocol fence rejects expiry after the async authorization without forwarding a call", async () => {
  const x = await setup(); let authorized = false, forwarded = "";
  const guards = runtimeSurfaceGuards(x.identity.toolSurfaceHash, x.identity.tools, async () => { authorized = true; }, {
    sendInternal: async message => { guards.responses.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { tools: x.identity.tools } }) + "\n"); },
    beforeForward: () => { if (authorized) throw new Error("BREAK_GLASS_EXPIRED"); },
  });
  guards.requests.on("data", chunk => { forwarded += chunk; }); guards.requests.on("error", () => {}); guards.responses.on("error", () => {});
  try {
    const message = call(); message.params._meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": { name: "test", version: "1" }, "io.modelcontextprotocol/clientCapabilities": {} };
    await assert.rejects(new Promise((resolve, reject) => guards.requests.write(JSON.stringify(message) + "\n", error => error ? reject(error) : resolve())), /BREAK_GLASS_EXPIRED/);
    assert.equal(authorized, true); assert.equal(forwarded, "");
  } finally { guards.close(); await x.cleanup(); }
});

test("audit append failure prevents the call from reaching a real child, and oversized ciphertext rejects startup", async () => {
  const x = await setup();
  try {
    const initial = x.open(); initial.close();
    const db = new DatabaseSync(x.config.auditFile);
    db.exec("CREATE TRIGGER synthetic_failed_write BEFORE INSERT ON emergency_audit WHEN NEW.phase='CALL' BEGIN SELECT RAISE(ABORT,'SYNTHETIC_DISK_FAILURE'); END;"); db.close();
    await assert.rejects(x.run(), /AUDIT_OR_REPLAY_REJECTED/);
    assert.equal(verifyBreakGlassAudit(x.paths.configPath).count, 1);
    const corrupt = new DatabaseSync(x.config.auditFile);
    corrupt.exec("DROP TRIGGER emergency_no_update"); corrupt.prepare("UPDATE emergency_audit SET encrypted=?").run("x".repeat(32_769)); corrupt.close();
    let fetched = false;
    await assert.rejects(x.run({ fetchImpl: async () => { fetched = true; return x.response(); } }), /AUDIT_INTEGRITY/);
    assert.equal(fetched, false);
  } finally { await x.cleanup(); }
});

test("local issuer CLI and real stdio proxy use private files and audit exactly one synthetic call", { timeout: 15_000 }, async () => {
  const x = await setup(), server = createServer(async (_request, response) => {
    const body = await x.response().text(); response.writeHead(200, { "content-type": "application/json" }); response.end(body);
  });
  let child;
  try {
    const { schemaVersion, grantId, issuedAt, expiresAt, argumentsDigest, ...template } = x.grant;
    const files = { template: join(x.directory, "template.json"), arguments: join(x.directory, "arguments.json"), key: join(x.directory, "operator.pem"), out: join(x.directory, "issued.json") };
    await writeFile(files.template, JSON.stringify({ ...template, ttlMs: 10_000 }), { mode: 0o600 });
    await writeFile(files.arguments, "{}", { mode: 0o600 }); await writeFile(files.key, privatePem, { mode: 0o600 });
    const issuance = execFileSync(process.execPath, [fileURLToPath(moduleUrl), ...Object.entries(files).flatMap(([key, value]) => [`--${key}`, value])], { encoding: "utf8", windowsHide: true, timeout: 5000 });
    assert.doesNotMatch(issuance, /Synthetic emergency|private-synthetic-actor|PRIVATE KEY/);
    assert.equal(JSON.parse(issuance).scope, "ONE_SESSION_ONE_CALL");
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const env = { ...process.env, MCPSHIELD_MODE: "live", MCPSHIELD_ARTIFACT_DIR: fixture, MCPSHIELD_API_URL: `http://127.0.0.1:${server.address().port}`,
      MCPSHIELD_CONTROL_RELEASE_ID: x.context.releaseId, MCPSHIELD_POLICY_HASH: x.context.policyHash, MCPSHIELD_CHAIN_ID: String(x.context.chainId),
      MCPSHIELD_REGISTRY_CONTRACT: x.context.registryContract, MCPSHIELD_TENANT_ID: x.context.tenantId, MCPSHIELD_CACHE_PUBLIC_KEY: x.options.publicKey,
      MCPSHIELD_CACHE_KEY_ID: x.options.keyId, MCPSHIELD_VALIDATOR_SET_VERSION: "1", MCPSHIELD_ADMISSION_MODE: "strict" };
    for (const key of Object.keys(env)) if (/^MCPSHIELD_(?:INDEXER_|RPC_|PREPARED_|ADMISSION_CACHE_FILE|RECEIPT_)/.test(key)) delete env[key];
    child = spawn(process.execPath, [fileURLToPath(new URL("../src/index.mjs", import.meta.url)), "stdio", "--break-glass-config", x.paths.configPath, "--break-glass-grant", files.out], { env, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; }); child.stderr.on("data", chunk => { stderr += chunk; });
    const result = new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
    child.stdin.end(input()); assert.equal(await result, 0);
    assert.match(stdout, /Welcome/); assert.match(stderr, /BREAK_GLASS_OVERRIDE/);
    assert.doesNotMatch(stdout + stderr, /Synthetic emergency|private-synthetic-actor|PRIVATE KEY/);
    assert.equal(verifyBreakGlassAudit(x.paths.configPath).count, 2);
  } finally { if (child?.exitCode === null) child.kill(); await new Promise(resolve => server.close(resolve)); await x.cleanup(); }
});
