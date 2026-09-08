import assert from "node:assert/strict";
import test from "node:test";
import { execFile, spawn } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2-identity.mjs";
import { prepareNpmClosure } from "../../../services/resolver/src/npm-closure.mjs";
import { artifactDigest } from "../../../services/scanner/src/scanner.mjs";
import { canonicalJson, verifyEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";
import { observePreparedRuntime } from "../../../services/scanner/src/prepared-runtime.mjs";
import { createPreparedReleaseBinding } from "../../../services/scanner/src/prepared-binding.mjs";
import { removeFixtureSnapshot } from "../../../services/scanner/src/snapshot.mjs";
import { AdmissionBlockedError, runArtifact } from "../src/index.mjs";

const exec = promisify(execFile), repo = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const tools = ["first", "second"].map(name => ({ name, inputSchema: { type: "object", properties: { linger: { type: "boolean" } }, additionalProperties: false }, annotations: { readOnlyHint: true, destructiveHint: false } }));
const modern = (message) => ({ jsonrpc: "2.0", ...message, params: { ...message.params, _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": { name: "prepared-gateway-test", version: "1" }, "io.modelcontextprotocol/clientCapabilities": {} } } });
const wire = (...messages) => messages.map(modern).map(JSON.stringify).join("\n") + "\n";
const call = (name, id = 2, args = {}) => ({ id, method: "tools/call", params: { name, arguments: args } });
const docker = async args => (await exec("docker", args, { timeout: 10000, maxBuffer: 131072 })).stdout.trim();
const ownedContainers = async () => (await docker(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "label=io.mcpshield.gateway.owner"])).split("\n").filter(Boolean).sort();

// Actual Docker/Node execution with an ephemeral, explicitly synthetic issuer. No chain/quorum claim is made here.
test("prepared npm image → observed identity → signed Gateway: full tools, isolation, revocation, timeout and EOF cleanup", {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== "1" || !process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE,
  timeout: 300000,
}, async () => {
  assert.equal(process.platform, "linux");
  const workspace = await mkdtemp(join(tmpdir(), "mcpshield-prepared-gateway-docker-")), root = join(workspace, "source");
  const before = await ownedContainers();
  let prepared, server;
  try {
    await mkdir(root);
    const pkg = { name: "synthetic-gateway-fixture", version: "1.0.0", bin: "server.js" };
    await writeFile(join(root, "package.json"), JSON.stringify(pkg));
    await writeFile(join(root, "package-lock.json"), JSON.stringify({ name: pkg.name, version: pkg.version, lockfileVersion: 3, packages: { "": { name: pkg.name, version: pkg.version } } }));
    await writeFile(join(root, "server.js"), [
      "const assert=require('node:assert/strict'),fs=require('node:fs'),readline=require('node:readline');",
      `const tools=${JSON.stringify(tools)};`,
      // The observer uses the non-root host UID for mount ownership; Gateway pins 1000.
      "function check(){ assert.ok(process.getuid()>0); assert.throws(()=>fs.readFileSync('/etc/passwd'),{code:'ERR_ACCESS_DENIED'});",
      "assert.throws(()=>fs.writeFileSync('/app/should-not-exist','synthetic'),{code:'ERR_ACCESS_DENIED'});",
      "assert.throws(()=>require('node:child_process').spawnSync('/bin/false'),{code:'ERR_ACCESS_DENIED'});",
      "if(process.execArgv.includes('--disallow-code-generation-from-strings')){assert.equal(process.getuid(),1000); assert.throws(()=>eval('1+1'),EvalError); assert.deepEqual(Object.keys(require('node:os').networkInterfaces()),['lo']);}",
      "assert.equal(process.env.MCPSHIELD_CONTROL_TOKEN,undefined); return 'SYNTHETIC_ISOLATION_OK'; }",
      "readline.createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);if(!Object.hasOwn(m,'id'))return;let result;",
      "if(m.method==='initialize')result={protocolVersion:m.params.protocolVersion,capabilities:{tools:{}},serverInfo:{name:'synthetic-gateway-fixture',version:'1.0.0'}};",
      "else if(m.method==='tools/list')result=m.params?.cursor==='second'?{tools:[tools[1]]}:{tools:[tools[0]],nextCursor:'second'};",
      "else if(m.method==='tools/call'){try{result={content:[{type:'text',text:check()+':'+m.params.name}]};if(m.params.arguments?.linger)setInterval(()=>{},1000);}catch{result={isError:true,content:[{type:'text',text:'SYNTHETIC_ISOLATION_FAILED'}]};}}else result={};",
      "process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result})+'\\n');process.stderr.write('SYNTHETIC_CANDIDATE_STDERR_MUST_NOT_LEAK\\n');});",
    ].join("\n"));
    const source = await artifactDigest(root);
    prepared = await prepareNpmClosure({ root, sourceDigest: source, sourceTreeDigest: source,
      builderImageDigest: process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE, platform: { os: "linux", architecture: "amd64" } });
    assert.deepEqual(prepared.issues, []); assert.equal(prepared.phase, "CLOSURE_PREPARED");
    const observed = await observePreparedRuntime({ descriptor: prepared.descriptor, expectedDescriptorDigest: prepared.descriptorDigest,
      probePlan: { scenarios: [
        { scenarioId: "normal-first", kind: "NORMAL", goal: "Read synthetic fixture output.", toolName: "first", argumentsJson: "{}" },
        { scenarioId: "adversarial-second", kind: "ADVERSARIAL", goal: "Exercise synthetic permission boundaries.", toolName: "second", argumentsJson: "{}" },
      ] } });
    assert.deepEqual(observed.report.issues, []);
    assert.equal(observed.report.checks.normalToolCallsSucceeded, true, 'SYNTHETIC_NORMAL_ISOLATION_CHECK_FAILED');
    assert.equal(observed.report.checks.adversarialToolCallsSucceeded, true, 'SYNTHETIC_ADVERSARIAL_ISOLATION_CHECK_FAILED');
    assert.equal(observed.report.steps.discovery.pages, 2);
    assert.equal(observed.report.ready, false); // Observation itself does not approve a release.
    assert.equal(verifyEvidenceBundle(observed.bundle, observed.bundle.manifest.root), true);
    const binding = createPreparedReleaseBinding({ sourceReleaseId: `0x${"1".repeat(64)}`, descriptor: observed.observedDescriptor,
      executionPolicy: JSON.parse(observed.bundle.files["runtime/execution-policy.json"]) });
    const identity = { schemaVersion: "mcpshield.gateway-prepared.v1", ...exactReleaseIdentity({ toolId: `npm:${pkg.name}`, ...binding }), binding, tools };
    const identityFile = join(workspace, "gateway.json"); await writeFile(identityFile, JSON.stringify(identity), { mode: 0o600 });
    const keys = generateKeyPairSync("ed25519");
    const context = { publicKey: keys.publicKey.export({ type: "spki", format: "pem" }), keyId: "synthetic-prepared-key", policyHash: `0x${"a".repeat(64)}`,
      tenantId: "synthetic-prepared-tenant", apiToken: "SYNTHETIC_ISSUER_TOKEN_ONLY", chainId: 31337, registryContract: `0x${"b".repeat(40)}`, validatorSetVersion: 1 };
    let requests = 0, revokeAt = Infinity, unsigned = false;
    server = createServer(async (request, response) => {
      assert.equal(request.url, "/v1/admission/check"); assert.equal(request.headers.authorization, `Bearer ${context.apiToken}`);
      const chunks = []; for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks));
      assert.equal(body.releaseId, identity.releaseId); assert.equal(body.artifactDigest, binding.artifactDigest); assert.equal(body.toolSurfaceHash, binding.toolSurfaceHash);
      const revoked = ++requests >= revokeAt, now = Date.now();
      const snapshot = { schemaVersion: "1.0.0", keyId: context.keyId, releaseId: body.releaseId, artifactDigest: body.artifactDigest, toolSurfaceHash: body.toolSurfaceHash,
        policyHash: context.policyHash, tenantId: context.tenantId, operationClass: body.operationClass, chainId: context.chainId,
        registryContract: context.registryContract, validatorSetVersion: 1, observedBlock: 123, blockHash: `0x${"c".repeat(64)}`,
        issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 30000).toISOString(),
        decision: revoked ? "BLOCK" : "ALLOW", status: revoked ? "REVOKED" : "VERIFIED", reasonCode: revoked ? "RELEASE_REVOKED" : "RELEASE_VERIFIED", reportUrl: `/v1/releases/${body.releaseId}` };
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ snapshot, ...(unsigned ? {} : { signature: sign(null, Buffer.from(canonicalJson(snapshot)), keys.privateKey).toString("base64url") }) }));
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const apiBaseUrl = `http://127.0.0.1:${server.address().port}`;
    const options = { ...context, apiBaseUrl, mode: "live", admissionMode: "strict", preparedIdentityPath: identityFile, capture: true };
    // Independent synthetic deployments per case: do not erase terminal revocation.
    let scenario = 0;
    const freshOptions = () => {
      requests = 0; context.registryContract = `0x${(++scenario).toString(16).padStart(40, "0")}`;
      return { ...options, registryContract: context.registryContract };
    };
    const input = wire({ id: 1, method: "tools/list" }, { id: 2, method: "tools/list", params: { cursor: "second" } }, call("second", 3));
    const safe = await runArtifact({ ...freshOptions(), input });
    assert.equal(safe.code, 0); assert.equal(safe.decision.source, "LIVE"); assert.equal(safe.decision.cacheHit, false); assert.equal(requests, 3);
    const output = safe.stdout.trim().split("\n").map(JSON.parse);
    assert.deepEqual(output.map(value => value.id), [1, 2, 3]); assert.equal(output[1].result.tools[0].name, "second");
    assert.equal(output[2].result.content[0].text, "SYNTHETIC_ISOLATION_OK:second");
    assert.equal(safe.stdout.includes("mcpshield."), false); assert.equal(safe.stderr.includes("SYNTHETIC_CANDIDATE_STDERR_MUST_NOT_LEAK"), false);
    assert.deepEqual(await ownedContainers(), before);
    for (const when of [1, 2, 3]) {
      requests = 0; revokeAt = when;
      await assert.rejects(runArtifact({ ...freshOptions(), input: wire(call("first")) }), error => error instanceof AdmissionBlockedError && error.decision.releaseStatus === "REVOKED");
      assert.equal(requests, when); assert.deepEqual(await ownedContainers(), before);
    }
    requests = 0; revokeAt = Infinity; unsigned = true;
    await assert.rejects(runArtifact({ ...freshOptions(), input }), /invalid proof metadata/);
    assert.equal(requests, 1); assert.deepEqual(await ownedContainers(), before); unsigned = false;
    requests = 0;
    await assert.rejects(runArtifact({ ...freshOptions(), input: wire(call("first", 1, { linger: true })), executionTimeoutMs: 2000 }), /timed out/);
    assert.deepEqual(await ownedContainers(), before);
    // The real stdio CLI also removes a still-running container on EOF and on a later denied call.
    const env = { ...process.env, MCPSHIELD_MODE: "live", MCPSHIELD_PREPARED_IDENTITY: identityFile, MCPSHIELD_API_URL: apiBaseUrl,
      MCPSHIELD_POLICY_HASH: context.policyHash, MCPSHIELD_CACHE_PUBLIC_KEY: context.publicKey, MCPSHIELD_CACHE_KEY_ID: context.keyId,
      MCPSHIELD_TENANT_ID: context.tenantId, MCPSHIELD_CONTROL_TOKEN: context.apiToken, MCPSHIELD_CHAIN_ID: String(context.chainId),
      MCPSHIELD_REGISTRY_CONTRACT: context.registryContract, MCPSHIELD_VALIDATOR_SET_VERSION: "1", MCPSHIELD_ADMISSION_MODE: "strict" };
    for (const key of ["MCPSHIELD_ARTIFACT_DIR", "MCPSHIELD_CONTROL_RELEASE_ID", "MCPSHIELD_RECEIPT_DB", "MCPSHIELD_ADMISSION_CACHE_FILE"]) delete env[key];
    const cli = (input) => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["apps/gateway/src/index.mjs", "stdio", "--prepared-identity", identityFile], { cwd: repo, env, stdio: ["pipe", "pipe", "pipe"] });
      let stdout = "", stderr = ""; let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; child.kill("SIGTERM"); }, 15000);
      child.stdout.on("data", chunk => { stdout += chunk; }); child.stderr.on("data", chunk => { stderr += chunk; });
      child.once("error", error => { clearTimeout(timer); reject(error); }); child.stdin.on("error", () => {});
      child.once("close", code => { clearTimeout(timer); timedOut ? reject(Error("SYNTHETIC_CLI_TIMEOUT")) : resolve({ code, stdout, stderr }); });
      child.stdin.end(input);
    });
    requests = 0; const eof = await cli(wire(call("first", 1, { linger: true })));
    assert.equal(eof.stdout.includes("SYNTHETIC_ISOLATION_OK:first"), true); assert.equal(eof.stderr.includes("SYNTHETIC_CANDIDATE_STDERR_MUST_NOT_LEAK"), false);
    assert.deepEqual(await ownedContainers(), before);
    requests = 0; revokeAt = 4;
    const later = await cli(wire(call("first", 1), call("second", 2)));
    assert.equal(requests, 4); assert.notEqual(later.code, 0); assert.equal(later.stdout.includes("SYNTHETIC_ISOLATION_OK:second"), false);
    assert.equal(later.stderr.includes("RELEASE_REVOKED"), true); assert.deepEqual(await ownedContainers(), before);
  } finally {
    await new Promise(resolve => server ? server.close(resolve) : resolve());
    await prepared?.cleanup?.();
    await removeFixtureSnapshot(workspace);
    assert.deepEqual(await ownedContainers(), before);
  }
});
