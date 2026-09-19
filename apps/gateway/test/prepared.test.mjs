import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AbiCoder, id, keccak256 } from "ethers";
import { bytes32, exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2-identity.mjs";
import { createPreparedReleaseBinding, preparedExecutionPolicy, scopedPreparedExecutionPolicy } from "../../../services/scanner/src/prepared-binding.mjs";
import { scopedReviewPolicy } from "../../../services/scanner/src/scoped-policy.mjs";
import { createPreparedSnapshot, preparedDockerArgs, validatePreparedIdentity, validatePreparedImage } from "../src/prepared.mjs";
import { toolSurfaceHash } from "../src/artifact.mjs";
import { runArtifact } from "../src/index.mjs";
import { getSignedAdmission, verifyAdmissionSnapshot } from "../src/signed-admission.mjs";

const sha = (letter) => `sha256:${letter.repeat(64)}`;
const tools = ["first", "second"].map(name => ({ name, inputSchema: { type: "object", properties: {}, additionalProperties: false }, annotations: { readOnlyHint: true, destructiveHint: false } }));
const descriptor = { schemaVersion: "mcpshield.prepared-runtime.v1", stage: "CLOSURE_PREPARED", profile: "npm-closure-v1",
  sourceDigest: sha("a"), sourceTreeDigest: sha("b"), lockDigest: sha("c"), lockOrigin: "SUPPLIED", builderImageDigest: sha("d"),
  platform: { os: "linux", architecture: "amd64" }, finalImageDigest: sha("e"), toolSurfaceHash: toolSurfaceHash(tools),
  entrypoint: { path: "server.js", digest: sha("f") }, argv: ["/usr/local/bin/node", "/app/server.js"],
  policy: { acquisitionNetwork: "REGISTRY_ONLY_SEPARATE", installNetwork: "NONE", installScripts: "DISABLED", executionNetwork: "INTERNAL_SYNTHETIC_PROXY", user: "NON_ROOT", rootFilesystem: "READ_ONLY" } };
const binding = createPreparedReleaseBinding({ sourceReleaseId: `0x${"1".repeat(64)}`, descriptor,
  executionPolicy: preparedExecutionPolicy({ collectorDigest: sha("2"), observerDigest: sha("3"), egressAllowHosts: [] }) });
const identity = { schemaVersion: "mcpshield.gateway-prepared.v1", ...exactReleaseIdentity({ toolId: "npm:synthetic-prepared", ...binding }), binding, tools };
const partitions = [identity, ...["LOCAL_CONTRACT_TEST", "PROVIDER_EXECUTION"].map(mode => {
  const binding = createPreparedReleaseBinding({ sourceReleaseId: identity.binding.sourceReleaseId, descriptor,
    executionPolicy: scopedPreparedExecutionPolicy({ collectorDigest: sha("2"), observerDigest: sha("3"), egressAllowHosts: [] }, scopedReviewPolicy(mode)) });
  return { ...identity, ...exactReleaseIdentity({ toolId: identity.toolId, ...binding }), binding };
})];
const image = () => ({ Id: binding.finalImageDigest, Os: "linux", Architecture: "amd64", Config: { User: "1000:1000", Env: ["PATH=/usr/local/bin:/usr/bin:/bin"], Volumes: null } });
const OWNER_LABEL = "io.mcpshield.gateway.owner", CID = "c".repeat(64);

async function withIdentity(run, value = identity) {
  const root = await mkdtemp(join(tmpdir(), "mcpshield-prepared-gateway-test-"));
  const file = join(root, "identity.json");
  try { await writeFile(file, typeof value === "string" ? value : JSON.stringify(value), { mode: 0o600 }); await run(file, root); }
  finally { await rm(root, { recursive: true, force: true }); }
}

function fakeDocker({ alter = () => {}, create = async () => CID, startError, ownerMismatch = false } = {}) {
  const commands = [], starts = []; let container, exists = false;
  const command = async args => {
    commands.push(args);
    if (args[0] === "image") return JSON.stringify(image());
    if (args[0] === "create") {
      const owner = args[args.indexOf("--label") + 1].split("=")[1];
      container = { Id: CID, Image: binding.finalImageDigest, Config: { User: "1000:1000", WorkingDir: "/app", Labels: { [OWNER_LABEL]: owner } },
        Path: "/usr/local/bin/node", Args: [...binding.executionPolicy.gateway.nodeArguments, "/app/server.js"], State: { Running: false }, Mounts: [],
        HostConfig: { NetworkMode: "none", ReadonlyRootfs: true, Privileged: false, Memory: 134217728, MemorySwap: 134217728,
          NanoCpus: 500000000, PidsLimit: 64, CapDrop: ["ALL"], CapAdd: null, SecurityOpt: ["no-new-privileges"], Binds: null, Tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=64m" } } };
      alter(container); exists = true;
      return create();
    }
    if (args[1] === "ls") { assert.match(args.at(-1), /^name=\^\/mcpshield-gateway-[a-f0-9-]{36}\$$/); return exists ? CID : ""; }
    if (args[1] === "inspect") {
      assert.equal(args[2], CID);
      return JSON.stringify(ownerMismatch ? { ...container, Config: { ...container.Config, Labels: { [OWNER_LABEL]: "another-owner" } } } : container);
    }
    if (args[0] === "rm") { assert.deepEqual(args, ["rm", "--force", CID]); exists = false; return CID; }
    assert.fail(`Unexpected Docker command: ${args[0]}`);
  };
  const start = (...args) => {
    starts.push(args); if (startError === true) throw Error("SYNTHETIC_START_FAILED");
    const child = new EventEmitter(); queueMicrotask(() => startError === "async" ? child.emit("error", Error("SYNTHETIC_PRIVATE_DAEMON_ERROR")) : child.emit("spawn")); return child;
  };
  return { command, start, commands, starts, platform: "linux" };
}

test("plain Node prepared identity uses the same four-field ABI commitment as Registry V2", () => {
  const input = { toolId: "npm:synthetic-prepared", artifactDigest: `sha256:${"a".repeat(64)}`, manifestDigest: `sha256:${"b".repeat(64)}`, toolSurfaceHash: `0x${"c".repeat(64)}` };
  const expected = keccak256(AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "bytes32", "bytes32"], [id(input.toolId), `0x${"a".repeat(64)}`, `0x${"b".repeat(64)}`, input.toolSurfaceHash]));
  assert.deepEqual(exactReleaseIdentity(input), { toolId: id(input.toolId), releaseId: expected });
  assert.equal(exactReleaseIdentity({ ...input, toolId: id(input.toolId) }).releaseId, expected);
  for (const field of ["toolId", "artifactDigest", "manifestDigest", "toolSurfaceHash"]) assert.notEqual(exactReleaseIdentity({ ...input, [field]: `0x${"d".repeat(64)}` }).releaseId, expected);
  assert.equal(bytes32(input.artifactDigest), `0x${"a".repeat(64)}`);
  assert.throws(() => bytes32("sha256:invalid"), /INVALID_DIGEST/);
});

test("prepared identity commits source, closure, execution policy and full raw tools without path/image overrides", () => {
  assert.deepEqual(validatePreparedIdentity(identity), identity);
  for (const mutate of [
    value => { value.releaseId = `0x${"9".repeat(64)}`; }, value => { value.toolId = `0x${"9".repeat(64)}`; },
    value => { value.image = "untrusted:latest"; }, value => { value.binding.sourceReleaseId = `0x${"9".repeat(64)}`; },
    value => { value.binding.finalImageDigest = "untrusted:latest"; }, value => { value.binding.platform.architecture = "arm64"; },
    value => { value.binding.descriptor.argv.push("--permission=false"); }, value => { value.binding.descriptor.entrypoint.path = "../host.js"; },
    value => { value.binding.executionPolicy.gateway.network = "HOST"; }, value => { value.binding.executionPolicy.gateway.nodeArguments.pop(); },
    value => { value.binding.executionPolicyDigest = sha("9"); }, value => { value.tools[0].description = "unattested text"; },
    value => { value.tools.push(value.tools[0]); }, value => { value.tools[0].inputSchema = []; },
  ]) { const changed = structuredClone(identity); mutate(changed); assert.throws(() => validatePreparedIdentity(changed), /PREPARED_/); }
});

test("actual image identity and executable environment must match the bound non-root profile", () => {
  validatePreparedImage(image(), binding);
  for (const mutate of [value => { value.Id = sha("f"); }, value => { value.Os = "windows"; }, value => { value.Architecture = "arm64"; },
    value => { value.Config.User = "root"; }, value => { value.Config.Volumes = { "/app": {} }; },
    ...["NODE_OPTIONS=--require=/injected.js", "NODE_PATH=/injected", "LD_PRELOAD=/injected.so", "DYLD_INSERT_LIBRARIES=/injected.so"].map(entry => value => { value.Config.Env.push(entry); }),
  ]) { const changed = image(); mutate(changed); assert.throws(() => validatePreparedImage(changed, binding), /PREPARED_IMAGE_/); }
  const args = preparedDockerArgs(identity, "12345678-1234-1234-1234-123456789abc");
  for (const flag of ["--pull=never", "--network=none", "--read-only", "--user=1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=128m", "--memory-swap=128m", "--cpus=0.5", "--pids-limit=64"]) assert.ok(args.includes(flag), flag);
  assert.deepEqual(args.slice(-5), [binding.finalImageDigest, ...binding.executionPolicy.gateway.nodeArguments, "/app/server.js"]);
  assert.equal(args.some(arg => /^--(?:mount|volume|env|publish|privileged)(?:=|$)/.test(arg)), false);
});

test("v1 and both scoped Node v2 modes retain separate identities with identical restricted Gateway arguments", () => {
  assert.equal(new Set(partitions.map(value => value.releaseId)).size, 3);
  const owner = "12345678-1234-1234-1234-123456789abc", args = preparedDockerArgs(identity, owner);
  for (const value of partitions) {
    assert.deepEqual(validatePreparedIdentity(value), value);
    assert.deepEqual(preparedDockerArgs(value, owner), args);
    for (const other of partitions.filter(other => other !== value)) {
      assert.throws(() => validatePreparedIdentity({ ...value, binding: other.binding }), /PREPARED_RELEASE_ID_MISMATCH/);
    }
  }
  for (const value of partitions.slice(1)) for (const mutate of [
    changed => { changed.binding.executionPolicy.semantic.evidenceMode = value.binding.executionPolicy.semantic.evidenceMode === "LOCAL_CONTRACT_TEST" ? "PROVIDER_EXECUTION" : "LOCAL_CONTRACT_TEST"; },
    changed => { changed.binding.executionPolicy.semantic.privacyScope.providerQuality = "CERTIFIED"; },
    changed => { delete changed.binding.executionPolicy.semantic; },
    changed => { changed.binding.executionPolicy.gateway.network = "HOST"; },
  ]) { const changed = structuredClone(value); mutate(changed); assert.throws(() => validatePreparedIdentity(changed), /PREPARED_IDENTITY_INVALID/); }
});

test("signed admission and cache cannot reuse v1 or cross-mode approvals, outlive expiry or undo revocation", async () => {
  const keys = generateKeyPairSync("ed25519"), now = Date.now();
  const shared = { publicKey: keys.publicKey.export({ type: "spki", format: "pem" }), keyId: "synthetic-scoped-key",
    policyHash: `0x${"8".repeat(64)}`, chainId: 31337, registryContract: `0x${"9".repeat(40)}`, validatorSetVersion: 1,
    tenantId: "synthetic-scoped-tenant", operationClass: "READ_PRIVATE", apiToken: "synthetic-token", cacheFile: null };
  // Keep even policyHash identical here to prove identity alone partitions the cache.
  const contexts = partitions.map(value => ({ ...shared, identity: { releaseId: value.releaseId, artifactDigest: value.binding.artifactDigest, toolSurfaceHash: value.binding.toolSurfaceHash } }));
  const snapshots = contexts.map(context => ({ schemaVersion: "1.0.0", keyId: shared.keyId, ...context.identity,
    decision: "ALLOW", status: "VERIFIED", reasonCode: "RELEASE_VERIFIED", policyHash: shared.policyHash,
    tenantId: shared.tenantId, operationClass: shared.operationClass, chainId: shared.chainId, registryContract: shared.registryContract,
    validatorSetVersion: 1, reportUrl: `/v1/releases/${context.identity.releaseId}`, observedBlock: 12, blockHash: `0x${"7".repeat(64)}`,
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 30_000).toISOString() }));
  const signed = snapshot => ({ snapshot, signature: sign(null, Buffer.from(JSON.stringify(Object.fromEntries(Object.keys(snapshot).sort().map(key => [key, snapshot[key]])))), keys.privateKey).toString("base64url") });
  const response = snapshot => async () => new Response(JSON.stringify(signed(snapshot)), { headers: { "content-type": "application/json" } });
  const offline = async () => { throw new TypeError("synthetic offline"); };
  for (let i = 0; i < contexts.length; i++) {
    const context = contexts[i], snapshot = snapshots[i], options = { ...context, apiBaseUrl: "http://127.0.0.1:3199", timeoutMs: 100, admissionMode: "balanced", now: () => now };
    assert.equal(verifyAdmissionSnapshot(signed(snapshot), { ...context, now }).decision, "ALLOW");
    for (let j = 0; j < contexts.length; j++) if (i !== j) assert.throws(() => verifyAdmissionSnapshot(signed(snapshot), { ...contexts[j], now }), /identity or policy mismatch/);
    assert.throws(() => verifyAdmissionSnapshot(signed(snapshot), { ...context, now: now + 30_000 }), /expired/);
    for (const change of [{ policyHash: `0x${"6".repeat(64)}` }, { tenantId: "other-tenant" }]) assert.throws(() => verifyAdmissionSnapshot(signed(snapshot), { ...context, ...change, now }), /identity or policy mismatch/);
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: offline }), /no matching signed cache/);
    assert.equal((await getSignedAdmission({ ...options, fetchImpl: response(snapshot) })).decision, "ALLOW");
    assert.equal((await getSignedAdmission({ ...options, fetchImpl: offline })).cacheHit, true);
  }
  for (let i = 0; i < contexts.length; i++) {
    const snapshot = snapshots[i], options = { ...contexts[i], apiBaseUrl: "http://127.0.0.1:3199", timeoutMs: 100, admissionMode: "balanced", now: () => now };
    await assert.rejects(getSignedAdmission({ ...options, now: () => now + 30_000, fetchImpl: offline }), /expired/);
    assert.equal((await getSignedAdmission({ ...options, fetchImpl: response({ ...snapshot, decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED" }) })).decision, "BLOCK");
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: response(snapshot) }), /previously revoked/);
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: offline }), /no matching signed cache/);
  }
});

test("operator identity files are bounded regular files; replay, missing MCP framing and ambiguous modes fail before Docker", async () => {
  for (const value of ["{bad-json", "x".repeat(1048577), { ...identity, privateKey: "SYNTHETIC_NOT_A_KEY" }]) await withIdentity(async file => {
    let called = false;
    await assert.rejects(createPreparedSnapshot(file, { platform: "linux", command: async () => { called = true; } }), /PREPARED_/);
    assert.equal(called, false);
  }, value);
  await withIdentity(async (file, root) => {
    await assert.rejects(createPreparedSnapshot(root), /PREPARED_IDENTITY_FILE_INVALID/);
    await assert.rejects(createPreparedSnapshot(file, { platform: "win32" }), /PREPARED_LINUX_DOCKER_REQUIRED/);
    if (process.platform === "linux") { const link = join(root, "symlink.json"); await symlink(file, link); await assert.rejects(createPreparedSnapshot(link), /PREPARED_IDENTITY_FILE_INVALID/); }
  });
  await assert.rejects(runArtifact({ preparedIdentityPath: "not-read" }), /PREPARED_MCP_INPUT_REQUIRED/);
  for (const mode of ["replay", "mock"]) await assert.rejects(runArtifact({ preparedIdentityPath: "not-read", input: "", mode, policyHash: `0x${"1".repeat(64)}` }), /PREPARED_SIGNED_LIVE_REQUIRED/);
  await assert.rejects(runArtifact({ preparedIdentityPath: "not-read", artifactDir: "not-read", input: "", mode: "live" }), /PREPARED_IDENTITY_AMBIGUOUS/);
});

test("container creation cannot execute before the second admission check; cleanup is exact-owner and idempotent", async () => withIdentity(async file => {
  const docker = fakeDocker(); const before = process.listenerCount("SIGTERM");
  const snapshot = await createPreparedSnapshot(file, docker);
  assert.equal(docker.commands.length, 1); assert.equal(docker.starts.length, 0);
  await snapshot.spawn(async () => { assert.equal(docker.starts.length, 0); assert.equal(docker.commands[1][0], "create"); });
  assert.deepEqual(docker.starts[0], ["docker", ["start", "--attach", "--interactive", CID], { shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] }]);
  await Promise.all([snapshot.cleanup(), snapshot.cleanup()]);
  assert.equal(docker.commands.filter(args => args[0] === "rm").length, 1);
  assert.equal(process.listenerCount("SIGTERM"), before);
  await assert.rejects(snapshot.spawn(async () => {}), /PREPARED_RUNTIME_ALREADY_USED/);
}));

test("revoked admission, Docker policy drift and start/create failure clean containers without executing candidates", async () => withIdentity(async file => {
  const cases = [
    { admit: async () => { throw Error("SYNTHETIC_REVOKED"); } },
    ...[value => { value.HostConfig.NetworkMode = "host"; }, value => { value.HostConfig.ReadonlyRootfs = false; },
      value => { value.HostConfig.MemorySwap = -1; }, value => { value.HostConfig.CapAdd = ["SYS_ADMIN"]; },
      value => { value.HostConfig.Binds = ["/host:/app"]; }, value => { value.Args = ["--permission=false", "/app/server.js"]; },
      value => { value.Args = undefined; }, value => { value.State.Running = true; },
    ].map(alter => ({ alter })),
    { create: async () => { throw Error("SYNTHETIC_CREATE_FAILED_AFTER_CREATE"); } },
  ];
  for (const options of cases) {
    const docker = fakeDocker(options), snapshot = await createPreparedSnapshot(file, docker);
    await assert.rejects(snapshot.spawn(options.admit ?? (async () => {})), /SYNTHETIC_|PREPARED_/);
    assert.equal(docker.starts.length, 0);
    assert.equal(docker.commands.filter(args => args[0] === "rm").length, 1);
  }
  const docker = fakeDocker({ startError: true }), snapshot = await createPreparedSnapshot(file, docker);
  await assert.rejects(snapshot.spawn(async () => {}), /SYNTHETIC_START_FAILED/);
  assert.equal(docker.commands.filter(args => args[0] === "rm").length, 1);
  const asyncDocker = fakeDocker({ startError: "async" }), asyncSnapshot = await createPreparedSnapshot(file, asyncDocker);
  await assert.rejects(asyncSnapshot.spawn(async () => {}), /^Error: PREPARED_DOCKER_START_FAILED$/);
  assert.equal(asyncDocker.commands.filter(args => args[0] === "rm").length, 1);
  const expiredDocker = fakeDocker(), expiredSnapshot = await createPreparedSnapshot(file, expiredDocker);
  let admissionAudited = false;
  await assert.rejects(expiredSnapshot.spawn(async () => { admissionAudited = true; }, () => { throw Error("BREAK_GLASS_EXPIRED"); }), /BREAK_GLASS_EXPIRED/);
  assert.equal(admissionAudited, true); assert.equal(expiredDocker.starts.length, 0);
  assert.equal(expiredDocker.commands.filter(args => args[0] === "rm").length, 1);
}));

test("cleanup refuses a foreign label and cancellation waits for pending create then removes the owned container", async () => withIdentity(async file => {
  const foreign = fakeDocker({ ownerMismatch: true }), rejected = await createPreparedSnapshot(file, foreign);
  await assert.rejects(rejected.spawn(async () => {}), /PREPARED_CONTAINER_CLEANUP_FAILED/);
  assert.equal(foreign.commands.some(args => args[0] === "rm"), false);
  let releaseCreate, created;
  const ready = new Promise(resolve => { created = resolve; });
  const docker = fakeDocker({ create: () => { created(); return new Promise(resolve => { releaseCreate = resolve; }); } });
  const before = process.listenerCount("SIGTERM"), snapshot = await createPreparedSnapshot(file, docker);
  const running = snapshot.spawn(async () => {});
  await ready; process.emit("SIGTERM"); releaseCreate(CID);
  await assert.rejects(running, /PREPARED_RUNTIME_CANCELLED/);
  assert.equal(docker.starts.length, 0);
  assert.equal(docker.commands.filter(args => args[0] === "rm").length, 1);
  assert.equal(process.listenerCount("SIGTERM"), before);
}));
