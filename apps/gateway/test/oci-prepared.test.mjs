import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2-identity.mjs";
import { canonicalJson } from "../../../services/scanner/src/evidence.mjs";
import { createOciReleaseBinding, ociExecutionPolicy } from "../../../services/scanner/src/oci-binding.mjs";
import { checkedOciConfig, ociHash, OCI_SOURCE_BUDGET_PROFILE, OCI_OBSERVATION_POLICY } from "../../../services/resolver/src/oci-runtime-descriptor.mjs";
import { toolSurfaceHash } from "../src/artifact.mjs";
import { createPreparedSnapshot, preparedDockerArgs, validatePreparedIdentity, validatePreparedImage } from "../src/prepared.mjs";
import { runArtifact } from "../src/index.mjs";
import { getSignedAdmission } from "../src/signed-admission.mjs";
import { breakGlassDigest, openBreakGlassSession, signBreakGlassGrant, verifyBreakGlassAudit } from "../src/break-glass.mjs";
import { syntheticRpc } from "./fixtures/synthetic-rpc.mjs";

// Authored contract fixture only: no scan, independent approval or native execution claim.
const digest = ociHash("synthetic-oci-gateway"), CID = "c".repeat(64), ownerLabel = "io.mcpshield.gateway.owner";
const tools = [{ name: "read_packaged_data", inputSchema: { type: "object", properties: {}, additionalProperties: false }, annotations: { readOnlyHint: true, destructiveHint: false } }];
const image = { Id: digest, Os: "linux", Architecture: "amd64", Config: { User: "root", Entrypoint: ["/bin/sh"], Cmd: ["/server.sh"], WorkingDir: "/", Env: ["PATH=/bin", "LANG=C", "PYTHONDONTWRITEBYTECODE=0"] } };
const descriptor = { schemaVersion: "mcpshield.oci-runtime.v1", profile: "oci-container-v1", stage: "OBSERVED", budgetProfile: OCI_SOURCE_BUDGET_PROFILE,
  sourceBytes: 1000, layerArchiveBytes: 2048, exportArchiveBytes: 2048, sourceTreeDigest: ociHash("original-source-tree"), sourceIndexDigest: digest, manifestDigest: digest,
  configDigest: digest, finalImageDigest: digest, imageDigestKind: "DOCKER_IMAGE_CONFIG_ID", platform: { os: "linux", architecture: "amd64" }, rootfsDigest: digest,
  entrypoint: { requestedPath: "/bin/sh", resolvedPath: "/bin/busybox", contentDigest: digest, linkChainDigest: digest }, ...checkedOciConfig({ config: image.Config }),
  toolSurfaceHash: toolSurfaceHash(tools), policy: OCI_OBSERVATION_POLICY };
const binding = createOciReleaseBinding({ sourceReleaseId: `0x${"1".repeat(64)}`, descriptor, executionPolicy: ociExecutionPolicy(Object.fromEntries(
  ["baseImageDigest", "baseCatalogueDigest", "trivyImageDigest", "databaseDigest", "observerDigest", "sinkImageDigest", "sinkCodeDigest"].map(name => [name, ociHash(name)]))) });
const identity = { schemaVersion: "mcpshield.gateway-prepared.v1", ...exactReleaseIdentity({ toolId: "oci:synthetic", ...binding }), binding, tools };
const container = owner => ({ Id: CID, Image: digest, Path: "/bin/sh", Args: ["/server.sh"], State: { Running: false }, Mounts: [],
  Config: { User: "1000:1000", WorkingDir: "/", Labels: { [ownerLabel]: owner }, Env: ["PATH=/bin", "LANG=C", "PYTHONDONTWRITEBYTECODE=1", "HOME=/nonexistent"], Healthcheck: { Test: ["NONE"] } },
  HostConfig: { NetworkMode: "none", ReadonlyRootfs: true, Privileged: false, Memory: 268435456, MemorySwap: 268435456, NanoCpus: 1000000000, PidsLimit: 64,
    CapDrop: ["ALL"], SecurityOpt: ["no-new-privileges"], Tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=32m" } } });

async function withIdentity(run) {
  const root = await mkdtemp(join(tmpdir(), "mcpshield-oci-gateway-contract-")), file = join(root, "identity.json");
  try { await writeFile(file, JSON.stringify(identity), { mode: 0o600 }); await run(file, root); }
  finally { await rm(root, { recursive: true, force: true }); }
}
function fakeDocker({ mutate = () => {}, inspectFailure = false, engine = ["name=seccomp,profile=builtin"] } = {}) {
  const calls = [], starts = []; let value, exists = false;
  return { calls, starts, platform: "linux", async inspectOci(input) {
    assert.equal(canonicalJson(input.descriptor), canonicalJson(descriptor)); assert.equal(input.expectedDescriptorDigest, binding.descriptorDigest);
    assert.equal(input.retainReviewSources, false); assert.equal(input.timeoutMs, 40000); calls.push(["independent-local-inspection"]);
    if (inspectFailure) throw Error("PRIVATE_DOCKER_FAILURE");
  }, async command(args) {
    calls.push(args);
    if (args[0] === "image") return JSON.stringify(image);
    if (args[0] === "info") return JSON.stringify(engine);
    if (args[0] === "create") { value = container(args[args.indexOf("--label") + 1].split("=")[1]); mutate(value); exists = true; return CID; }
    if (args[1] === "inspect") return JSON.stringify(value);
    if (args[1] === "ls") return exists ? CID : "";
    if (args[0] === "rm") { assert.deepEqual(args, ["rm", "--force", CID]); exists = false; return CID; }
    assert.fail("UNEXPECTED_SYNTHETIC_DOCKER_COMMAND");
  }, start(...args) { starts.push(args); const child = new EventEmitter(); queueMicrotask(() => child.emit("spawn")); return child; } };
}

test("OCI envelope commits six manifest fields, native descriptor and all anchors; phase/boolean/mutable runtime fields cannot authorize", () => {
  assert.deepEqual(validatePreparedIdentity(identity), identity); validatePreparedImage(image, binding);
  for (const alter of [v => v.ready = true, v => v.phase = "COMPLETE", v => v.binding.approved = true, v => v.binding.sourceReleaseId = `0x${"2".repeat(64)}`,
    v => v.binding.executionPolicy.trust.databaseDigest = ociHash("other"), v => v.binding.descriptor.rootfsDigest = ociHash("other"),
    v => v.binding.descriptor.entrypoint.contentDigest = ociHash("other"), v => v.binding.descriptor.argv.push("--injected"),
    v => v.binding.executionPolicy.gateway.hostMounts = ["/private"], v => v.tools[0].description = "changed", v => v.toolId = `0x${"2".repeat(64)}`]) {
    const value = structuredClone(identity); alter(value); assert.throws(() => validatePreparedIdentity(value), /PREPARED_/);
  }
  for (const alter of [v => v.Id = ociHash("other"), v => v.Config.Cmd = ["/other.sh"], v => v.Architecture = "arm64", v => v.Config.WorkingDir = "/tmp",
    v => v.Config.Env.push("LD_PRELOAD=/private.so"), v => v.Config.Env.push("API_TOKEN=SYNTHETIC"), v => v.Config.Env.push("PATH=/other"),
    v => v.Config.Volumes = { "/private": {} }, v => v.Config.OnBuild = ["RUN true"]]) {
    const value = structuredClone(image); alter(value); assert.throws(() => validatePreparedImage(value, binding), /PREPARED_/);
  }
  const args = preparedDockerArgs(identity, "12345678-1234-1234-1234-123456789abc");
  for (const flag of ["--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--no-healthcheck", "--memory=256m", "--memory-swap=256m", "--cpus=1", "--pids-limit=64", "--user=1000:1000"]) assert.ok(args.includes(flag));
  assert.deepEqual(args.slice(-3), ["--entrypoint=/bin/sh", digest, "/server.sh"]);
  assert.deepEqual(args.filter(arg => arg.startsWith("--env=")), ["--env=HOME=/nonexistent", "--env=PYTHONDONTWRITEBYTECODE=1"]);
  assert.equal(args.some(arg => /^--(?:mount|volume|privileged|permission)(?:=|$)/.test(arg)), false);
});

test("OCI independent local inspection and default seccomp precede creation; no unsigned demo can enter", async () => withIdentity(async file => {
  const docker = fakeDocker(), snapshot = await createPreparedSnapshot(file, docker);
  assert.deepEqual(docker.calls.map(args => args[0]), ["image", "info", "independent-local-inspection"]);
  assert.equal(snapshot.preparedProfile, "oci-container-v1"); assert.equal(docker.starts.length, 0);
  await snapshot.spawn(async () => { assert.equal(docker.starts.length, 0); }); await snapshot.cleanup();
  assert.deepEqual(docker.starts[0], ["docker", ["start", "--attach", "--interactive", CID], { shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] }]);
  for (const options of [{ inspectFailure: true }, { engine: [] }, { engine: ["name=seccomp,profile=unconfined"] }]) {
    const failed = fakeDocker(options); await assert.rejects(createPreparedSnapshot(file, failed), /^Error: PREPARED_OCI_/);
    assert.equal(failed.calls.some(args => args[0] === "create"), false);
  }
  for (const mode of ["mock", "replay"]) await assert.rejects(runArtifact({ preparedIdentityPath: file, input: "", mode, policyHash: `0x${"1".repeat(64)}` }), /SIGNED_LIVE/);
}));

test("OCI actual container config drift or revoked pre-start admission cannot execute and removes only the owned container", async () => withIdentity(async file => {
  for (const mutate of [v => v.Config.Env.push("HOST_TOKEN=SYNTHETIC"), v => v.Config.Env.push("LANG=C"), v => v.Config.User = "0:0",
    v => v.Args = ["-c", "unexpected"], v => v.Path = "/bin/other", v => v.Config.WorkingDir = "/tmp", v => v.Config.Healthcheck = { Test: ["CMD", "/bin/true"] },
    v => v.HostConfig.SecurityOpt.push("seccomp=unconfined"), v => v.HostConfig.MemorySwap = -1, v => v.HostConfig.Privileged = true,
    v => v.HostConfig.NetworkMode = "host", v => v.HostConfig.PidMode = "host", v => v.HostConfig.CapAdd = ["SYS_ADMIN"], v => v.HostConfig.Binds = ["/private:/private"],
    v => v.Mounts.push({ Type: "bind", Destination: "/var/run/docker.sock" }), v => v.HostConfig.Devices = [{}], v => v.HostConfig.Tmpfs["/tmp"] = "rw,size=32m",
    v => v.HostConfig.IpcMode = "container:synthetic-other", v => v.HostConfig.IpcMode = "shareable",
    v => v.HostConfig.Tmpfs["/tmp"] += ",exec", v => v.HostConfig.Tmpfs["/tmp"] += ",size=1g"]) {
    const docker = fakeDocker({ mutate }), snapshot = await createPreparedSnapshot(file, docker);
    await assert.rejects(snapshot.spawn(async () => {}), /PREPARED_/); assert.equal(docker.starts.length, 0); assert.equal(docker.calls.filter(args => args[0] === "rm").length, 1);
  }
  const docker = fakeDocker(), snapshot = await createPreparedSnapshot(file, docker);
  await assert.rejects(snapshot.spawn(async () => { throw Error("SYNTHETIC_SIGNED_REVOKED"); }), /SYNTHETIC_SIGNED_REVOKED/);
  assert.equal(docker.starts.length, 0); assert.equal(docker.calls.filter(args => args[0] === "rm").length, 1);
}));

const issuer = generateKeyPairSync("ed25519");
const context = snapshot => ({ identity: snapshot, publicKey: issuer.publicKey.export({ type: "spki", format: "pem" }), keyId: "synthetic-oci-issuer",
  policyHash: `0x${"d".repeat(64)}`, chainId: 1337, registryContract: `0x${randomBytes(20).toString("hex")}`, validatorSetVersion: 1,
  tenantId: "synthetic-oci", operationClass: "READ_PRIVATE", apiToken: "SYNTHETIC_LOCAL_CREDENTIAL", apiBaseUrl: "https://synthetic.invalid", timeoutMs: 100,
  cacheFile: null, indexer: null, rpc: null, admissionMode: "balanced" });
function signed(options, status = "VERIFIED", changes = {}) {
  const now = Date.now(), snapshot = { schemaVersion: "1.0.0", keyId: options.keyId, releaseId: options.identity.releaseId,
    artifactDigest: options.identity.artifactDigest, toolSurfaceHash: options.identity.toolSurfaceHash, policyHash: options.policyHash, chainId: options.chainId,
    registryContract: options.registryContract, tenantId: options.tenantId, operationClass: options.operationClass, validatorSetVersion: 1, observedBlock: 2, blockHash: `0x${"2".repeat(64)}`,
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 30000).toISOString(), decision: status === "VERIFIED" ? "ALLOW" : "BLOCK", status,
    reasonCode: `RELEASE_${status}`, reportUrl: `/v1/releases/${options.identity.releaseId}`, ...changes };
  return { snapshot, signature: sign(null, Buffer.from(canonicalJson(snapshot)), issuer.privateKey).toString("base64url") };
}
const unavailable = async () => new Response("", { status: 503 });

test("OCI snapshot reuses authenticated read-only cache; explicit denial, invalid or expired proof never becomes permission", async () => withIdentity(async file => {
  const docker = fakeDocker(), snapshot = await createPreparedSnapshot(file, { ...docker, admissionMode: "balanced" }), options = context(snapshot);
  try {
    const fresh = await getSignedAdmission({ ...options, fetchImpl: async () => Response.json(signed(options)) });
    assert.equal(fresh.decisionSource, "API");
    await snapshot.spawn(async () => { const cached = await getSignedAdmission({ ...options, fetchImpl: unavailable }); assert.equal(cached.decisionSource, "CACHE"); assert.equal(cached.cacheHit, true); });
    assert.equal(docker.starts.length, 1);
    await assert.rejects(getSignedAdmission({ ...options, operationClass: "WRITE_EXTERNAL", fetchImpl: unavailable }));
    for (const response of [{ ...signed(options), signature: "A".repeat(86) }, signed(options, "VERIFIED", { issuedAt: new Date(Date.now() - 60000).toISOString(), expiresAt: new Date(Date.now() - 30000).toISOString() })]) {
      await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => Response.json(response) }));
    }
    const denied = await getSignedAdmission({ ...options, fetchImpl: async () => Response.json(signed(options, "REVOKED")) });
    assert.equal(denied.decision, "BLOCK");
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => Response.json(signed(options)) }), /previously revoked/);
  } finally { await snapshot.cleanup(); }
}));

test("OCI direct RPC uses complete local identity, blocks known revocation and never bypasses signature or high-risk policy", async () => withIdentity(async file => {
  const snapshot = await createPreparedSnapshot(file, fakeDocker()), rpc = await syntheticRpc("oci-native-contract");
  Object.assign(rpc.identity, { ...snapshot, toolId: identity.toolId });
  const options = { ...context(snapshot), chainId: rpc.chainId, registryContract: rpc.registryContract, admissionMode: "strict", rpc: { rpcUrls: rpc.rpcUrls, confirmations: 2, timeoutMs: 1000 } };
  try {
    for (const response of [new Response("", { status: 403 }), Response.json({ ...signed(options), signature: "A".repeat(86) })]) {
      await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => response })); assert.equal(rpc.requests.length, 0);
    }
    const allow = await getSignedAdmission({ ...options, fetchImpl: unavailable }); assert.equal(allow.decisionSource, "DIRECT_RPC"); assert.equal(allow.decision, "ALLOW"); assert.equal(allow.cacheHit, false);
    const requestCount = rpc.requests.length;
    await assert.rejects(getSignedAdmission({ ...options, operationClass: "WRITE_EXTERNAL", fetchImpl: unavailable }), /HIGH_RISK/); assert.equal(rpc.requests.length, requestCount);
    await assert.rejects(getSignedAdmission({ ...options, identity: { ...snapshot, manifestDigest: ociHash("unbound-manifest") }, fetchImpl: unavailable }), /STATUS_UNAVAILABLE/);
    rpc.mode = "revoked";
    const revoked = await getSignedAdmission({ ...options, fetchImpl: unavailable }); assert.equal(revoked.releaseStatus, "REVOKED"); assert.equal(revoked.decision, "BLOCK");
    await assert.rejects(getSignedAdmission({ ...options, fetchImpl: async () => Response.json(signed(options)) }), /previously revoked/);
  } finally { await snapshot.cleanup(); await rpc.close(); }
}));

test("OCI emergency uses the unchanged private one-session/one-call claim without changing normal BLOCK or image isolation", async () => withIdentity(async (file, root) => {
  const firstDocker = fakeDocker(), secondDocker = fakeDocker(), first = await createPreparedSnapshot(file, firstDocker), second = await createPreparedSnapshot(file, secondDocker);
  const options = context(first), operator = generateKeyPairSync("ed25519"), now = Date.now();
  const grantContext = { releaseId: first.releaseId, artifactDigest: first.artifactDigest, manifestDigest: first.manifestDigest, toolSurfaceHash: first.toolSurfaceHash,
    policyHash: options.policyHash, chainId: options.chainId, registryContract: options.registryContract, tenantId: options.tenantId };
  const grant = { schemaVersion: "mcpshield.break-glass-grant.v1", keyId: "synthetic-oci-operator", grantId: randomUUID(), actorId: "private-oci-operator", reasonText: "Synthetic native contract test only",
    issuedAt: now, expiresAt: now + 10000, ...grantContext, toolName: tools[0].name, operationClass: "READ_PRIVATE", argumentsDigest: breakGlassDigest({}) };
  const paths = { configPath: join(root, "operator.json"), grantPath: join(root, "grant.json") }, auditKeyFile = join(root, "audit.key");
  const config = { schemaVersion: "mcpshield.break-glass-config.v1", keyId: grant.keyId, publicKey: operator.publicKey.export({ type: "spki", format: "pem" }),
    clientInfo: { name: "synthetic-oci-client", version: "1" }, auditFile: join(root, "audit.sqlite"), auditKeyFile, allowedCalls: [{ releaseId: first.releaseId, toolName: grant.toolName, operationClass: grant.operationClass }] };
  await writeFile(auditKeyFile, randomBytes(32).toString("hex"), { mode: 0o600 }); await writeFile(paths.configPath, JSON.stringify(config), { mode: 0o600 });
  await writeFile(paths.grantPath, JSON.stringify(signBreakGlassGrant(grant, operator.privateKey.export({ type: "pkcs8", format: "pem" }))), { mode: 0o600 });
  const a = openBreakGlassSession(paths, grantContext, tools), b = openBreakGlassSession(paths, grantContext, tools), block = { decision: "BLOCK", releaseStatus: "REVOKED", reasonCode: "RELEASE_REVOKED" };
  try {
    await first.spawn(async () => a.claim(block), () => a.assertCurrent());
    await assert.rejects(second.spawn(async () => b.claim(block), () => b.assertCurrent()), /AUDIT_OR_REPLAY_REJECTED/);
    assert.equal(firstDocker.starts.length, 1); assert.equal(secondDocker.starts.length, 0);
    const call = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: grant.toolName, arguments: {} } };
    assert.throws(() => a.call({ ...call, params: { ...call.params, arguments: { unbound: true } } }, block), /CALL_SCOPE_OR_REPLAY/);
    a.call(call, block); assert.throws(() => a.call(call, block), /CALL_SCOPE_OR_REPLAY/); assert.equal(block.releaseStatus, "REVOKED");
    assert.throws(() => openBreakGlassSession(paths, { ...grantContext, manifestDigest: ociHash("different-OCI-policy") }, tools), /IDENTITY_MISMATCH/);
  } finally { a.close(); b.close(); await first.cleanup(); await second.cleanup(); }
  assert.equal(verifyBreakGlassAudit(paths.configPath).count, 2);
}));
