import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
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
  try { await writeFile(file, JSON.stringify(identity), { mode: 0o600 }); await run(file); }
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

test("OCI independent local inspection, strict signed settings and default seccomp precede creation", async () => withIdentity(async file => {
  const docker = fakeDocker(), snapshot = await createPreparedSnapshot(file, docker);
  assert.deepEqual(docker.calls.map(args => args[0]), ["image", "info", "independent-local-inspection"]);
  assert.equal(snapshot.preparedProfile, "oci-container-v1"); assert.equal(docker.starts.length, 0);
  await snapshot.spawn(async () => { assert.equal(docker.starts.length, 0); }); await snapshot.cleanup();
  assert.deepEqual(docker.starts[0], ["docker", ["start", "--attach", "--interactive", CID], { shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] }]);
  for (const options of [{ inspectFailure: true }, { engine: [] }, { engine: ["name=seccomp,profile=unconfined"] }]) {
    const failed = fakeDocker(options); await assert.rejects(createPreparedSnapshot(file, failed), /^Error: PREPARED_OCI_/);
    assert.equal(failed.calls.some(args => args[0] === "create"), false);
  }
  for (const options of [{ admissionMode: "balanced" }, { breakGlass: {} }]) {
    const failed = fakeDocker(); await assert.rejects(createPreparedSnapshot(file, { ...failed, ...options }), /STRICT_SIGNED/); assert.deepEqual(failed.calls, []);
  }
  for (const mode of ["mock", "replay"]) await assert.rejects(runArtifact({ preparedIdentityPath: file, input: "", mode, policyHash: `0x${"1".repeat(64)}` }), /SIGNED_LIVE/);
  await assert.rejects(runArtifact({ preparedIdentityPath: file, input: "", mode: "live", policyHash: `0x${"1".repeat(64)}`, admissionMode: "balanced" }), /STRICT_SIGNED/);
}));

test("OCI actual container config drift or revoked pre-start admission cannot execute and removes only the owned container", async () => withIdentity(async file => {
  for (const mutate of [v => v.Config.Env.push("HOST_TOKEN=SYNTHETIC"), v => v.Config.Env.push("LANG=C"), v => v.Config.User = "0:0",
    v => v.Args = ["-c", "unexpected"], v => v.Path = "/bin/other", v => v.Config.WorkingDir = "/tmp", v => v.Config.Healthcheck = { Test: ["CMD", "/bin/true"] },
    v => v.HostConfig.SecurityOpt.push("seccomp=unconfined"), v => v.HostConfig.MemorySwap = -1, v => v.HostConfig.Privileged = true,
    v => v.HostConfig.NetworkMode = "host", v => v.HostConfig.PidMode = "host", v => v.HostConfig.CapAdd = ["SYS_ADMIN"], v => v.HostConfig.Binds = ["/private:/private"],
    v => v.Mounts.push({ Type: "bind", Destination: "/var/run/docker.sock" }), v => v.HostConfig.Devices = [{}], v => v.HostConfig.Tmpfs["/tmp"] = "rw,size=32m"]) {
    const docker = fakeDocker({ mutate }), snapshot = await createPreparedSnapshot(file, docker);
    await assert.rejects(snapshot.spawn(async () => {}), /PREPARED_/); assert.equal(docker.starts.length, 0); assert.equal(docker.calls.filter(args => args[0] === "rm").length, 1);
  }
  const docker = fakeDocker(), snapshot = await createPreparedSnapshot(file, docker);
  await assert.rejects(snapshot.spawn(async () => { throw Error("SYNTHETIC_SIGNED_REVOKED"); }), /SYNTHETIC_SIGNED_REVOKED/);
  assert.equal(docker.starts.length, 0); assert.equal(docker.calls.filter(args => args[0] === "rm").length, 1);
}));
