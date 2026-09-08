import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { promisify } from "node:util";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2-identity.mjs";
import { validatePreparedReleaseBinding } from "../../../services/scanner/src/prepared-binding.mjs";
import { canonicalJson } from "../../../services/scanner/src/evidence.mjs";
import { toolSurfaceHash } from "./artifact.mjs";

const runFile = promisify(execFile);
const OWNER_LABEL = "io.mcpshield.gateway.owner";
const sha = /^sha256:[a-f0-9]{64}$/, id = /^0x[a-f0-9]{64}$/, containerId = /^[a-f0-9]{64}$/;
const fail = (code) => { throw new Error(code); };
const dockerJson = (text) => { try { return JSON.parse(text); } catch { fail("PREPARED_DOCKER_RESPONSE_INVALID"); } };
const exact = (value, fields) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join() === [...fields].sort().join();

export function validatePreparedIdentity(value) {
  if (!exact(value, ["schemaVersion", "releaseId", "toolId", "binding", "tools"]) || value.schemaVersion !== "mcpshield.gateway-prepared.v1" || !id.test(value.releaseId) || !id.test(value.toolId) || !validatePreparedReleaseBinding(value.binding)) fail("PREPARED_IDENTITY_INVALID");
  const { binding, tools } = value;
  if (!Array.isArray(tools) || tools.length > 128 || tools.some(tool => !tool || typeof tool.name !== "string" || !tool.name || tool.name.length > 128 || /[\x00-\x1f\x7f]/.test(tool.name) || !tool.inputSchema || typeof tool.inputSchema !== "object" || Array.isArray(tool.inputSchema)) || new Set(tools.map(tool => tool.name)).size !== tools.length || toolSurfaceHash(tools) !== binding.toolSurfaceHash) fail("PREPARED_TOOL_SURFACE_INVALID");
  if (exactReleaseIdentity({ toolId: value.toolId, ...binding }).releaseId !== value.releaseId) fail("PREPARED_RELEASE_ID_MISMATCH");
  return structuredClone(value);
}

async function readIdentity(filename) {
  if (typeof filename !== "string" || !filename) fail("PREPARED_IDENTITY_FILE_REQUIRED");
  let file;
  try {
    file = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > 1_048_576) fail("PREPARED_IDENTITY_FILE_INVALID");
    const bytes = Buffer.alloc(stat.size + 1); let offset = 0;
    while (offset < bytes.length) { const { bytesRead } = await file.read(bytes, offset, bytes.length - offset); if (!bytesRead) break; offset += bytesRead; }
    if (offset !== stat.size) fail("PREPARED_IDENTITY_FILE_INVALID");
    return validatePreparedIdentity(JSON.parse(bytes.subarray(0, offset).toString("utf8")));
  } catch (error) { if (/^PREPARED_[A-Z_]+$/.test(error.message)) throw error; fail("PREPARED_IDENTITY_FILE_INVALID"); }
  finally { await file?.close(); }
}

export function validatePreparedImage(image, binding) {
  if (!sha.test(binding.finalImageDigest) || image?.Id !== binding.finalImageDigest || image.Os !== binding.platform.os || image.Architecture !== binding.platform.architecture || image.Config?.User !== "1000:1000" || Object.keys(image.Config?.Volumes ?? {}).length) fail("PREPARED_IMAGE_IDENTITY_MISMATCH");
  if (!Array.isArray(image.Config.Env) || image.Config.Env.some(entry => typeof entry !== "string" || !entry.includes("=") || /^(?:NODE_OPTIONS|NODE_PATH|LD_[A-Z_]+|DYLD_[A-Z_]+)=.+/i.test(entry))) fail("PREPARED_IMAGE_ENV_UNSAFE");
}

export function preparedDockerArgs(identity, owner) {
  if (!/^[a-f0-9-]{36}$/.test(owner)) fail("PREPARED_OWNER_INVALID");
  const { binding } = identity;
  return ["create", "--pull=never", "--name", `mcpshield-gateway-${owner}`, "--label", `${OWNER_LABEL}=${owner}`,
    "--network=none", "--read-only", "--user=1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--no-healthcheck",
    "--memory=128m", "--memory-swap=128m", "--cpus=0.5", "--pids-limit=64", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m", "--workdir=/app", "--interactive",
    "--entrypoint=/usr/local/bin/node", binding.finalImageDigest, ...binding.executionPolicy.gateway.nodeArguments, binding.descriptor.argv[1]];
}

function validateContainer(value, identity, owner) {
  const h = value?.HostConfig, binding = identity.binding;
  if (!Array.isArray(value?.Args) || !Array.isArray(h?.CapDrop) || !Array.isArray(h.SecurityOpt) || typeof h.Tmpfs?.["/tmp"] !== "string") fail("PREPARED_CONTAINER_POLICY_MISMATCH");
  if (!containerId.test(value?.Id ?? "") || value.Config?.Labels?.[OWNER_LABEL] !== owner || value.Image !== binding.finalImageDigest || value.Config?.User !== "1000:1000" || value.Config.WorkingDir !== "/app" || value.Path !== "/usr/local/bin/node" || canonicalJson(value.Args) !== canonicalJson([...binding.executionPolicy.gateway.nodeArguments, binding.descriptor.argv[1]]) || value.State?.Running !== false ||
    h?.NetworkMode !== "none" || h.ReadonlyRootfs !== true || h.Privileged !== false || h.Memory !== 134_217_728 || h.MemorySwap !== 134_217_728 || h.NanoCpus !== 500_000_000 || h.PidsLimit !== 64 || canonicalJson(h.CapDrop) !== '["ALL"]' || (h.CapAdd?.length ?? 0) !== 0 || !h.SecurityOpt?.some(option => ["no-new-privileges", "no-new-privileges:true"].includes(option)) ||
    (h.Binds?.length ?? 0) !== 0 || value.Mounts?.some(mount => mount.Type !== "tmpfs" || mount.Destination !== "/tmp") || Object.keys(h.Tmpfs ?? {}).join() !== "/tmp" || !["noexec", "nosuid", "nodev", "size=64m"].every(option => h.Tmpfs["/tmp"].split(",").includes(option))) fail("PREPARED_CONTAINER_POLICY_MISMATCH");
}

async function dockerCommand(args) {
  try { return (await runFile("docker", args, { timeout: 5_000, maxBuffer: 131_072, windowsHide: true, shell: false })).stdout; }
  catch { fail("PREPARED_DOCKER_COMMAND_FAILED"); } // Do not expose daemon/candidate stderr or operator credentials.
}

// Dependencies are injected only by trusted unit tests. The CLI/API never accepts command/image/path overrides.
export async function createPreparedSnapshot(filename, { command = dockerCommand, start = spawn, platform = process.platform } = {}) {
  const value = await readIdentity(filename);
  if (platform !== "linux") fail("PREPARED_LINUX_DOCKER_REQUIRED");
  const image = dockerJson(await command(["image", "inspect", value.binding.finalImageDigest, "--format", "{{json .}}"]));
  validatePreparedImage(image, value.binding);
  const owner = randomUUID(), name = `mcpshield-gateway-${owner}`;
  let creationAttempted = false, started = false, cid, cleaning, creation, cancelled = false;
  const onSignal = () => { cancelled = true; void cleanup().catch(() => { process.stderr.write('{"event":"prepared_cleanup_failed","code":"PREPARED_CONTAINER_CLEANUP_FAILED"}\n'); }); };
  const cleanup = () => cleaning ??= (async () => {
    if (!creationAttempted) return;
    try {
      await creation?.catch(() => {});
      // A failed create can still have created a container. Resolve only this generated name, then verify its ownership.
      const found = (await command(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter", `name=^/${name}$`])).trim();
      if (!found) return;
      if (!containerId.test(found) || (cid && found !== cid)) fail("PREPARED_CONTAINER_OWNER_MISMATCH");
      const owned = dockerJson(await command(["container", "inspect", found, "--format", "{{json .}}"]));
      if (owned.Id !== found || owned.Config?.Labels?.[OWNER_LABEL] !== owner) fail("PREPARED_CONTAINER_OWNER_MISMATCH");
      await command(["rm", "--force", found]);
    } catch { fail("PREPARED_CONTAINER_CLEANUP_FAILED"); }
    finally { for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.removeListener(signal, onSignal); }
  })();
  return { releaseId: value.releaseId, artifactDigest: value.binding.artifactDigest, manifestDigest: value.binding.manifestDigest,
    toolSurfaceHash: value.binding.toolSurfaceHash, tools: value.tools, runtimePolicyIssues: [], prepared: true,
    cleanup,
    async spawn(beforeStart) {
      if (started || cleaning) fail("PREPARED_RUNTIME_ALREADY_USED");
      if (typeof beforeStart !== "function") fail("PREPARED_ADMISSION_CHECK_REQUIRED");
      started = true;
      try {
        for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.once(signal, onSignal);
        creationAttempted = true;
        creation = command(preparedDockerArgs(value, owner));
        cid = (await creation).trim();
        if (!containerId.test(cid)) fail("PREPARED_CONTAINER_ID_INVALID");
        if (cancelled || cleaning) fail("PREPARED_RUNTIME_CANCELLED");
        const container = dockerJson(await command(["container", "inspect", cid, "--format", "{{json .}}"]));
        validateContainer(container, value, owner);
        // Creating is not executing: recheck signed admission immediately before the actual start.
        await beforeStart();
        if (cancelled || cleaning) fail("PREPARED_RUNTIME_CANCELLED");
        const child = start("docker", ["start", "--attach", "--interactive", cid], { shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
        try { await once(child, "spawn"); } catch { fail("PREPARED_DOCKER_START_FAILED"); }
        return child;
      } catch (error) { await cleanup(); throw error; }
    },
  };
}
