import { canonicalJson } from "../../../services/scanner/src/evidence.mjs";
import { checkedOciConfig } from "../../../services/resolver/src/oci-runtime-descriptor.mjs";

const fail = () => { throw new Error("PREPARED_OCI_RUNTIME_MISMATCH"); };
const fixedEnvironment = { HOME: "/nonexistent", PYTHONDONTWRITEBYTECODE: "1" };
const expectedEnvironment = image => Object.fromEntries([...image.Config.Env ?? [], ...Object.entries(fixedEnvironment).map(([name, value]) => `${name}=${value}`)].map(entry => {
  const separator = entry.indexOf("="); return [entry.slice(0, separator), entry.slice(separator + 1)];
}));

export function validateOciImage(image, binding) {
  if (image?.Id !== binding.finalImageDigest || image.Os !== binding.platform.os || image.Architecture !== binding.platform.architecture) fail();
  let runtime;
  try { runtime = checkedOciConfig({ config: image.Config }); } catch { fail(); }
  const descriptor = binding.descriptor;
  if (canonicalJson(runtime.argv) !== canonicalJson(descriptor.argv) || runtime.workingDirectory !== descriptor.workingDirectory || runtime.environmentDigest !== descriptor.environmentDigest) fail();
}

export async function inspectOciBinding(binding, inspect) {
  // Local image bytes are checked independently; phase/ready booleans are never authority.
  try {
    const read = inspect ?? (await import("../../../services/resolver/src/oci-runtime.mjs")).inspectImportedOciRuntime;
    await read({ descriptor: binding.descriptor, expectedDescriptorDigest: binding.descriptorDigest, retainReviewSources: false, timeoutMs: 40_000 });
  } catch { throw new Error("PREPARED_OCI_LOCAL_IMAGE_REJECTED"); }
}

export function ociDockerArgs(binding) {
  const { descriptor } = binding;
  return ["--memory=256m", "--memory-swap=256m", "--cpus=1", "--pids-limit=64", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m",
    `--workdir=${descriptor.workingDirectory}`, "--interactive", ...Object.entries(fixedEnvironment).map(([name, value]) => `--env=${name}=${value}`),
    `--entrypoint=${descriptor.argv[0]}`, binding.finalImageDigest, ...descriptor.argv.slice(1)];
}

export function validateOciContainer(value, binding, image) {
  const h = value?.HostConfig, config = value?.Config, descriptor = binding.descriptor;
  if (!h || !config || value.Path !== descriptor.argv[0] || !Array.isArray(value.Args) || canonicalJson(value.Args) !== canonicalJson(descriptor.argv.slice(1)) || config.WorkingDir !== descriptor.workingDirectory
    || config.User !== "1000:1000" || !Array.isArray(config.Healthcheck?.Test) || config.Healthcheck.Test.join() !== "NONE" || !Array.isArray(config.Env) || config.Env.length > 18
    || config.Env.some(entry => typeof entry !== "string" || !entry.includes("=")) || new Set(config.Env.map(entry => entry.split("=")[0])).size !== config.Env.length) fail();
  const env = Object.fromEntries(config.Env.map(entry => { const index = entry.indexOf("="); return [entry.slice(0, index), entry.slice(index + 1)]; }));
  if (canonicalJson(env) !== canonicalJson(expectedEnvironment(image)) || h.NetworkMode !== "none" || h.ReadonlyRootfs !== true || h.Privileged !== false
    || h.Memory !== 268_435_456 || h.MemorySwap !== 268_435_456 || h.NanoCpus !== 1_000_000_000 || h.PidsLimit !== 64
    || canonicalJson(h.CapDrop) !== '["ALL"]' || (h.CapAdd?.length ?? 0) !== 0 || !Array.isArray(h.SecurityOpt) || h.SecurityOpt.length !== 1
    || !["no-new-privileges", "no-new-privileges:true"].includes(h.SecurityOpt[0]) || h.PidMode || h.IpcMode === "host" || h.UTSMode === "host" || h.UsernsMode === "host"
    || (h.Binds?.length ?? 0) !== 0 || (h.Devices?.length ?? 0) !== 0 || (h.DeviceRequests?.length ?? 0) !== 0 || (h.VolumesFrom?.length ?? 0) !== 0
    || (h.Links?.length ?? 0) !== 0 || (h.ExtraHosts?.length ?? 0) !== 0 || Object.keys(h.PortBindings ?? {}).length !== 0
    || Object.keys(h.Tmpfs ?? {}).join() !== "/tmp" || typeof h.Tmpfs["/tmp"] !== "string"
    || !["noexec", "nosuid", "nodev", "size=32m"].every(option => h.Tmpfs["/tmp"].split(",").includes(option)) || !Array.isArray(value.Mounts)
    || value.Mounts.some(mount => mount.Type !== "tmpfs" || mount.Destination !== "/tmp")) fail();
}

export function validateOciEngine(options) {
  if (!Array.isArray(options) || !options.includes("name=seccomp,profile=builtin")) throw new Error("PREPARED_OCI_DEFAULT_SECCOMP_REQUIRED");
}
