// @ts-expect-error Shared installed-file trust anchors are ESM JavaScript.
import { readTrustedPreparedIdentity } from "../../../services/scanner/src/prepared-trust.mjs";
import type { ControlOptions } from "./control-plane.js";

export interface PreparedConfig { builderImageDigest: string; platform: { os: "linux"; architecture: "amd64" | "arm64" }; binName?: string }
export function checkedPreparedConfig(value: PreparedConfig): PreparedConfig {
  if (!value || Object.keys(value).some((key) => !["builderImageDigest", "platform", "binName"].includes(key))
    || !/^sha256:[a-f0-9]{64}$/.test(value.builderImageDigest) || !value.platform
    || Object.keys(value.platform).sort().join() !== "architecture,os" || value.platform.os !== "linux"
    || !["amd64", "arm64"].includes(value.platform.architecture)
    || value.binName !== undefined && !/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/.test(value.binName)) throw new Error("INVALID_PREPARED_CONFIG");
  return structuredClone(value);
}
// Read trusted installation files, not API-supplied hashes or candidate-mounted files.
export function preparedTrust(config: PreparedConfig) {
  return { ...checkedPreparedConfig(config), ...readTrustedPreparedIdentity(config.builderImageDigest) };
}
export function checkedPreparedTrust(proof: any, config?: PreparedConfig) {
  if (!proof || !config) return undefined;
  const local = preparedTrust(config);
  if (["builderImageDigest", "collectorDigest", "observerDigest"].some((key) => proof[key] !== local[key])
    || proof.platform?.os !== local.platform.os || proof.platform?.architecture !== local.platform.architecture) return undefined;
  return proof;
}
export async function inspectPreparedRuntime(binding: any, config: PreparedConfig, inspect?: (input: Record<string, any>) => Promise<Record<string, any>>) {
  const local = preparedTrust(config);
  if (binding.descriptor.builderImageDigest !== local.builderImageDigest || binding.platform.os !== local.platform.os
    || binding.platform.architecture !== local.platform.architecture) throw new Error("PREPARED_TRUST_ANCHOR_MISMATCH");
  // @ts-expect-error Shared image export is ESM JavaScript. The validator never injects a reader from an API response.
  const read = inspect ?? (await import("../../../services/scanner/src/prepared-scan.mjs")).readTrustedPreparedRuntime;
  const proof = await read({ descriptor: binding.descriptor, expectedDescriptorDigest: binding.descriptorDigest, builderImageDigest: local.builderImageDigest });
  if (!checkedPreparedTrust(proof, config)) throw new Error("PREPARED_TRUST_ANCHOR_MISMATCH");
  return proof;
}
export function preparedAi(options: ControlOptions) {
  const ai = options.scannerOptions;
  return ai?.allowRemoteAi ? { allowRemoteAi: true, provider: ai.aiProvider, model: ai.aiModel, url: ai.aiUrl, token: ai.aiToken, timeoutMs: ai.aiTimeoutMs,
    disclosurePolicy: checkedAiDisclosurePolicy(ai.aiDisclosurePolicy, ai.aiProvider, ai.aiUrl) } : { allowRemoteAi: false };
}
export function checkedAiDisclosurePolicy(value: unknown, provider: unknown, endpoint: unknown): "LOCAL_CONTRACT_TEST" | undefined {
  if (value === undefined) return undefined; // Never infer test authorization from allowRemoteAi or a loopback address.
  if (value !== "LOCAL_CONTRACT_TEST") throw new Error("AI_DISCLOSURE_POLICY_INVALID");
  let url;
  try { url = new URL(typeof endpoint === "string" ? endpoint : ""); } catch { throw new Error("AI_DISCLOSURE_LOCAL_CONTRACT_REQUIRED"); }
  if (provider !== "custom" || !["127.0.0.1", "[::1]"].includes(url.hostname) || !["http:", "https:"].includes(url.protocol)
    || url.username || url.password || url.hash) throw new Error("AI_DISCLOSURE_LOCAL_CONTRACT_REQUIRED");
  return value;
}
