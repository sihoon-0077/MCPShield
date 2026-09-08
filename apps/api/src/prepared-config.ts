import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

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
  const digest = (path: string) => `sha256:${createHash("sha256").update(readFileSync(new URL(path, import.meta.url))).digest("hex")}`;
  return { ...checkedPreparedConfig(config), collectorDigest: digest("../../../services/scanner/src/mcp-probe.cjs"),
    observerDigest: digest("../../../services/scanner/src/observer-preload.cjs") };
}
