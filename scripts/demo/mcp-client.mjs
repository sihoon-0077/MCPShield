import { resolve } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";

// Operator-pinned admission context only; never inherit model keys or runtime injection.
export const gatewayControlEnvironmentKeys = [
  "MCPSHIELD_POLICY_HASH", "MCPSHIELD_CONTROL_RELEASE_ID", "MCPSHIELD_TENANT_ID",
  "MCPSHIELD_CACHE_PUBLIC_KEY", "MCPSHIELD_CACHE_KEY_ID", "MCPSHIELD_CHAIN_ID",
  "MCPSHIELD_REGISTRY_CONTRACT", "MCPSHIELD_VALIDATOR_SET_VERSION", "MCPSHIELD_CONTROL_TOKEN",
  "MCPSHIELD_API_HTTP_HOSTS", "MCPSHIELD_ADMISSION_TIMEOUT_MS",
];

export function createGatewayClient({ root, artifactDir, preparedIdentityPath, mode, replayFile, apiUrl, controlEnvironment = {} }) {
  if (Boolean(artifactDir) === Boolean(preparedIdentityPath)) throw new TypeError("exactly one artifact or prepared identity is required");
  for (const [key, value] of Object.entries(controlEnvironment)) {
    if (!gatewayControlEnvironmentKeys.includes(key) || typeof value !== "string") throw new TypeError("unsupported Gateway control environment");
  }
  const env = {
    ...getDefaultEnvironment(),
    ...controlEnvironment,
    ...(artifactDir ? { MCPSHIELD_ARTIFACT_DIR: artifactDir } : {}),
    MCPSHIELD_MODE: mode,
    MCPSHIELD_ADMISSION_MODE: "strict",
  };
  if (replayFile) env.MCPSHIELD_REPLAY_FILE = replayFile;
  if (apiUrl) env.MCPSHIELD_API_URL = apiUrl;

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(root, "apps/gateway/src/index.mjs"), "stdio", ...(preparedIdentityPath ? ["--prepared-identity", resolve(preparedIdentityPath)] : [])],
    cwd: root,
    stderr: "pipe",
    env,
  });
  const client = new Client({ name: "mcpshield-demo", version: "1.0.0" });
  let stderr = "";
  transport.stderr?.setEncoding("utf8");
  transport.stderr?.on("data", (chunk) => { stderr = (stderr + chunk).slice(-1_048_576); });
  return {
    client,
    transport,
    stderr: () => stderr,
    close: () => client.close().catch(() => transport.close()),
  };
}
