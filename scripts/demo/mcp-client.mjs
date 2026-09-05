import { resolve } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";

export function createGatewayClient({ root, artifactDir, mode, replayFile, apiUrl }) {
  const env = {
    ...getDefaultEnvironment(),
    MCPSHIELD_ARTIFACT_DIR: artifactDir,
    MCPSHIELD_MODE: mode,
  };
  if (replayFile) env.MCPSHIELD_REPLAY_FILE = replayFile;
  if (apiUrl) env.MCPSHIELD_API_URL = apiUrl;

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(root, "apps/gateway/src/index.mjs"), "stdio"],
    cwd: root,
    stderr: "pipe",
    env,
  });
  const client = new Client({ name: "mcpshield-demo", version: "1.0.0" });
  let stderr = "";
  transport.stderr?.setEncoding("utf8");
  transport.stderr?.on("data", (chunk) => { stderr += chunk; });
  return {
    client,
    transport,
    stderr: () => stderr,
    close: () => client.close().catch(() => transport.close()),
  };
}
