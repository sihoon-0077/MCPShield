import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createGatewayClient } from "./mcp-client.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const fixtureRoot = resolve(process.env.MCPSHIELD_FIXTURE_ROOT ?? resolve(root, "demo/fixtures"));
const replay = resolve(process.env.MCPSHIELD_REPLAY_FILE ?? resolve(here, "replay.json"));

function gatewayTransport(version) {
  return createGatewayClient({
    root,
    artifactDir: resolve(fixtureRoot, `mail-mcp-${version}`),
    mode: "replay",
    replayFile: replay,
  });
}

const safe = gatewayTransport("1.0.0");
try {
  await safe.client.connect(safe.transport);
  const listed = await safe.client.listTools();
  assert.deepEqual(listed.tools.map(({ name }) => name), ["list_messages"]);

  const called = await safe.client.callTool({ name: "list_messages", arguments: {} });
  assert.notEqual(called.isError, true);
  const text = called.content.find((item) => item.type === "text")?.text;
  assert.deepEqual(JSON.parse(text), { ok: true, messages: [{ id: "demo-1", subject: "Welcome" }] });
} finally {
  await safe.close();
}

const blocked = gatewayTransport("1.0.1");
await assert.rejects(blocked.client.connect(blocked.transport));
await blocked.close().catch(() => {});
const admission = blocked.stderr().split(/\r?\n/).flatMap((line) => {
  try { return [JSON.parse(line)]; } catch { return []; }
}).find((record) => record.event === "admission");
assert.deepEqual(
  { releaseId: admission?.releaseId, decision: admission?.decision, status: admission?.status, source: admission?.source },
  { releaseId: "mail-mcp@1.0.1", decision: "BLOCK", status: "REVOKED", source: "REPLAY" },
);

console.log(JSON.stringify({ source: "REPLAY", protocol: "MCP stdio", safe: "initialize + tools/list + tools/call PASS", malicious: "BLOCK before initialize", result: "PASS" }, null, 2));
