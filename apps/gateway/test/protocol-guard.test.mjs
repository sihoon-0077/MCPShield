import assert from "node:assert/strict";
import test from "node:test";
import { runtimeSurfaceGuards } from "../src/protocol-guard.mjs";
import { toolSurfaceHash } from "../src/artifact.mjs";

const tools = [{ name: "alpha", description: "Read alpha" }, { name: "beta", description: "Read beta" }];
const metadata = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": { name: "protocol-test", version: "1" }, "io.modelcontextprotocol/clientCapabilities": {}, "example.test/trace": "preserve-this-value" };
const modern = (id, method = "tools/call", params = {}) => ({ jsonrpc: "2.0", id, method, params: { name: "alpha", arguments: {}, ...params, _meta: metadata } });
const write = (stream, value) => new Promise((resolve, reject) => stream.write(typeof value === "string" ? value : `${JSON.stringify(value)}\n`, (error) => error ? reject(error) : resolve()));

function harness({ result = (request) => request.params.cursor === "second" ? { tools: [tools[1]] } : { tools: [tools[0]], nextCursor: "second" }, beforeCall = async () => {}, timeoutMs = 100 } = {}) {
  const probes = [], forwarded = [], returned = [];
  const guards = runtimeSurfaceGuards(toolSurfaceHash(tools), tools, beforeCall, { timeoutMs,
    sendInternal: async (request) => {
      probes.push(request);
      const value = result(request);
      if (value !== undefined) await write(guards.responses, { jsonrpc: "2.0", id: request.id, result: value });
    },
  });
  guards.requests.on("data", (chunk) => forwarded.push(chunk.toString()));
  guards.responses.on("data", (chunk) => returned.push(chunk.toString()));
  for (const stream of [guards.requests, guards.responses]) stream.on("error", () => {});
  return { ...guards, probes, forwarded, returned };
}

test("invalid envelopes and legacy pre-initialization calls cannot reach the child or admission hook", async () => {
  for (const request of [
    { jsonrpc: "1.0", id: 1, method: "tools/call", params: { name: "undeclared" } },
    { jsonrpc: "2.0", id: {}, method: "tools/call", params: { name: "alpha" } },
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "alpha" } },
  ]) {
    let checks = 0;
    const guards = harness({ beforeCall: async () => { checks++; } });
    try {
      await assert.rejects(write(guards.requests, request), /envelope|initialization/);
      assert.equal(checks, 0); assert.equal(guards.forwarded.length, 0); assert.equal(guards.probes.length, 0);
    } finally { guards.close(); }
  }
});

test("legacy revisions complete initialization; modern requests preserve metadata without a handshake", async () => {
  for (const version of ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"]) {
    let checks = 0;
    const guards = harness({ beforeCall: async () => { checks++; } });
    try {
      if (version !== "2026-07-28") {
        await write(guards.requests, { jsonrpc: "2.0", id: "init", method: "initialize", params: { protocolVersion: version, capabilities: {}, clientInfo: { name: "test", version: "1" } } });
        await write(guards.responses, { jsonrpc: "2.0", id: "init", result: { protocolVersion: version, capabilities: {}, serverInfo: { name: "test", version: "1" } } });
        await write(guards.requests, { jsonrpc: "2.0", method: "notifications/initialized" });
      }
      const call = version === "2026-07-28" ? modern(1) : { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "alpha", arguments: {} } };
      const original = ` ${JSON.stringify(call)} \r\n`;
      await write(guards.requests, original);
      assert.equal(guards.forwarded.at(-1), original);
      assert.equal(guards.probes.length, 2); assert.equal(checks, 1);
      assert.equal(guards.returned.length, version === "2026-07-28" ? 0 : 1);
      if (version === "2026-07-28") assert.deepEqual(guards.probes[0].params._meta, metadata);
    } finally { guards.close(); }
  }
});

test("pagination is fully verified before exposing first page and private request IDs never escape", async () => {
  const guards = harness();
  try {
    await write(guards.requests, modern(1, "tools/list", { name: undefined, arguments: undefined }));
    assert.equal(guards.probes.length, 2); assert.equal(guards.returned.length, 0);
    const first = { jsonrpc: "2.0", id: 1, result: { tools: [tools[0]], nextCursor: "second", _meta: { "example.test/result": "unchanged" } } };
    const bytes = `${JSON.stringify(first)}\n`;
    await write(guards.responses, bytes);
    assert.deepEqual(guards.returned, [bytes]);
    await write(guards.requests, modern(2, "tools/list", { cursor: "second" }));
    await write(guards.responses, { jsonrpc: "2.0", id: 2, result: { tools: [tools[1]] } });
    assert.doesNotMatch(guards.returned.join(""), /mcpshield\./);
  } finally { guards.close(); }
});

test("pagination drift, duplicate names, looping cursor and a stalled page all fail before forwarding", async () => {
  for (const result of [
    () => ({ tools: [{ name: "unexpected" }] }),
    () => ({ tools: [tools[0], tools[0]] }),
    () => ({ tools: [tools[0]], nextCursor: "loop" }),
    () => undefined,
  ]) {
    const guards = harness({ result, timeoutMs: 15 });
    try {
      await assert.rejects(write(guards.requests, modern(1)), /drift|timed out/);
      assert.equal(guards.forwarded.length, 0); assert.equal(guards.returned.length, 0);
    } finally { guards.close(); }
  }
});

test("stateless envelope cannot be removed or downgraded after classification", async () => {
  for (const request of [
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "alpha" } },
    { ...modern(2), params: { ...modern(2).params, _meta: { ...metadata, "io.modelcontextprotocol/protocolVersion": "2025-11-25" } } },
  ]) {
    const guards = harness();
    try {
      await write(guards.requests, modern(1));
      await assert.rejects(write(guards.requests, request), /envelope/);
      assert.equal(guards.forwarded.length, 1);
    } finally { guards.close(); }
  }
});
