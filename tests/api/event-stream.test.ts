import assert from "node:assert/strict";
import { test } from "node:test";
import { setTimeout as pause } from "node:timers/promises";
import { request as httpRequest } from "node:http";
import Fastify from "fastify";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { registerEventStream } from "../../apps/api/src/event-stream.js";
import type { Credential } from "../../apps/api/src/control-plane.js";

const limits = { pollMs: 20, heartbeatMs: 40, idleMs: 1000, maxAgeMs: 2000, queryTimeoutMs: 80, global: 3, perTenant: 2 };
const credentials: Credential[] = [{ tenantId: "tenant-a", token: "synthetic-stream-reader-a", role: "reader" }, { tenantId: "tenant-b", token: "synthetic-stream-reader-b", role: "reader" }, { tenantId: "tenant-c", token: "synthetic-stream-reader-c", role: "admin" }];
async function until(predicate: () => boolean, timeoutMs = 3000) {
  const deadline = performance.now() + timeoutMs;
  while (!predicate()) { if (performance.now() >= deadline) assert.fail("stream condition timeout"); await pause(10); }
}
async function connect(base: string, token = credentials[0].token, headers = {}) {
  // Native one-shot sockets avoid fetch-pool replacement sockets obscuring the server-shutdown check.
  const request = httpRequest(`${base}/v1/events/stream`, { agent: false, headers: { authorization: `Bearer ${token}`, ...headers } });
  const raw = await new Promise<import("node:http").IncomingMessage>((resolve, reject) => { request.once("response", resolve); request.once("error", reject); request.end(); });
  let text = "", ended = false;
  const finished = new Promise<void>((resolve) => {
    const done = () => { ended = true; resolve(); };
    raw.on("data", (chunk) => { text += chunk.toString(); if (text.length > 65536) raw.destroy(); });
    raw.once("end", done); raw.once("close", done); raw.once("error", done);
  });
  const response = { status: raw.statusCode, headers: new Headers(Object.fromEntries(Object.entries(raw.headers).filter(([, value]) => value !== undefined).map(([key, value]) => [key, String(value)]))) };
  return { response, get text() { return text; }, get ended() { return ended; }, finished, stop: async () => { request.destroy(); raw.destroy(); await finished; } };
}
const status = (url: string, headers = {}) => new Promise<number>((resolve, reject) => {
  const request = httpRequest(url, { agent: false, headers }, (response) => { response.resume(); response.once("end", () => resolve(response.statusCode!)); });
  request.once("error", reject); request.end();
});
async function setup(overrides = {}, production = false, backpressure?: "write" | "length") {
  const store = await ControlStore.open(), active = credentials.map((entry) => ({ ...entry }));
  const app = production ? await buildApp({ adminApiToken: "unused-legacy-admin", scannerApiToken: "unused-legacy-scanner", controlPlane: {
    store, credentials: active, evidencePath: "unused-stream-evidence", artifactPath: "unused-stream-artifacts", evidenceKey: "d".repeat(64) } }) : Fastify();
  let simulated = false;
  if (!production) {
    if (backpressure) app.addHook("onRequest", async (_request, reply) => {
      if (simulated) return; simulated = true;
      // Target the actual route's native backpressure branch without buffering megabytes over a test socket.
      if (backpressure === "write") reply.raw.write = (() => false) as typeof reply.raw.write;
      else Object.defineProperty(reply.raw, "writableLength", { get: () => 5000 });
    });
    await app.register(async (api) => registerEventStream(api, store, (header) => {
      const identity = active.find((entry) => `Bearer ${entry.token}` === header);
      if (!identity) throw Object.assign(new Error("UNAUTHORIZED"), { statusCode: 401 }); return identity;
    }, { ...limits, ...overrides }), { prefix: "/v1" });
    app.addHook("onClose", () => store.close());
  }
  await app.listen({ host: "127.0.0.1", port: 0 });
  const base = `http://127.0.0.1:${(app.server.address() as any).port}`;
  return { app, store, active, base };
}

test("production stream authenticates readers, ignores replay IDs and never exposes event payloads", async () => {
  const f = await setup({}, true); let stream;
  try {
    assert.equal(await status(`${f.base}/v1/events/stream`), 401);
    assert.equal(await status(`${f.base}/v1/events/stream?token=${credentials[0].token}`), 401);
    assert.equal(await status(`${f.base}/v1/events/stream`, { authorization: "Bearer incorrect-token" }), 401);
    assert.equal(await status(`${f.base}/v1/events/stream?tenant=tenant-b`, { authorization: `Bearer ${credentials[0].token}` }), 400);
    await f.store.event("tenant-a", null, "synthetic.secret", { raw: "synthetic-private-event-body" });
    stream = await connect(f.base, credentials[0].token, { "last-event-id": "pretend-private-cursor" });
    assert.equal(stream.response.status, 200); assert.match(stream.response.headers.get("content-type")!, /text\/event-stream/);
    assert.match(stream.response.headers.get("cache-control")!, /no-store/);
    await until(() => stream!.text.includes('"reason":"INITIAL"'));
    assert.doesNotMatch(stream.text, /tenant-a|synthetic-private|pretend-private|synthetic.secret|eventId|^id:/m);
    await stream.stop();
    stream = await connect(f.base, credentials[0].token, { "last-event-id": "unused-reconnect-id" });
    await until(() => stream!.text.includes('"reason":"INITIAL"'));
  } finally { await stream?.stop(); await f.app.close(); }
});

test("only changes in the tenant's bounded event-ID set cause resync; heartbeat and credential revocation are bounded", async () => {
  const f = await setup(); const a = await connect(f.base), b = await connect(f.base, credentials[1].token);
  try {
    await until(() => a.text.includes("INITIAL") && b.text.includes("INITIAL"));
    await f.store.event("tenant-b", null, "synthetic.private", { raw: "private-payload-must-not-stream" });
    await until(() => b.text.includes("EVENTS_CHANGED"));
    assert.equal(a.text.includes("EVENTS_CHANGED"), false);
    await f.store.event("tenant-a", null, "changed", { secret: "private-payload-must-not-stream" });
    await until(() => a.text.includes("EVENTS_CHANGED") && a.text.includes(": heartbeat"));
    const changes = (a.text.match(/EVENTS_CHANGED/g) ?? []).length;
    const events = f.store.events.bind(f.store); f.store.events = async (...args) => (await events(...args)).reverse();
    await pause(80); assert.equal((a.text.match(/EVENTS_CHANGED/g) ?? []).length, changes);
    assert.doesNotMatch(a.text + b.text, /private-payload|tenant-|secret|eventId|^id:/m);
    f.active.splice(0, 1); await until(() => a.ended);
    assert.equal(await status(`${f.base}/v1/events/stream`, { authorization: `Bearer ${credentials[0].token}` }), 401);
  } finally { await a.stop(); await b.stop(); await f.app.close(); }
});

test("per-tenant/global caps release on abort and shutdown closes active SSE before DB shutdown", async () => {
  const f = await setup(); const streams = [];
  try {
    streams.push(await connect(f.base), await connect(f.base));
    assert.equal(await status(`${f.base}/v1/events/stream`, { authorization: `Bearer ${credentials[0].token}` }), 429);
    streams.push(await connect(f.base, credentials[1].token));
    assert.equal(await status(`${f.base}/v1/events/stream`, { authorization: `Bearer ${credentials[2].token}` }), 429);
    await streams[0].stop(); await pause(30);
    streams.push(await connect(f.base, credentials[2].token)); assert.equal(streams.at(-1)!.response.status, 200);
    const started = performance.now(); await f.app.close(); assert.ok(performance.now() - started < 1000);
    await Promise.all(streams.map((stream) => stream.finished)); assert.ok(streams.every((stream) => stream.ended));
  } finally { await Promise.all(streams.map((stream) => stream.stop())); await f.app.close(); }
});

test("idle timeout, max lifetime and initial query deadline force reconnect rather than unbounded streams", async () => {
  const idle = await setup({ idleMs: 100, maxAgeMs: 500 }); const first = await connect(idle.base);
  try { await until(() => first.ended); assert.match(first.text, /heartbeat/); assert.match(first.text, /RECONNECT/); }
  finally { await first.stop(); await idle.app.close(); }
  const lifetime = await setup({ idleMs: 100, maxAgeMs: 180 }); const second = await connect(lifetime.base);
  const producer = (async () => { while (!second.ended) { await lifetime.store.event("tenant-a", null, "synthetic.changed", {}); await pause(15); } })();
  try { await until(() => second.ended); assert.match(second.text, /EVENTS_CHANGED/); assert.match(second.text, /RECONNECT/); }
  finally { await second.stop(); await producer; await lifetime.app.close(); }
  const timeout = await setup({ queryTimeoutMs: 40, global: 1, perTenant: 1 });
  try {
    const read = timeout.store.events.bind(timeout.store); timeout.store.events = () => new Promise(() => {});
    assert.equal(await status(`${timeout.base}/v1/events/stream`, { authorization: `Bearer ${credentials[0].token}` }), 503);
    timeout.store.events = read; const recovered = await connect(timeout.base); assert.equal(recovered.response.status, 200); await recovered.stop();
  } finally { await timeout.app.close(); }
});

test("native write backpressure drops slow readers and frees admission slots without queues", async () => {
  for (const mode of ["write", "length"] as const) {
    const f = await setup({ global: 1, perTenant: 1 }, false, mode);
    try {
      let slow;
      try { slow = await connect(f.base); await until(() => slow!.ended); } catch (error: any) { assert.equal(error.code, "ECONNRESET"); }
      await slow?.stop(); await pause(20);
      const next = await connect(f.base); assert.equal(next.response.status, 200); await next.stop();
    } finally { await f.app.close(); }
  }
});
