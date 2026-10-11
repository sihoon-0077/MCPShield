import assert from "node:assert/strict";
import test from "node:test";
import { controlEventStream } from "../lib/control-events";

const url = new URL("http://127.0.0.1:3101/v1/events/stream"), token = "synthetic-stream-token-only";
const encode = (value: string) => new TextEncoder().encode(value);
const request = () => new Request("https://console.test/api/control/events/stream");

test("resync BFF forwards only the fixed vocabulary, bounds framing and never forwards arbitrary event data", async context => {
  context.mock.method(globalThis, "fetch", async (received: URL, init: RequestInit) => {
    assert.equal(received.href, url.href); assert.equal(init.redirect, "error");
    assert.deepEqual(init.headers, { accept: "text/event-stream", authorization: `Bearer ${token}` });
    const text = 'retry: 3000\r\n\r\n: heartbeat\r\n\r\nevent: resync\r\ndata: {"reason":"INITIAL","type":"RESYNC_REQUIRED"}\r\n\r\n';
    return new Response(new ReadableStream({ start(output) { for (const character of text) output.enqueue(encode(character)); output.close(); } }), { headers: { "content-type": "text/event-stream" } });
  });
  const response = await controlEventStream(request(), url, token);
  assert.match(response.headers.get("cache-control")!, /no-store/);
  assert.equal(await response.text(), 'retry: 3000\n\nevent: resync\ndata: {"type":"RESYNC_REQUIRED","reason":"INITIAL"}\n\n');
  for (const text of [
    'event: resync\ndata: {"type":"RESYNC_REQUIRED","reason":"INITIAL","privateKey":"SYNTHETIC_PRIVATE"}\n\n',
    'event: raw-release\ndata: {"privateData":"SYNTHETIC_PRIVATE"}\n\n',
    'event: resync\ndata: {"type":"RESYNC_REQUIRED","reason":"UNKNOWN"}\n\n',
    'event: resync\ndata: ' + "x".repeat(2049), " ".repeat(65537),
    'event: resync\ndata: {"type":"RESYNC_REQUIRED","reason":"INITIAL"}\n\n'.repeat(129),
  ]) {
    context.mock.method(globalThis, "fetch", async () => new Response(text, { headers: { "content-type": "text/event-stream" } }));
    const invalid = await controlEventStream(request(), url, token);
    await assert.rejects(invalid.text(), /CONTROL_EVENT_STREAM_CLOSED/);
  }
});

test("unauthorized stream does not wait for an error body and consumer cancellation closes the upstream", async context => {
  let cancelled = false;
  context.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { status: 403 }));
  const denied = await controlEventStream(request(), url, token);
  assert.equal(denied.status, 403); assert.equal(cancelled, true); assert.doesNotMatch(await denied.text(), /synthetic-stream-token/);
  cancelled = false;
  context.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { headers: { "content-type": "text/event-stream" } }));
  const stream = await controlEventStream(request(), url, token); await stream.body!.cancel(); assert.equal(cancelled, true);
});

test("request abort and the ten-minute lifetime stop a stalled stream", async context => {
  let cancelled = 0;
  context.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream({ cancel() { cancelled++; } }), { headers: { "content-type": "text/event-stream" } }));
  const abort = new AbortController();
  const response = await controlEventStream(new Request("https://console.test/api/control/events/stream", { signal: abort.signal }), url, token);
  abort.abort(); await response.text(); assert.equal(cancelled, 1);
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const bounded = await controlEventStream(request(), url, token);
  context.mock.timers.tick(600001); await bounded.text(); assert.equal(cancelled, 2);
});
