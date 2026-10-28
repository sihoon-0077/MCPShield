import assert from "node:assert/strict";
import test from "node:test";
import { setImmediate } from "node:timers/promises";
import { NextRequest } from "next/server";
import { GET } from "../app/api/control/[...path]/route";

const origin = "https://console.test", small = 4 * 1024 * 1024, evidence = 32 * 1024 * 1024 + 1024;
const request = (path: string) => GET(new NextRequest(`${origin}/api/control/${path}`, { headers: { cookie: "mcpshield_control=synthetic-body-limit-credential" } }), { params: Promise.resolve({ path: path.split("/") }) });

test("only successful private evidence gets the larger bounded upstream budget", async context => {
  const previous = process.env.MCPSHIELD_PUBLIC_ORIGIN; process.env.MCPSHIELD_PUBLIC_ORIGIN = origin;
  try {
    for (const [path, status, limit] of [["preparations/synthetic-id/evidence", 200, evidence], ["scans/synthetic-id/evidence", 200, evidence], ["preparations/synthetic-id/evidence", 500, small], ["operations", 200, small]] as const) {
      let sent = 0, cancelled = false;
      context.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream<Uint8Array>({
        pull(output) { if (sent >= limit + 4 * 65536) { output.close(); return; } const chunk = new Uint8Array(65536).fill(32); sent += chunk.length; output.enqueue(chunk); },
        cancel() { cancelled = true; },
      }), { status, headers: { "content-type": "application/json" } }));
      const response = await request(path);
      assert.equal(response.status, 503); assert.equal(cancelled, true);
      assert.ok(sent <= limit + 2 * 65536, "The BFF must cancel before consuming an unbounded source");
      assert.doesNotMatch(await response.text(), /synthetic-body-limit-credential|bundle/);
    }
    context.mock.method(globalThis, "fetch", async () => Response.json({ bundle: { files: { "report.json": "x".repeat(small) } }, value: "SYNTHETIC_PRIVATE" }));
    const legacy = await request("scans/synthetic-id/evidence");
    assert.equal(legacy.status, 503); assert.doesNotMatch(await legacy.text(), /SYNTHETIC_PRIVATE/);
  } finally { previous === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previous; }
});

test("private evidence body timeout cancels a stalled source instead of returning raw data", async context => {
  const previous = process.env.MCPSHIELD_PUBLIC_ORIGIN; process.env.MCPSHIELD_PUBLIC_ORIGIN = origin;
  let cancelled = false;
  context.mock.timers.enable({ apis: ["setTimeout"] });
  context.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { headers: { "content-type": "application/json" } }));
  try {
    const pending = request("preparations/synthetic-id/evidence");
    await setImmediate(); context.mock.timers.tick(10001);
    const response = await pending;
    assert.equal(response.status, 503); assert.equal(cancelled, true);
    assert.doesNotMatch(await response.text(), /synthetic-body-limit-credential/);
  } finally { previous === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previous; }
});
