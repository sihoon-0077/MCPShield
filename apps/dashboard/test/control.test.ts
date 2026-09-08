import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { NextRequest } from "next/server";
import { GET, POST } from "../app/api/control/[...path]/route";

test("console requires tenant credentials, uses HttpOnly cookies, and blocks CSRF and arbitrary proxy paths", async () => {
  const token = "synthetic-console-test-token-only";
  const calls: string[] = [];
  const backend = createServer((request, response) => {
    calls.push(request.url ?? "");
    response.setHeader("content-type", "application/json");
    if (request.headers.authorization !== `Bearer ${token}`) { response.writeHead(401); response.end('{"error":"Unauthorized"}'); return; }
    if (request.url === "/v1/session") { response.end(JSON.stringify({ tenantId: "test-tenant", role: "reader", capabilities: { read: true, scan: false, evidence: false, manage: false } })); return; }
    if (request.url === "/v1/releases") { response.end('{"items":[]}'); return; }
    response.writeHead(403); response.end('{"error":"Forbidden"}');
  });
  await new Promise<void>((resolve) => backend.listen(0, "127.0.0.1", resolve));
  const previous = process.env.MCPSHIELD_API_URL;
  const previousOrigin = process.env.MCPSHIELD_PUBLIC_ORIGIN;
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(backend.address() as { port: number }).port}`;
  process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  const context = (...path: string[]) => ({ params: Promise.resolve({ path }) });
  try {
    const missing = await GET(new NextRequest("https://console.test/api/control/releases"), context("releases"));
    assert.equal(missing.status, 401);
    assert.equal(calls.length, 0);
    const signedIn = await POST(new NextRequest("https://console.test/api/control/session", { method: "POST", headers: { origin: "https://console.test", "content-type": "application/json" }, body: JSON.stringify({ token }) }), context("session"));
    assert.equal(signedIn.status, 200);
    assert.doesNotMatch(await signedIn.text(), new RegExp(token));
    const cookie = signedIn.headers.get("set-cookie")!;
    assert.match(cookie, /HttpOnly/i); assert.match(cookie, /SameSite=strict/i); assert.match(cookie, /Secure/i);
    const headers = { cookie: cookie.split(";")[0] };
    const listed = await GET(new NextRequest("https://console.test/api/control/releases", { headers }), context("releases"));
    assert.equal(listed.status, 200);
    const csrf = await POST(new NextRequest("https://console.test/api/control/scans", { method: "POST", headers: { ...headers, origin: "https://attacker.invalid", "content-type": "application/json" }, body: "{}" }), context("scans"));
    assert.equal(csrf.status, 403);
    const escaped = await GET(new NextRequest("https://console.test/api/control/releases", { headers }), context("..", "admin"));
    assert.equal(escaped.status, 404);
    const forbidden = await GET(new NextRequest("https://console.test/api/control/scans/id/evidence", { headers }), context("scans", "id", "evidence"));
    assert.equal(forbidden.status, 403);
    assert.deepEqual(calls, ["/v1/session", "/v1/releases", "/v1/scans/id/evidence"]);
    const oversized = await POST(new NextRequest("https://console.test/api/control/scans", { method: "POST", headers: { ...headers, origin: "https://console.test", "content-type": "application/json" }, body: JSON.stringify({ value: "x".repeat(65_537) }) }), context("scans"));
    assert.equal(oversized.status, 413);
    process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
    const behindProxy = await POST(new NextRequest("http://next-internal:3000/api/control/session", { method: "POST", headers: { origin: "https://console.test", "content-type": "application/json" }, body: JSON.stringify({ token }) }), context("session"));
    assert.equal(behindProxy.status, 200);
    assert.match(behindProxy.headers.get("set-cookie")!, /Secure/i);
    process.env.MCPSHIELD_API_URL = "http://untrusted.example";
    const unsafeBackend = await GET(new NextRequest("https://console.test/api/control/releases", { headers }), context("releases"));
    assert.equal(unsafeBackend.status, 503);
    assert.equal(calls.length, 4);
  } finally {
    previous === undefined ? delete process.env.MCPSHIELD_API_URL : process.env.MCPSHIELD_API_URL = previous;
    previousOrigin === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previousOrigin;
    await new Promise<void>((resolve, reject) => backend.close((error) => error ? reject(error) : resolve()));
  }
});

test("production origin requires TLS except an explicitly opted-in loopback preview", async () => {
  const names = ["NODE_ENV", "MCPSHIELD_PUBLIC_ORIGIN", "MCPSHIELD_API_URL", "MCPSHIELD_CONTROL_ALLOW_LOOPBACK_HTTP"];
  const previous = names.map((name) => process.env[name]);
  const request = () => GET(new NextRequest("http://internal:3000/api/control/releases", { headers: { "x-forwarded-proto": "https", "x-forwarded-host": "console.test" } }), { params: Promise.resolve({ path: ["releases"] }) });
  try {
    process.env[names[0]] = "production";
    process.env.MCPSHIELD_API_URL = "http://127.0.0.1:3001";
    delete process.env.MCPSHIELD_PUBLIC_ORIGIN;
    assert.equal((await request()).status, 503);
    process.env.MCPSHIELD_PUBLIC_ORIGIN = "http://127.0.0.1:3000";
    assert.equal((await request()).status, 503);
    process.env.MCPSHIELD_CONTROL_ALLOW_LOOPBACK_HTTP = "true";
    assert.equal((await request()).status, 401);
    process.env.MCPSHIELD_PUBLIC_ORIGIN = "http://public.example";
    assert.equal((await request()).status, 503);
    process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
    assert.equal((await request()).status, 401);
  } finally {
    names.forEach((name, index) => { previous[index] === undefined ? delete process.env[name] : process.env[name] = previous[index]; });
  }
});

test("console bounds chunked requests and upstream response bodies", async (context) => {
  const previousOrigin = process.env.MCPSHIELD_PUBLIC_ORIGIN;
  process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  let cancelled = false;
  const headers = { origin: "https://console.test", "content-type": "application/json", cookie: "mcpshield_control=synthetic-test-token-only" };
  const params = { params: Promise.resolve({ path: ["scans"] }) };
  try {
    const oversized = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new TextEncoder().encode(" ".repeat(65_536))); controller.enqueue(new TextEncoder().encode("{}")); controller.close(); } });
    const response = await POST(new NextRequest("https://console.test/api/control/scans", { method: "POST", headers, body: oversized }), params);
    assert.equal(response.status, 413);
    context.mock.method(globalThis, "fetch", async () => new Response(" ".repeat(4 * 1024 * 1024) + "{}"));
    assert.equal((await GET(new NextRequest("https://console.test/api/control/scans", { headers }), params)).status, 503);
    context.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream({ cancel() { cancelled = true; } })));
    context.mock.timers.enable({ apis: ["setTimeout"] });
    const stalled = GET(new NextRequest("https://console.test/api/control/scans", { headers }), params);
    // Let fetch/body reading begin before advancing the bounded deadline.
    await new Promise<void>((resolve) => setImmediate(resolve));
    context.mock.timers.tick(10_001);
    assert.equal((await stalled).status, 503);
    assert.equal(cancelled, true);
  } finally {
    previousOrigin === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previousOrigin;
  }
});
