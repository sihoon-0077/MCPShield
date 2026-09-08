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
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(backend.address() as { port: number }).port}`;
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
  } finally {
    previous === undefined ? delete process.env.MCPSHIELD_API_URL : process.env.MCPSHIELD_API_URL = previous;
    await new Promise<void>((resolve, reject) => backend.close((error) => error ? reject(error) : resolve()));
  }
});
