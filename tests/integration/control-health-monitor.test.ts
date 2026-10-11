import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import test from "node:test";
import { checkControlReadiness } from "../../scripts/ops/check-control-health.js";

const token = "synthetic-health-monitor-token";
const report = (checkedAt = new Date().toISOString()) => ({ schemaVersion: "mcpshield.health.v1", status: "READY", checkedAt,
  components: Object.fromEntries(["api", "database", "chain", "scanner"].map(name => [name, { status: "UP", code: `${name.toUpperCase()}_OK`, checkedAt }])) });
async function fixture(run: (url: string, change: (fn: (req: IncomingMessage, res: ServerResponse) => void) => void) => Promise<void>) {
  let respond = (_request: IncomingMessage, response: ServerResponse) => { response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(report())); };
  const server = createServer((request, response) => respond(request, response));
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  try { await run(`http://127.0.0.1:${(server.address() as { port: number }).port}/v1/health`, fn => { respond = fn; }); }
  finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
}

test("readiness monitor reads authenticated snapshots, distinguishes 503 and never sends mutation requests", async () => fixture(async (url, change) => {
  const check = () => checkControlReadiness({ url, token }); let requests = 0;
  change((request, response) => {
    requests++; assert.equal(request.method, "GET"); assert.equal(request.url, "/v1/health"); assert.equal(request.headers.authorization, `Bearer ${token}`);
    response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(report()));
  });
  assert.equal((await check()).status, "READY");
  change((_request, response) => {
    requests++; const data = report(); data.status = "DEGRADED"; data.components.scanner.status = "LIMITED";
    response.writeHead(503, { "content-type": "application/json" }).end(JSON.stringify(data));
  });
  const degraded = await check(); assert.equal(degraded.status, "DEGRADED"); assert.equal(degraded.components.scanner, "LIMITED"); assert.equal(requests, 2);
}));

test("readiness monitor rejects redirects, stale/inconsistent/private responses, auth failures and oversized bodies", async () => fixture(async (url, change) => {
  let requests = 0;
  for (const [status, value, expected] of [
    [401, { private: "SYNTHETIC_PRIVATE" }, "HEALTH_AUTH_REQUIRED"],
    [200, report(new Date(Date.now() - 60_000).toISOString()), "HEALTH_STALE_RESPONSE"],
    [200, { ...report(), private: "SYNTHETIC_PRIVATE" }, "HEALTH_RESPONSE_INVALID"],
    [503, report(), "HEALTH_RESPONSE_INVALID"],
    [200, "SYNTHETIC_PRIVATE".repeat(2000), "HEALTH_BODY_LIMIT"],
  ] as const) {
    change((_request, response) => { requests++; response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value)); });
    await assert.rejects(checkControlReadiness({ url, token }), new RegExp(`^Error: ${expected}$`));
  }
  const before = requests;
  change((_request, response) => { requests++; response.writeHead(302, { location: url.replace("/v1/health", "/secret-destination") }).end(); });
  await assert.rejects(checkControlReadiness({ url, token }), /HEALTH_HTTP_UNEXPECTED/); assert.equal(requests, before + 1);
  for (const name of ["api", "database", "chain", "scanner"]) {
    const data = report(); data.components[name].checkedAt = new Date(Date.now() - 30_000).toISOString();
    change((_request, response) => { response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(data)); });
    await assert.rejects(checkControlReadiness({ url, token }), /^Error: HEALTH_STALE_COMPONENT$/);
  }
  const recent = report(); recent.components.scanner.checkedAt = new Date(Date.now() - 15_000).toISOString();
  change((_request, response) => { response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(recent)); });
  assert.equal((await checkControlReadiness({ url, token })).status, "READY");
}));

test("readiness monitor bounds a stalled HTTP body and rejects insecure/credential-bearing target configuration", async () => fixture(async (url, change) => {
  let requests = 0;
  change((_request, response) => { requests++; response.writeHead(200, { "content-type": "application/json" }); response.flushHeaders(); response.write('{"schemaVersion":'); });
  const started = performance.now();
  await assert.rejects(checkControlReadiness({ url, token, timeoutMs: 100 }), /HEALTH_TIMEOUT/);
  assert.ok(performance.now() - started < 1000);
  for (const target of ["http://external.invalid/v1/health", url + "?token=private", url + "#private", url.replace("http://", "http://name:private@"), url.replace("/v1/health", "/health")]) {
    await assert.rejects(checkControlReadiness({ url: target, token }), /HEALTH_CONFIG_INVALID/);
  }
  await assert.rejects(checkControlReadiness({ url, token: "bad\ncredential" }), /HEALTH_CONFIG_INVALID/);
  assert.equal(requests, 1);
}));
