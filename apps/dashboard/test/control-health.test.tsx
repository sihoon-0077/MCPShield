import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { NextRequest } from "next/server";
import { GET, POST } from "../app/api/control/[...path]/route";
import { controlApi } from "../lib/control-client";
import { parseControlHealth, type ControlHealth } from "../lib/control-health";
import { HealthStatus, HealthPanel } from "../components/health-panel";

const checkedAt = "2026-09-19T06:00:00.000Z";
const ready: ControlHealth = { schemaVersion: "mcpshield.health.v1", status: "READY", checkedAt, components: {
  api: { status: "UP", code: "API_READY", checkedAt }, database: { status: "UP", code: "DATABASE_READY", checkedAt },
  chain: { status: "UP", code: "CHAIN_READY", checkedAt }, scanner: { status: "UP", code: "SCANNER_DOCKER_READY", checkedAt },
} };
const degraded: ControlHealth = { ...ready, status: "DEGRADED", components: { ...ready.components, chain: { status: "NOT_CONFIGURED", code: "CHAIN_NOT_CONFIGURED", checkedAt: null }, scanner: { status: "LIMITED", code: "SCANNER_STATIC_ONLY", checkedAt } } };
const badReports = () => [null, [], { status: "ok" }, { ...ready, schemaVersion: "mcpshield.health.v2" }, { ...ready, checkedAt: "yesterday" },
  { ...ready, checkedAt: "2026-02-30T00:00:00.000Z" }, { ...ready, privateValue: "SYNTHETIC_PRIVATE" }, { ...ready, status: "DEGRADED" },
  { ...ready, components: { ...ready.components, scanner: undefined } }, { ...ready, components: { ...ready.components, extra: ready.components.api } },
  ...[{ status: ["UP"] }, { status: "GOOD" }, { checkedAt: null }, { checkedAt: "2026-09-20T06:00:00.000Z" }, { code: "<img src=x onerror=alert(1)>" }, { code: "X".repeat(81) }, { privateValue: "SYNTHETIC_PRIVATE" }].map(patch => ({ ...ready, components: { ...ready.components, scanner: { ...ready.components.scanner, ...patch } } })),
];

test("health reports require exact bounded fields, canonical observation timestamps and HTTP/component consistency", () => {
  assert.deepEqual(parseControlHealth(ready, 200), ready); assert.deepEqual(parseControlHealth(degraded, 503), degraded);
  for (const report of badReports()) assert.throws(() => parseControlHealth(report, 200), /INVALID_CONTROL_HEALTH/);
  for (const [body, status] of [[ready, 201], [ready, 503], [degraded, 200], [degraded, 401], [degraded, 500]] as const) assert.throws(() => parseControlHealth(body, status), /INVALID_CONTROL_HEALTH/);
  assert.throws(() => parseControlHealth({ ...degraded, components: { ...degraded.components, scanner: { ...degraded.components.scanner, status: ["UP"] } } }, 503), /INVALID_CONTROL_HEALTH/);
});

test("only the authenticated exact BFF health route forwards valid READY/DEGRADED and hides malformed bodies", async context => {
  const previous = process.env.MCPSHIELD_PUBLIC_ORIGIN; process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  let calls = 0, status = 200, payload: unknown = ready;
  context.mock.method(globalThis, "fetch", async (url: URL, init: RequestInit) => {
    calls++; assert.equal(url.pathname, "/v1/health"); assert.equal(new Headers(init.headers).get("authorization"), "Bearer synthetic-health-reader-token");
    return Response.json(payload, { status });
  });
  const request = (path = "health", token = "synthetic-health-reader-token") => GET(new NextRequest(`https://console.test/api/control/${path}`, { headers: { cookie: `mcpshield_control=${token}` } }), { params: Promise.resolve({ path: path.split("/") }) });
  try {
    assert.equal((await request("health", "")).status, 401); assert.equal(calls, 0);
    assert.equal((await request("health/arbitrary")).status, 404); assert.equal(calls, 0);
    assert.equal((await POST(new NextRequest("https://console.test/api/control/health", { method: "POST", headers: { origin: "https://console.test" } }), { params: Promise.resolve({ path: ["health"] }) })).status, 404);
    for (const [body, http] of [[ready, 200], [degraded, 503]] as const) { payload = body; status = http; const response = await request(); assert.equal(response.status, http); assert.deepEqual(await response.json(), body); assert.equal(response.headers.get("cache-control"), "no-store"); }
    for (const body of badReports()) { payload = body; status = 503; const response = await request(); assert.equal(response.status, 503); const text = await response.text(); assert.match(text, /종합 상태 응답을 검증하지 못했습니다/); assert.doesNotMatch(text, /SYNTHETIC_PRIVATE|onerror/); }
    status = 201; payload = ready; assert.equal((await request()).status, 503);
    status = 401; payload = { error: { code: "UNAUTHORIZED", message: "UNAUTHORIZED" } }; const expired = await request(); assert.equal(expired.status, 401); assert.match(expired.headers.get("set-cookie")!, /Max-Age=0/);
  } finally { previous === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previous; }
});

test("health client accepts validated 503 only for health, keeps other inventory errors and propagates cancellation", async context => {
  let status = 503, payload: unknown = degraded; const controller = new AbortController();
  context.mock.method(globalThis, "fetch", async (_url: string, init: RequestInit) => { assert.equal(init.cache, "no-store"); assert.equal(init.signal, controller.signal); return Response.json(payload, { status }); });
  const health = () => controlApi<ControlHealth>("health", undefined, "GET", undefined, controller.signal);
  assert.deepEqual(await health(), degraded);
  await assert.rejects(controlApi("releases", undefined, "GET", undefined, controller.signal), (error: any) => error.status === 503);
  for (const http of [200, 201, 503]) { status = http; payload = { error: "not-a-health-report" }; await assert.rejects(health(), (error: any) => error.code === "INVALID_HEALTH_RESPONSE"); }
  status = 401; payload = ready; await assert.rejects(health(), (error: any) => error.status === 401);
  status = 200; assert.deepEqual(await health(), ready);
});

test("health UI labels snapshot scope, unknown/limited states and hides previous success on loading or error", () => {
  const render = (report: ControlHealth | null, pending = false, error = "") => renderToStaticMarkup(<HealthStatus report={report} pending={pending} error={error} />);
  const html = render(degraded); for (const text of ["추가 확인", "연동 미설정", "확인 범위 제한", "실제 확인 기록 없음", "마지막 조회 기록", "실행 승인이 아닙니다", "탐지 품질"]) assert.ok(html.includes(text), text);
  for (const [status, label] of [["UNKNOWN", "상태 미확인"], ["DOWN", "연결 실패"]] as const) assert.match(render({ ...degraded, components: { ...degraded.components, scanner: { status, code: "SCANNER_HEARTBEAT_MISSING", checkedAt: null } } }), new RegExp(label));
  assert.match(render(ready), /필수 구성요소 응답 확인/);
  for (const hidden of [render(ready, true), render(ready, false, "운영 로그인이 만료되었습니다."), render(null)]) assert.doesNotMatch(hidden, /API_READY|DATABASE_READY|CHAIN_READY|SCANNER_DOCKER_READY|<code>READY/);
  assert.match(render(ready, false, "<script>synthetic error</script>"), /&lt;script&gt;/);
  const panel = renderToStaticMarkup(<HealthPanel refreshVersion={0} />); assert.match(panel, /15초/); assert.match(panel, /이 조회 실패만으로 릴리스 목록을 지우지 않습니다/); assert.match(panel, /연결 상태 다시 확인/);
});
