import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { NextRequest } from "next/server";
import { Wallet } from "ethers";
import { GET, POST } from "../app/api/control/[...path]/route";
import { buildApp } from "../../api/src/app.js";
import { ControlStore } from "../../api/src/control-store.js";
import { runControlWorkerOnce } from "../../api/src/control-worker.js";
import type { ControlOptions } from "../../api/src/control-plane.js";
import { V2Relayer } from "../../api/src/chain-outbox.js";
import { POST as judgePost, DELETE as judgeDelete } from "../app/api/judge/[...path]/route";
// @ts-expect-error Release smoke is import-safe ESM JavaScript; importing never invokes Docker.
import { smokeJudgeExperience } from "../../../scripts/ops/smoke-release-image.mjs";

const request = async (path: string, cookie = "", body?: unknown, origin = "https://console.test") => {
  const req = new NextRequest(`https://console.test/api/control/${path}`, { method: body === undefined ? "GET" : "POST", headers: { cookie, origin, "content-type": "application/json", "idempotency-key": "console-integration-once" }, body: body === undefined ? undefined : JSON.stringify(body) });
  return (body === undefined ? GET : POST)(req, { params: Promise.resolve({ path: path.split("/") }) });
};

test("release-image judge smoke traverses the real BFF/API and cleans only its synthetic session", { timeout: 30_000 }, async () => {
  const app = await buildApp({ databasePath: ":memory:", adminApiToken: "synthetic-smoke-admin-token", scannerApiToken: "synthetic-smoke-scanner-token", judgeDemo: true });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const previous = process.env.MCPSHIELD_API_URL;
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  const untouched = (await app.inject({ method: "POST", url: "/api/demo/sessions" })).json().sessionId;
  const calls: { path: string; method: string; body: unknown }[] = [];
  try {
    const result = await smokeJudgeExperience("http://127.0.0.1:3000", async (url: string, init: RequestInit) => {
      const req = new Request(url, init), path = new URL(url).pathname.replace("/api/judge/", "");
      assert.equal(req.headers.get("origin"), "http://127.0.0.1:3000"); assert.equal(init.redirect, "error");
      assert.equal(req.headers.get("authorization"), null); assert.equal(req.headers.get("cookie"), null);
      calls.push({ path, method: req.method, body: init.body });
      assert.match(path, /^sessions(?:\/[0-9a-f-]{36}(?:\/actions)?)?$/);
      return (req.method === "DELETE" ? judgeDelete : judgePost)(req, { params: Promise.resolve({ path: path.split("/") }) });
    });
    assert.deepEqual(result, { backend: "PASS", safe: "ALLOW", malicious: "BLOCK_BEFORE_SPAWN", source: "LIVE_DEMO", synthetic: true, ledger: "LOCAL_DEMO" });
    assert.equal(calls.length, 11); assert.equal(calls[0].path, "sessions"); assert.equal(calls[10].method, "DELETE");
    const ownPath = calls[10].path, ownId = ownPath.split("/")[1]; assert.notEqual(ownId, untouched);
    assert.ok(calls.slice(1, 10).every(call => call.path === `${ownPath}/actions` && call.method === "POST" && Object.keys(JSON.parse(call.body as string)).join() === "action"));
    assert.equal((await app.inject({ method: "GET", url: `/api/demo/sessions/${ownId}` })).statusCode, 404);
    assert.equal((await app.inject({ method: "GET", url: `/api/demo/sessions/${untouched}` })).json().step, 0);
  } finally {
    previous === undefined ? delete process.env.MCPSHIELD_API_URL : process.env.MCPSHIELD_API_URL = previous;
    await app.close();
  }
});

test("release-image judge smoke fails on unavailable, malformed or oversized bodies without logging them", async () => {
  const origin = "http://127.0.0.1:3000", secret = "synthetic-body-that-must-not-appear-in-errors";
  await assert.rejects(smokeJudgeExperience("https://public.example", () => assert.fail("No non-loopback request")), /loopback/);
  for (const response of [new Response(secret, { status: 503 }), Response.json({ error: secret }, { status: 200 }), new Response(secret, { status: 201, headers: { "content-type": "application/json" } }), Response.json({ secret: "x".repeat(65_536) }, { status: 201 })]) {
    await assert.rejects(smokeJudgeExperience(origin, async () => response), (error: Error) => { assert.doesNotMatch(error.message, new RegExp(secret)); return /RELEASE_JUDGE_/.test(error.message); });
  }
});

test("release-image judge smoke bounds a stalled error response body", async (context) => {
  let cancelled = false;
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const pending = smokeJudgeExperience("http://127.0.0.1:3000", async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { status: 503 }));
  await new Promise<void>(resolve => setImmediate(resolve));
  context.mock.timers.tick(20_001);
  await assert.rejects(pending, /RELEASE_JUDGE_TIMEOUT/); assert.equal(cancelled, true);
});

test("release-image judge smoke rejects a substituted session and deletes only the session it created", async () => {
  const sessionId = "12345678-1234-4123-8123-123456789abc", calls: string[] = [];
  const initial = { sessionId, schemaVersion: "1.0.0", synthetic: true, source: "LIVE_DEMO", ledgerMode: "LOCAL_DEMO", step: 0, nextAction: "SCAN_SAFE", complete: false,
    selectedRelease: "mail-mcp@1.0.0", releases: ["mail-mcp@1.0.0", "mail-mcp@1.0.1"].map(releaseId => ({ releaseId, scanStatus: "NOT_RUN", status: "UNVERIFIED" })), votes: [], executions: [] };
  await assert.rejects(smokeJudgeExperience("http://127.0.0.1:3000", async (url: string, init: RequestInit) => {
    calls.push(`${init.method} ${new URL(url).pathname}`);
    return init.method === "DELETE" ? new Response(null, { status: 204 }) : Response.json(calls.length === 1 ? initial : { ...initial, sessionId: "substituted-session" }, { status: calls.length === 1 ? 201 : 200 });
  }), /session identity\/source mismatch/);
  assert.deepEqual(calls, ["POST /api/judge/sessions", `POST /api/judge/sessions/${sessionId}/actions`, `DELETE /api/judge/sessions/${sessionId}`]);
});

test("judge BFF preserves bodyless 204, 205 and 304 responses", async (context) => {
  let upstreamStatus = 204;
  context.mock.method(globalThis, "fetch", async () => new Response(null, { status: upstreamStatus }));
  for (const status of [204, 205, 304]) {
    upstreamStatus = status;
    const path = ["sessions", "12345678-1234-4123-8123-123456789abc"];
    const response = await judgeDelete(new Request(`http://127.0.0.1:3000/api/judge/${path.join("/")}`, { method: "DELETE" }), { params: Promise.resolve({ path }) });
    assert.equal(response.status, status); assert.equal(await response.text(), "");
  }
});

test("console login to real resolver, worker, evidence and appeal keeps incomplete scans unverified", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-console-integration-"));
  const store = await ControlStore.open(join(directory, "control.sqlite"));
  const options: ControlOptions = { store, credentials: [
    { tenantId: "console-test", token: "synthetic-console-admin-token", role: "admin" },
    { tenantId: "console-test", token: "synthetic-console-reader-token", role: "reader" },
    { tenantId: "console-test", token: "synthetic-console-operator-token", role: "operator" },
    { tenantId: "other-tenant", token: "synthetic-other-reader-token", role: "reader" },
  ], artifactPath: join(directory, "artifacts"), evidencePath: join(directory, "evidence"), evidenceKey: "1".repeat(64) };
  const app = await buildApp({ databasePath: ":memory:", adminApiToken: "synthetic-legacy-admin-token", scannerApiToken: "synthetic-legacy-scanner-token", controlPlane: options });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const previous = process.env.MCPSHIELD_API_URL;
  const previousOrigin = process.env.MCPSHIELD_PUBLIC_ORIGIN;
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  try {
    const session = await request("session", "", { token: options.credentials[0].token });
    assert.equal(session.status, 200);
    const cookie = session.headers.get("set-cookie")!.split(";")[0];
    const resolved = await request("releases/resolve", cookie, { sourceType: "fixture", locator: "mail-mcp-1.0.0" });
    assert.equal(resolved.status, 201, await resolved.clone().text());
    const { release } = await resolved.json();
    const { items: policies } = await (await request("policies", cookie)).json();
    assert.ok(policies.length);
    const policy = policies.find((item: { document?: { profile?: string } }) => item.document?.profile === undefined);
    assert.ok(policy, "Legacy fixture scans require the legacy policy, independent of registry ordering");
    const submitted = await request("scans", cookie, { releaseId: release.releaseId, policyHash: policy.policyHash });
    assert.equal(submitted.status, 202, await submitted.clone().text());
    const queued = (await submitted.json()).scan;
    assert.match(queued.traceId, /^[a-f0-9]{32}$/);
    assert.notEqual(queued.traceId, "0".repeat(32));
    assert.equal(await runControlWorkerOnce(store, options), true);
    const completed = (await (await request(`scans/${queued.scanId}`, cookie)).json()).scan;
    assert.equal(completed.status, "COMPLETED");
    assert.equal(completed.result.scanResult.scanStatus, "INCONCLUSIVE");
    const evidence = await request(`scans/${queued.scanId}/evidence`, cookie);
    assert.equal(evidence.status, 200, await evidence.clone().text());
    assert.equal((await evidence.json()).reportRoot, completed.result.reportRoot);
    const appeal = await request(`releases/${release.releaseId}/appeals`, cookie, { reason: "Synthetic test requests complete sandbox revalidation." });
    assert.equal(appeal.status, 201, await appeal.clone().text());
    const history = (await (await request(`releases/${release.releaseId}/history`, cookie)).json()).items;
    assert.ok(history.some((event: { eventName: string }) => event.eventName === "evidence.accessed"));
    assert.ok(history.some((event: { eventName: string }) => event.eventName === "appeal.opened"));
    const inventory = (await (await request("releases", cookie)).json()).items;
    assert.equal(inventory[0].status, "UNVERIFIED");
    assert.equal(inventory[0].chain ?? null, null);
    const reader = await request("session", "", { token: options.credentials[1].token });
    const readerCookie = reader.headers.get("set-cookie")!.split(";")[0];
    assert.equal((await request(`scans/${queued.scanId}/evidence`, readerCookie)).status, 403);
    assert.equal((await request("scans", readerCookie, { releaseId: release.releaseId, policyHash: policy.policyHash })).status, 403);
    assert.deepEqual((await (await request("chain/actions", readerCookie)).json()).items, []);
    assert.equal((await request(`releases/${release.releaseId}/register`, readerCookie, {})).status, 403);
    assert.equal((await request(`policies/${policy.policyHash}/publish`, readerCookie, {})).status, 403);
    const operator = await request("session", "", { token: options.credentials[2].token });
    const operatorCookie = operator.headers.get("set-cookie")!.split(";")[0];
    assert.equal((await request(`releases/${release.releaseId}/register`, operatorCookie, {})).status, 403);
    assert.equal((await request(`policies/${policy.policyHash}/publish`, operatorCookie, {})).status, 403);
    const unconfigured = await request(`releases/${release.releaseId}/register`, cookie, {});
    assert.equal(unconfigured.status, 503);
    assert.match(await unconfigured.text(), /V2_RELAYER_NOT_CONFIGURED/);
    const receiptsDisabled = await request("receipt-ledgers", cookie, { writer: `0x${"1".repeat(40)}` });
    assert.equal(receiptsDisabled.status, 503); assert.match(await receiptsDisabled.text(), /RECEIPT_ANCHOR_NOT_CONFIGURED/);
    assert.deepEqual((await (await request("receipt-ledgers", readerCookie)).json()).items, []);
    const admissionBody = { releaseId: release.releaseId, policyHash: policy.policyHash, artifactDigest: release.artifactDigest, toolSurfaceHash: release.toolSurfaceHash, mode: "strict", operationClass: "READ_PRIVATE" };
    const admission = await request("admission/check", readerCookie, admissionBody);
    assert.equal(admission.status, 200);
    const decision = await admission.json();
    assert.equal(decision.decision, "BLOCK");
    assert.equal(decision.source, "LOCAL_DEMO");
    assert.equal(decision.snapshot, undefined);
    const other = await request("session", "", { token: options.credentials[3].token });
    assert.equal((await request("admission/check", other.headers.get("set-cookie")!.split(";")[0], admissionBody)).status, 404);
    for (const unsupported of ["validator/attestations", "validator/quarantines", "chain/actions/submit", "releases/unknown/delete"]) assert.equal((await request(unsupported, cookie, {})).status, 404);
  } finally {
    previous === undefined ? delete process.env.MCPSHIELD_API_URL : process.env.MCPSHIELD_API_URL = previous;
    previousOrigin === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previousOrigin;
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("admin BFF enqueues durable tenant-scoped chain requests without claiming transmission or finality", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-console-queue-"));
  const store = await ControlStore.open(join(directory, "control.sqlite"));
  // This is only a durable enqueue test. The ephemeral unfunded key never signs or sends a transaction.
  const relayer = new V2Relayer("http://127.0.0.1:1", `0x${"1".repeat(40)}`, 31337, Wallet.createRandom().privateKey);
  const options: ControlOptions = { store, v2Relayer: relayer, credentials: [
    { tenantId: "queue-test", token: "synthetic-queue-admin-token", role: "admin" },
    { tenantId: "other-queue-tenant", token: "synthetic-other-admin-token", role: "admin" },
  ], artifactPath: join(directory, "artifacts"), evidencePath: join(directory, "evidence"), evidenceKey: "1".repeat(64) };
  const app = await buildApp({ databasePath: ":memory:", adminApiToken: "synthetic-legacy-admin-token", scannerApiToken: "synthetic-legacy-scanner-token", controlPlane: options });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const previous = process.env.MCPSHIELD_API_URL, previousOrigin = process.env.MCPSHIELD_PUBLIC_ORIGIN;
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  try {
    const releaseId = `0x${"2".repeat(64)}`;
    await store.put("queue-test", "release", releaseId, { releaseId, toolId: `0x${"3".repeat(64)}`, artifactDigest: `sha256:${"4".repeat(64)}`, manifestDigest: `sha256:${"5".repeat(64)}`, toolSurfaceHash: `0x${"6".repeat(64)}`, status: "UNVERIFIED", chain: null });
    const login = await request("session", "", { token: options.credentials[0].token });
    const cookie = login.headers.get("set-cookie")!.split(";")[0];
    const enqueue = await request(`releases/${releaseId}/register`, cookie, {});
    assert.equal(enqueue.status, 202);
    const { action } = await enqueue.json();
    assert.equal(action.status, "NEW"); assert.equal(action.txHash, null); assert.equal(action.chainId, 31337);
    assert.equal((await (await request(`releases/${releaseId}/register`, cookie, {})).json()).action.actionId, action.actionId);
    const { items: policies } = await (await request("policies", cookie)).json();
    const policyAction = await request(`policies/${policies[0].policyHash}/publish`, cookie, {});
    assert.equal(policyAction.status, 202); assert.equal((await policyAction.json()).action.status, "NEW");
    assert.equal((await request(`releases/${releaseId}/register`, cookie, {}, "https://attacker.invalid")).status, 403);
    const listed = (await (await request("chain/actions", cookie)).json()).items;
    assert.equal(listed.length, 2);
    assert.ok(listed.every((item: { status: string; txHash: unknown }) => item.status === "NEW" && item.txHash === null));
    assert.equal((await request(`chain/actions/${action.actionId}`, cookie)).status, 200);
    const other = await request("session", "", { token: options.credentials[1].token });
    const otherCookie = other.headers.get("set-cookie")!.split(";")[0];
    assert.deepEqual((await (await request("chain/actions", otherCookie)).json()).items, []);
    assert.equal((await request(`chain/actions/${action.actionId}`, otherCookie)).status, 404);
    assert.equal((await (await request("releases", cookie)).json()).items[0].status, "UNVERIFIED");
  } finally {
    previous === undefined ? delete process.env.MCPSHIELD_API_URL : process.env.MCPSHIELD_API_URL = previous;
    previousOrigin === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previousOrigin;
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});
