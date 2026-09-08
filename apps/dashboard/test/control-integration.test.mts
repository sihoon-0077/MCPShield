import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { NextRequest } from "next/server";
import { GET, POST } from "../app/api/control/[...path]/route";
import { buildApp } from "../../api/src/app.js";
import { ControlStore } from "../../api/src/control-store.js";
import { runControlWorkerOnce } from "../../api/src/control-worker.js";
import type { ControlOptions } from "../../api/src/control-plane.js";

test("console login to real resolver, worker, evidence and appeal keeps incomplete scans unverified", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-console-integration-"));
  const store = await ControlStore.open(join(directory, "control.sqlite"));
  const options: ControlOptions = { store, credentials: [
    { tenantId: "console-test", token: "synthetic-console-admin-token", role: "admin" },
    { tenantId: "console-test", token: "synthetic-console-reader-token", role: "reader" },
  ], artifactPath: join(directory, "artifacts"), evidencePath: join(directory, "evidence"), evidenceKey: "1".repeat(64) };
  const app = await buildApp({ databasePath: ":memory:", adminApiToken: "synthetic-legacy-admin-token", scannerApiToken: "synthetic-legacy-scanner-token", controlPlane: options });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const previous = process.env.MCPSHIELD_API_URL;
  const previousOrigin = process.env.MCPSHIELD_PUBLIC_ORIGIN;
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  const request = async (path: string, cookie = "", body?: unknown) => {
    const req = new NextRequest(`https://console.test/api/control/${path}`, { method: body === undefined ? "GET" : "POST", headers: { cookie, origin: "https://console.test", "content-type": "application/json", "idempotency-key": "console-integration-once" }, body: body === undefined ? undefined : JSON.stringify(body) });
    return (body === undefined ? GET : POST)(req, { params: Promise.resolve({ path: path.split("/") }) });
  };
  try {
    const session = await request("session", "", { token: options.credentials[0].token });
    assert.equal(session.status, 200);
    const cookie = session.headers.get("set-cookie")!.split(";")[0];
    const resolved = await request("releases/resolve", cookie, { sourceType: "fixture", locator: "mail-mcp-1.0.0" });
    assert.equal(resolved.status, 201, await resolved.clone().text());
    const { release } = await resolved.json();
    const { items: policies } = await (await request("policies", cookie)).json();
    assert.ok(policies.length);
    const submitted = await request("scans", cookie, { releaseId: release.releaseId, policyHash: policies[0].policyHash });
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
    assert.equal((await request("scans", readerCookie, { releaseId: release.releaseId, policyHash: policies[0].policyHash })).status, 403);
  } finally {
    previous === undefined ? delete process.env.MCPSHIELD_API_URL : process.env.MCPSHIELD_API_URL = previous;
    previousOrigin === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previousOrigin;
    await app.close();
    await rm(directory, { recursive: true, force: true });
  }
});
