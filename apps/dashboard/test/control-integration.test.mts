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

const request = async (path: string, cookie = "", body?: unknown, origin = "https://console.test") => {
  const req = new NextRequest(`https://console.test/api/control/${path}`, { method: body === undefined ? "GET" : "POST", headers: { cookie, origin, "content-type": "application/json", "idempotency-key": "console-integration-once" }, body: body === undefined ? undefined : JSON.stringify(body) });
  return (body === undefined ? GET : POST)(req, { params: Promise.resolve({ path: path.split("/") }) });
};

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
    assert.deepEqual((await (await request("chain/actions", readerCookie)).json()).items, []);
    assert.equal((await request(`releases/${release.releaseId}/register`, readerCookie, {})).status, 403);
    assert.equal((await request(`policies/${policies[0].policyHash}/publish`, readerCookie, {})).status, 403);
    const operator = await request("session", "", { token: options.credentials[2].token });
    const operatorCookie = operator.headers.get("set-cookie")!.split(";")[0];
    assert.equal((await request(`releases/${release.releaseId}/register`, operatorCookie, {})).status, 403);
    assert.equal((await request(`policies/${policies[0].policyHash}/publish`, operatorCookie, {})).status, 403);
    const unconfigured = await request(`releases/${release.releaseId}/register`, cookie, {});
    assert.equal(unconfigured.status, 503);
    assert.match(await unconfigured.text(), /V2_RELAYER_NOT_CONFIGURED/);
    const receiptsDisabled = await request("receipt-ledgers", cookie, { writer: `0x${"1".repeat(40)}` });
    assert.equal(receiptsDisabled.status, 503); assert.match(await receiptsDisabled.text(), /RECEIPT_ANCHOR_NOT_CONFIGURED/);
    assert.deepEqual((await (await request("receipt-ledgers", readerCookie)).json()).items, []);
    const admissionBody = { releaseId: release.releaseId, policyHash: policies[0].policyHash, artifactDigest: release.artifactDigest, toolSurfaceHash: release.toolSurfaceHash, mode: "strict", operationClass: "READ_PRIVATE" };
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
