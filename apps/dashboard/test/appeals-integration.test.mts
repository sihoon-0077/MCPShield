import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { NextRequest } from "next/server";
import { GET, POST } from "../app/api/control/[...path]/route";
import { AppealRecords } from "../components/appeal-records";
import { buildApp } from "../../api/src/app.js";
import { ControlStore } from "../../api/src/control-store.js";

test("appeal conclusion uses admin API scope, preserves original prose and history, and never grants release execution", async () => {
  const store = await ControlStore.open();
  const credentials = ["admin", "operator", "reader"].map(role => ({ tenantId: "appeal-console", token: `synthetic-appeal-${role}-token`, role: role as "admin" | "operator" | "reader" }));
  credentials.push({ tenantId: "foreign", token: "synthetic-foreign-admin-token", role: "admin" });
  const app = await buildApp({ adminApiToken: "synthetic-legacy-admin-token", scannerApiToken: "synthetic-legacy-scanner-token", controlPlane: {
    store, credentials, artifactPath: "unused", evidencePath: "unused", evidenceKey: "1".repeat(64),
  } });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const release = { releaseId: "0x" + "1".repeat(64), status: "REVOKED", artifactDigest: "sha256:" + "2".repeat(64), policyHash: "0x" + "3".repeat(64), reportRoot: "0x" + "4".repeat(64) };
  await store.put(credentials[0].tenantId, "release", release.releaseId, release);
  const names = ["MCPSHIELD_API_URL", "MCPSHIELD_PUBLIC_ORIGIN"], previous = names.map(name => process.env[name]);
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`; process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  const request = (path: string, cookie = "", body?: unknown, origin = "https://console.test") => (body === undefined ? GET : POST)(new NextRequest(`https://console.test/api/control/${path}`, {
    method: body === undefined ? "GET" : "POST", headers: { cookie, origin, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body),
  }), { params: Promise.resolve({ path: path.split("/") }) });
  try {
    const cookies: string[] = [], capabilities: any[] = [];
    for (const credential of credentials) {
      const response = await request("session", "", { token: credential.token }); assert.equal(response.status, 200);
      cookies.push(response.headers.get("set-cookie")!.split(";")[0]); capabilities.push((await response.json()).capabilities);
    }
    const [admin, operator, reader, foreign] = cookies, path = `releases/${release.releaseId}/appeals`;
    const reason = "  Synthetic original reason\n<img src=x onerror=alert(1)>  ", resolution = "  Synthetic review conclusion\n<script>not executable</script>  ";
    const opened = await request(path, operator, { reason }); assert.equal(opened.status, 201); const original = (await opened.json()).appeal;
    const resolvePath = `appeals/${original.appealId}/resolve`;
    assert.equal((await request(resolvePath, operator, { resolution })).status, 403); assert.equal((await request(resolvePath, reader, { resolution })).status, 403);
    assert.equal((await request(resolvePath, foreign, { resolution })).status, 404); assert.equal((await request(path, foreign)).status, 404);
    assert.equal((await request(resolvePath, admin, { resolution }, "https://attacker.invalid")).status, 403);
    for (const invalid of [{ resolution: "short" }, { resolution: " ".repeat(10) }, { resolution: "x".repeat(2001) }, { resolution, status: "VERIFIED" }, { resolution, privateKey: "forbidden" }]) {
      const response = await request(resolvePath, admin, invalid); assert.equal(response.status, 400); assert.doesNotMatch(await response.text(), /<script>|forbidden/);
    }
    for (const index of [0, 1, 2]) {
      const html = renderToStaticMarkup(React.createElement(AppealRecords, { appeals: [original], manage: capabilities[index].manage }));
      assert.match(html, /&lt;img/); assert.doesNotMatch(html, /<img/); assert.ok(html.includes("  Synthetic original reason\n")); assert.match(html, /white-space:pre-wrap/);
      assert.match(html, /이의제기 종결은 실행 승인이 아닙니다/);
      if (index === 0) {
        assert.match(html, /관리자 검토 결론/); assert.match(html, /name="resolution" required="" minLength="8" maxLength="2000"/);
        assert.match(html, /<form[^>]*method="post"/);
        assert.match(html, /aria-describedby="appeal-help-/); assert.match(html, /type="checkbox" required=""/);
      } else assert.doesNotMatch(html, /<form|<textarea|결론 기록 · 이의제기 종결/);
    }
    const busyHtml = renderToStaticMarkup(React.createElement(AppealRecords, { appeals: [original], manage: true, busy: true })); assert.match(busyHtml, /disabled=""/);
    const resolvedResponse = await request(resolvePath, admin, { resolution }); assert.equal(resolvedResponse.status, 200);
    const resolved = (await resolvedResponse.json()).appeal;
    assert.equal(resolved.status, "RESOLVED"); assert.equal(resolved.reason, reason); assert.equal(resolved.resolution, resolution); assert.equal(resolved.createdAt, original.createdAt);
    assert.ok(Number.isFinite(Date.parse(resolved.resolvedAt))); assert.deepEqual(await store.get(credentials[0].tenantId, "release", release.releaseId), release);
    const publicList = (await (await request(path, reader)).json()).items; assert.equal(publicList[0].resolution, resolution);
    const html = renderToStaticMarkup(React.createElement(AppealRecords, { appeals: publicList, manage: true }));
    assert.match(html, /RESOLVED/); assert.match(html, /종결 일시/); assert.match(html, /appeal.resolved/); assert.match(html, /&lt;script&gt;not executable&lt;\/script&gt;/); assert.doesNotMatch(html, /<script|<form|<textarea/);
    const history = (await (await request(`releases/${release.releaseId}/history`, reader)).json()).items;
    assert.equal(history.filter((event: any) => event.eventName === "appeal.opened").length, 1); assert.equal(history.filter((event: any) => event.eventName === "appeal.resolved").length, 1);
    assert.doesNotMatch(JSON.stringify(history), /Synthetic original reason|Synthetic review conclusion|synthetic-appeal-admin-token/);
    const foreignBody = await (await request(`releases/${release.releaseId}/history`, foreign)).text(); assert.doesNotMatch(foreignBody, /Synthetic|resolution|appealId/);
  } finally {
    names.forEach((name, index) => previous[index] === undefined ? delete process.env[name] : process.env[name] = previous[index]);
    await app.close();
  }
});
