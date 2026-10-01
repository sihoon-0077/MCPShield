// Synthetic-only browser fixture. No scanner, chain, external network or production data.
// node --import tsx apps/dashboard/test/manual-rescan-preview.mts [--response-loss]
// Start the built dashboard separately with the printed loopback MCPSHIELD_API_URL.
// --response-loss replaces the first accepted scan response with 503 AFTER commit;
// it also pauses SSE so the user can retry the still-mounted form deliberately.
import { createServer } from "node:http";
import { buildApp } from "../../api/src/app.js";
import { ControlStore } from "../../api/src/control-store.js";
import { defaultPolicy } from "../../api/src/control-policy.js";
import { hash } from "../../api/src/control-plane.js";

const tenantId = "SYNTHETIC_BROWSER_QA", store = await ControlStore.open();
const credentials = (["operator", "reader", "admin"] as const).map(role => ({ tenantId, role, token: `synthetic-browser-${role}-token` }));
const app = await buildApp({ databasePath: ":memory:", adminApiToken: "synthetic-browser-legacy-admin", scannerApiToken: "synthetic-browser-legacy-scanner",
  controlPlane: { store, credentials, artifactPath: "UNUSED_SYNTHETIC_QA", evidencePath: "UNUSED_SYNTHETIC_QA", evidenceKey: "1".repeat(64) } });
const original = { releaseId: `0x${"1".repeat(64)}`, toolId: "synthetic-browser-mail", legacyReleaseId: "SYNTHETIC-browser-mail@1.0.0", version: "1.0.0", sourceType: "fixture",
  artifactDigest: `sha256:${"2".repeat(64)}`, toolSurfaceHash: `0x${"3".repeat(64)}`, policyHash: hash(defaultPolicy), reportRoot: `0x${"4".repeat(64)}`, status: "REVOKED", validUntil: null, chain: null };
for (const item of [original,
  { ...original, releaseId: `0x${"a".repeat(64)}`, artifactDigest: `sha256:${"a".repeat(64)}`, legacyReleaseId: "SYNTHETIC-corrected@1.0.1", version: "1.0.1", status: "UNVERIFIED" },
  { ...original, releaseId: `0x${"b".repeat(64)}`, legacyReleaseId: "SYNTHETIC-same-digest-new-id@1.0.0" },
  { ...original, releaseId: `0x${"c".repeat(64)}`, toolId: "synthetic-unrelated", legacyReleaseId: "SYNTHETIC-unrelated@1.0.0" },
]) await store.put(tenantId, "release", item.releaseId, item);
const newPolicy = { ...defaultPolicy, validitySeconds: 7200 }, policyHash = hash(newPolicy);
await store.put(tenantId, "policy", policyHash, { policyHash, alias: "SYNTHETIC-changed-policy", version: "1.0.0", document: newPolicy, createdAt: new Date().toISOString(), deprecatedAt: null });
const opened = await app.inject({ method: "POST", url: `/v1/releases/${original.releaseId}/appeals`, headers: { authorization: `Bearer ${credentials[0].token}` }, payload: { reason: "SYNTHETIC browser QA: verify corrected release without changing original revoked evidence." } });
if (opened.statusCode !== 201) throw Error("SYNTHETIC_APPEAL_SETUP_FAILED");
await app.listen({ host: "127.0.0.1", port: 0 });
const apiOrigin = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
const faultMode = process.argv.includes("--response-loss"); let dropNextScan = faultMode;
const proxy = createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (!url.pathname.startsWith("/v1/")) { response.writeHead(404); response.end(); return; }
    if (faultMode && url.pathname === "/v1/events/stream") { response.writeHead(503); response.end("SYNTHETIC_QA_SSE_PAUSED"); return; }
    const parts: Buffer[] = []; let bytes = 0;
    for await (const part of request) { bytes += part.length; if (bytes > 65536) throw Error("BODY_TOO_LARGE"); parts.push(part); }
    const body = request.method === "GET" ? undefined : Buffer.concat(parts);
    const upstream = await fetch(new URL(url.pathname + url.search, apiOrigin), { method: request.method, headers: {
      authorization: request.headers.authorization ?? "", "content-type": "application/json", "idempotency-key": String(request.headers["idempotency-key"] ?? ""),
    }, body, signal: AbortSignal.timeout(10000), redirect: "error" });
    // Stream resync frames in normal mode; fault mode exits above.
    if (url.pathname === "/v1/events/stream" && upstream.ok && upstream.body) {
      response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
      const reader = upstream.body.getReader(); response.on("close", () => { void reader.cancel(); });
      while (true) { const chunk = await reader.read(); if (chunk.done) break; response.write(chunk.value); } response.end(); return;
    }
    const payload = await upstream.text();
    if (url.pathname === "/v1/scans" && request.method === "POST") {
      console.log(JSON.stringify({ event: "synthetic.qa.scan", key: request.headers["idempotency-key"], request: JSON.parse(body!.toString()), status: upstream.status,
        scanId: JSON.parse(payload).scan?.scanId, deduplicated: JSON.parse(payload).deduplicated, responseReplaced: dropNextScan && upstream.status === 202 }));
      if (dropNextScan && upstream.status === 202) {
        dropNextScan = false; response.writeHead(503, { "content-type": "application/json" }); response.end(JSON.stringify({ error: { code: "SYNTHETIC_RESPONSE_LOST", message: "SYNTHETIC_RESPONSE_LOST" } })); return;
      }
    }
    response.writeHead(upstream.status, { "content-type": "application/json", "cache-control": "no-store" }); response.end(payload);
  } catch { if (!response.headersSent) response.writeHead(503); response.end(); }
});
proxy.listen(4187, "127.0.0.1", () => console.log(JSON.stringify({ event: "synthetic.qa.ready", api: "http://127.0.0.1:4187", faultMode, credentials, original: original.releaseId, appealId: opened.json().appeal.appealId })));
let closing = false;
async function close() { if (closing) return; closing = true; proxy.closeAllConnections(); await new Promise<void>(resolve => proxy.close(() => resolve())); await app.close(); }
process.on("SIGINT", () => { void close(); }); process.on("SIGTERM", () => { void close(); });
