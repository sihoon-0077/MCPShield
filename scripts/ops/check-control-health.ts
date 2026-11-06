import { pathToFileURL } from "node:url";
import { parseControlHealth } from "../../apps/dashboard/lib/control-health.js";

// One read-only check for a deployment gate or an operator's existing monitor.
// No scheduling, webhook delivery, automatic retries or service mutations.
export async function checkControlReadiness(input: { url: string; token: string; timeoutMs?: number }) {
  let url: URL;
  const timeoutMs = input.timeoutMs ?? 5000;
  try {
    url = new URL(input.url);
    if (url.username || url.password || url.search || url.hash || url.pathname !== "/v1/health"
      || !(url.protocol === "https:" || url.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname))
      || !/^[\x21-\x7e]{16,2048}$/.test(input.token) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 5000) throw Error();
  } catch { throw Error("HEALTH_CONFIG_INVALID"); }
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined, reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => { reject(Error("HEALTH_TIMEOUT")); controller.abort(); }, timeoutMs);
  });
  try {
    const response = await Promise.race([fetch(url, { method: "GET", headers: { accept: "application/json", authorization: `Bearer ${input.token}` },
      cache: "no-store", redirect: "manual", signal: controller.signal }), deadline]);
    if ([401, 403].includes(response.status)) throw Error("HEALTH_AUTH_REQUIRED");
    if (![200, 503].includes(response.status)) throw Error("HEALTH_HTTP_UNEXPECTED");
    if (!/^application\/json\b/i.test(response.headers.get("content-type") ?? "")) throw Error("HEALTH_JSON_REQUIRED");
    reader = response.body?.getReader();
    const chunks: Uint8Array[] = []; let bytes = 0;
    if (reader) for (;;) {
      const { done, value } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 16_384) throw Error("HEALTH_BODY_LIMIT");
      chunks.push(value);
    }
    let report;
    try { report = parseControlHealth(JSON.parse(Buffer.concat(chunks).toString("utf8")), response.status); }
    catch { throw Error("HEALTH_RESPONSE_INVALID"); }
    const age = Date.now() - Date.parse(report.checkedAt);
    if (age < -5000 || age > 15_000) throw Error("HEALTH_STALE_RESPONSE");
    for (const [name, component] of Object.entries(report.components)) {
      // A fresh envelope must not launder old successful observations. Account for
      // the API cache/probe budget and at most five seconds of network transit.
      if (component.status === "UP" && Date.now() - Date.parse(component.checkedAt!) > (name === "scanner" ? 25_000 : 10_000)) throw Error("HEALTH_STALE_COMPONENT");
    }
    // Only the fixed component names and statuses are emitted, not the raw body/codes.
    return { schemaVersion: report.schemaVersion, status: report.status, checkedAt: report.checkedAt,
      components: Object.fromEntries(Object.entries(report.components).map(([name, component]) => [name, component.status])) };
  } catch (error) {
    const code = error instanceof Error ? error.message : "";
    throw Error(["HEALTH_TIMEOUT", "HEALTH_AUTH_REQUIRED", "HEALTH_HTTP_UNEXPECTED", "HEALTH_JSON_REQUIRED", "HEALTH_BODY_LIMIT", "HEALTH_RESPONSE_INVALID", "HEALTH_STALE_RESPONSE", "HEALTH_STALE_COMPONENT"].includes(code) ? code : "HEALTH_UNAVAILABLE");
  } finally { clearTimeout(timer); controller.abort(); void reader?.cancel().catch(() => {}); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 2) throw Error("HEALTH_CONFIG_INVALID");
    const report = await checkControlReadiness({ url: process.env.MCPSHIELD_HEALTH_URL ?? "", token: process.env.MCPSHIELD_HEALTH_TOKEN ?? "" });
    console.log(JSON.stringify({ event: "control.health", ...report }));
    process.exitCode = report.status === "READY" ? 0 : 1;
  } catch (error) {
    console.error(JSON.stringify({ event: "control.health", status: "UNAVAILABLE", code: error instanceof Error ? error.message : "HEALTH_UNAVAILABLE" }));
    process.exitCode = 2;
  }
}
