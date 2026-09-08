import { FetchRequest } from "ethers";

export function checkedServiceUrl(value: string, allowedHttpHosts: string[] = []) {
  const url = new URL(value);
  const local = ["127.0.0.1", "localhost", "[::1]", ...allowedHttpHosts];
  if (url.username || url.password || url.hash || !(url.protocol === "https:" || (url.protocol === "http:" && local.includes(url.hostname)))) throw new Error("SERVICE_HTTPS_OR_EXPLICIT_INTERNAL_REQUIRED");
  return url;
}

export async function boundedServiceRequest(url: string, init: RequestInit, { timeoutMs = 5000, maxBytes = 8 * 1024 * 1024, allowedHttpHosts = [] as string[] } = {}) {
  const target = checkedServiceUrl(url, allowedHttpHosts), controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(new Error("SERVICE_TIMEOUT")), timeoutMs);
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    const response = await fetch(target, { ...init, redirect: "error", signal: init.signal ? AbortSignal.any([init.signal, controller.signal]) : controller.signal });
    const declared = response.headers.get("content-length");
    if (declared && Number(declared) > maxBytes) throw new Error("SERVICE_RESPONSE_TOO_LARGE");
    reader = response.body?.getReader();
    const chunks: Buffer[] = []; let size = 0;
    while (reader) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength; if (size > maxBytes) throw new Error("SERVICE_RESPONSE_TOO_LARGE"); chunks.push(Buffer.from(value));
    }
    return { statusCode: response.status, statusMessage: response.statusText, headers: Object.fromEntries(response.headers), body: Buffer.concat(chunks) };
  } finally { clearTimeout(deadline); void reader?.cancel().catch(() => {}); }
}

export function v2RpcRequest(url: string, { timeoutMs = 5000, signal, allowedHttpHosts = (process.env.CONTROL_V2_ALLOW_HTTP_HOSTS ?? "").split(",").filter(Boolean) }: { timeoutMs?: number; signal?: AbortSignal; allowedHttpHosts?: string[] } = {}) {
  const checked = checkedServiceUrl(url, allowedHttpHosts), request = new FetchRequest(checked.href);
  request.timeout = timeoutMs; request.setThrottleParams({ maxAttempts: 1 });
  request.getUrlFunc = async (call, cancel) => {
    if (call.url !== checked.href) throw new Error("RPC_REDIRECT_DENIED");
    const controller = new AbortController(); cancel?.addListener(() => controller.abort());
    return boundedServiceRequest(call.url, { method: call.method, headers: call.headers, body: call.body ? Buffer.from(call.body) : undefined,
      signal: signal ? AbortSignal.any([signal, controller.signal]) : controller.signal }, { timeoutMs, maxBytes: 4 * 1024 * 1024, allowedHttpHosts });
  };
  return request;
}
