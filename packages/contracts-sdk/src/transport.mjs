import { FetchRequest } from "ethers";

// Fixed machine-readable errors never carry endpoint, response body or credentials.
export class TransportUnavailableError extends Error {
  constructor() { super("SERVICE_TRANSPORT_UNAVAILABLE"); this.name = "TransportUnavailableError"; }
}

export function checkedServiceUrl(value, allowedHttpHosts = []) {
  const url = new URL(value);
  const local = ["127.0.0.1", "localhost", "[::1]", ...allowedHttpHosts];
  if (url.username || url.password || url.hash || !(url.protocol === "https:" || (url.protocol === "http:" && local.includes(url.hostname)))) throw new Error("SERVICE_HTTPS_OR_EXPLICIT_INTERNAL_REQUIRED");
  return url;
}

export async function boundedServiceRequest(url, init, { timeoutMs = 5000, maxBytes = 8 * 1024 * 1024, allowedHttpHosts = [] } = {}) {
  const target = checkedServiceUrl(url, allowedHttpHosts), controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(new TransportUnavailableError()), timeoutMs);
  let reader;
  try {
    const response = await fetch(target, { ...init, redirect: "manual", signal: init.signal ? AbortSignal.any([init.signal, controller.signal]) : controller.signal });
    if (!response.ok) {
      void response.body?.cancel().catch(() => {});
      return { statusCode: response.status, statusMessage: response.statusText, headers: Object.fromEntries(response.headers), body: Buffer.alloc(0) };
    }
    const declared = response.headers.get("content-length");
    if (declared && Number(declared) > maxBytes) throw new Error("SERVICE_RESPONSE_TOO_LARGE");
    reader = response.body?.getReader();
    const chunks = []; let size = 0;
    while (reader) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength; if (size > maxBytes) throw new Error("SERVICE_RESPONSE_TOO_LARGE"); chunks.push(Buffer.from(value));
    }
    return { statusCode: response.status, statusMessage: response.statusText, headers: Object.fromEntries(response.headers), body: Buffer.concat(chunks) };
  } catch (error) {
    if (init.signal?.aborted && !(init.signal.reason instanceof TransportUnavailableError)) throw new Error("SERVICE_REQUEST_CANCELLED");
    if (controller.signal.aborted || init.signal?.reason instanceof TransportUnavailableError
      || ["ECONNREFUSED", "ECONNRESET", "ENOTFOUND", "EAI_AGAIN", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_SOCKET"].includes(error?.cause?.code)) throw new TransportUnavailableError();
    throw error;
  } finally { clearTimeout(deadline); void reader?.cancel().catch(() => {}); }
}

export function v2RpcRequest(url, { timeoutMs = 5000, signal, allowedHttpHosts = (process.env.CONTROL_V2_ALLOW_HTTP_HOSTS ?? "").split(",").filter(Boolean) } = {}) {
  const checked = checkedServiceUrl(url, allowedHttpHosts), request = new FetchRequest(checked.href);
  request.timeout = timeoutMs + 50; request.setThrottleParams({ maxAttempts: 1 });
  request.getUrlFunc = async (call, cancel) => {
    if (call.url !== checked.href) throw new Error("RPC_REDIRECT_DENIED");
    const controller = new AbortController(); cancel?.addListener(() => controller.abort());
    try {
      const response = await boundedServiceRequest(call.url, { method: call.method, headers: call.headers, body: call.body ? Buffer.from(call.body) : undefined,
        signal: signal ? AbortSignal.any([signal, controller.signal]) : controller.signal }, { timeoutMs, maxBytes: 4 * 1024 * 1024, allowedHttpHosts });
      if (response.statusCode >= 500) throw new TransportUnavailableError();
      if (response.statusCode < 200 || response.statusCode >= 300) throw new Error("RPC_TRUST_REJECTED");
      // Reject JSON-RPC errors and malformed/wrong-ID envelopes before ethers can
      // wrap private remote data in its diagnostic error objects.
      const sent = JSON.parse(Buffer.from(call.body).toString()), received = JSON.parse(response.body.toString());
      const calls = Array.isArray(sent) ? sent : [sent], replies = Array.isArray(received) ? received : [received];
      if (Array.isArray(sent) !== Array.isArray(received) || calls.length !== replies.length || replies.some(reply => !reply || reply.jsonrpc !== "2.0" || !Object.hasOwn(reply, "result")
        || Object.keys(reply).sort().join() !== "id,jsonrpc,result" || calls.filter(item => item.id === reply.id).length !== 1)
        || new Set(replies.map(reply => reply.id)).size !== replies.length) throw new Error("RPC_TRUST_REJECTED");
      return response;
    } catch (error) { if (error instanceof TransportUnavailableError) throw error; throw new Error("RPC_TRUST_REJECTED"); }
  };
  return request;
}
