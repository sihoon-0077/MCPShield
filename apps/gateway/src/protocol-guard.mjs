import { randomUUID } from "node:crypto";
import { Transform } from "node:stream";
import { parseJSONRPCMessage, PROTOCOL_VERSION_META_KEY, CLIENT_INFO_META_KEY, CLIENT_CAPABILITIES_META_KEY, SUPPORTED_PROTOCOL_VERSIONS } from "@modelcontextprotocol/server";
import { canonicalJson, toolSurfaceHash } from "./artifact.mjs";

export class ToolSurfaceDriftError extends Error {
  constructor(expected, observed) {
    super(`Runtime tools/list drift: expected ${expected}, observed ${observed}`);
    this.name = "ToolSurfaceDriftError"; this.expected = expected; this.observed = observed;
  }
}

const idKey = (id) => `${typeof id}:${JSON.stringify(id)}`;
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const MODERN = "2026-07-28";
const CLIENT_METHODS = new Set(["initialize", "notifications/initialized", "ping", "server/discover", "tools/list", "tools/call", "notifications/cancelled", "notifications/progress"]);
const SERVER_NOTIFICATIONS = new Set(["notifications/tools/list_changed", "notifications/progress"]);

function frameTransform(inspect, beforeForward) {
  let pending = Buffer.alloc(0);
  async function frame(line, output) {
    if (!line.toString("utf8").trim()) return;
    let value;
    try { value = JSON.parse(line); } catch { throw new Error("Invalid MCP JSON-RPC JSON"); }
    const messages = Array.isArray(value) ? value : [value];
    if (!messages.length || messages.length > 128) throw new Error("Invalid MCP JSON-RPC batch size");
    const visible = [];
    for (const message of messages) {
      try { parseJSONRPCMessage(message); } catch { throw new Error("Invalid MCP JSON-RPC envelope"); }
      if (typeof message.id === "string" && message.id.length > 256) throw new Error("MCP request ID is oversized");
      visible.push(await inspect(message) !== false);
    }
    if (visible.some(Boolean) && !visible.every(Boolean)) throw new Error("Mixed private and client response batch");
    if (visible.every(Boolean)) { beforeForward?.(); output.push(line); }
  }
  return new Transform({
    transform(chunk, _encoding, callback) {
      const receive = async () => {
        pending = Buffer.concat([pending, chunk]);
        let newline;
        while ((newline = pending.indexOf(10)) !== -1) {
          if (newline > 1_048_576) throw new Error("MCP JSON-RPC line exceeds 1 MiB");
          const line = pending.subarray(0, newline + 1); pending = pending.subarray(newline + 1);
          await frame(line, this);
        }
        if (pending.length > 1_048_576) throw new Error("MCP JSON-RPC line exceeds 1 MiB");
      };
      receive().then(() => callback(), callback);
    },
    flush(callback) { (pending.length ? frame(pending, this) : Promise.resolve()).then(() => callback(), callback); },
  });
}

// The SDK validates envelopes. These guards add artifact-bound admission and hide
// private pagination probes; external JSON-RPC frames remain byte-for-byte intact.
export function runtimeSurfaceGuards(expectedHash, tools = [], beforeCall, { sendInternal, timeoutMs = 3_000, beforeForward, beforeRequest } = {}) {
  const allowedTools = new Set(tools.map(({ name }) => name));
  const requestsById = new Map(), privateCalls = new Map(), completed = new Set();
  const privatePrefix = `mcpshield.${randomUUID()}.`;
  let era, initialized = false, initialization, initializationId, surfaceChanged = false;
  let pages, activeMeta, sequence = 0, revision = 0, closed = false;
  const waiting = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    // A timeout may precede the next client message that awaits initialization.
    promise.catch(() => {});
    const timer = setTimeout(() => reject(new Error("MCP verification response timed out")), timeoutMs);
    return { promise, resolve: (value) => { clearTimeout(timer); resolve(value); }, reject: (error) => { clearTimeout(timer); reject(error); } };
  };
  const privateRequest = async (params) => {
    if (!sendInternal || closed) throw new Error("MCP private surface collector is unavailable");
    const id = `${privatePrefix}${++sequence}`, pending = waiting();
    privateCalls.set(id, pending);
    try {
      await sendInternal({ jsonrpc: "2.0", id, method: "tools/list", params });
      return await pending.promise;
    } finally { privateCalls.delete(id); pending.reject(new Error("MCP private request closed")); }
  };
  const ensureSurface = async (meta) => {
    const context = canonicalJson(meta ?? {});
    if (pages && !surfaceChanged && activeMeta === context) return;
    const startedRevision = revision;
    const nextPages = new Map(), collected = [], names = new Set();
    let cursor;
    for (let page = 0; page < 32; page++) {
      const result = await privateRequest({ ...(cursor === undefined ? {} : { cursor }), ...(meta ? { _meta: meta } : {}) });
      if (!object(result) || !Array.isArray(result.tools) || result.tools.length > 128) throw new ToolSurfaceDriftError(expectedHash, "INVALID_TOOLS_LIST");
      for (const tool of result.tools) {
        if (!object(tool) || typeof tool.name !== "string" || names.has(tool.name)) throw new ToolSurfaceDriftError(expectedHash, "DUPLICATE_OR_INVALID_TOOL");
        names.add(tool.name); collected.push(tool);
      }
      if (collected.length > 128) throw new ToolSurfaceDriftError(expectedHash, "TOO_MANY_TOOLS");
      const next = result.nextCursor;
      if (next !== undefined && (typeof next !== "string" || !next || next.length > 1_024 || nextPages.has(next) || next === cursor)) throw new ToolSurfaceDriftError(expectedHash, "INVALID_TOOLS_CURSOR");
      nextPages.set(cursor ?? "", { hash: toolSurfaceHash(result.tools), nextCursor: next });
      if (next === undefined) {
        if (revision !== startedRevision) throw new ToolSurfaceDriftError(expectedHash, "SURFACE_CHANGED_DURING_COLLECTION");
        const observed = toolSurfaceHash(collected);
        if (observed !== expectedHash) throw new ToolSurfaceDriftError(expectedHash, observed);
        pages = nextPages; activeMeta = context; surfaceChanged = false;
        return;
      }
      cursor = next;
    }
    throw new ToolSurfaceDriftError(expectedHash, "TOO_MANY_TOOLS_PAGES");
  };
  const requests = frameTransform(async (message) => {
    beforeRequest?.(message);
    if (typeof message.id === "string" && message.id.startsWith(privatePrefix)) throw new Error("Reserved Gateway request ID");
    if (typeof message.method !== "string") {
      throw new Error("Gateway tools-only profile does not accept client responses");
    }
    if (!CLIENT_METHODS.has(message.method)) throw new Error("Unsupported client method in Gateway tools-only profile");
    const meta = message.params?._meta;
    if (object(meta) && Object.hasOwn(meta, PROTOCOL_VERSION_META_KEY)) {
      if (meta[PROTOCOL_VERSION_META_KEY] !== MODERN || !object(meta[CLIENT_INFO_META_KEY]) || typeof meta[CLIENT_INFO_META_KEY].name !== "string" || typeof meta[CLIENT_INFO_META_KEY].version !== "string" || !object(meta[CLIENT_CAPABILITIES_META_KEY])) throw new Error("Invalid stateless MCP request envelope");
      if (era === "legacy") throw new Error("MCP protocol era cannot change during a session");
      era = "modern";
    } else if (era === "modern") throw new Error("Stateless MCP requests require their protocol envelope");
    if (message.method === "server/discover" && era !== "modern") throw new Error("MCP discovery requires a stateless protocol envelope");
    if (message.method === "initialize") {
      if (era || initialization || !Object.hasOwn(message, "id") || !SUPPORTED_PROTOCOL_VERSIONS.includes(message.params?.protocolVersion)) throw new Error("Invalid or duplicate MCP initialization");
      era = "legacy"; initializationId = idKey(message.id); initialization = waiting();
    } else if (message.method === "notifications/initialized") {
      if (era !== "legacy" || !initialization || initialized) throw new Error("Invalid MCP initialized notification");
      await initialization.promise; initialized = true;
    } else if (message.method.startsWith("tools/")) {
      if (!Object.hasOwn(message, "id")) throw new Error("MCP tool methods require a request ID");
      if (message.method === "tools/call" && !allowedTools.has(message.params?.name)) throw new Error("Undeclared runtime tool call");
      if (era !== "modern" && !initialized) throw new Error("MCP initialization required before tool requests");
      await ensureSurface(era === "modern" ? meta : undefined);
      if (message.method === "tools/list") {
        const cursor = message.params?.cursor ?? "";
        if (typeof cursor !== "string" || !pages.has(cursor)) throw new Error("Unknown MCP tools/list cursor");
      }
      if (message.method === "tools/call" && beforeCall) await beforeCall(message);
    }
    if (Object.hasOwn(message, "id")) {
      const key = idKey(message.id);
      if (requestsById.has(key)) throw new Error("Duplicate pending MCP request ID");
      if (requestsById.size >= 1_024) throw new Error("Too many pending MCP requests");
      completed.delete(key);
      requestsById.set(key, { method: message.method, cursor: message.params?.cursor ?? "" });
    }
  }, beforeForward);
  const responses = frameTransform((message) => {
    if (typeof message.method === "string" && (Object.hasOwn(message, "id") || !SERVER_NOTIFICATIONS.has(message.method))) throw new Error("Unsupported server method in Gateway tools-only profile");
    if (message.method === "notifications/tools/list_changed") { surfaceChanged = true; revision++; return; }
    if (typeof message.method === "string") {
      return;
    }
    if (typeof message.id === "string" && message.id.startsWith(privatePrefix)) {
      const pending = privateCalls.get(message.id);
      if (!pending) throw new Error("Unexpected private MCP response");
      privateCalls.delete(message.id);
      if (message.error) pending.reject(new ToolSurfaceDriftError(expectedHash, "TOOLS_LIST_ERROR"));
      else pending.resolve(message.result);
      return false;
    }
    const key = idKey(message.id), request = requestsById.get(key);
    if (!request) throw new Error(completed.has(key) ? "Duplicate MCP response" : "Unsolicited MCP response");
    requestsById.delete(key); completed.add(key);
    if (completed.size > 1_024) completed.delete(completed.values().next().value);
    if (key === initializationId) {
      if (message.error || !SUPPORTED_PROTOCOL_VERSIONS.includes(message.result?.protocolVersion)) {
        const error = new Error("MCP initialization failed"); initialization.reject(error); throw error;
      }
      initialization.resolve();
    }
    if (request.method === "tools/list") {
      const page = pages?.get(request.cursor);
      if (message.error || !Array.isArray(message.result?.tools)) throw new ToolSurfaceDriftError(expectedHash, "TOOLS_LIST_ERROR");
      if (!page || surfaceChanged || toolSurfaceHash(message.result.tools) !== page.hash || message.result.nextCursor !== page.nextCursor) throw new ToolSurfaceDriftError(expectedHash, "RUNTIME_TOOL_SURFACE_DRIFT");
    }
  });
  const close = () => {
    closed = true;
    const error = new Error("MCP channel closed");
    initialization?.reject(error);
    for (const pending of privateCalls.values()) pending.reject(error);
    privateCalls.clear(); requests.destroy(); responses.destroy();
  };
  return { requests, responses, close };
}
