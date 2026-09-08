import { createHash } from "node:crypto";
import { setTimeout as pause } from "node:timers/promises";
import type { FastifyInstance } from "fastify";
import type { ControlStore } from "./control-store.js";
import type { Credential } from "./control-plane.js";

const limits = { pollMs: 1000, heartbeatMs: 15000, idleMs: 120000, maxAgeMs: 600000, queryTimeoutMs: 3000, global: 32, perTenant: 3 };
const message = (reason: "INITIAL" | "EVENTS_CHANGED" | "RECONNECT") => `event: resync\ndata: ${JSON.stringify({ type: "RESYNC_REQUIRED", reason })}\n\n`;
const failure = (code: string, statusCode: number) => Object.assign(new Error(code), { statusCode });

// Timing overrides are for direct module tests; the public control-plane route always uses fixed limits.
export function registerEventStream(api: FastifyInstance, store: ControlStore, authenticate: (header: string | undefined) => Credential, settings = limits) {
  for (const [key, value] of Object.entries(settings)) if (!Number.isSafeInteger(value) || value < 1 || value > limits[key as keyof typeof limits]) throw new Error("INVALID_EVENT_STREAM_LIMITS");
  const connections = new Set<{ tenantId: string; stop: () => void; finished: Promise<void> }>();
  let stopping = false;
  api.addHook("preClose", async () => {
    stopping = true;
    const open = [...connections]; for (const connection of open) connection.stop();
    await Promise.all(open.map((connection) => connection.finished));
  });
  const snapshot = async (tenantId: string, signal: AbortSignal) => {
    signal.throwIfAborted();
    const timeout = new AbortController();
    try {
      const events = await Promise.race([store.events(tenantId), pause(settings.queryTimeoutMs, undefined, { signal: AbortSignal.any([signal, timeout.signal]) }).then(() => { throw new Error("EVENT_SNAPSHOT_TIMEOUT"); })]);
      // A bounded set fingerprint, not a cursor: UUID/time ordering never promises lossless delivery.
      return createHash("sha256").update(JSON.stringify(events.map((event) => event.eventId).sort())).digest("hex");
    } finally { timeout.abort(); }
  };
  api.get("/events/stream", async (request, reply) => {
    const identity = authenticate(request.headers.authorization);
    if (Object.keys(request.query ?? {}).length) throw failure("EVENT_STREAM_QUERY_UNSUPPORTED", 400);
    if (stopping) throw failure("EVENT_STREAM_STOPPING", 503);
    if (connections.size >= settings.global || [...connections].filter((item) => item.tenantId === identity.tenantId).length >= settings.perTenant) throw failure("EVENT_STREAM_LIMIT", 429);
    const controller = new AbortController(), raw = reply.raw;
    let closed = false, finish!: () => void;
    const connection = { tenantId: identity.tenantId, stop: () => stop(true), finished: new Promise<void>((resolve) => { finish = resolve; }) };
    const stop = (destroy = false) => {
      if (closed) return; closed = true; controller.abort(); connections.delete(connection);
      request.raw.off("aborted", aborted); raw.off("close", aborted);
      if (destroy) raw.destroy(); else if (raw.headersSent && !raw.writableEnded && !raw.destroyed) raw.end();
    };
    const aborted = () => stop(true);
    const write = (frame: string) => {
      if (closed || raw.destroyed || raw.writableEnded) return false;
      // Drop a slow consumer instead of retaining an unbounded per-client event queue.
      if (raw.writableLength > 4096 || !raw.write(frame)) { stop(true); return false; }
      return true;
    };
    connections.add(connection); request.raw.once("aborted", aborted); raw.once("close", aborted);
    try {
      let previous = await snapshot(identity.tenantId, controller.signal);
      if (closed) return reply;
      if (authenticate(request.headers.authorization).tenantId !== identity.tenantId) throw new Error("STREAM_IDENTITY_CHANGED");
      reply.hijack();
      for (const [key, value] of Object.entries(reply.getHeaders())) if (value !== undefined) raw.setHeader(key, value);
      raw.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store, no-transform", "x-accel-buffering": "no" });
      raw.flushHeaders();
      if (!write(`retry: 3000\n\n${message("INITIAL")}`)) return reply;
      const started = performance.now(); let changedAt = started, heartbeatAt = started;
      while (!closed) {
        await pause(settings.pollMs, undefined, { signal: controller.signal });
        // Static credentials can be revoked/reassigned at runtime; never retain old tenant access.
        if (authenticate(request.headers.authorization).tenantId !== identity.tenantId) throw new Error("STREAM_IDENTITY_CHANGED");
        const now = performance.now();
        if (now - started >= settings.maxAgeMs || now - changedAt >= settings.idleMs) { write(message("RECONNECT")); break; }
        const current = await snapshot(identity.tenantId, controller.signal);
        if (closed) break;
        if (authenticate(request.headers.authorization).tenantId !== identity.tenantId) throw new Error("STREAM_IDENTITY_CHANGED");
        if (current !== previous) { previous = current; changedAt = performance.now(); if (!write(message("EVENTS_CHANGED"))) break; }
        else if (now - heartbeatAt >= settings.heartbeatMs) { if (!write(": heartbeat\n\n")) break; heartbeatAt = now; }
      }
    } catch {
      if (!closed && !raw.headersSent) reply.code(503).send({ error: { code: "EVENT_STREAM_UNAVAILABLE" } });
      else if (!closed) write(message("RECONNECT"));
    } finally { stop(); finish(); }
    return reply;
  });
}
