const reasons = new Set(["INITIAL", "EVENTS_CHANGED", "RECONNECT"]);
const json = (status: number) => Response.json({ error: "자동 갱신 알림에 연결할 수 없습니다. 수동 새로고침을 사용하세요." }, { status, headers: { "cache-control": "no-store" } });

// Only the fixed invalidation vocabulary crosses this stream, never upstream event data or credentials.
export async function controlEventStream(request: Request, url: URL, token: string): Promise<Response> {
  const abort = new AbortController();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  const cancel = () => { abort.abort(); void reader?.cancel().catch(() => {}); };
  request.signal.addEventListener("abort", cancel, { once: true });
  if (request.signal.aborted) cancel();
  let timer = setTimeout(cancel, 10000);
  const cleanup = () => { clearTimeout(timer); request.signal.removeEventListener("abort", cancel); cancel(); };
  try {
    const upstream = await fetch(url, { headers: { accept: "text/event-stream", authorization: `Bearer ${token}` }, cache: "no-store", redirect: "error", signal: abort.signal });
    if (!upstream.ok || !upstream.body || !upstream.headers.get("content-type")?.startsWith("text/event-stream")) {
      void upstream.body?.cancel().catch(() => {}); cleanup(); return json(upstream.ok ? 503 : upstream.status);
    }
    clearTimeout(timer); timer = setTimeout(cancel, 600000);
    reader = upstream.body.getReader();
    const body = new ReadableStream<Uint8Array>({
      start(output) {
        void (async () => {
          const decoder = new TextDecoder("utf-8", { fatal: true }), encoder = new TextEncoder();
          let pending = "", bytes = 0, events = 0;
          try {
            while (true) {
              const result = await reader!.read();
              if (result.done) { output.close(); break; }
              bytes += result.value.byteLength; if (bytes > 65536) throw Error();
              pending = (pending + decoder.decode(result.value, { stream: true })).replace(/\r\n/g, "\n");
              let end;
              while ((end = pending.indexOf("\n\n")) >= 0) {
                if (end > 2048) throw Error();
                const frame = pending.slice(0, end); pending = pending.slice(end + 2);
                const lines = frame.split("\n").filter(line => line && !line.startsWith(":"));
                if (!lines.length) continue;
                if (lines.length === 1 && /^retry: ?3000$/.test(lines[0])) { output.enqueue(encoder.encode("retry: 3000\n\n")); continue; }
                if (lines.length !== 2 || !/^event: ?resync$/.test(lines[0]) || !lines[1].startsWith("data:")) throw Error();
                const data = JSON.parse(lines[1].slice(5));
                if (Object.keys(data).sort().join() !== "reason,type" || data.type !== "RESYNC_REQUIRED" || !reasons.has(data.reason) || ++events > 128) throw Error();
                output.enqueue(encoder.encode(`event: resync\ndata: ${JSON.stringify({ type: "RESYNC_REQUIRED", reason: data.reason })}\n\n`));
              }
              if (pending.length > 2048) throw Error();
            }
          } catch { try { output.error(new Error("CONTROL_EVENT_STREAM_CLOSED")); } catch { /* disconnected consumer */ } }
          finally { cleanup(); }
        })();
      },
      cancel: cleanup,
    });
    return new Response(body, { headers: { "content-type": "text/event-stream", "cache-control": "no-store, no-transform", "x-accel-buffering": "no", "x-content-type-options": "nosniff" } });
  } catch { cleanup(); return json(503); }
}
