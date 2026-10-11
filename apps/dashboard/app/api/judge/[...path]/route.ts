export const dynamic = "force-dynamic";

type Context = { params: Promise<{ path: string[] }> };
const allowedPath = /^sessions(?:\/[0-9a-f-]{36}(?:\/actions)?)?$/;

async function proxy(request: Request, context: Context) {
  const path = (await context.params).path.join("/");
  if (!allowedPath.test(path)) return Response.json({ error: "Not found" }, { status: 404 });
  const body = request.method === "POST" ? await request.text() : undefined;
  if (body && body.length > 1_024) return Response.json({ error: "Request too large" }, { status: 413 });
  const baseUrl = (process.env.MCPSHIELD_API_URL ?? "http://127.0.0.1:3001").replace(/\/$/, "");
  try {
    const response = await fetch(`${baseUrl}/api/demo/${path}`, {
      method: request.method,
      headers: body ? { "content-type": "application/json" } : undefined,
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(20_000),
    });
    return new Response([204, 205, 304].includes(response.status) ? null : await response.arrayBuffer(), {
      status: response.status,
      headers: { "content-type": response.headers.get("content-type") ?? "application/json", "cache-control": "no-store" },
    });
  } catch {
    return Response.json({ error: "Judge demo backend unavailable" }, { status: 503, headers: { "cache-control": "no-store" } });
  }
}

export const GET = proxy;
export const POST = proxy;
export const DELETE = proxy;
