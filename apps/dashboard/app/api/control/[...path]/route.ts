import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";
const COOKIE = "mcpshield_control";
const json = (body: unknown, status = 200) => NextResponse.json(body, { status, headers: { "cache-control": "no-store" } });
const routes = {
  GET: [/^session$/, /^operations$/, /^releases$/, /^releases\/[^/]+\/(history|appeals)$/, /^scans$/, /^scans\/[^/]+(?:\/evidence)?$/, /^policies$/],
  POST: [/^releases\/resolve$/, /^releases\/[^/]+\/appeals$/, /^appeals\/[^/]+\/resolve$/, /^scans$/, /^scans\/[^/]+\/retry$/, /^policies$/, /^policies\/[^/]+\/deprecate$/],
};

type Context = { params: Promise<{ path: string[] }> };

async function handle(request: NextRequest, context: Context) {
  const { path } = await context.params;
  if (!path.length || path.some((part) => !part || part === "." || part === ".." || /[/\\\x00-\x1f]/.test(part))) return json({ error: "Unknown control route" }, 404);
  const route = path.join("/");
  const mutating = request.method !== "GET";
  if (mutating && request.headers.get("origin") !== request.nextUrl.origin) return json({ error: "Same-origin request required" }, 403);
  const cookieOptions = { httpOnly: true, sameSite: "strict" as const, secure: request.nextUrl.protocol === "https:" || request.headers.get("x-forwarded-proto") === "https", path: "/api/control", maxAge: 8 * 60 * 60 };
  if (route === "session" && request.method === "DELETE") {
    const response = json({ signedOut: true });
    response.cookies.set(COOKIE, "", { ...cookieOptions, maxAge: 0 });
    return response;
  }
  const login = route === "session" && request.method === "POST";
  if (!login && !routes[request.method as keyof typeof routes]?.some((pattern) => pattern.test(route))) return json({ error: "Unknown control route" }, 404);
  let token = request.cookies.get(COOKIE)?.value;
  let body: string | undefined;
  if (mutating) {
    if (!request.headers.get("content-type")?.startsWith("application/json")) return json({ error: "JSON required" }, 415);
    if (Number(request.headers.get("content-length") ?? 0) > 65_536) return json({ error: "Request too large" }, 413);
    body = await request.text();
    if (Buffer.byteLength(body) > 65_536) return json({ error: "Request too large" }, 413);
    try {
      const parsed: unknown = JSON.parse(body);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
      if (login) token = (parsed as { token?: string }).token;
    } catch { return json({ error: "Invalid JSON object" }, 400); }
  }
  if (typeof token !== "string" || !/^[\x21-\x7e]{16,2048}$/.test(token)) return json({ error: "운영 액세스 토큰으로 로그인하세요." }, 401);
  const baseUrl = process.env.MCPSHIELD_API_URL ?? "http://127.0.0.1:3001";
  const url = new URL(`/v1/${path.map(encodeURIComponent).join("/")}`, baseUrl);
  for (const key of ["q", "status", "releaseId", "cursor", "limit"]) {
    const value = request.nextUrl.searchParams.get(key);
    if (value && value.length <= 512) url.searchParams.set(key, value);
  }
  try {
    const upstream = await fetch(url, {
      method: login ? "GET" : request.method,
      headers: { accept: "application/json", authorization: `Bearer ${token}`, ...(mutating && !login ? { "content-type": "application/json", "idempotency-key": request.headers.get("idempotency-key") ?? crypto.randomUUID() } : {}) },
      body: login ? undefined : body, cache: "no-store", signal: AbortSignal.timeout(10_000), redirect: "error",
    });
    const payload = await upstream.json();
    const response = json(payload, upstream.status);
    if (login && upstream.ok) response.cookies.set(COOKIE, token, cookieOptions);
    if (upstream.status === 401) response.cookies.set(COOKIE, "", { ...cookieOptions, maxAge: 0 });
    return response;
  } catch { return json({ error: "운영 API에 연결할 수 없습니다. 연결 설정을 확인하세요." }, 503); }
}

export const GET = handle;
export const POST = handle;
export const DELETE = handle;
