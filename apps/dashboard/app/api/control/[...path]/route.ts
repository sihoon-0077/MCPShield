import { NextRequest, NextResponse } from "next/server";
import { receiptEvidenceSummary, validReceiptWriter } from "../../../../lib/receipt-summary";

export const dynamic = "force-dynamic";
const COOKIE = "mcpshield_control";
const json = (body: unknown, status = 200) => NextResponse.json(body, { status, headers: { "cache-control": "no-store" } });
const routes = {
  GET: [/^session$/, /^operations$/, /^releases$/, /^releases\/[^/]+\/(history|appeals)$/, /^scans$/, /^scans\/[^/]+(?:\/evidence)?$/, /^policies$/, /^chain\/actions(?:\/[^/]+)?$/, /^receipt-ledgers(?:\/[^/]+(?:\/batches)?)?$/, /^receipt-batches\/[^/]+(?:\/evidence)?$/],
  POST: [/^releases\/resolve$/, /^releases\/[^/]+\/(appeals|register)$/, /^appeals\/[^/]+\/resolve$/, /^scans$/, /^scans\/[^/]+\/retry$/, /^policies$/, /^policies\/[^/]+\/(deprecate|publish)$/, /^admission\/check$/, /^receipt-ledgers$/],
};

type Context = { params: Promise<{ path: string[] }> };

async function boundedJson(body: ReadableStream<Uint8Array> | null, maxBytes: number, timeoutMs = 10_000) {
  if (!body) throw new Error("EMPTY_JSON");
  const reader = body.getReader();
  let timer: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("BODY_TIMEOUT")), timeoutMs); });
  const parts: Buffer[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) throw new Error("BODY_TOO_LARGE");
      parts.push(Buffer.from(value));
    }
    return JSON.parse(Buffer.concat(parts).toString("utf8")) as unknown;
  } finally { clearTimeout(timer!); void reader.cancel().catch(() => {}); }
}

function controlOrigins(request: NextRequest) {
  const loopback = new Set(["127.0.0.1", "localhost", "[::1]"]);
  const publicUrl = new URL(process.env.MCPSHIELD_PUBLIC_ORIGIN ?? request.nextUrl.origin);
  if (publicUrl.username || publicUrl.password || publicUrl.pathname !== "/" || publicUrl.search || publicUrl.hash || !["http:", "https:"].includes(publicUrl.protocol)) throw new Error("PUBLIC_ORIGIN_INVALID");
  const localDemo = process.env.MCPSHIELD_CONTROL_ALLOW_LOOPBACK_HTTP === "true" && publicUrl.protocol === "http:" && loopback.has(publicUrl.hostname);
  if (process.env.NODE_ENV === "production" && (!process.env.MCPSHIELD_PUBLIC_ORIGIN || (publicUrl.protocol !== "https:" && !localDemo))) throw new Error("PUBLIC_ORIGIN_HTTPS_REQUIRED");
  const api = new URL(process.env.MCPSHIELD_API_URL ?? "http://127.0.0.1:3001");
  const allowedHttp = new Set([...loopback, ...(process.env.MCPSHIELD_API_HTTP_HOSTS ?? "").split(",").map((host) => host.trim()).filter(Boolean)]);
  if (api.username || api.password || api.search || api.hash || (api.protocol !== "https:" && !(api.protocol === "http:" && allowedHttp.has(api.hostname)))) throw new Error("API_HTTPS_REQUIRED");
  return { publicOrigin: publicUrl.origin, secure: publicUrl.protocol === "https:", api };
}

async function handle(request: NextRequest, context: Context) {
  const { path } = await context.params;
  if (!path.length || path.some((part) => !part || part === "." || part === ".." || /[/\\\x00-\x1f]/.test(part))) return json({ error: "Unknown control route" }, 404);
  const route = path.join("/");
  const mutating = request.method !== "GET";
  let origins;
  try { origins = controlOrigins(request); } catch { return json({ error: "운영 콘솔의 공개 HTTPS 주소와 API 연결 설정을 확인하세요." }, 503); }
  if (mutating && request.headers.get("origin") !== origins.publicOrigin) return json({ error: "Same-origin request required" }, 403);
  const cookieOptions = { httpOnly: true, sameSite: "strict" as const, secure: origins.secure, path: "/api/control", maxAge: 8 * 60 * 60 };
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
    try {
      const parsed = await boundedJson(request.body, 65_536);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
      if (login) token = (parsed as { token?: string }).token;
      if (route === "receipt-ledgers") {
        const key = request.headers.get("idempotency-key");
        if (Object.keys(parsed).length !== 1 || !validReceiptWriter((parsed as { writer?: unknown }).writer) || !key?.trim() || key.length > 256) return json({ error: "0이 아닌 공개 writer 주소(0x + 40자리 hex)와 재시도 식별키가 필요합니다. 개인키는 입력하지 마세요." }, 400);
      }
      body = JSON.stringify(parsed);
    } catch (error) { return json({ error: "요청 JSON이 잘못되었거나 제한 크기·시간을 초과했습니다." }, error instanceof Error && error.message === "BODY_TOO_LARGE" ? 413 : 400); }
  }
  if (typeof token !== "string" || !/^[\x21-\x7e]{16,2048}$/.test(token)) return json({ error: "운영 액세스 토큰으로 로그인하세요." }, 401);
  const url = new URL(`/v1/${path.map(encodeURIComponent).join("/")}`, origins.api);
  for (const key of ["q", "status", "releaseId", "cursor", "limit"]) {
    const value = request.nextUrl.searchParams.get(key);
    if (value && value.length <= 512) url.searchParams.set(key, value);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const upstream = await fetch(url, {
      method: login ? "GET" : request.method,
      headers: { accept: "application/json", authorization: `Bearer ${token}`, ...(mutating && !login ? { "content-type": "application/json", "idempotency-key": request.headers.get("idempotency-key") ?? crypto.randomUUID() } : {}) },
      body: login ? undefined : body, cache: "no-store", signal: controller.signal, redirect: "error",
    });
    const payload = await boundedJson(upstream.body, 4 * 1024 * 1024);
    const response = json(upstream.ok && /^receipt-batches\/[^/]+\/evidence$/.test(route) ? receiptEvidenceSummary(payload) : payload, upstream.status);
    if (login && upstream.ok) response.cookies.set(COOKIE, token, cookieOptions);
    if (upstream.status === 401) response.cookies.set(COOKIE, "", { ...cookieOptions, maxAge: 0 });
    return response;
  } catch { return json({ error: "운영 API 응답을 안전하게 불러올 수 없습니다. 연결 상태나 응답 크기를 확인하세요." }, 503); }
  finally { clearTimeout(timer); }
}

export const GET = handle;
export const POST = handle;
export const DELETE = handle;
