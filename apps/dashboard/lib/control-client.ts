export async function controlApi<T>(path: string, body?: unknown, method = body === undefined ? "GET" : "POST"): Promise<T> {
  const response = await fetch(`/api/control/${path}`, { method, cache: "no-store", headers: body === undefined ? {} : { "content-type": "application/json", "idempotency-key": crypto.randomUUID() }, body: body === undefined ? undefined : JSON.stringify(body) });
  const payload = await response.json();
  if (!response.ok) throw new Error(typeof payload.error === "string" ? payload.error : payload.error?.message ?? payload.message ?? `요청 실패 (${response.status})`);
  return payload as T;
}
