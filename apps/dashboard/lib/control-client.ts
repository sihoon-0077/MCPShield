const messages: Record<string, string> = {
  APPEAL_NOT_OPEN: "이미 종결된 이의제기입니다. 목록을 새로고침해 검토 결과를 확인하세요.",
  APPEAL_ALREADY_RESOLVED: "이미 다른 검토 결론이 기록되어 있습니다. 새로고침해 기존 결론을 확인하세요.",
  APPEAL_RESCAN_ALREADY_REQUESTED: "이 이의제기에는 새 검사가 이미 연결되어 있습니다. 새로고침해 해당 검사를 확인하세요.",
  APPEAL_TOOL_MISMATCH: "원본과 같은 도구의 릴리스를 선택하세요.",
  APPEAL_TARGET_CHANGED: "선택한 릴리스 정보가 바뀌었습니다. 새로고침 후 다시 선택하세요.",
  APPEAL_ORIGINAL_POLICY_REQUIRED: "원본 정책 기록이 없어 같은 파일을 재검사할 수 없습니다. 수정된 파일의 릴리스를 선택하세요.",
  APPEAL_NEW_DIGEST_OR_POLICY_REQUIRED: "원본과 파일·정책이 같습니다. 수정된 파일 또는 다른 활성 정책을 선택하세요.",
  POLICY_DEPRECATED: "사용이 중단된 정책입니다. 새로고침 후 활성 정책을 선택하세요.",
  SCAN_PROFILE_MISMATCH: "릴리스 실행 환경과 정책이 맞지 않습니다. 같은 프로필의 정책을 선택하세요.",
  SCAN_QUOTA_EXCEEDED: "검사 한도에 도달했습니다. 대기 중인 검사와 조직의 사용 한도를 확인하세요.",
  IDEMPOTENCY_CONFLICT: "재시도 식별키가 다른 요청에 사용되었습니다. 새로고침해 기존 요청을 확인하세요.",
};
const statusMessages: Record<number, string> = {
  400: "입력 내용을 확인한 뒤 다시 요청하세요.", 401: "운영 로그인 정보가 없거나 만료되었습니다. 다시 연결하세요.",
  403: "현재 계정으로 실행할 수 없는 작업입니다. 계정 권한과 접속 주소를 확인하세요.",
  404: "요청한 기록을 찾을 수 없습니다. 현재 조직과 목록을 확인하세요.",
  409: "기록 상태가 변경되었거나 기존 요청과 충돌합니다. 새로고침해 현재 상태를 확인하세요.",
  413: "요청 내용이 너무 큽니다. 입력 분량을 줄여 다시 요청하세요.",
  415: "지원하지 않는 요청 형식입니다. 화면을 새로고침해 다시 시도하세요.",
  429: "요청 한도에 도달했습니다. 잠시 후 현재 상태를 확인하세요.",
};

export async function controlApi<T>(path: string, body?: unknown, method = body === undefined ? "GET" : "POST", idempotencyKey?: string): Promise<T> {
  const response = await fetch(`/api/control/${path}`, { method, cache: "no-store", headers: body === undefined ? {} : { "content-type": "application/json", "idempotency-key": idempotencyKey ?? crypto.randomUUID() }, body: body === undefined ? undefined : JSON.stringify(body) })
    .catch(() => { throw Object.assign(new Error("서버에 연결하지 못했습니다. 요청이 접수됐을 수 있으니 새로고침해 기록부터 확인하세요."), { code: "NETWORK_ERROR" }); });
  const payload = await response.json().catch(() => { throw Object.assign(new Error("서버 응답을 확인할 수 없습니다. 새로고침해 요청 기록을 확인하세요."), { code: "INVALID_RESPONSE", status: response.status }); });
  if (!response.ok) {
    const original = typeof payload?.error === "string" ? payload.error : payload?.error?.message ?? payload?.message;
    const rawCode = payload?.error?.code ?? original, code = typeof rawCode === "string" && /^[A-Z][A-Z0-9_]{0,79}$/.test(rawCode) ? rawCode : undefined;
    // Retain machine-readable diagnostics without putting server detail objects in the user's alert.
    const message = code && messages[code] || (typeof original === "string" && /[가-힣]/.test(original) ? original : statusMessages[response.status] ?? "서버가 요청을 처리하지 못했습니다. 새로고침해 기록을 확인한 뒤 다시 시도하세요.");
    throw Object.assign(new Error(`${message}${code ? ` (${code})` : ""}`), { code, status: response.status, serverMessage: original, details: payload?.error?.details });
  }
  return payload as T;
}
