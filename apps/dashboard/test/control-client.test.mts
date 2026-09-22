import assert from "node:assert/strict";
import test from "node:test";
import { controlApi } from "../lib/control-client";

test("control client explains failures while retaining codes, HTTP status and private diagnostic details", async context => {
  let status = 400, payload: unknown = { error: { code: "INVALID_SCAN_REQUEST", message: "INVALID_SCAN_REQUEST" } };
  context.mock.method(globalThis, "fetch", async () => Response.json(payload, { status }));
  for (const [http, code, message] of [
    [400, "INVALID_SCAN_REQUEST", "입력 내용을 확인"], [401, "UNAUTHORIZED", "다시 연결"], [403, "FORBIDDEN", "계정 권한"],
    [404, "APPEAL_NOT_FOUND", "기록을 찾을 수 없습니다"], [409, "APPEAL_RESCAN_ALREADY_REQUESTED", "검사가 이미 연결"],
    [409, "APPEAL_NEW_DIGEST_OR_POLICY_REQUIRED", "수정된 파일"], [409, "SCAN_PROFILE_MISMATCH", "같은 프로필"],
    [409, "SCAN_SEMANTIC_MODE_MISMATCH", "같은 분석 모드"],
    [400, "SCOPED_OPERATOR_PROVENANCE_REQUIRED", "관리자에게 허가 목록"],
    [400, "SCOPED_SOURCE_BUDGET_EXCEEDED", "파일 용량"], [400, "SCOPED_CONFIG_REQUIRED", "관리자 설정"],
    [409, "SCOPED_CONFIG_CHANGED", "검사 설정이 변경"], [409, "PREPARATION_CONFIG_CHANGED", "이미지 준비 설정이 변경"],
    [400, "SCOPED_EVIDENCE_MODE_MISMATCH", "검사 방식과 서버 설정"],
    [429, "SCAN_QUOTA_EXCEEDED", "조직의 사용 한도"], [503, "CONTROL_PLANE_FAILED", "기록을 확인"],
  ] as const) {
    status = http; payload = { error: { code, message: code, details: { reason: "SYNTHETIC_PRIVATE_DIAGNOSTIC" } } };
    await assert.rejects(controlApi("scans"), (error: any) => {
      assert.equal(error.code, code); assert.equal(error.status, http); assert.equal(error.details.reason, "SYNTHETIC_PRIVATE_DIAGNOSTIC");
      assert.ok(error.message.includes(message)); assert.equal(error.serverMessage, code); assert.doesNotMatch(error.message, /SYNTHETIC_PRIVATE/); return true;
    });
  }
  status = 403; payload = { error: "FORBIDDEN" };
  await assert.rejects(controlApi("scans"), (error: any) => error.code === "FORBIDDEN" && /계정 권한/.test(error.message));
  status = 400; payload = { error: "검토 결론은 8자 이상 작성하세요." };
  await assert.rejects(controlApi("scans"), (error: any) => /입력 내용을 확인/.test(error.message) && error.serverMessage === "검토 결론은 8자 이상 작성하세요.");
  payload = null; await assert.rejects(controlApi("scans"), /입력 내용을 확인/);
});

test("alert text never reflects arbitrary Korean/English server messages, paths, tokens or unknown codes", async context => {
  let payload: unknown;
  context.mock.method(globalThis, "fetch", async () => Response.json(payload, { status: 409 }));
  for (const original of ["SYNTHETIC_PRIVATE_TOKEN_ABC", "private English failure C:/private/source token=synthetic-private-value",
    "검사 실패: C:/private/source token=synthetic-private-value", "<script>비공개 synthetic-private-value</script>"]) {
    for (const code of [undefined, "SYNTHETIC_PRIVATE_TOKEN_ABC", "SCAN_SEMANTIC_MODE_MISMATCH"]) {
      payload = { error: { code, message: original, details: { path: "C:/private/catalogue", token: "synthetic-private-value" } } };
      await assert.rejects(controlApi("scans"), (error: any) => {
        const expectedCode = code ?? (original === "SYNTHETIC_PRIVATE_TOKEN_ABC" ? original : undefined);
        assert.equal(error.code, expectedCode); assert.equal(error.status, 409); assert.equal(error.serverMessage, original);
        assert.deepEqual(error.details, { path: "C:/private/catalogue", token: "synthetic-private-value" });
        assert.doesNotMatch(error.message, /SYNTHETIC_PRIVATE|synthetic-private|C:\/private|<script>|private English|검사 실패/);
        assert.match(error.message, code === "SCAN_SEMANTIC_MODE_MISMATCH" ? /같은 분석 모드.*\(SCAN_SEMANTIC_MODE_MISMATCH\)/ : /새로고침해 현재 상태/);
        return true;
      });
    }
    for (const body of [{ error: original }, { message: original }]) {
      payload = body;
      await assert.rejects(controlApi("scans"), (error: any) => error.serverMessage === original && /새로고침해 현재 상태/.test(error.message) && !error.message.includes(original));
    }
  }
});

test("invalid responses and network failures advise reconciliation, never automatic mutation retries", async context => {
  let calls = 0;
  context.mock.method(globalThis, "fetch", async () => { calls++; return new Response("<html>upstream unavailable</html>", { status: 502 }); });
  await assert.rejects(controlApi("scans", {}, "POST", "stable-attempt"), (error: any) => error.code === "INVALID_RESPONSE" && error.status === 502 && /기록을 확인/.test(error.message));
  assert.equal(calls, 1);
  context.mock.method(globalThis, "fetch", async () => { calls++; throw new Error("SYNTHETIC_PRIVATE_NETWORK_DETAIL"); });
  await assert.rejects(controlApi("scans", {}, "POST", "stable-attempt"), (error: any) => error.code === "NETWORK_ERROR" && /접수됐을 수/.test(error.message) && !error.message.includes("SYNTHETIC_PRIVATE"));
  assert.equal(calls, 2);
});
