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
    [429, "SCAN_QUOTA_EXCEEDED", "조직의 사용 한도"], [503, "CONTROL_PLANE_FAILED", "기록을 확인"],
  ] as const) {
    status = http; payload = { error: { code, message: code, details: { reason: "SYNTHETIC_PRIVATE_DIAGNOSTIC" } } };
    await assert.rejects(controlApi("scans"), (error: any) => {
      assert.equal(error.code, code); assert.equal(error.status, http); assert.equal(error.details.reason, "SYNTHETIC_PRIVATE_DIAGNOSTIC");
      assert.ok(error.message.includes(message)); assert.ok(error.message.includes(code)); assert.doesNotMatch(error.message, /SYNTHETIC_PRIVATE/); return true;
    });
  }
  status = 403; payload = { error: "FORBIDDEN" };
  await assert.rejects(controlApi("scans"), /계정 권한.*FORBIDDEN/);
  status = 400; payload = { error: "검토 결론은 8자 이상 작성하세요." };
  await assert.rejects(controlApi("scans"), /검토 결론은 8자 이상/);
  payload = null; await assert.rejects(controlApi("scans"), /입력 내용을 확인/);
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
