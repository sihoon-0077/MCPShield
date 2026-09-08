import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ReceiptConsole, ReceiptEvidenceView, ReceiptRecordsView, ReceiptStatus, type ReceiptRecord } from "../components/receipt-console";
import { receiptEvidenceSummary, validReceiptWriter } from "../lib/receipt-summary";
import { controlApi } from "../lib/control-client";

const record: ReceiptRecord = { ledgerKey: `0x${"1".repeat(64)}`, writer: `0x${"2".repeat(40)}`, batchId: `0x${"3".repeat(64)}`, root: `0x${"4".repeat(64)}`, count: 2, fromSequence: 1, toSequence: 2, assurance: "CONFIRMED", queueStatus: "COMPLETED", txHash: `0x${"5".repeat(64)}`, errorCode: null, confirmations: 2, requiredConfirmations: 2, chainId: 1337, registryAddress: `0x${"6".repeat(40)}`, createdAt: "2026-09-09T00:00:00Z", sources: ["MOCK", "REPLAY"] };

test("receipt assurance, queue completion, synthetic sources and unavailable stale state remain distinct", () => {
  for (const [assurance, label] of [["LOCAL_UNANCHORED", "로컬 기록"], ["SUBMITTED", "확정 대기"], ["CONFIRMED", "확인 수 충족"], ["ORPHANED", "이전 확정 무효"]]) {
    const html = renderToStaticMarkup(<ReceiptStatus record={{ ...record, assurance, confirmations: assurance === "CONFIRMED" ? 2 : 0 }} />);
    assert.ok(html.includes(assurance)); assert.ok(html.includes(label)); assert.match(html, /COMPLETED/); assert.match(html, /확정 상태와 별도/);
    if (assurance !== "CONFIRMED") assert.doesNotMatch(html, /ops-badge verified/);
  }
  const html = renderToStaticMarkup(<ReceiptRecordsView ledgers={[record]} batches={[record]} selected={record.ledgerKey} error="" />);
  for (const text of ["MOCK + REPLAY", "실운영 실행 증거 아님", "체크포인트", "2 / 2", "COMPLETED", record.txHash!]) assert.ok(html.includes(text), text);
  const unavailable = renderToStaticMarkup(<ReceiptRecordsView ledgers={[record]} batches={[record]} selected={record.ledgerKey} error="RECEIPT_CHAIN_UNAVAILABLE" />);
  assert.match(unavailable, /이전 확정 표시는 숨겼습니다/); assert.doesNotMatch(unavailable, /CONFIRMED|COMPLETED|<table/);
});

test("receipt UI offers public writer registration only to admin and labels API-only evidence verification", () => {
  const reader = renderToStaticMarkup(<ReceiptConsole manage={false} evidenceAccess={false} />);
  assert.doesNotMatch(reader, /<form|name="writer"|type="password"/); assert.match(reader, /실제 writer CLI/);
  const admin = renderToStaticMarkup(<ReceiptConsole manage evidenceAccess />);
  assert.match(admin, /name="writer"/); assert.match(admin, /maxLength="42"/); assert.match(admin, /type="checkbox" required=""/);
  assert.doesNotMatch(admin, /name="(?:privateKey|signature|arguments|apiKey)"/);
  assert.equal(validReceiptWriter(record.writer), true);
  for (const invalid of [null, "0x" + "0".repeat(40), "0x" + "a".repeat(64), "0x" + "g".repeat(40), {}, ""]) assert.equal(validReceiptWriter(invalid), false);
  const summary = receiptEvidenceSummary({ bundle: { manifest: { algorithm: "sha256-path-merkle-v1", root: record.root, leaves: [{ path: "batch.json" }, { path: "receipt.json" }] }, files: { "receipt.json": "synthetic-private-content-not-for-browser" } } });
  assert.deepEqual(Object.keys(summary).sort(), ["checkedAt", "leafCount", "root", "verification"]);
  assert.doesNotMatch(JSON.stringify(summary), /private-content|receipt.json/);
  const verified = renderToStaticMarkup(<ReceiptEvidenceView batch={record} evidence={summary} />);
  assert.match(verified, /API가 증거 루트를 검증함/); assert.match(verified, /브라우저 독립 검증이 아닙니다/);
  const mismatch = renderToStaticMarkup(<ReceiptEvidenceView batch={{ ...record, root: "wrong-root" }} evidence={summary} />);
  assert.match(mismatch, /루트 불일치/); assert.doesNotMatch(mismatch, /API가 증거 루트를 검증함/);
  assert.throws(() => receiptEvidenceSummary({ bundle: { manifest: { root: record.root, leaves: [] } } }), /INVALID/);
});

test("caller-supplied idempotency key survives an uncertain response and is not sent in the body", async (context) => {
  const calls: RequestInit[] = [];
  context.mock.method(globalThis, "fetch", async (_path: string, init: RequestInit) => { calls.push(init); return calls.length === 1 ? Response.json({ error: "synthetic-response-lost" }, { status: 503 }) : Response.json({ ledger: record }); });
  const register = () => controlApi("receipt-ledgers", { writer: record.writer }, "POST", "synthetic-stable-attempt");
  await assert.rejects(register(), /synthetic-response-lost/); await register();
  for (const call of calls) { assert.equal((call.headers as Record<string, string>)["idempotency-key"], "synthetic-stable-attempt"); assert.equal(call.body, JSON.stringify({ writer: record.writer })); }
});
