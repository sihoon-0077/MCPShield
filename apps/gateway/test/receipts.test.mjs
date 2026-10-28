import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { promisify } from "node:util";
import { openReceiptLedger, verifyReceiptBatch } from "../src/receipts.mjs";
import { verifyEvidenceLeaf } from "../../../services/scanner/src/evidence.mjs";

const input = { agentIdHash: `sha256:${"a".repeat(64)}`, requestedScopeHash: `sha256:${"b".repeat(64)}`, releaseId: `0x${"c".repeat(64)}`, policyHash: `0x${"d".repeat(64)}`,
  toolName: "send_synthetic_message", operationClass: "WRITE_EXTERNAL", decision: "ALLOW", phase: "CALL", source: "REPLAY", reasonCode: "RELEASE_VERIFIED", traceId: null };

test("private receipts link order, reject raw fields and produce verifiable unanchored inclusion proofs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-receipts-"));
  const path = join(directory, "receipts.sqlite"), ledger = openReceiptLedger(path);
  try {
    const first = ledger.append(input), second = ledger.append({ ...input, decision: "BLOCK", reasonCode: "RELEASE_REVOKED" });
    assert.equal(second.receipt.previousReceiptHash, first.receiptHash);
    assert.deepEqual(ledger.verify(), { sequence: 2, receiptHash: second.receiptHash });
    assert.throws(() => ledger.append({ ...input, arguments: { secret: "must-not-persist" } }), /raw arguments/);
    const { assurance, bundle } = ledger.createBatch({ fromSequence: 1, toSequence: 2 });
    assert.equal(assurance, "LOCAL_UNANCHORED");
    assert.equal(verifyReceiptBatch(bundle, bundle.manifest.root), true);
    const leaf = bundle.manifest.leaves.find(({ path }) => path.startsWith("receipts/"));
    assert.equal(verifyEvidenceLeaf({ ...leaf, content: bundle.files[leaf.path] }, bundle.manifest.root), true);
    const altered = structuredClone(bundle);
    altered.files[leaf.path] = altered.files[leaf.path].replace("ALLOW", "BLOCK");
    assert.equal(verifyReceiptBatch(altered, bundle.manifest.root), false);
    assert.throws(() => ledger.createBatch({ fromSequence: 1, toSequence: 128 }), /1 to 127/);
    assert.throws(() => ledger.createBatch({ fromSequence: 1, toSequence: 3 }), /missing sequence/);
  } finally { ledger.close(); }
  try { assert.doesNotMatch((await readFile(path)).toString(), /must-not-persist|arguments/); }
  finally { await rm(directory, { recursive: true, force: true }); }
});

test("independent processes serialize appends without dropping or forking the hash chain", { timeout: 20_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-receipt-concurrency-")), path = join(directory, "receipts.sqlite");
  const initialized = openReceiptLedger(path); initialized.close();
  try {
    const moduleUrl = new URL("../src/receipts.mjs", import.meta.url).href;
    const source = `import{openReceiptLedger}from ${JSON.stringify(moduleUrl)};const ledger=openReceiptLedger(process.argv[1]);try{for(let i=0;i<25;i++)ledger.append(${JSON.stringify(input)});}finally{ledger.close();}`;
    await Promise.all(Array.from({ length: 4 }, () => promisify(execFile)(process.execPath, ["--input-type=module", "-e", source, path], { windowsHide: true })));
    const ledger = openReceiptLedger(path);
    try {
      assert.equal(ledger.verify().sequence, 100);
      const result = ledger.createBatch({ fromSequence: 1, toSequence: 100 });
      assert.equal(verifyReceiptBatch(result.bundle, result.bundle.manifest.root), true);
    } finally { ledger.close(); }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("SQL append-only enforcement and external checkpoints detect mutation and tail truncation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-receipt-tamper-")), path = join(directory, "receipts.sqlite");
  let ledger = openReceiptLedger(path);
  ledger.append(input); ledger.append(input);
  const checkpoint = ledger.verify(); ledger.close();
  try {
    const database = new DatabaseSync(path);
    try {
      assert.throws(() => database.exec("DELETE FROM gateway_receipts"), /APPEND_ONLY/);
      assert.throws(() => database.exec("UPDATE gateway_receipts SET receipt_json='{}'"), /APPEND_ONLY/);
      // Simulated storage administrator bypasses the application enforcement.
      database.exec("DROP TRIGGER gateway_receipts_no_delete; DELETE FROM gateway_receipts WHERE sequence=2");
    } finally { database.close(); }
    ledger = openReceiptLedger(path);
    try {
      assert.equal(ledger.verify().sequence, 1);
      assert.throws(() => ledger.verify({ expectedCheckpoint: checkpoint }), /truncated/);
    } finally { ledger.close(); }
    const modified = new DatabaseSync(path);
    try { modified.exec("DROP TRIGGER gateway_receipts_no_update; UPDATE gateway_receipts SET receipt_json='{}' WHERE sequence=1"); }
    finally { modified.close(); }
    assert.throws(() => openReceiptLedger(path), /integrity/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
