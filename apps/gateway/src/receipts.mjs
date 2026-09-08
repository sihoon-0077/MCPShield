import { createHash, randomUUID } from "node:crypto";
import { closeSync, lstatSync, mkdirSync, openSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { canonicalJson, createEvidenceBundle, verifyEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";

const ZERO = `sha256:${"0".repeat(64)}`;
const sha = (value) => `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
const HASH = /^sha256:[a-f0-9]{64}$/, BYTES32 = /^0x[a-f0-9]{64}$/;
const INPUT_FIELDS = ["agentIdHash", "releaseId", "toolName", "operationClass", "requestedScopeHash", "decision", "policyHash", "phase", "source", "reasonCode", "traceId"].sort();
const RECORD_FIELDS = [...INPUT_FIELDS, "schemaVersion", "sequence", "receiptId", "timestamp", "previousReceiptHash"].sort();
const sameFields = (value, fields) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join() === fields.join();

function validateInput(value) {
  if (!sameFields(value, INPUT_FIELDS) || !HASH.test(value.agentIdHash) || !HASH.test(value.requestedScopeHash) ||
    !BYTES32.test(value.releaseId) || !BYTES32.test(value.policyHash) || typeof value.toolName !== "string" || !/^[A-Za-z0-9_.:-]{1,128}$/.test(value.toolName) ||
    !["WRITE_LOCAL", "WRITE_EXTERNAL", "DESTRUCTIVE", "FINANCIAL"].includes(value.operationClass) || !["ALLOW", "BLOCK"].includes(value.decision) ||
    !["ADMISSION", "CALL"].includes(value.phase) || !["LIVE", "REPLAY", "MOCK"].includes(value.source) || !/^[A-Z][A-Z0-9_]{1,79}$/.test(value.reasonCode) ||
    !(value.traceId === null || /^[a-f0-9]{32}$/.test(value.traceId))) throw new TypeError("Invalid private receipt fields; raw arguments and scope are not accepted");
}

function validateRecord(record, sequence, previous) {
  if (!sameFields(record, RECORD_FIELDS) || record.schemaVersion !== "1.0.0" || record.sequence !== sequence ||
    record.previousReceiptHash !== previous || !/^rcpt_[a-f0-9-]{36}$/.test(record.receiptId) ||
    typeof record.timestamp !== "string" || !Number.isFinite(Date.parse(record.timestamp))) throw new Error("Receipt hash chain integrity failed");
  validateInput(Object.fromEntries(INPUT_FIELDS.map((field) => [field, record[field]])));
}

export function openReceiptLedger(filename) {
  const path = resolve(filename);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  try { closeSync(openSync(path, "ax", 0o600)); } catch (error) { if (error.code !== "EEXIST") throw error; }
  const info = lstatSync(path);
  if (!info.isFile() || info.isSymbolicLink() || (process.platform !== "win32" && (info.mode & 0o077))) throw new Error("Receipt ledger must be a private regular file");
  const database = new DatabaseSync(path, { allowExtension: false });
  try {
    database.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS gateway_receipts (sequence INTEGER PRIMARY KEY, receipt_json TEXT NOT NULL, receipt_hash TEXT NOT NULL UNIQUE);
      CREATE TRIGGER IF NOT EXISTS gateway_receipts_no_update BEFORE UPDATE ON gateway_receipts BEGIN SELECT RAISE(ABORT, 'RECEIPTS_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS gateway_receipts_no_delete BEFORE DELETE ON gateway_receipts BEGIN SELECT RAISE(ABORT, 'RECEIPTS_APPEND_ONLY'); END;`);
  } catch (error) { database.close(); throw error; }
  const decode = (row) => {
    let receipt;
    try { receipt = JSON.parse(row.receipt_json); } catch { throw new Error("Receipt JSON integrity failed"); }
    if (sha(receipt) !== row.receipt_hash || receipt.sequence !== row.sequence) throw new Error("Receipt digest integrity failed");
    return receipt;
  };
  const verify = ({ expectedCheckpoint } = {}) => {
    if (expectedCheckpoint && (!Number.isSafeInteger(expectedCheckpoint.sequence) || expectedCheckpoint.sequence < 1 || !HASH.test(expectedCheckpoint.receiptHash))) throw new TypeError("Invalid trusted receipt checkpoint");
    let sequence = 0, receiptHash = ZERO, checkpointFound = !expectedCheckpoint;
    for (const row of database.prepare("SELECT * FROM gateway_receipts ORDER BY sequence").iterate()) {
      const receipt = decode(row);
      validateRecord(receipt, ++sequence, receiptHash);
      receiptHash = row.receipt_hash;
      if (expectedCheckpoint?.sequence === sequence) {
        if (expectedCheckpoint.receiptHash !== receiptHash) throw new Error("Trusted receipt checkpoint mismatch");
        checkpointFound = true;
      }
    }
    if (!checkpointFound) throw new Error("Receipt ledger truncated before trusted checkpoint");
    return { sequence, receiptHash };
  };
  try { verify(); } catch (error) { database.close(); throw error; }
  return {
    verify,
    append(value) {
      validateInput(value);
      database.exec("BEGIN IMMEDIATE");
      try {
        const rows = database.prepare("SELECT * FROM gateway_receipts ORDER BY sequence DESC LIMIT 2").all();
        const tail = rows[0];
        if (tail) {
          const previous = rows[1];
          validateRecord(decode(tail), tail.sequence, previous?.receipt_hash ?? ZERO);
          if (previous && previous.sequence !== tail.sequence - 1) throw new Error("Receipt tail sequence integrity failed");
        }
        const receipt = { ...value, schemaVersion: "1.0.0", sequence: (tail?.sequence ?? 0) + 1, receiptId: `rcpt_${randomUUID()}`, timestamp: new Date().toISOString(), previousReceiptHash: tail?.receipt_hash ?? ZERO };
        const receiptHash = sha(receipt);
        database.prepare("INSERT INTO gateway_receipts(sequence,receipt_json,receipt_hash) VALUES(?,?,?)").run(receipt.sequence, canonicalJson(receipt), receiptHash);
        database.exec("COMMIT");
        return { receipt, receiptHash };
      } catch (error) { database.exec("ROLLBACK"); throw error; }
    },
    createBatch({ fromSequence, toSequence }) {
      if (!Number.isSafeInteger(fromSequence) || !Number.isSafeInteger(toSequence) || fromSequence < 1 || toSequence < fromSequence || toSequence - fromSequence >= 127) throw new TypeError("Receipt batch must contain 1 to 127 consecutive records");
      database.exec("BEGIN");
      try {
        verify();
        const rows = database.prepare("SELECT * FROM gateway_receipts WHERE sequence BETWEEN ? AND ? ORDER BY sequence").all(fromSequence, toSequence);
        if (rows.length !== toSequence - fromSequence + 1) throw new Error("Receipt batch contains a missing sequence");
        const receipts = rows.map(decode);
        const batch = { schemaVersion: "1.0.0", fromSequence, toSequence, count: receipts.length, previousReceiptHash: receipts[0].previousReceiptHash, tipReceiptHash: rows.at(-1).receipt_hash };
        const bundle = createEvidenceBundle({ "batch.json": batch, ...Object.fromEntries(receipts.map((receipt) => [`receipts/${String(receipt.sequence).padStart(12, "0")}.json`, receipt])) });
        database.exec("COMMIT");
        return { assurance: "LOCAL_UNANCHORED", batch, bundle };
      } catch (error) { database.exec("ROLLBACK"); throw error; }
    },
    close() { database.close(); },
  };
}

export function verifyReceiptBatch(bundle, expectedRoot) {
  try {
    if (!verifyEvidenceBundle(bundle, expectedRoot)) return false;
    const batch = JSON.parse(bundle.files["batch.json"]);
    if (batch.schemaVersion !== "1.0.0" || !Number.isSafeInteger(batch.fromSequence) || batch.fromSequence < 1 || !Number.isSafeInteger(batch.toSequence) ||
      batch.count !== batch.toSequence - batch.fromSequence + 1 || batch.count < 1 || batch.count > 127 || !HASH.test(batch.previousReceiptHash)) return false;
    const paths = Object.keys(bundle.files).filter((path) => path !== "batch.json").sort();
    if (paths.length !== batch.count) return false;
    let previous = batch.previousReceiptHash;
    for (let index = 0; index < paths.length; index++) {
      const receipt = JSON.parse(bundle.files[paths[index]]), sequence = batch.fromSequence + index;
      if (paths[index] !== `receipts/${String(sequence).padStart(12, "0")}.json`) return false;
      validateRecord(receipt, sequence, previous); previous = sha(receipt);
    }
    return previous === batch.tipReceiptHash;
  } catch { return false; }
}

// One process normally owns one configured ledger; SQLite serializes other wrappers.
const ledgers = new Map();
export function appendConfiguredReceipt(filename, fields) {
  const path = resolve(filename);
  if (!ledgers.has(path)) {
    if (ledgers.size >= 8) throw new Error("Too many configured receipt ledgers");
    ledgers.set(path, openReceiptLedger(path));
  }
  return ledgers.get(path).append(fields);
}
export function closeConfiguredReceiptLedgers() {
  for (const ledger of ledgers.values()) ledger.close();
  ledgers.clear();
}
process.once("exit", closeConfiguredReceiptLedgers);

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const { values } = parseArgs({ options: { db: { type: "string" }, from: { type: "string" }, to: { type: "string" } } });
  if (!values.db) throw new Error("--db is required");
  const ledger = openReceiptLedger(values.db);
  try {
    console.log(JSON.stringify(values.from || values.to ? ledger.createBatch({ fromSequence: Number(values.from), toSequence: Number(values.to) }) : ledger.verify()));
  } finally { ledger.close(); }
}
