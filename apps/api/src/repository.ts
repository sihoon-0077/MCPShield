import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import type {
  ReleaseStatus,
  ScanResult,
  ValidatorDecision,
} from "../../../packages/protocol/api/types.js";

export interface ReleaseRecord {
  releaseId: string;
  artifactDigest: string;
  toolSurfaceHash: string;
  status: ReleaseStatus;
  createdAt: string;
  updatedAt: string;
  registrationTxHash?: string;
  registrationBlockNumber?: number;
}

export interface VoteRecord {
  releaseId: string;
  validatorAddress: string;
  decision: ValidatorDecision;
  evidenceHash: string;
  scanId?: string;
  nonce: number;
  signature: string;
  txHash?: string;
}

type ReleaseRow = {
  release_id: string;
  artifact_digest: string;
  tool_surface_hash: string;
  status: ReleaseStatus;
  created_at: string;
  updated_at: string;
  registration_tx_hash: string | null;
  registration_block_number: number | null;
};

export class Repository {
  private readonly db: DatabaseSync;

  constructor(databasePath: string) {
    this.db = new DatabaseSync(databasePath);
    this.db.exec("PRAGMA busy_timeout = 5000");
    this.db.exec("PRAGMA journal_mode = WAL");
    const here = path.dirname(fileURLToPath(import.meta.url));
    const migrationPath = path.resolve(
      here,
      "../../../database/migrations/001_initial.sqlite.sql",
    );
    this.db.exec(fs.readFileSync(migrationPath, "utf8"));
  }

  close() {
    this.db.close();
  }

  createRelease(input: Omit<ReleaseRecord, "status" | "createdAt" | "updatedAt">) {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO releases
          (release_id, artifact_digest, tool_surface_hash, status, registration_tx_hash,
           registration_block_number, created_at, updated_at)
         VALUES (?, ?, ?, 'UNVERIFIED', ?, ?, ?, ?)`,
      )
      .run(input.releaseId, input.artifactDigest, input.toolSurfaceHash,
        input.registrationTxHash ?? null, input.registrationBlockNumber ?? null, now, now);
    this.addEvent(input.releaseId, "ReleaseRegistered", "UNVERIFIED", undefined, undefined, {
      artifactDigest: input.artifactDigest,
      toolSurfaceHash: input.toolSurfaceHash,
    });
    return this.getRelease(input.releaseId)!;
  }

  getRelease(releaseId: string): ReleaseRecord | undefined {
    const row = this.db
      .prepare("SELECT * FROM releases WHERE release_id = ?")
      .get(releaseId) as ReleaseRow | undefined;
    return row
      ? {
          releaseId: row.release_id,
          artifactDigest: row.artifact_digest,
          toolSurfaceHash: row.tool_surface_hash,
          status: row.status,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          registrationTxHash: row.registration_tx_hash ?? undefined,
          registrationBlockNumber: row.registration_block_number ?? undefined,
        }
      : undefined;
  }

  saveScan(scan: ScanResult) {
    const release = this.getRelease(scan.releaseId);
    if (!release) throw new Error("RELEASE_NOT_FOUND");
    if (
      release.artifactDigest !== scan.artifactDigest ||
      release.toolSurfaceHash !== scan.toolSurfaceHash
    ) {
      throw new Error("RELEASE_HASH_MISMATCH");
    }
    this.db
      .prepare(
        `INSERT INTO scans
          (scan_id, release_id, schema_version, artifact_digest, tool_surface_hash,
           scan_status, findings_json, evidence_hash, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        scan.scanId,
        scan.releaseId,
        scan.schemaVersion,
        scan.artifactDigest,
        scan.toolSurfaceHash,
        scan.scanStatus,
        JSON.stringify(scan.findings),
        scan.evidenceHash,
        scan.source,
        new Date().toISOString(),
      );
    this.db.prepare(
      `UPDATE validator_votes SET scan_id = ? WHERE scan_id IS NULL
       AND release_id = ? AND evidence_hash = ?`,
    ).run(scan.scanId, scan.releaseId, scan.evidenceHash);
    return scan;
  }

  getScan(scanId: string): ScanResult | undefined {
    const row = this.db
      .prepare("SELECT * FROM scans WHERE scan_id = ?")
      .get(scanId) as Record<string, string> | undefined;
    if (!row) return undefined;
    return {
      schemaVersion: "1.0.0",
      scanId: row.scan_id,
      releaseId: row.release_id,
      artifactDigest: row.artifact_digest,
      toolSurfaceHash: row.tool_surface_hash,
      scanStatus: row.scan_status as ScanResult["scanStatus"],
      findings: JSON.parse(row.findings_json),
      evidenceHash: row.evidence_hash,
      source: row.source as ScanResult["source"],
    };
  }

  getLatestScan(releaseId: string) {
    const row = this.db.prepare(
      `SELECT scan_id FROM scans WHERE release_id = ?
       ORDER BY created_at DESC, rowid DESC LIMIT 1`,
    ).get(releaseId) as { scan_id: string } | undefined;
    return row ? this.getScan(row.scan_id) : undefined;
  }

  findScanByEvidence(releaseId: string, evidenceHash: string) {
    const row = this.db.prepare(
      `SELECT scan_id FROM scans WHERE release_id = ? AND evidence_hash = ?
       ORDER BY created_at DESC LIMIT 1`,
    ).get(releaseId, evidenceHash) as { scan_id: string } | undefined;
    return row ? this.getScan(row.scan_id) : undefined;
  }

  recordVote(vote: VoteRecord): ReleaseRecord {
    this.validateVote(vote);
    const release = this.getRelease(vote.releaseId)!;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(
          `INSERT INTO validator_votes
            (release_id, validator_address, decision, evidence_hash, scan_id,
             nonce, signature, tx_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          vote.releaseId,
          vote.validatorAddress,
          vote.decision,
          vote.evidenceHash,
          vote.scanId ?? null,
          vote.nonce,
          vote.signature,
          vote.txHash ?? null,
          new Date().toISOString(),
        );

      const counts = this.db
        .prepare(
          `SELECT
             SUM(CASE WHEN decision = 'PASS' THEN 1 ELSE 0 END) AS pass_count,
             SUM(CASE WHEN decision = 'FAIL' THEN 1 ELSE 0 END) AS fail_count
           FROM validator_votes WHERE release_id = ?`,
        )
        .get(vote.releaseId) as { pass_count: number; fail_count: number };

      let next: ReleaseStatus = release.status;
      if (vote.decision === "FAIL") {
        next = counts.fail_count >= 2 ? "REVOKED" : "QUARANTINED";
      } else if (
        vote.decision === "PASS" &&
        counts.pass_count >= 2 &&
        release.status === "UNVERIFIED"
      ) {
        next = "VERIFIED";
      }

      this.addEvent(vote.releaseId, "VoteSubmitted", release.status, vote.txHash, undefined, {
        validatorAddress: vote.validatorAddress,
        decision: vote.decision,
        evidenceHash: vote.evidenceHash,
      });
      if (next !== release.status) {
        this.db
          .prepare("UPDATE releases SET status = ?, updated_at = ? WHERE release_id = ?")
          .run(next, new Date().toISOString(), vote.releaseId);
        this.addEvent(vote.releaseId, "StatusChanged", next, vote.txHash, undefined, {
          previousStatus: release.status,
          newStatus: next,
        });
      }
      this.db.prepare(
        `INSERT INTO validator_nonces (validator_address, next_nonce) VALUES (?, ?)
         ON CONFLICT(validator_address) DO UPDATE SET next_nonce = excluded.next_nonce`,
      ).run(vote.validatorAddress, vote.nonce + 1);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    return this.getRelease(vote.releaseId)!;
  }

  validateVote(
    vote: Pick<
      VoteRecord,
      "releaseId" | "validatorAddress" | "scanId" | "evidenceHash" | "nonce"
    >,
  ) {
    const release = this.getRelease(vote.releaseId);
    if (!release) throw new Error("RELEASE_NOT_FOUND");
    if (release.status === "REVOKED") throw new Error("RELEASE_REVOKED");
    const scan = vote.scanId ? this.getScan(vote.scanId) : undefined;
    if (
      !scan ||
      scan.releaseId !== vote.releaseId ||
      scan.evidenceHash !== vote.evidenceHash
    ) throw new Error("SCAN_EVIDENCE_MISMATCH");
    if (vote.nonce !== this.getValidatorNonce(vote.validatorAddress)) {
      throw new Error("INVALID_NONCE");
    }
  }

  reconcileVoteFromChain(
    vote: VoteRecord,
    status: ReleaseStatus,
    chainNonce: number,
  ) {
    const scan = vote.scanId ? this.getScan(vote.scanId) : undefined;
    if (!scan || scan.releaseId !== vote.releaseId || scan.evidenceHash !== vote.evidenceHash) {
      throw new Error("SCAN_EVIDENCE_MISMATCH");
    }
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare(
        `INSERT OR IGNORE INTO validator_votes
         (release_id, validator_address, decision, evidence_hash, scan_id, nonce,
          signature, tx_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(vote.releaseId, vote.validatorAddress, vote.decision, vote.evidenceHash,
        vote.scanId ?? null, vote.nonce, vote.signature, vote.txHash ?? null, new Date().toISOString());
      this.db.prepare(
        `INSERT INTO validator_nonces (validator_address, next_nonce) VALUES (?, ?)
         ON CONFLICT(validator_address) DO UPDATE SET next_nonce =
         MAX(next_nonce, excluded.next_nonce)`,
      ).run(vote.validatorAddress, chainNonce);
      this.db.prepare("UPDATE releases SET status = ?, updated_at = ? WHERE release_id = ?")
        .run(status, new Date().toISOString(), vote.releaseId);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  reconcileObservedVoteFromChain(
    vote: Omit<VoteRecord, "scanId" | "signature">,
    status: ReleaseStatus,
    chainNonce: number,
  ) {
    const scan = this.findScanByEvidence(vote.releaseId, vote.evidenceHash);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare(
        `INSERT INTO validator_votes
         (release_id, validator_address, decision, evidence_hash, scan_id, nonce,
          signature, tx_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, 'CHAIN_RECOVERED', ?, ?)
         ON CONFLICT(release_id, validator_address) DO UPDATE SET
          decision = excluded.decision, evidence_hash = excluded.evidence_hash,
          scan_id = excluded.scan_id, nonce = excluded.nonce,
          signature = excluded.signature, tx_hash = COALESCE(excluded.tx_hash, validator_votes.tx_hash)`,
      ).run(vote.releaseId, vote.validatorAddress, vote.decision, vote.evidenceHash,
        scan?.scanId ?? null, vote.nonce, vote.txHash ?? null, new Date().toISOString());
      this.db.prepare(
        `INSERT INTO validator_nonces (validator_address, next_nonce) VALUES (?, ?)
         ON CONFLICT(validator_address) DO UPDATE SET next_nonce =
         MAX(next_nonce, excluded.next_nonce)`,
      ).run(vote.validatorAddress, chainNonce);
      this.db.prepare("UPDATE releases SET status = ?, updated_at = ? WHERE release_id = ?")
        .run(status, new Date().toISOString(), vote.releaseId);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  getValidatorNonce(validatorAddress: string) {
    const row = this.db
      .prepare("SELECT next_nonce FROM validator_nonces WHERE validator_address = ?")
      .get(validatorAddress) as { next_nonce: number } | undefined;
    return row?.next_nonce ?? 0;
  }

  hasVote(releaseId: string, validatorAddress: string) {
    return Boolean(
      this.db
        .prepare(
          "SELECT 1 AS found FROM validator_votes WHERE release_id = ? AND validator_address = ?",
        )
        .get(releaseId, validatorAddress),
    );
  }

  setProjectedStatus(
    releaseId: string,
    status: ReleaseStatus,
  ) {
    const previous = this.getRelease(releaseId);
    if (!previous || previous.status === status) return;
    this.db
      .prepare("UPDATE releases SET status = ?, updated_at = ? WHERE release_id = ?")
      .run(status, new Date().toISOString(), releaseId);
  }

  addEvent(
    releaseId: string,
    eventName: string,
    status?: ReleaseStatus,
    txHash?: string,
    blockNumber?: number,
    payload: Record<string, unknown> = {},
    logIndex?: number,
  ) {
    this.db
      .prepare(
        `INSERT INTO chain_events
          (release_id, event_name, status, tx_hash, block_number, log_index, payload_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        releaseId,
        eventName,
        status ?? null,
        txHash ?? null,
        blockNumber ?? null,
        logIndex ?? null,
        JSON.stringify(payload),
        new Date().toISOString(),
      );
  }

  upsertReleaseFromChain(
    input: Omit<ReleaseRecord, "createdAt" | "updatedAt">,
  ) {
    const now = new Date().toISOString();
    this.db.prepare(
      `INSERT INTO releases
       (release_id, artifact_digest, tool_surface_hash, status, registration_tx_hash,
        registration_block_number, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(release_id) DO UPDATE SET artifact_digest = excluded.artifact_digest,
       tool_surface_hash = excluded.tool_surface_hash, status = excluded.status,
       registration_tx_hash = COALESCE(excluded.registration_tx_hash, releases.registration_tx_hash),
       registration_block_number = COALESCE(excluded.registration_block_number, releases.registration_block_number),
       updated_at = excluded.updated_at`,
    ).run(input.releaseId, input.artifactDigest, input.toolSurfaceHash, input.status,
      input.registrationTxHash ?? null, input.registrationBlockNumber ?? null, now, now);
  }

  private hasIndexedLog(txHash: string, logIndex: number) {
    return Boolean(this.db.prepare(
      "SELECT 1 FROM chain_events WHERE tx_hash = ? AND log_index = ?",
    ).get(txHash, logIndex));
  }

  applyIndexedRelease(input: {
    releaseId: string;
    artifactDigest: string;
    toolSurfaceHash: string;
    txHash: string;
    blockNumber: number;
    logIndex: number;
  }) {
    if (this.hasIndexedLog(input.txHash, input.logIndex)) return false;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.upsertReleaseFromChain({ ...input, status: "UNVERIFIED",
        registrationTxHash: input.txHash, registrationBlockNumber: input.blockNumber });
      this.addEvent(
        input.releaseId,
        "ReleaseRegistered",
        "UNVERIFIED",
        input.txHash,
        input.blockNumber,
        { indexed: true },
        input.logIndex,
      );
      this.db.exec("COMMIT");
      return true;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  applyIndexedStatus(input: {
    releaseId: string;
    status: ReleaseStatus;
    txHash: string;
    blockNumber: number;
    logIndex: number;
  }) {
    if (this.hasIndexedLog(input.txHash, input.logIndex)) return false;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.addEvent(input.releaseId, "StatusChanged", input.status, input.txHash,
        input.blockNumber, { indexed: true }, input.logIndex);
      this.db.prepare("UPDATE releases SET status = ?, updated_at = ? WHERE release_id = ?")
        .run(input.status, new Date().toISOString(), input.releaseId);
      this.db.exec("COMMIT");
      return true;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  applyIndexedVote(input: {
    releaseId: string;
    validatorAddress: string;
    decision: ValidatorDecision;
    evidenceHash: string;
    nonce: number;
    chainNonce: number;
    txHash: string;
    blockNumber: number;
    logIndex: number;
  }) {
    if (this.hasIndexedLog(input.txHash, input.logIndex)) return false;
    const scan = this.findScanByEvidence(input.releaseId, input.evidenceHash);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.addEvent(input.releaseId, "VoteSubmitted", undefined, input.txHash,
        input.blockNumber, { indexed: true, validatorAddress: input.validatorAddress,
          decision: input.decision, evidenceHash: input.evidenceHash }, input.logIndex);
      this.db.prepare(
        `INSERT OR IGNORE INTO validator_votes
         (release_id, validator_address, decision, evidence_hash, scan_id, nonce,
          signature, tx_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, 'CHAIN_RECOVERED', ?, ?)`,
      ).run(input.releaseId, input.validatorAddress, input.decision, input.evidenceHash,
        scan?.scanId ?? null, input.nonce, input.txHash, new Date().toISOString());
      this.db.prepare(
        `INSERT INTO validator_nonces (validator_address, next_nonce) VALUES (?, ?)
         ON CONFLICT(validator_address) DO UPDATE SET next_nonce =
         MAX(next_nonce, excluded.next_nonce)`,
      ).run(input.validatorAddress, input.chainNonce);
      this.db.exec("COMMIT");
      return true;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  getCheckpoint(name: string) {
    const row = this.db.prepare(
      "SELECT block_number, block_hash FROM indexer_checkpoints WHERE name = ?",
    ).get(name) as { block_number: number; block_hash: string } | undefined;
    return row ? { blockNumber: row.block_number, blockHash: row.block_hash } : undefined;
  }

  setCheckpoint(name: string, blockNumber: number, blockHash: string) {
    this.db.prepare(
      `INSERT INTO indexer_checkpoints (name, block_number, block_hash) VALUES (?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET block_number = excluded.block_number,
       block_hash = excluded.block_hash`,
    ).run(name, blockNumber, blockHash);
  }

  rewindChainProjection(afterBlock: number) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const orphaned = this.db.prepare(
        `SELECT release_id FROM releases WHERE registration_block_number > ?`,
      ).all(afterBlock) as Array<{ release_id: string }>;
      for (const { release_id: releaseId } of orphaned) {
        this.db.prepare(
          `UPDATE pending_operations SET status = 'FAILED', tx_hash = NULL,
           error = 'REORG_ORPHANED', updated_at = ?
           WHERE json_extract(payload_json, '$.releaseId') = ?`,
        ).run(new Date().toISOString(), releaseId);
        this.db.prepare("DELETE FROM validator_votes WHERE release_id = ?").run(releaseId);
        this.db.prepare("DELETE FROM scans WHERE release_id = ?").run(releaseId);
        this.db.prepare("DELETE FROM chain_events WHERE release_id = ?").run(releaseId);
        this.db.prepare("DELETE FROM releases WHERE release_id = ?").run(releaseId);
      }
      this.db.prepare(
        `DELETE FROM validator_votes WHERE tx_hash IN
         (SELECT tx_hash FROM chain_events WHERE block_number > ?)`,
      ).run(afterBlock);
      this.db.prepare("DELETE FROM chain_events WHERE block_number > ?").run(afterBlock);
      this.db.prepare("UPDATE releases SET status = 'UNVERIFIED'").run();
      const statuses = this.db.prepare(
        `SELECT release_id, status FROM chain_events ce WHERE event_name = 'StatusChanged'
         AND block_number IS NOT NULL AND id = (
           SELECT MAX(id) FROM chain_events latest
           WHERE latest.release_id = ce.release_id AND latest.event_name = 'StatusChanged'
           AND latest.block_number IS NOT NULL
         )`,
      ).all() as Array<{ release_id: string; status: ReleaseStatus }>;
      for (const row of statuses) this.db.prepare(
        "UPDATE releases SET status = ?, updated_at = ? WHERE release_id = ?",
      ).run(row.status, new Date().toISOString(), row.release_id);
      this.db.prepare("DELETE FROM validator_nonces").run();
      const nonces = this.db.prepare(
        `SELECT validator_address, MAX(nonce) + 1 AS next_nonce
         FROM validator_votes GROUP BY validator_address`,
      ).all() as Array<{ validator_address: string; next_nonce: number }>;
      for (const row of nonces) this.db.prepare(
        "INSERT INTO validator_nonces (validator_address, next_nonce) VALUES (?, ?)",
      ).run(row.validator_address, row.next_nonce);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  claimOperation(
    operationId: string,
    operationType: string,
    payload: Record<string, unknown>,
    leaseMs = 30_000,
  ) {
    const now = new Date().toISOString();
    const leaseExpiresAt = new Date(Date.now() + leaseMs).toISOString();
    const result = this.db.prepare(
      `INSERT OR IGNORE INTO pending_operations
       (operation_id, operation_type, status, payload_json, claimed_at, lease_expires_at,
        created_at, updated_at)
       VALUES (?, ?, 'PENDING', ?, ?, ?, ?, ?)`,
    ).run(operationId, operationType, JSON.stringify(payload), now, leaseExpiresAt, now, now);
    return { claimed: result.changes === 1, operation: this.getPendingOperation(operationId)! };
  }

  createPendingOperation(
    operationId: string,
    operationType: string,
    payload: Record<string, unknown>,
  ) {
    return this.claimOperation(operationId, operationType, payload);
  }

  retryFailedOperation(operationId: string, leaseMs = 30_000) {
    const now = new Date().toISOString();
    const result = this.db.prepare(
      `UPDATE pending_operations SET status = 'PENDING', tx_hash = NULL, error = NULL,
       claimed_at = ?, lease_expires_at = ?, updated_at = ?
       WHERE operation_id = ? AND status = 'FAILED'`,
    ).run(now, new Date(Date.now() + leaseMs).toISOString(), now, operationId);
    return result.changes === 1;
  }

  reclaimStalePending(operationId: string, leaseMs = 30_000) {
    const now = new Date().toISOString();
    return this.db.prepare(
      `UPDATE pending_operations SET claimed_at = ?, lease_expires_at = ?, updated_at = ?
       WHERE operation_id = ? AND status = 'PENDING' AND tx_hash IS NULL
       AND lease_expires_at <= ?`,
    ).run(now, new Date(Date.now() + leaseMs).toISOString(), now, operationId, now).changes === 1;
  }

  failOperationAsConflict(operationId: string, error: string) {
    return this.db.prepare(
      `UPDATE pending_operations SET status = 'FAILED', error = ?, updated_at = ?
       WHERE operation_id = ? AND status IN ('PENDING', 'FAILED')`,
    ).run(error, new Date().toISOString(), operationId).changes === 1;
  }

  completeFailedOperation(operationId: string, txHash?: string) {
    return this.db.prepare(
      `UPDATE pending_operations SET status = 'COMPLETED', tx_hash = COALESCE(?, tx_hash),
       error = NULL, updated_at = ? WHERE operation_id = ? AND status = 'FAILED'`,
    ).run(txHash ?? null, new Date().toISOString(), operationId).changes === 1;
  }

  updatePendingOperation(
    operationId: string,
    status: "SUBMITTED" | "COMPLETED" | "FAILED",
    txHash?: string,
    error?: string,
  ) {
    const transition = status === "SUBMITTED"
      ? "status = 'PENDING'"
      : status === "COMPLETED"
        ? "status IN ('PENDING', 'SUBMITTED')"
        : txHash
          ? "status = 'SUBMITTED' AND tx_hash = ?"
          : "status = 'PENDING' AND tx_hash IS NULL";
    const sql = `UPDATE pending_operations SET status = ?, tx_hash = COALESCE(?, tx_hash),
       error = ?, updated_at = ? WHERE operation_id = ? AND ${transition}`;
    const params: Array<string | null> = [status, txHash ?? null, error ?? null,
      new Date().toISOString(), operationId];
    if (status === "FAILED" && txHash) params.push(txHash);
    return this.db.prepare(sql).run(...params).changes === 1;
  }

  listSubmittedOperations() {
    const rows = this.db.prepare(
      `SELECT operation_id, operation_type, status, tx_hash, payload_json
       FROM pending_operations WHERE status = 'SUBMITTED' ORDER BY created_at`,
    ).all() as Array<Record<string, string>>;
    return rows.map((row) => ({
      operationId: row.operation_id,
      operationType: row.operation_type,
      status: row.status,
      txHash: row.tx_hash,
      payload: JSON.parse(row.payload_json) as Record<string, unknown>,
    }));
  }

  getPendingOperation(operationId: string) {
    const row = this.db.prepare(
      `SELECT operation_id, operation_type, status, tx_hash, payload_json,
       claimed_at, lease_expires_at
       FROM pending_operations WHERE operation_id = ?`,
    ).get(operationId) as Record<string, string> | undefined;
    return row ? {
      operationId: row.operation_id,
      operationType: row.operation_type,
      status: row.status,
      txHash: row.tx_hash,
      claimedAt: row.claimed_at,
      leaseExpiresAt: row.lease_expires_at,
      stale: row.status === "PENDING" && row.lease_expires_at <= new Date().toISOString(),
      payload: JSON.parse(row.payload_json) as Record<string, unknown>,
    } : undefined;
  }

  listEvents(releaseId?: string) {
    const rows = (releaseId
      ? this.db
          .prepare("SELECT * FROM chain_events WHERE release_id = ? ORDER BY id")
          .all(releaseId)
      : this.db.prepare("SELECT * FROM chain_events ORDER BY id").all()) as Array<
      Record<string, string | number | null>
    >;
    return rows.map((row) => ({
      id: row.id,
      releaseId: row.release_id,
      eventName: row.event_name,
      status: row.status,
      txHash: row.tx_hash,
      blockNumber: row.block_number,
      payload: JSON.parse(row.payload_json as string),
      createdAt: row.created_at,
    }));
  }
}
