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
}

export interface VoteRecord {
  releaseId: string;
  validatorAddress: string;
  decision: ValidatorDecision;
  evidenceHash: string;
  txHash?: string;
}

type ReleaseRow = {
  release_id: string;
  artifact_digest: string;
  tool_surface_hash: string;
  status: ReleaseStatus;
  created_at: string;
  updated_at: string;
};

export class Repository {
  private readonly db: DatabaseSync;

  constructor(databasePath: string) {
    this.db = new DatabaseSync(databasePath);
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
          (release_id, artifact_digest, tool_surface_hash, status, created_at, updated_at)
         VALUES (?, ?, ?, 'UNVERIFIED', ?, ?)`,
      )
      .run(input.releaseId, input.artifactDigest, input.toolSurfaceHash, now, now);
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

  recordVote(vote: VoteRecord): ReleaseRecord {
    const release = this.getRelease(vote.releaseId);
    if (!release) throw new Error("RELEASE_NOT_FOUND");
    if (release.status === "REVOKED") throw new Error("RELEASE_REVOKED");

    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare(
          `INSERT INTO validator_votes
            (release_id, validator_address, decision, evidence_hash, tx_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(
          vote.releaseId,
          vote.validatorAddress,
          vote.decision,
          vote.evidenceHash,
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
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    return this.getRelease(vote.releaseId)!;
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
    txHash?: string,
    blockNumber?: number,
  ) {
    const previous = this.getRelease(releaseId);
    if (!previous || previous.status === status) return;
    this.db
      .prepare("UPDATE releases SET status = ?, updated_at = ? WHERE release_id = ?")
      .run(status, new Date().toISOString(), releaseId);
    this.addEvent(releaseId, "StatusChanged", status, txHash, blockNumber, {
      previousStatus: previous.status,
      newStatus: status,
      indexed: true,
    });
  }

  addEvent(
    releaseId: string,
    eventName: string,
    status?: ReleaseStatus,
    txHash?: string,
    blockNumber?: number,
    payload: Record<string, unknown> = {},
  ) {
    this.db
      .prepare(
        `INSERT INTO chain_events
          (release_id, event_name, status, tx_hash, block_number, payload_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        releaseId,
        eventName,
        status ?? null,
        txHash ?? null,
        blockNumber ?? null,
        JSON.stringify(payload),
        new Date().toISOString(),
      );
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
