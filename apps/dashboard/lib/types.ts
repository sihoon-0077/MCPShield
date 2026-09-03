export type Source = "LIVE" | "MOCK" | "REPLAY";

export type Snapshot = {
  schemaVersion: "1.0.0";
  source: Source;
  availability?: "UNAVAILABLE";
  generatedAt: string;
  ledgerMode?: "EVM" | "LOCAL_DEMO" | "OFFLINE";
  explorerBaseUrl?: string;
  releases: Array<{
    releaseId: string;
    signature: "VALID" | "UNKNOWN";
    artifactDigest: string;
    toolSurfaceHash: string;
    scanStatus: "QUEUED" | "RUNNING" | "PASSED" | "FAILED" | "INCONCLUSIVE";
    chainStatus: "UNVERIFIED" | "VERIFIED" | "QUARANTINED" | "REVOKED";
    txHash?: string;
  }>;
  pipeline: Array<{ stage: "STATIC" | "AI" | "SANDBOX"; status: string; detail: string }>;
  sandboxEvents: Array<{ time: string; type: string; detail: string; level: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" }>;
  validators: Array<{ id: string; decision: "PASS" | "FAIL" | "ABSTAIN"; txHash?: string }>;
  admissions: Array<{ gateway: string; releaseId: string; decision: "ALLOW" | "BLOCK"; reasonCode: string; checkedAt?: string; source?: Source; spawnAttempted?: boolean }>;
};
