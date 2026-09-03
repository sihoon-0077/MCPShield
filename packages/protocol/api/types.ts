export const SCHEMA_VERSION = "1.0.0" as const;

export type ReleaseStatus =
  | "UNVERIFIED"
  | "VERIFIED"
  | "QUARANTINED"
  | "REVOKED";

export type ScanStatus =
  | "QUEUED"
  | "RUNNING"
  | "PASSED"
  | "FAILED"
  | "INCONCLUSIVE";

export type ValidatorDecision = "PASS" | "FAIL" | "ABSTAIN";
export type Source = "LIVE" | "MOCK" | "REPLAY";

export interface Finding {
  code:
    | "SENSITIVE_FILE_READ"
    | "UNDECLARED_EGRESS"
    | "CANARY_EXFILTRATION"
    | "TOOL_SURFACE_CHANGED"
    | "SEMANTIC_BEHAVIOR_MISMATCH"
    | "UNSAFE_MODULE_LOAD";
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  deterministic: boolean;
  stage: "STATIC" | "AI" | "SANDBOX" | "POLICY";
  message: string;
  evidence: Record<string, unknown>;
}

export interface ScanResult {
  schemaVersion: typeof SCHEMA_VERSION;
  scanId: string;
  releaseId: string;
  artifactDigest: string;
  toolSurfaceHash: string;
  scanStatus: ScanStatus;
  findings: Finding[];
  evidenceHash: string;
  source: Source;
}

export interface AdmissionDecision {
  schemaVersion: typeof SCHEMA_VERSION;
  releaseId: string;
  decision: "ALLOW" | "BLOCK";
  releaseStatus: ReleaseStatus;
  reasonCode:
    | "RELEASE_VERIFIED"
    | "RELEASE_UNVERIFIED"
    | "RELEASE_QUARANTINED"
    | "RELEASE_REVOKED"
    | "DIGEST_MISMATCH"
    | "STATUS_UNAVAILABLE";
  checkedAt: string;
  source: Source;
}

export interface RegisterReleaseRequest {
  schemaVersion: typeof SCHEMA_VERSION;
  releaseId: string;
  artifactDigest: string;
  toolSurfaceHash: string;
}

export interface SubmitScanRequest extends Omit<ScanResult, "source"> {
  source?: Source;
}

export interface SubmitAttestationRequest {
  schemaVersion: typeof SCHEMA_VERSION;
  releaseId: string;
  scanId: string;
  decision: ValidatorDecision;
  evidenceHash: string;
  nonce: number;
  deadline: number;
  signature: string;
}

export interface AdmissionRequest {
  schemaVersion: typeof SCHEMA_VERSION;
  releaseId: string;
  artifactDigest: string;
  toolSurfaceHash: string;
}
