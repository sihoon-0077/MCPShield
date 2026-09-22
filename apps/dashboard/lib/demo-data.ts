import type { Snapshot } from "./types";

const a = "a345d325671967586298ff058ad4d65a2e65a1a5cb40070289234c58cd77f422";
const b = "b7014044a72759a20257de22b14714d588f1cda7a68d6a0caa16f1b5d4c0d020";
const c = "861b2161cedf0f1e6552b22b9aeeaaeda7f106437b33094a7e884a85f8eabdab";
const d = "e6b50801aa384636c2a31efea3ac6277ac5d1d6eb89d038099e068c685afa0d1";

export const mockSnapshot: Snapshot = {
  schemaVersion: "1.0.0",
  source: "MOCK",
  generatedAt: "2026-01-01T00:00:00.000Z",
  ledgerMode: "OFFLINE",
  releases: [
    { releaseId: "mail-mcp@1.0.0", signature: "VALID", artifactDigest: `sha256:${a}`, toolSurfaceHash: `0x${b}`, scanStatus: "PASSED", chainStatus: "VERIFIED", txHash: `0x${a}` },
    { releaseId: "mail-mcp@1.0.1", signature: "VALID", artifactDigest: `sha256:${c}`, toolSurfaceHash: `0x${d}`, scanStatus: "FAILED", chainStatus: "REVOKED", txHash: `0x${c}` }
  ],
  pipeline: [
    { stage: "STATIC", status: "PASSED", detail: "Tool surface changed; review required" },
    { stage: "AI", status: "FLAGGED", detail: "Behavior differs from declared mail scope" },
    { stage: "SANDBOX", status: "FAILED", detail: "Dummy canary reached the local sink" }
  ],
  sandboxEvents: [
    { time: "00:00.180", type: "SENSITIVE_FILE_READ", detail: "Fixture read /sandbox/canary.txt", level: "INFO" },
    { time: "00:00.412", type: "UNDECLARED_EGRESS", detail: "POST to local exfil sink", level: "CRITICAL" },
    { time: "00:00.419", type: "CANARY_EXFILTRATION", detail: "Dummy token matched by the sink", level: "CRITICAL" }
  ],
  validators: [
    { id: "Validator A", decision: "FAIL", txHash: `0x${a}` },
    { id: "Validator B", decision: "FAIL", txHash: `0x${b}` },
    { id: "Validator C", decision: "ABSTAIN" }
  ],
  admissions: [
    { gateway: "Gateway A", releaseId: "mail-mcp@1.0.0", decision: "ALLOW", reasonCode: "RELEASE_VERIFIED" },
    { gateway: "Gateway A", releaseId: "mail-mcp@1.0.1", decision: "BLOCK", reasonCode: "RELEASE_REVOKED" },
    { gateway: "Gateway B", releaseId: "mail-mcp@1.0.1", decision: "BLOCK", reasonCode: "RELEASE_REVOKED" }
  ]
};

export const unavailableSnapshot = (source: Snapshot["source"]): Snapshot => ({
  schemaVersion: "1.0.0",
  source,
  availability: "UNAVAILABLE",
  generatedAt: new Date().toISOString(),
  releases: [],
  pipeline: (["STATIC", "AI", "SANDBOX"] as const).map((stage) => ({ stage, status: "INCONCLUSIVE", detail: "No current evidence is available" })),
  sandboxEvents: [],
  validators: [],
  admissions: [],
});
