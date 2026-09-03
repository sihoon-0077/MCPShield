import type { Snapshot } from "./types";

const a = "832b83fe46e8682d5b8cfd75bae7d193fa9ca7bd8027c333107b0e4869ae0af8";
const b = "dc62858eaccd6be4610102d4dbd9fc13b3f5dc5ced1ce27befbd1ef8722f1511";
const c = "186e20e6e68b50c907d48209188d82d5afc0bc9bebdad39efe773da0ee30a336";
const d = "d0bf6289b1a1c64f2b5099332e51dc2684fb8ac8aa31b48d358f1719adfd1922";

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
