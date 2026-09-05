import type { Snapshot } from "./types";

const a = "8ef9cb6c1cb212b3d32ebc99f47d11028ba2db8ce15948729c0f089079bffef8";
const b = "fc4b6f6c60517bec321002472cf8fbd646067cc1aa4ccbf2a9c8fd62197a43bc";
const c = "01cbe916a8d67caf7e022a0fa758f63ada1a5c2ebf1fb50fa1aa645a9fab38c9";
const d = "6c1be4f5520587dc36cc3f74273cffac6c180e612cf2c157a45941d156fb4ce3";

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
