import { BackendClient, type BackendEvent, type BackendFinding, type BackendRelease, type BackendScan } from "../../../lib/backend-client";
import type { Snapshot } from "../../../lib/types";
import { readFile } from "node:fs/promises";
import path from "node:path";

export const dynamic = "force-dynamic";

const releaseIds = ["mail-mcp@1.0.0", "mail-mcp@1.0.1"] as const;

async function gatewayEvidence(releases: BackendRelease[]): Promise<Snapshot["admissions"] | undefined> {
  const directory = process.env.MCPSHIELD_GATEWAY_EVIDENCE_DIR;
  if (!directory) return undefined;
  const expected = new Map(releases.map((release) => [release.releaseId, release]));
  return Promise.all([["gateway-a.json", "Gateway A LIVE probe"], ["gateway-b.json", "Gateway B LIVE probe"]].map(async ([file, expectedGateway]) => {
    const evidenceFile = path.join(/* turbopackIgnore: true */ directory, file);
    const evidence = JSON.parse(await readFile(/* turbopackIgnore: true */ evidenceFile, "utf8")) as Record<string, unknown>;
    const releaseId = typeof evidence.releaseId === "string" ? evidence.releaseId : "";
    const gateway = typeof evidence.gateway === "string" ? evidence.gateway : "";
    const checkedAt = typeof evidence.checkedAt === "string" ? evidence.checkedAt : "";
    const release = expected.get(releaseId);
    if (evidence.schemaVersion !== "1.0.0" || releaseId !== "mail-mcp@1.0.1" || !release || gateway !== expectedGateway || evidence.source !== "LIVE" || evidence.decision !== "BLOCK" ||
      evidence.releaseStatus !== "REVOKED" || evidence.reasonCode !== "RELEASE_REVOKED" || evidence.spawnAttempted !== false ||
      evidence.artifactDigest !== release.artifactDigest || evidence.toolSurfaceHash !== release.toolSurfaceHash ||
      !gateway || Number.isNaN(Date.parse(checkedAt))) {
      throw new Error(`Invalid Gateway evidence: ${file}`);
    }
    return { gateway, releaseId, decision: "BLOCK", reasonCode: "RELEASE_REVOKED", checkedAt, source: "LIVE", spawnAttempted: false };
  }));
}

function explorerBaseUrl() {
  try {
    const url = new URL(process.env.MCPSHIELD_EXPLORER_URL ?? "");
    return ["https:", "http:"].includes(url.protocol) ? url.toString().replace(/\/$/, "") : undefined;
  } catch {
    return undefined;
  }
}

function asRelease(release: BackendRelease, scan?: BackendScan): Snapshot["releases"][number] {
  return {
    releaseId: release.releaseId,
    signature: "UNKNOWN",
    artifactDigest: release.artifactDigest,
    toolSurfaceHash: release.toolSurfaceHash,
    scanStatus: scan?.scanStatus ?? "INCONCLUSIVE",
    chainStatus: release.status,
    txHash: release.registrationTxHash,
  };
}

function validatorsFrom(events: BackendEvent[]): Snapshot["validators"] {
  const latest = new Map<string, Snapshot["validators"][number]>();
  for (const event of events) {
    if (event.eventName !== "VoteSubmitted") continue;
    const address = typeof event.payload.validatorAddress === "string" ? event.payload.validatorAddress : "";
    const decision = event.payload.decision;
    if (!address || !["PASS", "FAIL", "ABSTAIN"].includes(String(decision))) continue;
    latest.set(address.toLowerCase(), { id: `Validator ${address.slice(0, 6)}…${address.slice(-4)}`, decision: decision as "PASS" | "FAIL" | "ABSTAIN", txHash: event.txHash });
  }
  return [...latest.values()];
}

function pipelineFrom(scan?: BackendScan): Snapshot["pipeline"] {
  const stages = ["STATIC", "AI", "SANDBOX"] as const;
  return stages.map((stage) => {
    const findings = scan?.findings.filter((finding) => finding.stage === stage) ?? [];
    const serious = findings.some((finding) => ["HIGH", "CRITICAL"].includes(finding.severity));
    const status = !scan ? "INCONCLUSIVE" : serious ? "FAILED" : findings.length ? "FLAGGED" : ["QUEUED", "RUNNING", "INCONCLUSIVE"].includes(scan.scanStatus) ? scan.scanStatus : "PASSED";
    return {
      stage,
      status,
      detail: !scan ? "No submitted scan exists for this release" : findings.length ? findings.map((finding) => finding.code).join(", ") : "No findings for this stage",
    };
  });
}

function timelineFrom(findings: BackendFinding[], events: BackendEvent[]): Snapshot["sandboxEvents"] {
  const evidence = findings.map((finding, index) => ({
    time: `finding-${String(index + 1).padStart(2, "0")}`,
    type: finding.code,
    detail: finding.message,
    level: finding.severity,
  }));
  if (evidence.length) return evidence;
  return events.slice(-8).map((event) => ({
    time: event.createdAt,
    type: event.eventName,
    detail: event.status ? `Release status: ${event.status}` : "On-chain event observed",
    level: event.eventName === "StatusChanged" && event.status === "REVOKED" ? "CRITICAL" : "INFO",
  }));
}

export async function GET() {
  const baseUrl = process.env.MCPSHIELD_API_URL ?? "http://127.0.0.1:3001";
  const timeoutMs = Number(process.env.MCPSHIELD_API_TIMEOUT_MS ?? 3_000);
  const client = new BackendClient({ baseUrl, timeoutMs });
  try {
    const [health, releases, events, scans] = await Promise.all([
      client.health(),
      Promise.all(releaseIds.map((releaseId) => client.getRelease(releaseId))),
      client.listEvents(),
      Promise.all(releaseIds.map((releaseId) => client.getLatestScan(releaseId))),
    ]);
    const scanByRelease = new Map(scans.filter((scan): scan is BackendScan => Boolean(scan)).map((scan) => [scan.releaseId, scan]));
    const releaseViews = releases.map((release) => asRelease(release, scanByRelease.get(release.releaseId)));
    const admissions = await gatewayEvidence(releases) ?? await Promise.all(releases.map(async (release) => {
      const result = await client.checkAdmission({ schemaVersion: "1.0.0", releaseId: release.releaseId, artifactDigest: release.artifactDigest, toolSurfaceHash: release.toolSurfaceHash });
      return { gateway: "Backend admission API (not a Gateway probe)", releaseId: result.releaseId, decision: result.decision, reasonCode: result.reasonCode, checkedAt: result.checkedAt, source: result.source } as Snapshot["admissions"][number];
    }));
    const maliciousScan = scanByRelease.get("mail-mcp@1.0.1");
    const snapshot: Snapshot = {
      schemaVersion: "1.0.0",
      source: "LIVE",
      generatedAt: new Date().toISOString(),
      ledgerMode: health.ledgerMode,
      explorerBaseUrl: health.ledgerMode === "EVM" ? explorerBaseUrl() : undefined,
      releases: releaseViews,
      pipeline: pipelineFrom(maliciousScan),
      sandboxEvents: timelineFrom(maliciousScan?.findings ?? [], events.filter((event) => event.releaseId === "mail-mcp@1.0.1")),
      validators: validatorsFrom(events.filter((event) => event.releaseId === "mail-mcp@1.0.1")),
      admissions,
    };
    return Response.json(snapshot, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return Response.json({ error: "Live API unavailable", detail: error instanceof Error ? error.message : "unknown error", source: "LIVE" }, { status: 503, headers: { "cache-control": "no-store" } });
  }
}
