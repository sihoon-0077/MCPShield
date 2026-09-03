import type { Snapshot } from "../../../lib/types";

export const dynamic = "force-dynamic";

function unwrap(value: unknown): Record<string, unknown> {
  const object = value && typeof value === "object" ? value as Record<string, unknown> : {};
  return (object.release ?? object.data ?? object) as Record<string, unknown>;
}

const text = (value: unknown, fallback: string) => typeof value === "string" ? value : fallback;

export async function GET() {
  const base = (process.env.MCPSHIELD_API_URL ?? "http://127.0.0.1:3001").replace(/\/$/, "");
  try {
    const [safeResponse, maliciousResponse, eventsResponse] = await Promise.all([
      fetch(`${base}/api/releases/${encodeURIComponent("mail-mcp@1.0.0")}`, { signal: AbortSignal.timeout(3000), cache: "no-store" }),
      fetch(`${base}/api/releases/${encodeURIComponent("mail-mcp@1.0.1")}`, { signal: AbortSignal.timeout(3000), cache: "no-store" }),
      fetch(`${base}/api/events`, { signal: AbortSignal.timeout(3000), cache: "no-store" })
    ]);
    if (![safeResponse, maliciousResponse, eventsResponse].every((response) => response.ok)) throw new Error("Backend returned a non-success status");
    const safe = unwrap(await safeResponse.json());
    const malicious = unwrap(await maliciousResponse.json());
    const eventPayload = await eventsResponse.json() as Record<string, unknown> | unknown[];
    const events = Array.isArray(eventPayload) ? eventPayload : Array.isArray(eventPayload.events) ? eventPayload.events : [];
    const release = (value: Record<string, unknown>, releaseId: string): Snapshot["releases"][number] => ({
      releaseId,
      signature: value.signature === "VALID" || value.signatureStatus === "VALID" ? "VALID" : "UNKNOWN",
      artifactDigest: text(value.artifactDigest, "sha256:" + "0".repeat(64)),
      toolSurfaceHash: text(value.toolSurfaceHash, "0x" + "0".repeat(64)),
      scanStatus: text(value.scanStatus, "INCONCLUSIVE") as Snapshot["releases"][number]["scanStatus"],
      chainStatus: text(value.releaseStatus ?? value.status, "UNVERIFIED") as Snapshot["releases"][number]["chainStatus"],
      txHash: text(value.txHash ?? value.transactionHash, "") || undefined
    });
    const validators = events
      .map(unwrap)
      .filter((event) => ["PASS", "FAIL", "ABSTAIN"].includes(String(event.decision)))
      .map((event, index) => ({ id: text(event.validatorId ?? event.validator, `Validator ${index + 1}`), decision: event.decision as "PASS" | "FAIL" | "ABSTAIN", txHash: text(event.txHash, "") || undefined }));
    const maliciousRelease = release(malicious, "mail-mcp@1.0.1");
    const snapshot: Snapshot = {
      schemaVersion: "1.0.0",
      source: "LIVE",
      generatedAt: new Date().toISOString(),
      releases: [release(safe, "mail-mcp@1.0.0"), maliciousRelease],
      pipeline: [
        { stage: "STATIC", status: maliciousRelease.scanStatus, detail: "Backend release scan status" },
        { stage: "AI", status: maliciousRelease.scanStatus, detail: "See backend event stream for semantic findings" },
        { stage: "SANDBOX", status: maliciousRelease.scanStatus, detail: `${events.length} chain/API events received` }
      ],
      sandboxEvents: events.slice(-8).map((raw, index) => {
        const event = unwrap(raw);
        return { time: text(event.createdAt ?? event.timestamp, `event-${index + 1}`), type: text(event.type ?? event.code, "CHAIN_EVENT"), detail: text(event.message, JSON.stringify(event)), level: event.severity === "CRITICAL" ? "CRITICAL" : "INFO" };
      }),
      validators,
      admissions: ["Gateway A", "Gateway B"].map((gateway) => ({ gateway, releaseId: maliciousRelease.releaseId, decision: maliciousRelease.chainStatus === "VERIFIED" ? "ALLOW" : "BLOCK", reasonCode: `RELEASE_${maliciousRelease.chainStatus}` }))
    };
    return Response.json(snapshot);
  } catch (error) {
    return Response.json({ error: "Live API unavailable", detail: error instanceof Error ? error.message : "unknown error" }, { status: 503 });
  }
}
