type Json = Record<string, unknown>;

export type BackendRelease = {
  releaseId: string;
  artifactDigest: string;
  toolSurfaceHash: string;
  status: "UNVERIFIED" | "VERIFIED" | "QUARANTINED" | "REVOKED";
  registrationTxHash?: string;
};

export type BackendFinding = {
  code: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  deterministic: boolean;
  stage: "STATIC" | "AI" | "SANDBOX" | "POLICY";
  message: string;
  evidence: Record<string, unknown>;
};

export type BackendScan = {
  schemaVersion: "1.0.0";
  scanId: string;
  releaseId: string;
  artifactDigest: string;
  toolSurfaceHash: string;
  scanStatus: "QUEUED" | "RUNNING" | "PASSED" | "FAILED" | "INCONCLUSIVE";
  findings: BackendFinding[];
  evidenceHash: string;
  source: "LIVE" | "MOCK" | "REPLAY";
};

export type BackendEvent = {
  id: number;
  releaseId: string;
  eventName: string;
  status?: string;
  txHash?: string;
  blockNumber?: number;
  payload: Record<string, unknown>;
  createdAt: string;
};

export type Admission = {
  schemaVersion: "1.0.0";
  releaseId: string;
  decision: "ALLOW" | "BLOCK";
  releaseStatus: BackendRelease["status"];
  reasonCode: string;
  checkedAt: string;
  source: "LIVE" | "MOCK" | "REPLAY";
};

type ClientOptions = {
  baseUrl: string;
  timeoutMs?: number;
  adminToken?: string;
  scannerToken?: string;
};

export class BackendError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "BackendError";
  }
}

const object = (value: unknown, label: string): Json => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is not an object`);
  return value as Json;
};

const requiredString = (value: unknown, label: string) => {
  if (typeof value !== "string" || !value) throw new Error(`${label} is missing`);
  return value;
};

const releaseStatuses = new Set(["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED"]);
const scanStatuses = new Set(["QUEUED", "RUNNING", "PASSED", "FAILED", "INCONCLUSIVE"]);
const sources = new Set(["LIVE", "MOCK", "REPLAY"]);
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const bytes32Pattern = /^0x[0-9a-f]{64}$/;

function parseRelease(value: unknown): BackendRelease {
  const release = object(value, "release");
  const releaseId = requiredString(release.releaseId, "release.releaseId");
  const artifactDigest = requiredString(release.artifactDigest, "release.artifactDigest");
  const toolSurfaceHash = requiredString(release.toolSurfaceHash, "release.toolSurfaceHash");
  const status = requiredString(release.status, "release.status");
  if (!digestPattern.test(artifactDigest) || !bytes32Pattern.test(toolSurfaceHash) || !releaseStatuses.has(status)) throw new Error("Release identity or status is not canonical");
  const registrationTxHash = typeof release.registrationTxHash === "string" && bytes32Pattern.test(release.registrationTxHash) ? release.registrationTxHash : undefined;
  return { releaseId, artifactDigest, toolSurfaceHash, status: status as BackendRelease["status"], registrationTxHash };
}

function parseScan(value: unknown): BackendScan {
  const scan = object(value, "scan");
  const scanStatus = requiredString(scan.scanStatus, "scan.scanStatus");
  const source = requiredString(scan.source, "scan.source");
  if (scan.schemaVersion !== "1.0.0" || !scanStatuses.has(scanStatus) || !sources.has(source) || !Array.isArray(scan.findings)) throw new Error("Scan response is not canonical");
  return scan as unknown as BackendScan;
}

function parseAdmission(value: unknown): Admission {
  const admission = object(value, "admission");
  const decision = requiredString(admission.decision, "admission.decision");
  const releaseStatus = requiredString(admission.releaseStatus, "admission.releaseStatus");
  const source = requiredString(admission.source, "admission.source");
  if (admission.schemaVersion !== "1.0.0" || !["ALLOW", "BLOCK"].includes(decision) || !releaseStatuses.has(releaseStatus) || !sources.has(source)) throw new Error("Admission response is not canonical");
  if (decision === "ALLOW" && releaseStatus !== "VERIFIED") throw new Error("Backend returned an unsafe ALLOW decision");
  return admission as unknown as Admission;
}

export class BackendClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly adminToken?: string;
  private readonly scannerToken?: string;

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 3_000;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 30_000) throw new Error("Backend timeout must be between 1 and 30000ms");
    this.adminToken = options.adminToken;
    this.scannerToken = options.scannerToken;
  }

  private async request(path: string, init: RequestInit = {}) {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      cache: "no-store",
      signal: AbortSignal.timeout(this.timeoutMs),
      headers: { accept: "application/json", ...init.headers },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const body = object(payload, "Backend error");
      const error = body.error && typeof body.error === "object" ? body.error as Json : body;
      throw new BackendError(response.status, String(error.message ?? error.code ?? `HTTP ${response.status}`));
    }
    return object(payload, "Backend response");
  }

  async health() {
    const payload = await this.request("/health");
    return { status: requiredString(payload.status, "health.status"), ledgerMode: requiredString(payload.ledgerMode, "health.ledgerMode") as "EVM" | "LOCAL_DEMO" };
  }

  async registerRelease(input: { schemaVersion: "1.0.0"; releaseId: string; artifactDigest: string; toolSurfaceHash: string }) {
    if (!this.adminToken) throw new Error("Admin token is not configured");
    return this.request("/api/releases", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${this.adminToken}` }, body: JSON.stringify(input) });
  }

  async getRelease(releaseId: string): Promise<BackendRelease> {
    const payload = await this.request(`/api/releases/${encodeURIComponent(releaseId)}`);
    const release = parseRelease(payload.release);
    if (release.releaseId !== releaseId) throw new Error("Backend returned the wrong release");
    return release;
  }

  async submitScan(input: Omit<BackendScan, "source"> & { source?: BackendScan["source"] }) {
    if (!this.scannerToken) throw new Error("Scanner token is not configured");
    return this.request("/api/scans", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${this.scannerToken}` }, body: JSON.stringify(input) }) as Promise<unknown>;
  }

  async getScan(scanId: string): Promise<BackendScan> {
    const scan = parseScan(await this.request(`/api/scans/${encodeURIComponent(scanId)}`));
    if (scan.scanId !== scanId) throw new Error("Backend returned the wrong scan");
    return scan;
  }

  async getLatestScan(releaseId: string): Promise<BackendScan | undefined> {
    try {
      const payload = await this.request(`/api/releases/${encodeURIComponent(releaseId)}/scans/latest`);
      const scan = parseScan(payload.scan);
      if (scan.releaseId !== releaseId) throw new Error("Backend returned a latest scan for the wrong release");
      return scan;
    } catch (error) {
      if (error instanceof BackendError && error.status === 404) return undefined;
      throw error;
    }
  }

  async submitValidatorVote(input: Json) {
    return this.request("/api/validators/vote", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input) });
  }

  async checkAdmission(input: { schemaVersion: "1.0.0"; releaseId: string; artifactDigest: string; toolSurfaceHash: string }): Promise<Admission> {
    const admission = parseAdmission(await this.request("/api/admission/check", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input) }));
    if (admission.releaseId !== input.releaseId) throw new Error("Backend returned admission for the wrong release");
    return admission;
  }

  async listEvents(releaseId?: string): Promise<BackendEvent[]> {
    const query = releaseId ? `?releaseId=${encodeURIComponent(releaseId)}` : "";
    const payload = await this.request(`/api/events${query}`);
    if (!Array.isArray(payload.events)) throw new Error("events is not an array");
    return payload.events.map((value) => {
      const event = object(value, "event");
      if (typeof event.id !== "number" || typeof event.eventName !== "string" || typeof event.releaseId !== "string" || typeof event.createdAt !== "string") throw new Error("Event response is not canonical");
      return {
        id: event.id,
        releaseId: event.releaseId,
        eventName: event.eventName,
        status: typeof event.status === "string" ? event.status : undefined,
        txHash: typeof event.txHash === "string" ? event.txHash : undefined,
        blockNumber: typeof event.blockNumber === "number" ? event.blockNumber : undefined,
        payload: object(event.payload, "event.payload"),
        createdAt: event.createdAt,
      } as BackendEvent;
    });
  }
}
