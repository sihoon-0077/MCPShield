import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { bytes32, exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2.js";
import { hash } from "../../api/src/control-plane.js";
import { policyVerdict, validPolicy } from "../../api/src/control-policy.js";
import { checkedPreparedValidatorAi, deterministicScopes, type PreparedValidatorAi } from "./prepared-verification.js";
// @ts-expect-error Shared immutable artifact resolver.
import { resolveArtifact } from "../../../services/resolver/src/resolver.mjs";
// @ts-expect-error Shared actual scanner.
import { scanResolvedArtifact } from "../../../services/scanner/src/scanner.mjs";
// @ts-expect-error Shared Merkle verifier.
import { verifyEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared canonical protocol validation.
import { assertCanonicalScanResult } from "../../../services/scanner/src/protocol-schema.mjs";

type Source = { releaseId: string; sourceType: "local" | "npm" | "tarball" | "oci"; locator: string };
export type ValidatorSources = { schemaVersion: "mcpshield.validator-sources.v1"; sources: Source[] };
const exact = (value: any, fields: string[]) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join() === fields.sort().join();
export function checkedValidatorSources(value: any): ValidatorSources {
  if (!exact(value, ["schemaVersion", "sources"]) || value.schemaVersion !== "mcpshield.validator-sources.v1" || !Array.isArray(value.sources)
    || value.sources.length < 1 || value.sources.length > 128 || Buffer.byteLength(JSON.stringify(value)) > 512 * 1024) throw Error("VALIDATOR_SOURCES_INVALID");
  for (const source of value.sources) {
    if (!exact(source, ["releaseId", "sourceType", "locator"]) || !/^0x[a-f0-9]{64}$/.test(source.releaseId)
      || !["local", "npm", "tarball", "oci"].includes(source.sourceType) || typeof source.locator !== "string" || !source.locator || source.locator.length > 2048
      || /[\x00-\x1f\x7f]/.test(source.locator)) throw Error("VALIDATOR_SOURCES_INVALID");
    if (source.sourceType === "local" && !isAbsolute(source.locator)) throw Error("VALIDATOR_LOCAL_SOURCE_MUST_BE_ABSOLUTE");
    if (source.sourceType === "npm" && !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(source.locator)) throw Error("VALIDATOR_NPM_EXACT_VERSION_REQUIRED");
    if (source.sourceType === "tarball") {
      const url = new URL(source.locator);
      if (url.protocol !== "https:" || url.hostname !== "registry.npmjs.org" || url.port || url.username || url.password || url.hash) throw Error("VALIDATOR_SOURCE_URL_INVALID");
    }
    if (source.sourceType === "oci" && !/@sha256:[a-f0-9]{64}$/.test(source.locator)) throw Error("VALIDATOR_OCI_DIGEST_REQUIRED");
  }
  if (new Set(value.sources.map((source: Source) => source.releaseId)).size !== value.sources.length) throw Error("VALIDATOR_SOURCE_DUPLICATE");
  return structuredClone(value);
}
export async function loadValidatorSources(filename: string) {
  const file = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = await file.stat(); if (!stat.isFile() || stat.size < 1 || stat.size > 512 * 1024) throw Error("VALIDATOR_SOURCES_FILE_INVALID");
    const bytes = Buffer.alloc(stat.size + 1); let offset = 0;
    while (offset < bytes.length) { const read = await file.read(bytes, offset, bytes.length - offset); if (!read.bytesRead) break; offset += read.bytesRead; }
    if (offset !== stat.size) throw Error("VALIDATOR_SOURCES_FILE_INVALID");
    return checkedValidatorSources(JSON.parse(bytes.subarray(0, offset).toString("utf8")));
  } finally { await file.close(); }
}
export function checkedSourceIdentity(source: any, identity: any, releaseId: string) {
  const exact = exactReleaseIdentity(source);
  if (!identity?.exists || exact.releaseId !== releaseId || exact.toolId !== identity.toolId || bytes32(source.artifactDigest) !== identity.artifactDigest
    || bytes32(source.manifestDigest) !== identity.manifestDigest || bytes32(source.toolSurfaceHash) !== identity.toolSurfaceDigest) throw Error("VALIDATOR_SOURCE_CHAIN_MISMATCH");
  return { ...exact, artifactDigest: source.artifactDigest, manifestDigest: source.manifestDigest, toolSurfaceHash: source.toolSurfaceHash };
}
export function compareSourceScans(original: any, independent: any, policy: any, identity: any, releaseId: string, baselineReleaseId: string | null = null) {
  if (!validPolicy(policy) || policy.profile !== undefined) throw Error("VALIDATOR_SOURCE_POLICY_REQUIRED");
  assertCanonicalScanResult(original.result); assertCanonicalScanResult(independent.result);
  checkedSourceIdentity(independent.sourceIdentity, identity, releaseId);
  if (!verifyEvidenceBundle(original.bundle, original.bundle.manifest.root) || !verifyEvidenceBundle(independent.bundle, independent.bundle.manifest.root)
    || original.result.source !== "LIVE" || independent.result.source !== "LIVE" || original.result.scanId === independent.result.scanId || original.result.releaseId !== independent.result.releaseId
    || bytes32(independent.result.artifactDigest) !== identity.artifactDigest || bytes32(independent.result.toolSurfaceHash) !== identity.toolSurfaceDigest
    || baselineReleaseId !== independent.baselineReleaseId) throw Error("INDEPENDENT_SOURCE_IDENTITY_MISMATCH");
  const originalDiff = JSON.parse(original.bundle.files["static/package-diff.json"] ?? "null"), independentDiff = JSON.parse(independent.bundle.files["static/package-diff.json"] ?? "null");
  if (originalDiff?.hasBaseline !== Boolean(baselineReleaseId) || hash(originalDiff) !== hash(independentDiff)) throw Error("INDEPENDENT_BASELINE_MISMATCH");
  const first = policyVerdict(original.bundle, original.result, policy), second = policyVerdict(independent.bundle, independent.result, policy);
  // A static FAIL with missing Docker is not an independent runtime verification.
  const events = JSON.parse(independent.bundle.files["sandbox/events.json"] ?? "null"), mcp = JSON.parse(independent.bundle.files["sandbox/mcp.json"] ?? "null");
  if (first === "ABSTAIN" || second !== first || events?.mode !== "DOCKER" || events.complete !== true || mcp?.complete !== true
    || hash(deterministicScopes(original.result, true)) !== hash(deterministicScopes(independent.result, true))) throw Error("INDEPENDENT_SOURCE_DID_NOT_CONFIRM");
  return { verdict: first, originalReportRoot: original.bundle.manifest.root, independentReportRoot: independent.bundle.manifest.root,
    findingScopeHash: hash(deterministicScopes(independent.result, true)), verificationProfile: "SOURCE_DOCKER_V1",
    semanticExecution: JSON.parse(independent.bundle.files["semantic/model-output.json"])?.execution?.status === "LOCAL_FALLBACK" ? "LOCAL_STRUCTURED_FALLBACK_V1" : "EXPLICIT_LOCAL_PROVIDER" };
}
export async function independentlyScanSource(original: any, policy: any, identity: any, releaseId: string, sources: ValidatorSources,
  baseline?: { releaseId: string; identity: any }, ai?: PreparedValidatorAi) {
  const catalog = checkedValidatorSources(sources);
  const selected = (id: string) => { const source = catalog.sources.find((source) => source.releaseId === id); if (!source) throw Error("VALIDATOR_SOURCE_NOT_CONFIGURED"); return source; };
  const source = selected(releaseId), baseSource = baseline ? selected(baseline.releaseId) : undefined;
  // The existing OCI resolver inspects metadata, not an executing generic OCI MCP runtime.
  if (source.sourceType === "oci" || baseSource?.sourceType === "oci") throw Error("VALIDATOR_OCI_RUNTIME_UNOBSERVED");
  assertCanonicalScanResult(original.result);
  if (!identity.exists || bytes32(original.result.artifactDigest) !== identity.artifactDigest || bytes32(original.result.toolSurfaceHash) !== identity.toolSurfaceDigest
    || !verifyEvidenceBundle(original.bundle, original.bundle.manifest.root) || !validPolicy(policy) || policy.profile !== undefined
    || policyVerdict(original.bundle, original.result, policy) === "ABSTAIN") throw Error("INDEPENDENT_ORIGINAL_NOT_APPROVABLE");
  const localAi = ai ? checkedPreparedValidatorAi(ai) : undefined;
  if (JSON.parse(original.bundle.files["static/package-diff.json"] ?? "null")?.hasBaseline !== Boolean(baseline)) throw Error("INDEPENDENT_BASELINE_MISMATCH");
  let resolved: any, baselineResolved: any;
  try {
    resolved = await resolveArtifact({ sourceType: source.sourceType, locator: source.locator });
    const sourceIdentity = checkedSourceIdentity(resolved, identity, releaseId);
    if (baseline && baseSource) {
      baselineResolved = await resolveArtifact({ sourceType: baseSource.sourceType, locator: baseSource.locator });
      const previous = checkedSourceIdentity(baselineResolved, baseline.identity, baseline.releaseId);
      if (previous.toolId !== sourceIdentity.toolId) throw Error("VALIDATOR_BASELINE_TOOL_MISMATCH");
    }
    const scanned = await scanResolvedArtifact({ artifactDir: resolved.artifactDir, baselineDir: baselineResolved?.artifactDir, sandbox: "docker", sandboxTimeoutMs: 15000,
      allowRemoteAi: Boolean(localAi), aiProvider: localAi?.provider, aiModel: localAi?.model, aiUrl: localAi?.url, aiToken: localAi?.token,
      aiTimeoutMs: localAi?.timeoutMs ?? 45000, aiDisclosurePolicy: localAi?.disclosurePolicy, logger: () => {} });
    const independent = { result: scanned.result, bundle: scanned.bundle, sourceIdentity, baselineReleaseId: baseline?.releaseId ?? null };
    return { independent, comparison: compareSourceScans(original, independent, policy, identity, releaseId, baseline?.releaseId ?? null) };
  } finally { await baselineResolved?.cleanup?.(); await resolved?.cleanup?.(); }
}
