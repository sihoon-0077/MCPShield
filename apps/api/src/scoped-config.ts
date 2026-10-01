import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { hash, loadEvidence, type ControlOptions } from "./control-plane.js";
import { preparedTrust, checkedPreparedTrust, inspectPreparedRuntime } from "./prepared-config.js";
import type { ControlStore } from "./control-store.js";
import { isScopedBaselinePolicy } from "./control-policy.js";
import { sourceIdentity } from "./preparation-control.js";
import { checkedPreparedEvidence } from "./prepared-evidence.js";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Local immutable acquisition reuses the bounded stable snapshot.
import { resolveArtifact } from "../../../services/resolver/src/resolver.mjs";
// @ts-expect-error Shared exact provenance/policy contracts.
import { checkedScopedProvenance, SCOPED_NODE_PROFILE, validateScopedReviewPolicy, validateScopedBaselineReviewPolicy } from "../../../services/scanner/src/scoped-policy.mjs";
// @ts-expect-error Pure baseline evidence/authority checks, no Docker or provider access.
import { checkedScopedBaselineAuthority, readPreparedClosureEvidence, SCOPED_BASELINE_TRUST_FIELDS } from "../../../services/scanner/src/scoped-baseline.mjs";
// @ts-expect-error Shared immutable execution commitment.
import { scopedPreparedExecutionPolicy } from "../../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared transport/privacy validator; no provider request is made here.
import * as scopedSemantic from "../../../services/scanner/src/scoped-semantic.mjs";
// @ts-expect-error Existing operator-pinned Ed25519 contract, not candidate authority.
import { verifyDemoPublisherManifest } from "../../../services/resolver/src/demo-publisher.mjs";

export interface DemoPublisher { publisherId: string; pinnedPublicKey: string; manifest: any }
export function publisherEvidence(resolved: any, publisher?: DemoPublisher) {
  if (!publisher) return undefined;
  try {
    return { manifest: publisher.manifest, verification: verifyDemoPublisherManifest({ manifest: publisher.manifest, pinnedPublicKey: publisher.pinnedPublicKey,
      expectedIdentity: { publisherId: publisher.publisherId, name: resolved.metadata.name, version: resolved.metadata.version, artifactDigest: resolved.artifactDigest } }) };
  } catch { throw Error("SCOPED_PUBLISHER_SIGNATURE_INVALID"); }
}
export function publicPublisherVerification(evidence?: ReturnType<typeof publisherEvidence>) {
  return { status: evidence ? "VERIFIED" : "NOT_CONFIGURED", purpose: "DEMO_ONLY_NOT_NPM_PROVENANCE", behaviorSafety: "NOT_ASSESSED",
    ...(evidence ? { publisherId: evidence.verification.publisherId, sourceArtifactDigest: evidence.verification.artifactDigest,
      publicKeyFingerprint: evidence.verification.publicKeyFingerprint } : {}) };
}
export function assertPublisherEvidence(bundle: any, expected?: ReturnType<typeof publisherEvidence>) {
  try {
    const actual = bundle.files["prepared/publisher.json"];
    if (expected === undefined ? actual !== undefined : actual === undefined || hash(JSON.parse(actual)) !== hash(expected)) throw Error();
  } catch { throw Error("SCOPED_PUBLISHER_EVIDENCE_MISMATCH"); }
}
export function publisherDocuments(bundle: any, evidence?: ReturnType<typeof publisherEvidence>) {
  // Only locally verified source evidence may occupy this leaf. A scanner cannot self-certify.
  if (!evidence) assertPublisherEvidence(bundle);
  return evidence ? { "prepared/publisher.json": evidence } : {};
}

export type ScopedAi = Record<string, any>;
export function checkedScopedAi(ai: ScopedAi, semantic: any) {
  (validateScopedBaselineReviewPolicy(semantic) ? scopedSemantic.validateScopedAiV21 : scopedSemantic.validateScopedAiV2)(ai, semantic);
  return structuredClone(ai);
}
export interface ScopedPreparedConfig { provenancePaths: Record<string, string>; ai: ScopedAi }
const exact = (value: any, keys: string[]) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join() === keys.sort().join();
export function checkedScopedConfig(value: any): ScopedPreparedConfig {
  if (!exact(value, ["provenancePaths", "ai"]) || !value.provenancePaths || typeof value.provenancePaths !== "object" || Array.isArray(value.provenancePaths)
    || Object.entries(value.provenancePaths).length > 128 || Object.entries(value.provenancePaths).some(([tenant, path]) => !/^[A-Za-z0-9_-]{1,64}$/.test(tenant)
      || typeof path !== "string" || path.length > 4096 || !isAbsolute(path) || /[\x00-\x1f]/.test(path))
    || !value.ai || typeof value.ai !== "object" || Array.isArray(value.ai)) throw Error("SCOPED_CONFIG_INVALID");
  return structuredClone(value);
}
export function checkedProvenanceCatalogue(value: any) {
  if (!(exact(value, ["schemaVersion", "artifacts"]) || exact(value, ["schemaVersion", "artifacts", "publishers"])) || value.schemaVersion !== "mcpshield.scoped-provenance-catalogue.v1" || !Array.isArray(value.artifacts)
    || value.artifacts.length > 128 || Buffer.byteLength(JSON.stringify(value)) > 512 * 1024) throw Error("SCOPED_CATALOGUE_INVALID");
  const artifacts = value.artifacts.map((item: any) => checkedScopedProvenance(item, item?.sourceArtifactDigest));
  if (new Set(artifacts.map((item: any) => item.sourceArtifactDigest)).size !== artifacts.length) throw Error("SCOPED_CATALOGUE_INVALID");
  if (Object.hasOwn(value, "publishers")) {
    if (!value.publishers || typeof value.publishers !== "object" || Array.isArray(value.publishers) || Object.keys(value.publishers).length > 128) throw Error("SCOPED_CATALOGUE_INVALID");
    for (const [digest, entry] of Object.entries(value.publishers) as [string, DemoPublisher][]) {
      if (!artifacts.some((item: any) => item.sourceArtifactDigest === digest) || !exact(entry, ["publisherId", "pinnedPublicKey", "manifest"])) throw Error("SCOPED_CATALOGUE_INVALID");
      publisherEvidence({ artifactDigest: digest, metadata: { name: entry.manifest?.payload?.name, version: entry.manifest?.payload?.version } }, entry);
    }
  }
  return artifacts as Record<string, any>[];
}
export async function loadScopedAuthority(filename: string | undefined, sourceArtifactDigest: string, requireProvenance = true) {
  // No cached approvals: empty/replaced local files revoke eligibility immediately.
  try {
    if (!filename || !isAbsolute(filename)) throw Error();
    const file = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const stat = await file.stat(); if (!stat.isFile() || stat.size < 1 || stat.size > 512 * 1024) throw Error();
      const bytes = Buffer.alloc(stat.size + 1); let offset = 0;
      while (offset < bytes.length) { const read = await file.read(bytes, offset, bytes.length - offset); if (!read.bytesRead) break; offset += read.bytesRead; }
      if (offset !== stat.size) throw Error();
      const document = JSON.parse(bytes.subarray(0, offset).toString("utf8")), catalogue = checkedProvenanceCatalogue(document);
      const sourceProvenance = requireProvenance ? checkedScopedProvenance(catalogue.find(item => item.sourceArtifactDigest === sourceArtifactDigest), sourceArtifactDigest) : undefined;
      if (Object.hasOwn(document, "publishers") && !Object.hasOwn(document.publishers, sourceArtifactDigest)) throw Error("SCOPED_PUBLISHER_SIGNATURE_REQUIRED");
      return { sourceProvenance, demoPublisher: document.publishers?.[sourceArtifactDigest] as DemoPublisher | undefined };
    } finally { await file.close(); }
  } catch (error: any) { throw Error(/^SCOPED_PUBLISHER_[A-Z_]+$/.test(error?.message ?? "") ? error.message : "SCOPED_OPERATOR_PROVENANCE_REQUIRED"); }
}
export async function loadScopedProvenance(filename: string | undefined, sourceArtifactDigest: string) {
  return (await loadScopedAuthority(filename, sourceArtifactDigest)).sourceProvenance;
}
export function scopedMetadata(policy: any) {
  if (policy?.profile !== SCOPED_NODE_PROFILE || !(validateScopedReviewPolicy(policy.semantic) || isScopedBaselinePolicy(policy))) return {};
  return { semanticEvidenceMode: policy.semantic.evidenceMode, providerQuality: "PROVIDER_QUALITY_NOT_MEASURED" };
}
async function scopedSource(options: ControlOptions, tenant: string, policy: any, source: Record<string, any>) {
  const config = checkedScopedConfig(options.scopedPrepared);
  const { sourceProvenance, demoPublisher } = await loadScopedAuthority(Object.hasOwn(config.provenancePaths, tenant) ? config.provenancePaths[tenant] : undefined, source?.artifactDigest);
  let resolved, sourceBudget, publisher;
  try {
    if (!source?.artifactDir || !isAbsolute(source.artifactDir)) throw Error("SCOPED_SOURCE_UNAVAILABLE");
    resolved = await resolveArtifact({ sourceType: "local", locator: source.artifactDir }, { demoPublisher });
    if (exactReleaseIdentity(resolved).releaseId !== source.releaseId || resolved.artifactDigest !== source.artifactDigest) throw Error("SCOPED_SOURCE_IDENTITY_MISMATCH");
    const sourceBytes = resolved.metadata?.sizeBytes;
    if (!Number.isSafeInteger(sourceBytes) || sourceBytes < 0 || sourceBytes > policy.maxArtifactBytes) throw Error("SCOPED_SOURCE_BUDGET_EXCEEDED");
    sourceBudget = { sourceArtifactDigest: source.artifactDigest, sourceBytes };
    publisher = publisherEvidence(resolved, demoPublisher);
  } catch (error: any) {
    throw Error(/^DEMO_PUBLISHER_/.test(error?.message ?? "") ? "SCOPED_PUBLISHER_SIGNATURE_INVALID" : /^SCOPED_[A-Z0-9_]+$/.test(error?.message ?? "") ? error.message : "SCOPED_SOURCE_UNAVAILABLE");
  } finally { await resolved?.cleanup?.(); }
  return { sourceProvenance, sourceBudget, publisher, ...(publisher ? { publisherTrustHash: hash(demoPublisher) } : {}) };
}
export function checkedBaselineRequest(policy: any, request: any) {
  if (isScopedBaselinePolicy(policy) && (!Object.hasOwn(request, "baselineReleaseId") ||
    request.baselineReleaseId !== null && (typeof request.baselineReleaseId !== "string" || !/^0x[a-f0-9]{64}$/.test(request.baselineReleaseId)))) {
    throw Object.assign(Error("SCOPED_BASELINE_SELECTION_REQUIRED"), { statusCode: 400 });
  }
}
export async function scopedPreparationContext(options: ControlOptions, tenant: string, policy: any, source: Record<string, any>, store?: ControlStore, baselineReleaseId?: string | null) {
  if (policy?.profile !== SCOPED_NODE_PROFILE || !(validateScopedReviewPolicy(policy.semantic) || isScopedBaselinePolicy(policy)) || !options.preparedRuntime || !options.scopedPrepared) throw Error("SCOPED_CONFIG_REQUIRED");
  const config = checkedScopedConfig(options.scopedPrepared), current = await scopedSource(options, tenant, policy, source);
  const { sourceProvenance, sourceBudget, publisher } = current;
  const trusted: Record<string, any> = preparedTrust(options.preparedRuntime);
  const executionPolicy = scopedPreparedExecutionPolicy({ collectorDigest: trusted.collectorDigest, observerDigest: trusted.observerDigest,
    egressAllowHosts: ["mail-api.local", "exfil-sink.local"] }, policy.semantic);
  if (config.ai.evidenceMode !== policy.semantic.evidenceMode) throw Error("SCOPED_EVIDENCE_MODE_MISMATCH");
  const ai = checkedScopedAi(config.ai, policy.semantic);
  const scopedReview: Record<string, any> = { executionPolicy, sourceProvenance };
  let baselineAuthority;
  if (isScopedBaselinePolicy(policy)) {
    checkedBaselineRequest(policy, { baselineReleaseId });
    scopedReview.sourceIdentity = sourceIdentity(source); scopedReview.baseline = null;
    trusted.sourceIdentity = scopedReview.sourceIdentity; trusted.baseline = null;
    if (baselineReleaseId !== null) {
      const previous = await store?.get(tenant, "release", baselineReleaseId!);
      if (!previous || previous.runtimeProfile !== SCOPED_NODE_PROFILE || !previous.preparedEvidenceKey) throw Error("SCOPED_BASELINE_UNAVAILABLE");
      const bundle = await loadEvidence(options, tenant, previous.preparedEvidenceKey, previous.preparedReportRoot);
      const before = checkedPreparedEvidence(bundle, previous), original = await store!.get(tenant, "release", before.binding.sourceReleaseId);
      if (!original || hash(sourceIdentity(original)) !== hash(before.source)) throw Error("SCOPED_BASELINE_SOURCE_MISMATCH");
      baselineAuthority = await scopedSource(options, tenant, policy, original);
      assertPublisherEvidence(bundle, baselineAuthority.publisher);
      const scan = await store!.scan(tenant, JSON.parse(bundle.files["report.json"]).scanId);
      const proof = checkedPreparedTrust(scan?.result?.preparedRuntimeTrust, options.preparedRuntime);
      if (!scan || scan.status !== "COMPLETED" || scan.releaseId !== baselineReleaseId || scan.result?.evidenceKey !== previous.preparedEvidenceKey ||
        scan.result?.reportRoot !== previous.preparedReportRoot || !proof) throw Error("SCOPED_BASELINE_RUNTIME_UNAVAILABLE");
      scopedReview.baseline = { releaseId: baselineReleaseId, sourceIdentity: before.source, binding: before.binding, sourceProvenance: baselineAuthority.sourceProvenance };
      trusted.baseline = { ...Object.fromEntries(SCOPED_BASELINE_TRUST_FIELDS.slice(0, 8).map((key: string) => [key, proof[key]])),
        releaseId: baselineReleaseId, sourceIdentity: before.source, sourceProvenance: baselineAuthority.sourceProvenance,
        sourceBudget: baselineAuthority.sourceBudget, publisher: baselineAuthority.publisher ?? null };
      // Reuse stored worker proof only at the API boundary; workers/validators separately export the image.
      checkedScopedBaselineAuthority(scopedReview, trusted.baseline);
      readPreparedClosureEvidence({ inventory: JSON.parse(bundle.files["static/closure-inventory.json"]), report: JSON.parse(bundle.files["static/closure-report.json"]),
        source: JSON.parse(bundle.files["static/closure-source.json"]), sbom: JSON.parse(bundle.files["static/sbom.json"]), findings: JSON.parse(bundle.files["static/findings.json"]) }, before.binding, trusted.baseline);
    }
  }
  // A private commitment detects worker-local changes without persisting endpoints,
  // credentials or local paths. The scanner repeats validation at the actual tier.
  return { trusted, scopedReview, ai, sourceBudget, publisher,
    frozen: { ...trusted, scopedReview, sourceBudget, aiConfigHash: hash(config.ai),
      ...(publisher ? { publisher, publisherTrustHash: current.publisherTrustHash } : {}),
      ...(isScopedBaselinePolicy(policy) ? { baselineAuthority: baselineAuthority ? { sourceProvenance: baselineAuthority.sourceProvenance,
        sourceBudget: baselineAuthority.sourceBudget, publisher: baselineAuthority.publisher ?? null, publisherTrustHash: baselineAuthority.publisherTrustHash ?? null } : null } : {}) } };
}
export async function inspectScopedBaseline(scoped: Awaited<ReturnType<typeof scopedPreparationContext>>, options: ControlOptions) {
  if (!scoped.scopedReview.baseline) return;
  const expected = scoped.trusted.baseline, actual = await inspectPreparedRuntime(scoped.scopedReview.baseline.binding, options.preparedRuntime!, options.inspectPreparedRuntime);
  if (SCOPED_BASELINE_TRUST_FIELDS.slice(0, 8).some((key: string) => hash(actual[key]) !== hash(expected[key]))) throw Error("SCOPED_BASELINE_RUNTIME_CHANGED");
}
