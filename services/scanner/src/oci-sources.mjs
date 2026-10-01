import { canonicalJson } from './evidence.mjs';
import { inspectOciCoverage } from './oci-coverage.mjs';
import { checkedOciConfig, hashOciRuntimeDescriptor, ociHash } from '../../resolver/src/oci-runtime-descriptor.mjs';
import { preparedSemanticPrompt, LOCAL_CONTRACT_DISCLOSURE } from './prepared-review.mjs';
import { citationCatalogue, promptSources, validateSemanticReport } from './semantic.mjs';
import { redactEvidenceDocument, redactPromptText } from './redaction.mjs';

const limit = 8 * 1024 * 1024;
const same = (a, b) => canonicalJson(a) === canonicalJson(b);

// Reconstruct from encrypted ORIGINAL bytes, not supplied benign excerpts.
// A separate local export/Trivy rerun must establish the inventories' authority.
export function reconstructOciSemanticSources(descriptor, privateEvidence) {
  hashOciRuntimeDescriptor(descriptor);
  const { catalogue, inventory, sources, runtime } = privateEvidence ?? {};
  if (privateEvidence?.access !== 'ENCRYPTED_OPERATOR_EVIDENCE_ONLY' || inventory?.digest !== descriptor.rootfsDigest ||
    !same(catalogue?.platform, descriptor.platform) || !Array.isArray(sources) || sources.length > 50_000 ||
    !runtime || !Array.isArray(runtime.environment) || !same(runtime.argv, descriptor.argv) || runtime.workingDirectory !== descriptor.workingDirectory) throw Error('OCI_SEMANTIC_INVENTORY_REQUIRED');
  const checked = checkedOciConfig({ config: { Entrypoint: runtime.argv, WorkingDir: runtime.workingDirectory, Env: runtime.environment } });
  if (checked.environmentDigest !== descriptor.environmentDigest) throw Error('OCI_SEMANTIC_RUNTIME_MISMATCH');
  const before = new Map(catalogue.entries.map((entry) => [entry.path, entry]));
  const after = new Map(inventory.entries.map((entry) => [entry.path, entry]));
  const required = inventory.entries.filter((entry) => entry.type === 'File' && (!before.has(entry.path) || !same(before.get(entry.path), entry)));
  const requiredByPath = new Map(required.map((entry) => [entry.path, entry.digest]));
  if (required.length !== sources.length || new Set(sources.map(({ path }) => path)).size !== sources.length) throw Error('OCI_SEMANTIC_RAW_SOURCE_SET_MISMATCH');
  let bytes = 0;
  const decoded = sources.map(({ path, digest, contentBase64 }) => {
    if (requiredByPath.get(path) !== digest ||
      contentBase64 !== null && (typeof contentBase64 !== 'string' || contentBase64.length > Math.ceil(limit / 3) * 4)) throw Error('OCI_SEMANTIC_RAW_SOURCE_INVALID');
    const raw = contentBase64 === null ? null : Buffer.from(contentBase64, 'base64');
    if (raw && (raw.toString('base64') !== contentBase64 || ociHash(raw) !== digest || (bytes += raw.length) > limit)) throw Error('OCI_SEMANTIC_RAW_SOURCE_INVALID');
    return { path, digest, bytes: raw };
  });
  const classified = inspectOciCoverage({ ...inventory, reviewSources: decoded }, catalogue);
  const changes = [...new Set([...before.keys(), ...after.keys()])].sort().flatMap((path) => {
    const old = before.get(path) ?? null, current = after.get(path) ?? null;
    return same(old, current) ? [] : [{ path, before: old, after: current }];
  });
  const structure = { schemaVersion: 'mcpshield.oci-structure-review.v1', baseCatalogueDigest: catalogue.catalogueDigest,
    baseRootfsDigest: catalogue.rootfsDigest, imageRootfsDigest: inventory.digest,
    runtime: { ...runtime, entrypoint: descriptor.entrypoint, finalImageDigest: descriptor.finalImageDigest }, changes };
  const content = canonicalJson(structure);
  if (Buffer.byteLength(content) > limit) throw Error('OCI_STRUCTURE_REVIEW_BUDGET_EXCEEDED');
  // Prefix candidate paths: a file named like a synthetic metadata record cannot
  // shadow the tool list or structural evidence inside the semantic engine.
  const files = [{ path: 'oci/structure.json', rawDigest: ociHash(content), content },
    ...classified.files.map((file) => ({ ...file, path: 'oci/source/' + file.path }))];
  return { files, coverage: classified.coverage, classifications: classified.classifications, issues: classified.issues,
    structure, sourceBytes: bytes, semanticInputDigest: ociHash(canonicalJson(files)) };
}

// Schema-valid output alone is not coverage. Independently reconstruct every
// redacted character from original bytes and validate both role-specific prompts.
// This proves self-consistency; provider/collector authenticity requires local rerun.
export function verifyOciSemanticReview({ semantic, files, tools, releaseId }) {
  const incomplete = () => ({ semanticComplete: false, independentCriticComplete: false, semanticNoUnresolvedRisk: false });
  try {
    if (semantic.semanticProfile !== 'restricted-oci-offline-v1' || !same(semantic.disclosure, LOCAL_CONTRACT_DISCLOSURE) || !Array.isArray(semantic.reviews) ||
      !Number.isSafeInteger(semantic.expectedBatches) || semantic.expectedBatches < 1 || semantic.expectedBatches > 128 ||
      semantic.reviews.length !== semantic.expectedBatches || !Array.isArray(semantic.sources)) return incomplete();
    const originals = [{ path: 'MCP_TOOLS_COMPLETE.json', content: canonicalJson(redactEvidenceDocument(tools)) }, ...files];
    const expected = new Map(originals.map((file) => {
      const text = redactPromptText(file.content);
      return [file.path, { text, source: { path: file.path, rawDigest: file.rawDigest ?? ociHash(file.content), length: text.length, digest: ociHash(text) } }];
    }));
    if (expected.size !== originals.length || !same(semantic.sources, originals.map(({ path }) => expected.get(path).source))) return incomplete();
    const coverage = new Map();
    let analyzerComplete = true, criticComplete = true, clean = true;
    for (const [index, review] of semantic.reviews.entries()) {
      if (review.batchIndex !== index || !Array.isArray(review.input?.excerpts) || !review.input.excerpts.length || review.input.excerpts.length > 24 ||
        !same(review.input, { releaseId, tools: [], baselineTools: [], excerpts: review.input.excerpts }) || ociHash(canonicalJson(review.input)) !== review.inputDigest) return incomplete();
      for (const part of review.input.excerpts) {
        if (!same(part, { path: part.path, offset: part.offset, content: part.content }) || !expected.has(part.path) ||
          typeof part.content !== 'string' || part.content.length > 8000 || !Number.isSafeInteger(part.offset) || part.offset < 0) return incomplete();
        const old = coverage.get(part.path) ?? '';
        if (part.offset !== old.length || old.length + part.content.length > expected.get(part.path).text.length) return incomplete();
        coverage.set(part.path, old + part.content);
      }
      for (const role of ['analyzer', 'critic']) {
        const item = review[role];
        if (!item) { if (role === 'analyzer') analyzerComplete = false; else criticComplete = false; continue; }
        const prompt = preparedSemanticPrompt(review.input, role, 'restricted-oci-offline-v1');
        if (item.execution?.promptHash !== ociHash(prompt) || item.execution.tools !== 'NONE' || item.execution.schemaName !== `mcpshield_oci_${role}` ||
          item.execution.provider !== 'custom' || !same(item.execution.disclosure, LOCAL_CONTRACT_DISCLOSURE)) return incomplete();
        const report = validateSemanticReport(item.report, promptSources(prompt), citationCatalogue(review.input));
        if (report.needsHumanReview || report.riskClaims.length || Object.values(report.semanticDiff).some(Boolean)) clean = false;
      }
    }
    const complete = coverage.size === expected.size && [...expected].every(([path, { text }]) => coverage.get(path) === text);
    return { semanticComplete: complete && analyzerComplete, independentCriticComplete: complete && criticComplete,
      semanticNoUnresolvedRisk: complete && analyzerComplete && criticComplete && clean };
  } catch { return incomplete(); }
}
