import { canonicalJson } from './evidence.mjs';
import { inspectOciCoverage, readOciRuntimeCatalogue } from './oci-coverage.mjs';
import { scanOciWithTrivy } from './oci-trivy.mjs';
import { inspectImportedOciRuntime } from '../../resolver/src/oci-runtime.mjs';
import { hashOciRuntimeDescriptor, ociHash } from '../../resolver/src/oci-runtime-descriptor.mjs';

const sha = /^sha256:[a-f0-9]{64}$/;
const pending = ['AI_AND_INDEPENDENT_CRITIC', 'RUNTIME_POLICY_APPROVAL', 'VALIDATOR_INDEPENDENT_REPLAY', 'GATEWAY_EXECUTION_BINDING'];

// Server/operator-local trust only. COMPLETE means this inventory/Trivy phase
// completed, never approval. This OCI policy does not reuse npm's PASS verdict.
export async function reviewOciImage({ descriptor, expectedDescriptorDigest, trust, timeoutMs = 180_000 }) {
  const started = Date.now();
  const common = { schemaVersion: 'mcpshield.oci-review.v1', approvalVerdict: 'ABSTAIN', ready: false,
    phase: 'INVENTORY_VULNERABILITY_AND_SBOM', candidateExecutionPerformed: false, pendingChecks: pending };
  let stage = 'INPUT';
  try {
    if (hashOciRuntimeDescriptor(descriptor) !== expectedDescriptorDigest) throw Error('OCI_RUNTIME_IDENTITY_MISMATCH');
    if (![trust?.baseImageDigest, trust?.trivyImageDigest, trust?.databaseDigest].every((value) => sha.test(value)) ||
      trust.baseCatalogueDigest !== undefined && !sha.test(trust.baseCatalogueDigest) ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 180_000) throw Error('OCI_REVIEW_TRUST_REQUIRED');
    if (process.platform !== 'linux') throw Error('OCI_LINUX_DOCKER_REQUIRED');
    const remaining = (cap = timeoutMs) => {
      const left = started + timeoutMs - Date.now();
      if (left < 1) throw Error('OCI_REVIEW_TOTAL_TIMEOUT');
      return Math.min(cap, left);
    };
    stage = 'BASE_CATALOGUE';
    const catalogue = await readOciRuntimeCatalogue({ baseImageDigest: trust.baseImageDigest, platform: descriptor.platform,
      expectedCatalogueDigest: trust.baseCatalogueDigest, timeoutMs: remaining(40_000) });
    stage = 'CANDIDATE_INVENTORY';
    const proof = await inspectImportedOciRuntime({ descriptor, expectedDescriptorDigest, trustedEntries: catalogue.entries,
      retainReviewSources: true, timeoutMs: remaining(40_000) });
    const classified = inspectOciCoverage(proof.filesystem, catalogue);
    stage = 'TRIVY';
    const { privateEvidence: trivyEvidence, ...vulnerability } = await scanOciWithTrivy({ imageDigest: descriptor.finalImageDigest,
      baseImageDigest: trust.baseImageDigest, platform: descriptor.platform, trust, timeoutMs: remaining() });
    remaining();
    const summary = { ...common,
      status: classified.coverage.sourceClassificationComplete && vulnerability.status === 'COMPLETE' ? 'COMPLETE' : 'INCONCLUSIVE',
      image: { descriptorDigest: expectedDescriptorDigest, finalImageDigest: descriptor.finalImageDigest, rootfsDigest: proof.filesystem.digest },
      runtimeCatalogue: { baseImageDigest: catalogue.baseImageDigest, catalogueDigest: catalogue.catalogueDigest,
        platform: catalogue.platform, source: catalogue.source },
      coverage: classified.coverage, vulnerability, issues: [...new Set([...classified.issues, ...vulnerability.issues])],
      durationMs: Date.now() - started };
    return { ...summary, reviewDigest: ociHash(canonicalJson(summary)),
      // INTERNAL ONLY. Strip this field before any public API/telemetry output.
      // Persist only in the existing encrypted operator-evidence boundary.
      privateEvidence: { access: 'ENCRYPTED_OPERATOR_EVIDENCE_ONLY', catalogue,
        runtime: { argv: proof.argv, workingDirectory: proof.workingDirectory, environment: proof.image.Config?.Env ?? [] },
        inventory: { digest: proof.filesystem.digest, entries: proof.filesystem.entries }, classifications: classified.classifications,
        sources: proof.filesystem.reviewSources.map(({ path, digest, bytes }) => ({ path, digest, contentBase64: bytes?.toString('base64') ?? null })),
        trivy: trivyEvidence } };
  } catch (error) {
    return { ...common, status: 'INCONCLUSIVE', issues: [Date.now() - started >= timeoutMs ? 'OCI_REVIEW_TOTAL_TIMEOUT' :
      /^OCI_[A-Z_]+$/.test(error.message) ? error.message : 'OCI_REVIEW_FAILED'], diagnostics: { stage }, privateEvidence: null };
  }
}
