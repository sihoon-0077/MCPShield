import { readOciRuntimeCatalogue } from './oci-coverage.mjs';
import { readTrivyDatabaseIdentity } from './oci-trivy.mjs';
import { readOciObservationPolicy } from './oci-observer.mjs';
import { inspectImportedOciRuntime } from '../../resolver/src/oci-runtime.mjs';
import { hashOciRuntimeDescriptor } from '../../resolver/src/oci-runtime-descriptor.mjs';
import { runRuntimeDocker } from '../../resolver/src/npm-closure.mjs';

// This context is an in-process authority result, NEVER accepted from API/bundle.
// It proves local immutable bytes/settings; independent full replay still must
// authenticate Trivy, provider and observation effects before any signature.
export async function readTrustedOciRuntime({ descriptor, expectedDescriptorDigest, trust, timeoutMs = 120_000 }) {
  if (hashOciRuntimeDescriptor(descriptor) !== expectedDescriptorDigest || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000 ||
    ![trust?.baseImageDigest, trust?.trivyImageDigest, trust?.databaseDigest, trust?.sinkImageDigest].every((value) => /^sha256:[a-f0-9]{64}$/.test(value)))
    throw Error('OCI_LOCAL_TRUST_INPUT_INVALID');
  const deadline = Date.now() + timeoutMs, signal = AbortSignal.timeout(timeoutMs);
  const remaining = (cap = timeoutMs) => { signal.throwIfAborted(); if (Date.now() >= deadline) throw Error('OCI_LOCAL_TRUST_TIMEOUT'); return Math.min(cap, deadline - Date.now()); };
  const catalogue = await readOciRuntimeCatalogue({ baseImageDigest: trust.baseImageDigest, platform: descriptor.platform,
    expectedCatalogueDigest: trust.baseCatalogueDigest, timeoutMs: remaining(40_000) });
  const actual = await inspectImportedOciRuntime({ descriptor, expectedDescriptorDigest, timeoutMs: remaining(40_000) });
  for (const imageDigest of [...new Set([trust.trivyImageDigest, trust.sinkImageDigest])]) {
    const image = JSON.parse(await runRuntimeDocker(['image', 'inspect', imageDigest, '--format', '{{json .}}'], remaining(5000), 128 * 1024));
    if (image.Id !== imageDigest || image.Os !== descriptor.platform.os || image.Architecture !== descriptor.platform.architecture) throw Error('OCI_LOCAL_TOOL_IMAGE_MISMATCH');
  }
  const database = await readTrivyDatabaseIdentity({ databaseDir: trust.databaseDir, signal });
  if (database.databaseDigest !== trust.databaseDigest) throw Error('OCI_LOCAL_DATABASE_MISMATCH');
  const observationPolicy = await readOciObservationPolicy(trust.sinkImageDigest);
  remaining();
  return { anchors: { baseImageDigest: trust.baseImageDigest, baseCatalogueDigest: catalogue.catalogueDigest,
    trivyImageDigest: trust.trivyImageDigest, databaseDigest: database.databaseDigest,
    observerDigest: observationPolicy.collectorDigest, sinkImageDigest: trust.sinkImageDigest, sinkCodeDigest: observationPolicy.sinkCodeDigest },
    descriptorDigest: expectedDescriptorDigest, finalImageDigest: descriptor.finalImageDigest,
    rootfsDigest: actual.filesystem.digest, platform: descriptor.platform, observationPolicy,
    database: { updatedAt: database.updatedAt, nextUpdate: database.nextUpdate, maxAgeHours: database.maxAgeHours } };
}
