import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

// Operator/validator configuration only: never construct these anchors from candidate metadata.
export function readTrustedPreparedIdentity(builderImageDigest) {
  if (!/^sha256:[a-f0-9]{64}$/.test(builderImageDigest)) throw Error('PREPARED_TRUSTED_BUILDER_REQUIRED');
  const digest = (path) => `sha256:${createHash('sha256').update(readFileSync(new URL(path, import.meta.url))).digest('hex')}`;
  return { builderImageDigest, collectorDigest: digest('./mcp-probe.cjs'), observerDigest: digest('./observer-preload.cjs') };
}
