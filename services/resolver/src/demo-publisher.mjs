import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import { canonicalJson } from '../../scanner/src/canonical-json.mjs';

const fixed = Object.freeze({ schemaVersion: 'mcpshield.demo-publisher-signature.v1', algorithm: 'Ed25519',
  purpose: 'DEMO_ONLY_NOT_NPM_PROVENANCE', digestKind: 'sha256-sorted-path-nul-content-nul-v1' });
const fields = ['publisherId', 'name', 'version', 'artifactDigest'];

function payload(identity) {
  if (!identity || Object.keys(identity).length !== fields.length || !fields.every((field) => Object.hasOwn(identity, field)) ||
    !fields.every((field) => typeof identity[field] === 'string' && identity[field].length <= 256) ||
    !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(identity.publisherId) ||
    !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(identity.name) ||
    !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(identity.version) ||
    !/^sha256:[a-f0-9]{64}$/.test(identity.artifactDigest)) throw Error('DEMO_PUBLISHER_IDENTITY_INVALID');
  return { ...fixed, ...identity };
}

// Ephemeral demo keys only. A signature authenticates these source bytes, not their behavior.
export function signDemoPublisherManifest(identity, privateKey) {
  if (privateKey?.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') throw Error('DEMO_PUBLISHER_KEY_INVALID');
  const document = payload(identity);
  return { payload: document, signature: sign(null, Buffer.from(canonicalJson(document)), privateKey).toString('base64') };
}

export function verifyDemoPublisherManifest({ manifest, expectedIdentity, pinnedPublicKey }) {
  const expected = payload(expectedIdentity);
  if (!manifest || Object.keys(manifest).length !== 2 || !Object.hasOwn(manifest, 'payload') || !Object.hasOwn(manifest, 'signature') ||
    typeof manifest.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(manifest.signature) ||
    Buffer.from(manifest.signature, 'base64').toString('base64') !== manifest.signature || !manifest.payload ||
    Object.keys(manifest.payload).length !== Object.keys(expected).length || Object.keys(expected).some((field) =>
      !Object.hasOwn(manifest.payload, field) || manifest.payload[field] !== expected[field])) throw Error('DEMO_PUBLISHER_SIGNATURE_OR_IDENTITY_INVALID');
  let key;
  try {
    if (typeof pinnedPublicKey !== 'string' || pinnedPublicKey.length > 4096 || !pinnedPublicKey.startsWith('-----BEGIN PUBLIC KEY-----')) throw Error();
    key = createPublicKey(pinnedPublicKey);
    if (key.asymmetricKeyType !== 'ed25519' || !verify(null, Buffer.from(canonicalJson(expected)), key, Buffer.from(manifest.signature, 'base64'))) throw Error();
  } catch { throw Error('DEMO_PUBLISHER_SIGNATURE_INVALID'); }
  return { type: 'DEMO_PUBLISHER_SIGNATURE_VALID', verified: true, ...expected,
    publicKeyFingerprint: `sha256:${createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex')}`,
    behaviorSafety: 'NOT_ASSESSED' };
}
