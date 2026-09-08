import { createHash } from 'node:crypto';

// JCS-compatible for parsed JSON: sort UTF-16 keys, retain string bytes (no NFC rewrite).
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) throw new TypeError('canonical JSON requires finite numbers');
  const json = JSON.stringify(value);
  if (json === undefined) throw new TypeError('canonical JSON cannot contain undefined');
  return json;
}

const hash = (data) => createHash('sha256').update(data).digest('hex');
const leafHash = (path, digest) => hash(Buffer.concat([Buffer.from([0]), Buffer.from(path), Buffer.from([0]), Buffer.from(digest, 'hex')]));
const parentHash = (left, right) => hash(Buffer.concat([Buffer.from([1]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]));
const validPath = (path) => typeof path === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._/-]*$/.test(path) && !path.split('/').some((part) => ['', '.', '..'].includes(part));

export function createEvidenceBundle(documents) {
  const paths = Object.keys(documents).sort();
  if (!paths.length || paths.length > 128 || paths.some((path) => !validPath(path))) throw new TypeError('invalid evidence paths');
  const files = Object.fromEntries(paths.map((path) => [path, canonicalJson(documents[path])]));
  const leaves = paths.map((path) => ({ path, digest: `sha256:${hash(files[path])}`, proof: [] }));
  let nodes = leaves.map(({ path, digest }, index) => ({ hash: leafHash(path, digest.slice(7)), indices: [index] }));
  while (nodes.length > 1) {
    const next = [];
    for (let index = 0; index < nodes.length; index += 2) {
      const left = nodes[index];
      const right = nodes[index + 1] ?? left;
      for (const leaf of left.indices) leaves[leaf].proof.push({ side: 'right', hash: `0x${right.hash}` });
      if (right !== left) for (const leaf of right.indices) leaves[leaf].proof.push({ side: 'left', hash: `0x${left.hash}` });
      next.push({ hash: parentHash(left.hash, right.hash), indices: right === left ? left.indices : [...left.indices, ...right.indices] });
    }
    nodes = next;
  }
  return { files, manifest: { schemaVersion: '1.0.0', algorithm: 'sha256-path-merkle-v1', root: `0x${nodes[0].hash}`, leaves } };
}

export function verifyEvidenceLeaf({ path, content, digest, proof }, expectedRoot) {
  if (!validPath(path) || typeof content !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(digest) || !Array.isArray(proof) || proof.length > 8) return false;
  if (`sha256:${hash(content)}` !== digest) return false;
  let current = leafHash(path, digest.slice(7));
  for (const sibling of proof) {
    if (!['left', 'right'].includes(sibling.side) || !/^0x[a-f0-9]{64}$/.test(sibling.hash)) return false;
    current = sibling.side === 'left' ? parentHash(sibling.hash.slice(2), current) : parentHash(current, sibling.hash.slice(2));
  }
  return `0x${current}` === expectedRoot;
}

export function verifyEvidenceBundle(bundle, expectedRoot) {
  try {
    if (bundle.manifest.algorithm !== 'sha256-path-merkle-v1' || bundle.manifest.root !== expectedRoot) return false;
    const paths = Object.keys(bundle.files).sort();
    if (canonicalJson(paths) !== canonicalJson(bundle.manifest.leaves.map(({ path }) => path).sort())) return false;
    if (!bundle.manifest.leaves.every((leaf) => verifyEvidenceLeaf({ ...leaf, content: bundle.files[leaf.path] }, expectedRoot))) return false;
    return createEvidenceBundle(Object.fromEntries(paths.map((path) => [path, JSON.parse(bundle.files[path])]))).manifest.root === expectedRoot;
  } catch { return false; }
}
