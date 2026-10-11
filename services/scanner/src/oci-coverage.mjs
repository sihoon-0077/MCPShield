import { canonicalJson } from './evidence.mjs';
import { exportOciFilesystem } from '../../resolver/src/oci-runtime.mjs';
import { ociHash, ociAbsolutePath } from '../../resolver/src/oci-runtime-descriptor.mjs';
import { validateRuntimePlatform } from '../../resolver/src/runtime-descriptor.mjs';

const sha = /^sha256:[a-f0-9]{64}$/;
const exact = (entry) => canonicalJson(entry);

function checkedInventory(filesystem) {
  const entries = filesystem?.entries;
  if (!Array.isArray(entries) || !entries.length || entries.length > 50_000 || ociHash(canonicalJson(entries)) !== filesystem.digest ||
    new Set(entries.map((entry) => entry.path)).size !== entries.length || entries.some((entry) =>
      !ociAbsolutePath('/' + entry.path) || !['File', 'Directory', 'SymbolicLink', 'Link', 'CharacterDevice', 'BlockDevice', 'FIFO'].includes(entry.type) ||
      ![entry.mode, entry.uid, entry.gid].every((value) => Number.isSafeInteger(value) && value >= 0) || entry.mode > 0o7777 ||
      (entry.type === 'File' ? !sha.test(entry.digest) : entry.digest !== null) ||
      (['Link', 'SymbolicLink'].includes(entry.type) ? typeof entry.link !== 'string' : entry.link !== null))) throw Error('OCI_COVERAGE_INVENTORY_INVALID');
}

export function createOciRuntimeCatalogue({ baseImageDigest, platform, filesystem }) {
  if (!sha.test(baseImageDigest)) throw Error('OCI_BASE_CATALOGUE_INVALID');
  checkedInventory(filesystem);
  validateRuntimePlatform(platform);
  const body = { schemaVersion: 'mcpshield.oci-runtime-catalogue.v1', baseImageDigest, platform,
    rootfsDigest: filesystem.digest, entries: filesystem.entries,
    matchRule: 'EXACT_PATH_TYPE_MODE_UID_GID_LINK_CONTENT', semanticClaim: 'TRUSTED_BASE_PROVENANCE_NOT_BINARY_SAFETY_PROOF' };
  return { ...body, catalogueDigest: ociHash(canonicalJson(body)) };
}

export async function readOciRuntimeCatalogue({ baseImageDigest, platform, expectedCatalogueDigest, timeoutMs }) {
  const { filesystem } = await exportOciFilesystem({ imageDigest: baseImageDigest, platform, timeoutMs });
  const catalogue = createOciRuntimeCatalogue({ baseImageDigest, platform, filesystem });
  if (expectedCatalogueDigest !== undefined && catalogue.catalogueDigest !== expectedCatalogueDigest) throw Error('OCI_BASE_CATALOGUE_MISMATCH');
  return { ...catalogue, source: 'LIVE_DOCKER_EXPORT' };
}

// Pure classification only. A validator must obtain the base catalogue from its
// own approved image; a scanner-supplied catalogue is not a trust authority.
export function inspectOciCoverage(filesystem, catalogue) {
  checkedInventory(filesystem);
  const expected = createOciRuntimeCatalogue({ baseImageDigest: catalogue?.baseImageDigest, platform: catalogue?.platform,
    filesystem: { entries: catalogue?.entries, digest: catalogue?.rootfsDigest } });
  if (expected.catalogueDigest !== catalogue.catalogueDigest || ociHash(canonicalJson(filesystem.entries)) !== filesystem.digest) throw Error('OCI_COVERAGE_INVENTORY_MISMATCH');
  const base = new Map(catalogue.entries.map((entry) => [entry.path, exact(entry)]));
  const sources = new Map((filesystem.reviewSources ?? []).map((source) => [source.path, source]));
  if (sources.size !== (filesystem.reviewSources ?? []).length) throw Error('OCI_REVIEW_SOURCE_DUPLICATE');
  const files = [], classifications = [], issues = new Set();
  const unsupportedGroups = new Map();
  let otherUnsupportedEntries = 0;
  let trustedRuntimeFiles = 0, unknownBinaryFiles = 0, unsupportedEntries = 0, omittedSourceFiles = 0;
  for (const entry of filesystem.entries) {
    const baseMatch = base.get(entry.path) === exact(entry);
    if (!['File', 'Directory', 'SymbolicLink', 'Link'].includes(entry.type) || entry.mode & 0o6000 || entry.type !== 'File' && !baseMatch) {
      unsupportedEntries++; issues.add('OCI_UNSUPPORTED_FILESYSTEM_ENTRY');
      const group = { type: entry.type, mode: entry.mode, baseMatch, reason: !['File', 'Directory', 'SymbolicLink', 'Link'].includes(entry.type)
        ? 'SPECIAL_ENTRY' : entry.mode & 0o6000 ? 'SET_ID_BITS' : 'BASE_STRUCTURE_CHANGED' };
      const key = canonicalJson(group), current = unsupportedGroups.get(key);
      if (current) current.count++;
      else if (unsupportedGroups.size < 64) unsupportedGroups.set(key, { ...group, count: 1 });
      else otherUnsupportedEntries++;
      classifications.push({ path: entry.path, kind: 'UNREVIEWED_FILESYSTEM_STRUCTURE_OR_PRIVILEGE', type: entry.type });
    }
    if (entry.type !== 'File') continue;
    if (baseMatch) {
      trustedRuntimeFiles++; classifications.push({ path: entry.path, digest: entry.digest, kind: 'TRUSTED_BASE_EXACT_MATCH' }); continue;
    }
    const source = sources.get(entry.path);
    if (!source?.bytes) {
      omittedSourceFiles++; issues.add('OCI_SOURCE_REVIEW_BUDGET_OR_BYTES_MISSING');
      classifications.push({ path: entry.path, digest: entry.digest, kind: 'NOT_REVIEWED' }); continue;
    }
    if (!Buffer.isBuffer(source.bytes) || source.digest !== entry.digest || ociHash(source.bytes) !== entry.digest) throw Error('OCI_REVIEW_SOURCE_HASH_MISMATCH');
    let content;
    try {
      content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(source.bytes);
      if (content.includes('\0') || /\.(?:node|pyc|pyo|wasm|jar|class|dll|so|dylib|exe)$/i.test(entry.path)) throw Error();
    } catch {
      unknownBinaryFiles++; issues.add('OCI_UNKNOWN_BINARY_REQUIRES_REVIEW');
      classifications.push({ path: entry.path, digest: entry.digest, kind: 'UNKNOWN_BINARY' }); continue;
    }
    files.push({ path: entry.path, rawDigest: entry.digest, content });
    classifications.push({ path: entry.path, digest: entry.digest, kind: 'TEXT_REQUIRES_AI_AND_CRITIC' });
  }
  return { coverage: { inventoryComplete: true, trustedRuntimeFiles, reviewableTextFiles: files.length,
    unknownBinaryFiles, unsupportedEntries, omittedSourceFiles, sourceClassificationComplete: !unknownBinaryFiles && !unsupportedEntries && !omittedSourceFiles,
    filesystemObservation: 'STATIC_IMAGE_INVENTORY_NOT_SYSCALL_TRACE', binaryReview: 'EXACT_APPROVED_BASE_PROVENANCE_ONLY', semanticReview: 'NOT_RUN' },
    // Fixed enum/type/mode/count groups only: never include paths or source in diagnostics.
    diagnostics: { unsupportedGroups: [...unsupportedGroups.values()], otherUnsupportedEntries },
    issues: [...issues], files, classifications };
}
