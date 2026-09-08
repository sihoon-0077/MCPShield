import { createHash } from 'node:crypto';
import { chmod, lstat, readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

export const CLOSURE_LIMITS = Object.freeze({ files: 8192, bytes: 100 * 1024 * 1024, archiveBytes: 112 * 1024 * 1024 });
export const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
export function closurePath(path) {
  return typeof path === 'string' && path.length <= 1024 && path.split('/').every((part) => part && part !== '.' && part !== '..' &&
    !/[\\:\x00-\x1f\x7f]/.test(part) && !/[. ]$/.test(part) && !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part));
}
export function closureManifest(entries) {
  // Restore the versioned field order after canonical JSON evidence round trips.
  const sorted = entries.map((entry) => {
    if (!entry || Object.keys(entry).sort().join(',') !== 'digest,mode,path,type' || !closurePath(entry.path) ||
      !['File', 'Directory'].includes(entry.type) || ![0o444, 0o555].includes(entry.mode) ||
      (entry.type === 'Directory' ? entry.digest !== null || entry.mode !== 0o555 : !/^sha256:[a-f0-9]{64}$/.test(entry.digest))) throw Error('CLOSURE_MANIFEST_ENTRY_INVALID');
    return { path: entry.path, type: entry.type, mode: entry.mode, digest: entry.digest };
  }).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return { algorithm: 'sha256-path-type-mode-content-v2', entries: sorted,
    digest: sha256(`mcpshield-closure-v2\0${JSON.stringify(sorted)}`) };
}

// Called only by the trusted installer, never imports/executes files from the candidate tree.
export async function inspectClosure(root, normalizeModes = false) {
  const entries = [];
  let bytes = 0;
  const visit = async (parent, prefix = '') => {
    for (const name of (await readdir(parent)).sort()) {
      const path = prefix ? `${prefix}/${name}` : name;
      if (!closurePath(path)) throw Error('CLOSURE_PATH_INVALID');
      const full = join(parent, name);
      const stat = await lstat(full);
      if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory())) throw Error('CLOSURE_LINK_OR_SPECIAL_FILE');
      if (entries.length >= CLOSURE_LIMITS.files || (bytes += stat.isFile() ? stat.size : 0) > CLOSURE_LIMITS.bytes) throw Error('CLOSURE_SIZE_LIMIT');
      const mode = normalizeModes ? (stat.isDirectory() || (stat.mode & 0o111) ? 0o555 : 0o444) : stat.mode & 0o777;
      if (normalizeModes) await chmod(full, mode);
      entries.push({ path, type: stat.isDirectory() ? 'Directory' : 'File', mode,
        digest: stat.isFile() ? sha256(await readFile(full)) : null });
      if (stat.isDirectory()) await visit(full, path);
    }
  };
  await visit(root);
  if (normalizeModes) await chmod(root, 0o555);
  return { ...closureManifest(entries), bytes };
}
