import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, readdir, realpath, rm } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

export const SNAPSHOT_LIMITS = Object.freeze({ files: 1_024, bytes: 16 * 1024 * 1024 });
export const OCI_SOURCE_BUDGET_PROFILE = 'oci-100m-512m-v1';
const OCI_SOURCE_LIMITS = Object.freeze({ files: 50_000, bytes: 100 * 1024 * 1024 });
export const TRIVY_DATABASE_BUDGET_PROFILE = 'trivy-db-1g-v1';
const TRIVY_DATABASE_LIMITS = Object.freeze({ files: 2, bytes: 1024 * 1024 * 1024 });
export function snapshotLimits(profile = 'fixture-v1') {
  if (profile === 'fixture-v1') return SNAPSHOT_LIMITS;
  if (profile === OCI_SOURCE_BUDGET_PROFILE) return OCI_SOURCE_LIMITS;
  if (profile === TRIVY_DATABASE_BUDGET_PROFILE) return TRIVY_DATABASE_LIMITS;
  throw Error('ARTIFACT_BUDGET_PROFILE_UNSUPPORTED');
}

async function makeWritable(root) {
  let stat;
  try { stat = await lstat(root, { bigint: false }); } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    if (!stat.isSymbolicLink()) await chmod(root, 0o600);
    return;
  }
  await chmod(root, 0o700);
  for (const entry of await readdir(root)) await makeWritable(join(root, entry));
}

export async function removeFixtureSnapshot(snapshotRoot) {
  await makeWritable(snapshotRoot);
  await rm(snapshotRoot, { recursive: true, force: true });
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function stillSameFile(before, during, after) {
  return sameIdentity(before, during) && sameIdentity(during, after) &&
    before.size === during.size && during.size === after.size &&
    before.mtimeMs === during.mtimeMs && during.mtimeMs === after.mtimeMs &&
    before.ctimeMs === during.ctimeMs && during.ctimeMs === after.ctimeMs;
}

function metadata(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
  };
}

function sameMetadata(left, right) {
  return left && left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function entryKey(root, path, kind) {
  const nested = relative(root, path).split(sep).join('/') || '.';
  return `${kind}:${nested}`;
}

function assertWithin(root, candidate) {
  const nested = relative(root, candidate);
  if (!nested || isAbsolute(nested) || nested === '..' || nested.startsWith(`..${sep}`)) {
    throw new Error('snapshot path escapes scanner-owned directory');
  }
}

async function copyFileStable(source, target, state) {
  const before = await lstat(source, { bigint: false });
  if (before.isSymbolicLink()) throw new Error(`fixture symlinks are not allowed: ${relative(state.sourceRoot, source)}`);
  if (!before.isFile()) throw new Error(`unsupported fixture entry: ${relative(state.sourceRoot, source)}`);
  state.files += 1;
  if (state.files > state.limits.files) throw new Error(`fixture exceeds ${state.limits.files} files`);

  const noFollow = constants.O_NOFOLLOW ?? 0;
  let handle;
  try {
    handle = await open(source, constants.O_RDONLY | noFollow);
  } catch (error) {
    if (noFollow && ['EINVAL', 'ENOTSUP'].includes(error?.code)) handle = await open(source, constants.O_RDONLY);
    else throw error;
  }
  try {
    const during = await handle.stat();
    if (!during.isFile() || !sameIdentity(before, during)) throw new Error('fixture changed while snapshot was created');
    if (state.bytes + during.size > state.limits.bytes) throw new Error(`fixture exceeds ${state.limits.bytes} bytes`);
    // Read and copy with a fixed working buffer; a growing candidate cannot
    // turn readFile's allocation into an unbounded memory read.
    const output = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o400);
    let copied = 0;
    try {
      const buffer = Buffer.alloc(64 * 1024);
      while (true) {
        state.signal?.throwIfAborted();
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
        if (!bytesRead) break;
        copied += bytesRead; state.bytes += bytesRead;
        if (state.bytes > state.limits.bytes || copied > during.size) throw Error('fixture changed or exceeded its byte budget');
        await output.writeFile(buffer.subarray(0, bytesRead));
      }
    } finally { await output.close(); }
    const afterHandle = await handle.stat();
    const afterPath = await lstat(source, { bigint: false });
    if (copied !== during.size || afterPath.isSymbolicLink() || !stillSameFile(before, afterHandle, afterPath)) {
      throw new Error('fixture changed while snapshot was created');
    }
    state.entries.set(entryKey(state.sourceRoot, source, 'F'), metadata(afterPath));
  } finally {
    await handle.close();
  }
}

async function copyDirectoryStable(source, target, state) {
  state.signal?.throwIfAborted();
  if (++state.directoryCount + state.files > state.limits.files) throw Error('fixture exceeds its entry budget');
  const before = await lstat(source, { bigint: false });
  if (before.isSymbolicLink()) throw new Error(`fixture symlinks are not allowed: ${relative(state.sourceRoot, source)}`);
  if (!before.isDirectory()) throw new Error(`unsupported fixture entry: ${relative(state.sourceRoot, source)}`);
  await mkdir(target, { mode: 0o700 });
  const entries = await readdir(source, { withFileTypes: true });
  entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    if (state.directoryCount + state.files >= state.limits.files) throw Error('fixture exceeds its entry budget');
    const sourcePath = resolve(source, entry.name);
    const targetPath = resolve(target, entry.name);
    assertWithin(state.sourceRoot, sourcePath);
    assertWithin(state.snapshotRoot, targetPath);
    const entryStat = await lstat(sourcePath, { bigint: false });
    if (entryStat.isSymbolicLink()) throw new Error(`fixture symlinks are not allowed: ${relative(state.sourceRoot, sourcePath)}`);
    if (entryStat.isDirectory()) await copyDirectoryStable(sourcePath, targetPath, state);
    else if (entryStat.isFile()) await copyFileStable(sourcePath, targetPath, state);
    else throw new Error(`unsupported fixture entry: ${relative(state.sourceRoot, sourcePath)}`);
  }
  const after = await lstat(source, { bigint: false });
  if (after.isSymbolicLink() || !sameIdentity(before, after) || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
    throw new Error('fixture changed while snapshot was created');
  }
  state.entries.set(entryKey(state.sourceRoot, source, 'D'), metadata(after));
  await chmod(target, 0o500);
}

async function verifySourceTree(source, state, seen = new Set()) {
  state.signal?.throwIfAborted();
  const stat = await lstat(source, { bigint: false });
  if (stat.isSymbolicLink()) throw new Error('fixture changed while snapshot was verified');
  const kind = stat.isDirectory() ? 'D' : stat.isFile() ? 'F' : null;
  if (!kind) throw new Error('fixture contains an unsupported entry');
  const key = entryKey(state.sourceRoot, source, kind);
  if (!sameMetadata(state.entries.get(key), metadata(stat))) throw new Error('fixture changed while snapshot was created');
  seen.add(key);
  if (kind === 'D') {
    const entries = await readdir(source, { withFileTypes: true });
    entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      await verifySourceTree(resolve(source, entry.name), state, seen);
    }
  }
  if (source === state.sourceRoot && seen.size !== state.entries.size) {
    throw new Error('fixture file set changed while snapshot was created');
  }
}

export async function copyFixtureSnapshot(sourceDir, snapshotDir, { profile = 'fixture-v1', signal } = {}) {
  signal?.throwIfAborted();
  const sourceRoot = resolve(sourceDir);
  const snapshotRoot = resolve(snapshotDir);
  const rootStat = await lstat(sourceRoot, { bigint: false });
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new TypeError('fixture root must be a real directory');
  const canonicalRoot = await realpath(sourceRoot);
  if (resolve(canonicalRoot) !== sourceRoot) throw new TypeError('fixture root symlinks or aliases are not allowed');
  const state = { sourceRoot, snapshotRoot, files: 0, directoryCount: -1, bytes: 0, entries: new Map(), limits: snapshotLimits(profile), signal };
  try {
    await copyDirectoryStable(sourceRoot, snapshotRoot, state);
    await verifySourceTree(sourceRoot, state);
    signal?.throwIfAborted();
    return Object.freeze({ root: snapshotRoot, files: state.files, bytes: state.bytes });
  } catch (error) {
    await removeFixtureSnapshot(snapshotRoot);
    throw error;
  }
}
