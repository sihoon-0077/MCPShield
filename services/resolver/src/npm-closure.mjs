import { createHash, randomUUID } from 'node:crypto';
import { chmod, copyFile, mkdtemp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import * as tar from 'tar';
import { artifactDigest } from '../../scanner/src/scanner.mjs';
import { copyFixtureSnapshot, removeFixtureSnapshot } from '../../scanner/src/snapshot.mjs';
import { downloadRegistryUrl, extractNpmArchive, validateIntegrity, RESOLVER_LIMITS } from './resolver.mjs';
import { preflightNpmRuntime, hashPreparedRuntimeDescriptor } from './runtime-preflight.mjs';
import { CLOSURE_LIMITS, closurePath, closureManifest, sha256 } from './closure-files.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const errorCode = (error) => /^(?:RUNTIME|CLOSURE|ARTIFACT|OFFLINE)_[A-Z_]+$/.test(error?.message) ? error.message : 'RUNTIME_PREPARATION_FAILED';

async function readableInput(root) {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) await readableInput(path);
    else if (entry.isFile()) await chmod(path, 0o444);
    else throw Error('RUNTIME_INPUT_LINK_INVALID');
  }
  await chmod(root, 0o555);
}

// The injectable downloader is for trusted offline tests/operators, not a public URL-fetch API.
export async function acquireNpmClosure(options, { download = downloadRegistryUrl, timeoutMs = 60_000 } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw Error('RUNTIME_ACQUISITION_BUDGET_INVALID');
  const preflight = await preflightNpmRuntime(options);
  if (preflight.issues.length) return { ...preflight, acquisitionPerformed: false };
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-closure-input-'));
  const input = join(workspace, 'input');
  const artifact = join(input, 'artifact');
  const archives = join(input, 'archives');
  const controller = new AbortController();
  let rejectDeadline;
  const expired = new Promise((_, reject) => { rejectDeadline = reject; });
  const timer = setTimeout(() => { controller.abort(); rejectDeadline(Error('RUNTIME_ACQUISITION_TIMEOUT')); }, timeoutMs);
  // Keep a rejection listener attached even between awaited downloads.
  expired.catch(() => {});
  try {
    await mkdir(input);
    await mkdir(archives);
    const snapshot = await copyFixtureSnapshot(options.root, artifact);
    if (await artifactDigest(artifact) !== options.sourceTreeDigest) throw Error('RUNTIME_SOURCE_DIGEST_MISMATCH');
    // The original source snapshot is verified before adding the separately
    // committed resolver-generated lock. Never modify the caller's source tree.
    if (options.generatedLock !== undefined) {
      if (!Buffer.isBuffer(options.generatedLock) || sha256(options.generatedLock) !== preflight.descriptor.lockDigest) throw Error('RUNTIME_LOCK_DIGEST_MISMATCH');
      // Snapshot directories are owner-read/execute only. Open only this
      // task-owned copy for one exclusive write, then restore its closed mode.
      try {
        await chmod(artifact, 0o700);
        await writeFile(join(artifact, 'package-lock.json'), options.generatedLock, { flag: 'wx', mode: 0o444 });
      } catch { throw Error('RUNTIME_GENERATED_LOCK_WRITE_FAILED'); }
      finally { await chmod(artifact, 0o500); }
    }
    let lockBytes;
    let lockFile = 'npm-shrinkwrap.json';
    try { lockBytes = await readFile(join(artifact, lockFile)); }
    catch (error) { if (error.code !== 'ENOENT') throw error; lockFile = 'package-lock.json'; lockBytes = await readFile(join(artifact, lockFile)); }
    if (sha256(lockBytes) !== preflight.descriptor.lockDigest) throw Error('RUNTIME_LOCK_DIGEST_MISMATCH');
    const entries = Object.entries(JSON.parse(lockBytes).packages).filter(([path]) => path !== '');
    const evidence = [];
    const seen = new Map();
    let totalBytes = 0;
    let expandedBytes = snapshot.bytes;
    let expandedFiles = snapshot.files;
    for (const [path, entry] of entries) {
      if (controller.signal.aborted) throw Error('RUNTIME_ACQUISITION_TIMEOUT');
      const key = `${entry.resolved}\n${entry.integrity}`;
      let downloaded = seen.get(key);
      if (!downloaded) {
        const bytes = await Promise.race([download(entry.resolved, Math.min(RESOLVER_LIMITS.downloadBytes,
          CLOSURE_LIMITS.bytes - totalBytes), { signal: controller.signal }), expired]);
        if (!Buffer.isBuffer(bytes) || (totalBytes += bytes.length) > CLOSURE_LIMITS.bytes) throw Error('RUNTIME_ACQUISITION_SIZE_LIMIT');
        validateIntegrity(bytes, entry.integrity);
        const archiveDigest = sha256(bytes);
        const quarantined = join(workspace, `package-${seen.size}`);
        // Reuse full-tar path/link/checksum validation before npm sees any package bytes.
        const unpacked = await extractNpmArchive(bytes, quarantined, entry.integrity);
        const pkg = JSON.parse(await readFile(join(quarantined, 'package.json')));
        downloaded = { archiveDigest, name: pkg.name, version: pkg.version, sizeBytes: bytes.length,
          expandedBytes: unpacked.expandedBytes, files: unpacked.files };
        await writeFile(join(archives, `${archiveDigest.slice(7)}.tgz`), bytes, { flag: 'wx', mode: 0o400 }).catch((error) => {
          if (error.code !== 'EEXIST') throw error;
        });
        await removeFixtureSnapshot(quarantined);
        seen.set(key, downloaded);
      }
      const name = path.split('/node_modules/').at(-1).replace(/^node_modules\//, '');
      if (downloaded.name !== name || downloaded.version !== entry.version) throw Error('RUNTIME_DEPENDENCY_IDENTITY_MISMATCH');
      // Count repeated lock locations too: one cached tar can be installed at many nested paths.
      expandedBytes += downloaded.expandedBytes;
      expandedFiles += downloaded.files;
      if (expandedBytes > CLOSURE_LIMITS.bytes || expandedFiles > CLOSURE_LIMITS.files) throw Error('RUNTIME_ACQUISITION_EXPANDED_LIMIT');
      evidence.push({ path, name, version: entry.version, integrity: entry.integrity, ...downloaded });
    }
    if (controller.signal.aborted) throw Error('RUNTIME_ACQUISITION_TIMEOUT');
    await writeFile(join(input, 'preparation.json'), JSON.stringify({ lockFile, sourceDescriptorDigest: preflight.descriptorDigest }));
    await readableInput(input);
    if (controller.signal.aborted) throw Error('RUNTIME_ACQUISITION_TIMEOUT');
    return { ...preflight, acquisitionPerformed: true, acquisition: { archives: evidence, uniqueArchives: seen.size,
      sizeBytes: totalBytes, expandedBytes, expandedFiles, integrityVerified: true }, inputDir: input, cleanup: () => removeFixtureSnapshot(workspace) };
  } catch (error) {
    await removeFixtureSnapshot(workspace);
    return { ...preflight, acquisitionPerformed: false, issues: [errorCode(error)] };
  } finally { clearTimeout(timer); controller.abort(); }
}

export function inspectClosureArchive(bytes, { includeContents = false } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length > CLOSURE_LIMITS.archiveBytes || bytes.length < 1024 ||
    bytes.length % 512 || !new tar.Header(bytes).cksumValid) throw Error('CLOSURE_ARCHIVE_INVALID');
  const entries = [];
  const contents = [];
  const seen = new Set();
  let totalBytes = 0;
  const listing = tar.t({ sync: true, strict: true, onReadEntry(entry) {
    const path = entry.path.replace(/^\.\//, '').replace(/\/$/, '');
    if (['.', './'].includes(entry.path) && entry.type === 'Directory' && entry.mode === 0o555 && !entry.linkpath && entry.size === 0) return;
    if (!closurePath(path) || entry.linkpath || !['File', 'Directory'].includes(entry.type) ||
      ![0o444, 0o555].includes(entry.mode) || (entry.type === 'Directory' && entry.mode !== 0o555)) throw Error('CLOSURE_ARCHIVE_ENTRY_INVALID');
    const alias = path.normalize('NFC').toLowerCase();
    if (seen.has(alias)) throw Error('CLOSURE_ARCHIVE_DUPLICATE');
    seen.add(alias);
    if (seen.size > CLOSURE_LIMITS.files || !Number.isSafeInteger(entry.size) || entry.size < 0 ||
      (totalBytes += entry.size) > CLOSURE_LIMITS.bytes) throw Error('CLOSURE_SIZE_LIMIT');
    const item = { path, type: entry.type, mode: entry.mode, digest: null };
    entries.push(item);
    if (entry.type === 'File') {
      const hash = createHash('sha256');
      const chunks = [];
      entry.on('data', (chunk) => { hash.update(chunk); if (includeContents) chunks.push(chunk); });
      entry.on('end', () => {
        item.digest = `sha256:${hash.digest('hex')}`;
        if (includeContents) contents.push({ path, bytes: Buffer.concat(chunks) });
      });
    }
  } });
  listing.end(bytes);
  if (!entries.length || entries.some((entry) => entry.type === 'File' && !digestPattern.test(entry.digest))) throw Error('CLOSURE_ARCHIVE_INCOMPLETE');
  return { ...closureManifest(entries), bytes: totalBytes, ...(includeContents ? { contents } : {}) };
}

function closureReport(bytes) {
  const reports = [];
  const listing = tar.t({ sync: true, strict: true, onReadEntry(entry) {
    if (entry.type !== 'File' || entry.linkpath || !['closure-report.json', 'mcpshield-closure-report.json'].includes(entry.path) ||
      entry.size > 2 * 1024 * 1024) throw Error('CLOSURE_REPORT_INVALID');
    const chunks = []; entry.on('data', (chunk) => chunks.push(chunk)); entry.on('end', () => reports.push(Buffer.concat(chunks)));
  } });
  listing.end(bytes);
  if (reports.length !== 1) throw Error('CLOSURE_REPORT_INVALID');
  return { bytes: reports[0], value: JSON.parse(reports[0]) };
}

export function runRuntimeDocker(args, timeoutMs, maxBytes = 128 * 1024) {
  return new Promise((resolveResult, reject) => {
    const child = spawn('docker', args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks = [];
    let total = 0;
    let failure;
    let diagnostics = '';
    const timer = setTimeout(() => { failure = Error('RUNTIME_DOCKER_TIMEOUT'); child.kill('SIGKILL'); }, Math.max(1, timeoutMs));
    child.stdout.on('data', (chunk) => { total += chunk.length; if (total > maxBytes) { failure = Error('RUNTIME_DOCKER_OUTPUT_LIMIT'); child.kill('SIGKILL'); } else chunks.push(chunk); });
    // Drain but never surface candidate/daemon stderr, which may contain private paths or metadata.
    child.stderr.on('data', (chunk) => {
      // Only a small trusted installer's constant vocabulary can leave this helper.
      if (diagnostics.length < 2048) diagnostics += chunk.toString('utf8').slice(0, 2048 - diagnostics.length);
    });
    child.once('error', () => { clearTimeout(timer); reject(Error('RUNTIME_DOCKER_UNAVAILABLE')); });
    child.once('close', (code) => { clearTimeout(timer);
      const safeCode = /(?:^|\n)MCPSHIELD_CLOSURE_FAILURE:(TOOLCHAIN|INPUT|CACHE|INSTALL|MANIFEST):(ENOTCACHED|EUSAGE|EINTEGRITY|ENOENT|EACCES|EPERM|NPM_FAILED|FAILED)(?:\r?\n|$)/.exec(diagnostics);
      const lockCode = /(?:^|\n)MCPSHIELD_LOCK_FAILURE:(TOOLCHAIN|INPUT|SOLVE|VERIFY):(E401|E403|E404|EUSAGE|ERESOLVE|ENOTFOUND|ETIMEDOUT|ECONNREFUSED|EAI_AGAIN|ENETUNREACH|EINTEGRITY|EACCES|EPERM|EBADENGINE|EUNSUPPORTEDPROTOCOL|EINVALIDPACKAGENAME|EINVALIDTAGNAME|EJSONPARSE|NPM_FAILED|FAILED)(?:\r?\n|$)/.exec(diagnostics);
      if (failure || code !== 0) reject(failure ?? Error(safeCode ? `RUNTIME_${safeCode[1]}_${safeCode[2]}` : lockCode ? `RUNTIME_LOCK_${lockCode[1]}_${lockCode[2]}` : 'RUNTIME_DOCKER_COMMAND_FAILED'));
      else resolveResult(Buffer.concat(chunks)); });
  });
}
const docker = runRuntimeDocker;

// Export filesystem bytes through a never-started container; no candidate is imported
// or extracted to executable host paths. The complete node_modules tree is included.
export async function readPreparedClosure({ descriptor, expectedDescriptorDigest }) {
  if (hashPreparedRuntimeDescriptor(descriptor) !== expectedDescriptorDigest || descriptor.stage !== 'CLOSURE_PREPARED') throw Error('RUNTIME_DESCRIPTOR_IDENTITY_INVALID');
  if (process.platform !== 'linux') throw Error('RUNTIME_LINUX_DOCKER_REQUIRED');
  const container = `mcpshield-review-${randomUUID()}`;
  const deadline = Date.now() + 30_000;
  const run = (args, size) => docker(args, Math.max(1, deadline - Date.now()), size);
  try {
    const info = JSON.parse(await run(['image', 'inspect', descriptor.finalImageDigest, '--format', '{{json .}}']));
    if (info.Id !== descriptor.finalImageDigest || info.Os !== descriptor.platform.os || info.Architecture !== descriptor.platform.architecture) throw Error('RUNTIME_IMAGE_IDENTITY_MISMATCH');
    await run(['create', '--pull=never', '--name', container, '--network=none', '--read-only', '--user=1000:1000',
      '--cap-drop=ALL', '--security-opt=no-new-privileges', '--entrypoint=/usr/local/bin/node', descriptor.finalImageDigest, '--version']);
    const { value: report } = closureReport(await run(['cp', `${container}:/mcpshield-closure-report.json`, '-'], 4 * 1024 * 1024));
    const closure = inspectClosureArchive(await run(['cp', `${container}:/app/.`, '-'], CLOSURE_LIMITS.archiveBytes), { includeContents: true });
    const original = { ...descriptor, stage: 'PREFLIGHT', finalImageDigest: null, toolSurfaceHash: null };
    if (report.digest !== closure.digest || report.sourceDescriptorDigest !== hashPreparedRuntimeDescriptor(original) ||
      report.installScripts !== false || report.installNetwork !== 'NONE' || report.npmVersion !== '12.0.2' ||
      report.toolchainPatches !== 'brace-expansion@5.0.9,ip-address@10.3.1,tar@7.5.22' ||
      closure.entries.find(({ path }) => path === descriptor.entrypoint.path)?.digest !== descriptor.entrypoint.digest) throw Error('CLOSURE_REPORT_MISMATCH');
    return { ...closure, report, source: 'LIVE_DOCKER_IMAGE_EXPORT', candidateExecutionPerformed: false };
  } finally { try { await docker(['rm', '-f', container], 5000); } catch { /* exact task-owned unstarted container */ } }
}

export async function prepareNpmClosure(options, acquisitionOptions) {
  if (!digestPattern.test(options.builderImageDigest ?? '')) return { status: 'INCONCLUSIVE', ready: false, phase: 'NOT_RUN', issues: ['RUNTIME_BUILDER_DIGEST_REQUIRED'] };
  if (process.platform !== 'linux') return { status: 'INCONCLUSIVE', ready: false, phase: 'NOT_RUN', issues: ['RUNTIME_LINUX_DOCKER_REQUIRED'] };
  const acquired = await acquireNpmClosure(options, acquisitionOptions);
  if (!acquired.acquisitionPerformed) return { ...acquired, phase: 'NOT_RUN' };
  const suffix = randomUUID();
  const container = `mcpshield-prepare-${suffix}`;
  const volume = `mcpshield-closure-${suffix}`;
  const builderTag = `mcpshield-builder-${suffix}:local`;
  const runtimeTag = `mcpshield-runtime-${suffix}:local`;
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-closure-image-'));
  const deadline = Date.now() + 180_000;
  const run = (args, maxBytes) => {
    if (Date.now() >= deadline) throw Error('RUNTIME_DOCKER_TIMEOUT');
    return docker(args, deadline - Date.now(), maxBytes);
  };
  let success = false;
  let stage = 'BUILDER_INSPECT';
  try {
    const info = JSON.parse(await run(['image', 'inspect', options.builderImageDigest, '--format', '{{json .}}']));
    if (info.Id !== options.builderImageDigest || info.Os !== 'linux' || info.Architecture !== options.platform.architecture ||
      info.Config?.Labels?.['io.mcpshield.runtime-builder'] !== 'node-closure-v1' || info.Config?.Labels?.['io.mcpshield.npm-version'] !== '12.0.2' ||
      info.Config?.Labels?.['io.mcpshield.npm-patches'] !== 'brace-expansion@5.0.9,ip-address@10.3.1,tar@7.5.22' ||
      JSON.stringify(info.Config?.Entrypoint) !== JSON.stringify(['/usr/local/bin/node', '/trusted/prepare-container.mjs'])) throw Error('RUNTIME_BUILDER_IDENTITY_MISMATCH');
    stage = 'VOLUME_CREATE';
    await run(['volume', 'create', volume]);
    stage = 'INSTALL_RUN';
    const output = await run(['run', '--pull=never', '--name', container, '--network=none', '--read-only', '--user=1000:1000',
      '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=512m', '--cpus=1', '--pids-limit=64',
      '--tmpfs=/tmp:rw,noexec,nosuid,size=32m', '--mount', `type=bind,source=${acquired.inputDir},target=/input,readonly`,
      '--mount', `type=volume,source=${volume},target=/work`, options.builderImageDigest]);
    if (output.toString('utf8').trim() !== 'MCPSHIELD_CLOSURE_PREPARED') throw Error('RUNTIME_INSTALLATION_FAILED');
    stage = 'REPORT_EXPORT';
    const reportBytes = await run(['cp', `${container}:/work/closure-report.json`, '-'], 4 * 1024 * 1024);
    const { bytes: rawReport, value: report } = closureReport(reportBytes);
    stage = 'CLOSURE_EXPORT';
    const archive = await run(['cp', `${container}:/work/app/.`, '-'], CLOSURE_LIMITS.archiveBytes);
    const verified = inspectClosureArchive(archive);
    if (report.digest !== verified.digest || report.sourceDescriptorDigest !== acquired.descriptorDigest ||
      report.installScripts !== false || report.installNetwork !== 'NONE' || report.npmVersion !== '12.0.2' ||
      report.toolchainPatches !== 'brace-expansion@5.0.9,ip-address@10.3.1,tar@7.5.22' ||
      verified.entries.find((entry) => entry.path === acquired.descriptor.entrypoint.path)?.digest !== acquired.descriptor.entrypoint.digest) throw Error('CLOSURE_REPORT_MISMATCH');
    await writeFile(join(workspace, 'closure.tar'), archive);
    await writeFile(join(workspace, 'closure-report.json'), rawReport);
    await copyFile(resolve(HERE, '../Dockerfile.runtime'), join(workspace, 'Dockerfile'));
    stage = 'IMAGE_TAG';
    await run(['image', 'tag', options.builderImageDigest, builderTag]);
    stage = 'IMAGE_BUILD';
    await run(['build', '--pull=false', '--network=none', '--quiet', '--build-arg', `BUILDER_IMAGE=${builderTag}`, '--tag', runtimeTag, workspace]);
    stage = 'FINAL_INSPECT';
    const finalImageDigest = (await run(['image', 'inspect', runtimeTag, '--format', '{{.Id}}'])).toString('utf8').trim();
    if (!digestPattern.test(finalImageDigest)) throw Error('RUNTIME_FINAL_IMAGE_DIGEST_INVALID');
    const descriptor = { ...acquired.descriptor, stage: 'CLOSURE_PREPARED', finalImageDigest };
    success = true;
    return { status: 'INCONCLUSIVE', ready: false, phase: 'CLOSURE_PREPARED', candidateExecutionPerformed: false,
      descriptor, descriptorDigest: hashPreparedRuntimeDescriptor(descriptor), acquisition: acquired.acquisition,
      closure: { digest: verified.digest, files: verified.entries.length, bytes: verified.bytes, reportDigest: sha256(rawReport) },
      imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID', runtimeTag, issues: [],
      pending: ['ACTUAL_MCP_DISCOVERY', 'RUNTIME_OBSERVATION', 'GATEWAY_RELEASE_IDENTITY_BINDING'],
      cleanup: () => docker(['image', 'rm', runtimeTag], 5000) };
  } catch (error) {
    return { status: 'INCONCLUSIVE', ready: false, phase: 'FAILED', candidateExecutionPerformed: false,
      issues: [errorCode(error)], diagnostics: { stage } };
  } finally {
    for (const args of [['rm', '-f', container], ['volume', 'rm', volume], ['image', 'rm', builderTag], ...(!success ? [['image', 'rm', runtimeTag]] : [])]) {
      try { await docker(args, 5000); } catch { /* exact task-owned resource, best effort cleanup */ }
    }
    await acquired.cleanup();
    await removeFixtureSnapshot(workspace);
  }
}
