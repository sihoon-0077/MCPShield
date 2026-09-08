import { randomBytes, randomUUID } from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isIP } from 'node:net';
import * as tar from 'tar';
import { preflightNpmRuntime } from './runtime-preflight.mjs';
import { runRuntimeDocker } from './npm-closure.mjs';
import { sha256 } from './closure-files.mjs';
import { artifactDigest } from '../../scanner/src/scanner.mjs';
import { copyFixtureSnapshot, removeFixtureSnapshot } from '../../scanner/src/snapshot.mjs';

function archiveFile(bytes, name, maxBytes) {
  const files = [];
  const listing = tar.t({ sync: true, strict: true, onReadEntry(entry) {
    if (entry.path !== name || entry.type !== 'File' || entry.linkpath || entry.size > maxBytes) throw Error('RUNTIME_LOCK_EXPORT_INVALID');
    const chunks = []; entry.on('data', (chunk) => chunks.push(chunk)); entry.on('end', () => files.push(Buffer.concat(chunks)));
  } });
  listing.end(bytes);
  if (files.length !== 1) throw Error('RUNTIME_LOCK_EXPORT_INVALID');
  return files[0];
}

// metadataFixture is a trusted offline regression input, not a public API option.
export async function generateNpmLock(options, { metadataFixture } = {}) {
  if (options.generatedLock !== undefined) throw Error('RUNTIME_LOCK_ALREADY_GENERATED');
  const preflight = await preflightNpmRuntime(options);
  if (preflight.issues.length !== 1 || preflight.issues[0] !== 'RUNTIME_LOCK_REQUIRED') return { ...preflight, phase: 'NOT_RUN', lockGenerated: false };
  if (process.platform !== 'linux') return { ...preflight, phase: 'NOT_RUN', lockGenerated: false, issues: ['RUNTIME_LINUX_DOCKER_REQUIRED'] };
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-lock-'));
  const snapshot = join(workspace, 'source');
  const input = join(workspace, 'input');
  const suffix = randomUUID();
  const network = `mcpshield-registry-${suffix}`, broker = `mcpshield-broker-${suffix}`;
  const solver = `mcpshield-lock-${suffix}`, volume = `mcpshield-lock-work-${suffix}`;
  const token = randomBytes(24).toString('hex');
  const deadline = Date.now() + 120_000;
  const run = (args, maxBytes) => {
    if (Date.now() >= deadline) throw Error('RUNTIME_LOCK_TIMEOUT');
    return runRuntimeDocker(args, Math.max(1, deadline - Date.now()), maxBytes);
  };
  let stage = 'INPUT';
  try {
    await copyFixtureSnapshot(options.root, snapshot);
    if (await artifactDigest(snapshot) !== options.sourceTreeDigest) throw Error('RUNTIME_SOURCE_DIGEST_MISMATCH');
    const pkg = await readFile(join(snapshot, 'package.json'));
    if (pkg.length > 1024 * 1024) throw Error('RUNTIME_PACKAGE_SIZE_LIMIT');
    await mkdir(input);
    await writeFile(join(input, 'package.json'), pkg, { flag: 'wx', mode: 0o444 });
    if (metadataFixture !== undefined) {
      const fixture = Buffer.from(JSON.stringify(metadataFixture));
      if (fixture.length > 32 * 1024 * 1024) throw Error('RUNTIME_METADATA_FIXTURE_LIMIT');
      await writeFile(join(input, 'registry-fixture.json'), fixture, { flag: 'wx', mode: 0o444 });
    }
    await chmod(input, 0o555);
    stage = 'BUILDER';
    const image = JSON.parse(await run(['image', 'inspect', options.builderImageDigest, '--format', '{{json .}}']));
    if (image.Id !== options.builderImageDigest || image.Os !== options.platform.os || image.Architecture !== options.platform.architecture ||
      image.Config?.Labels?.['io.mcpshield.runtime-builder'] !== 'node-closure-v1' || image.Config?.Labels?.['io.mcpshield.npm-version'] !== '12.0.2' ||
      image.Config?.Labels?.['io.mcpshield.npm-patches'] !== 'brace-expansion@5.0.9,ip-address@10.3.1,tar@7.5.22' ||
      image.Config?.Labels?.['io.mcpshield.lock-generator'] !== 'npm-package-lock-only-v1') throw Error('RUNTIME_LOCK_BUILDER_PROFILE_REQUIRED');
    stage = 'BROKER';
    await run(['network', 'create', '--internal', network]);
    const isolation = ['--pull=never', '--read-only', '--user=1000:1000', '--cap-drop=ALL', '--security-opt=no-new-privileges',
      '--pids-limit=64', '--cpus=1', '--tmpfs=/tmp:rw,noexec,nosuid,size=32m', '--entrypoint=/usr/local/bin/node'];
    await run(['create', '--name', broker, '--network', metadataFixture === undefined ? 'bridge' : network, ...isolation, '--memory=256m',
      '-e', `REGISTRY_BROKER_TOKEN=${token}`, ...(metadataFixture === undefined ? [] : ['-e', 'MCPSHIELD_REGISTRY_FIXTURE=1',
        '--mount', `type=bind,source=${join(input, 'registry-fixture.json')},target=/input/registry-fixture.json,readonly`]),
      options.builderImageDigest, '/trusted/registry-broker.mjs']);
    if (metadataFixture === undefined) await run(['network', 'connect', network, broker]);
    await run(['start', broker]);
    const networks = JSON.parse(await run(['inspect', broker, '--format', '{{json .NetworkSettings.Networks}}']));
    const address = networks[network]?.IPAddress;
    if (isIP(address ?? '') !== 4) throw Error('RUNTIME_BROKER_NAMESPACE_INVALID');
    const readyDeadline = Date.now() + 5000;
    let ready = false;
    while (Date.now() < readyDeadline) {
      if ((await run(['logs', broker])).toString('utf8').trim() === 'MCPSHIELD_REGISTRY_BROKER_READY') { ready = true; break; }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (!ready) throw Error('RUNTIME_BROKER_START_FAILED');
    stage = 'SOLVER';
    await run(['volume', 'create', volume]);
    const output = await run(['run', '--name', solver, '--network', network, '--dns=127.0.0.1', '--add-host', `registry-broker:${address}`,
      ...isolation, '--memory=512m', '-e', `REGISTRY_BROKER_TOKEN=${token}`,
      '--mount', `type=bind,source=${join(input, 'package.json')},target=/input/package.json,readonly`,
      '--mount', `type=volume,source=${volume},target=/work`, options.builderImageDigest, '/trusted/lock-container.mjs']);
    if (output.toString('utf8').trim() !== 'MCPSHIELD_LOCK_GENERATED') throw Error('RUNTIME_LOCK_GENERATION_FAILED');
    stage = 'EXPORT';
    const generatedLock = archiveFile(await run(['cp', `${solver}:/work/resolve/package-lock.json`, '-'], 2 * 1024 * 1024), 'package-lock.json', 1024 * 1024);
    const report = JSON.parse(archiveFile(await run(['cp', `${solver}:/work/lock-report.json`, '-']), 'lock-report.json', 16 * 1024));
    const registry = JSON.parse(await run(['exec', broker, '/usr/local/bin/node', '/trusted/registry-broker.mjs', '--evidence']));
    if (report.lockDigest !== sha256(generatedLock) || report.packageDigest !== sha256(pkg) || report.installScripts !== false ||
      report.candidateExecutionPerformed !== false || report.installedNodeModules !== false || report.npmVersion !== '12.0.2' ||
      report.network !== 'METADATA_BROKER_ONLY' || report.git !== 'DISABLED' || registry.metadataOnly !== true ||
      registry.source !== (metadataFixture === undefined ? 'OFFICIAL_REGISTRY_HTTPS' : 'SYNTHETIC_METADATA_FIXTURE')) throw Error('RUNTIME_LOCK_REPORT_MISMATCH');
    const checked = await preflightNpmRuntime({ ...options, generatedLock });
    if (checked.issues.length) return { ...checked, phase: 'FAILED', lockGenerated: false };
    return { ...checked, phase: 'LOCK_GENERATED', lockGenerated: true, generatedLock,
      generation: { ...report, builderImageDigest: options.builderImageDigest, platform: options.platform,
        sourceTreeDigest: options.sourceTreeDigest, registry, candidateFilesMounted: ['package.json'],
        dns: 'LOOPBACK_ONLY_STATIC_BROKER_HOST', originalSourceModified: false } };
  } catch (error) {
    return { ...preflight, phase: 'FAILED', lockGenerated: false, issues: [/^RUNTIME_[A-Z_]+$/.test(error.message) ? error.message : 'RUNTIME_LOCK_GENERATION_FAILED'], diagnostics: { stage } };
  } finally {
    for (const args of [['rm', '-f', solver], ['rm', '-f', broker], ['volume', 'rm', volume], ['network', 'rm', network]]) {
      try { await runRuntimeDocker(args, 5000); } catch { /* exact task-owned resources only */ }
    }
    await removeFixtureSnapshot(workspace);
  }
}
