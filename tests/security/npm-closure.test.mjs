import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as tar from 'tar';
import { acquireNpmClosure, inspectClosureArchive, prepareNpmClosure } from '../../services/resolver/src/npm-closure.mjs';
import { inspectClosure } from '../../services/resolver/src/closure-files.mjs';
import { artifactDigest } from '../../services/scanner/src/scanner.mjs';
import { removeFixtureSnapshot } from '../../services/scanner/src/snapshot.mjs';
import { hashPreparedRuntimeDescriptor } from '../../services/resolver/src/runtime-preflight.mjs';

const exec = promisify(execFile);
const builderImageDigest = process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE ?? `sha256:${'b'.repeat(64)}`;
const platform = { os: 'linux', architecture: 'amd64' };

async function fixture(run) {
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-closure-test-'));
  const root = join(workspace, 'root');
  const dependency = join(workspace, 'package');
  try {
    await mkdir(root);
    await mkdir(dependency);
    const hook = "node -e \"require('fs').writeFileSync('/work/app/lifecycle-must-not-run','synthetic')\"";
    await writeFile(join(dependency, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0', main: 'index.js', scripts: { postinstall: hook } }));
    await writeFile(join(dependency, 'index.js'), "module.exports='SYNTHETIC_DEPENDENCY';");
    const bytes = tar.c({ cwd: workspace, sync: true, portable: true }, ['package/package.json', 'package/index.js']).read();
    const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
    const pkg = { name: 'closure-fixture', version: '1.0.0', bin: 'server.js', dependencies: { fixture: '1.0.0' }, scripts: { postinstall: hook } };
    await writeFile(join(root, 'package.json'), JSON.stringify(pkg));
    await writeFile(join(root, 'package-lock.json'), JSON.stringify({ name: pkg.name, version: pkg.version, lockfileVersion: 3,
      packages: { '': { name: pkg.name, version: pkg.version, dependencies: pkg.dependencies },
        'node_modules/fixture': { version: '1.0.0', resolved: 'https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz', integrity } } }));
    await writeFile(join(root, '.npmrc'), 'registry=https://forbidden.example.test/\nignore-scripts=false\naudit=true\n');
    await writeFile(join(root, 'server.js'), [
      "const assert=require('node:assert/strict'),fs=require('node:fs');",
      "assert.equal(require('fixture'),'SYNTHETIC_DEPENDENCY'); assert.notEqual(process.getuid(),0);",
      "assert.equal(fs.existsSync('/app/lifecycle-must-not-run'),false); assert.equal(fs.existsSync('/app/.npmrc'),false);",
      "assert.equal(fs.existsSync('/var/run/docker.sock'),false); assert.throws(()=>fs.writeFileSync('/app/change','blocked'));",
      "assert.match(fs.readFileSync('/proc/self/status','utf8'),/NoNewPrivs:\\s+1/);",
      "assert.match(fs.readFileSync('/proc/self/status','utf8'),/CapEff:\\s+0000000000000000/);",
      "assert.deepEqual(Object.keys(require('node:os').networkInterfaces()),['lo']); console.log('SYNTHETIC_CLOSURE_EXECUTION_OK');",
    ].join('\n'));
    const options = { root, sourceDigest: await artifactDigest(root), sourceTreeDigest: await artifactDigest(root), builderImageDigest, platform };
    await run({ root, workspace, bytes, integrity, options });
  } finally { await removeFixtureSnapshot(workspace); }
}

test('supplied lock acquisition validates each actual tar and never executes scripts or uses package npmrc', async () => fixture(async ({ options, bytes }) => {
  const urls = [];
  const acquired = await acquireNpmClosure(options, { download: async (url) => { urls.push(url); return bytes; } });
  try {
    assert.equal(acquired.acquisitionPerformed, true);
    assert.equal(acquired.acquisition.integrityVerified, true);
    assert.equal(acquired.acquisition.uniqueArchives, 1);
    assert.equal(acquired.ready, false);
    assert.equal(acquired.status, 'INCONCLUSIVE');
    assert.deepEqual(urls, ['https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz']);
    assert.equal((await readFile(join(acquired.inputDir, 'archives', acquired.acquisition.archives[0].archiveDigest.slice(7) + '.tgz'))).equals(bytes), true);
    await assert.rejects(() => readFile(join(acquired.inputDir, 'artifact/lifecycle-must-not-run')), { code: 'ENOENT' });
  } finally { await acquired.cleanup?.(); }
  const tampered = await acquireNpmClosure(options, { download: async () => Buffer.from('modified') });
  assert.equal(tampered.acquisitionPerformed, false);
  assert.ok(tampered.issues.includes('ARTIFACT_INTEGRITY_MISMATCH'));
}));

test('acquisition total deadline covers stalled downloaders without leaking URL/data or claiming preparation', async () => fixture(async ({ options }) => {
  const started = Date.now();
  const result = await acquireNpmClosure(options, { timeoutMs: 30, download: async () => new Promise(() => {}) });
  assert.equal(result.acquisitionPerformed, false);
  assert.deepEqual(result.issues, ['RUNTIME_ACQUISITION_TIMEOUT']);
  assert.ok(Date.now() - started < 2000);
  assert.equal(result.ready, false);
}));

test('closure manifest covers node_modules and rejects tar path/link/permission aliases before image import', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mcpshield-closure-hash-'));
  try {
    await mkdir(join(root, 'node_modules/fixture'), { recursive: true });
    await writeFile(join(root, 'server.js'), 'never execute');
    await writeFile(join(root, 'node_modules/fixture/index.js'), 'first dependency bytes');
    const first = await inspectClosure(root, true);
    // Windows chmod does not preserve POSIX modes; encode the trusted installer's explicit modes with tar's own Header.
    const blocks = [];
    for (const entry of first.entries) {
      const content = entry.type === 'File' ? await readFile(join(root, entry.path)) : Buffer.alloc(0);
      const header = new tar.Header({ path: `./${entry.path}`, type: entry.type, size: content.length, mode: entry.mode });
      header.encode(); blocks.push(header.block, content, Buffer.alloc((512 - content.length % 512) % 512));
    }
    const bytes = Buffer.concat([...blocks, Buffer.alloc(1024)]);
    assert.equal(inspectClosureArchive(bytes).digest, first.digest);
    await chmod(join(root, 'node_modules/fixture/index.js'), 0o600);
    await writeFile(join(root, 'node_modules/fixture/index.js'), 'changed dependency bytes');
    const changed = await inspectClosure(root, true);
    assert.notEqual(changed.digest, first.digest);
    assert.ok(first.entries.some((entry) => entry.path === 'node_modules/fixture/index.js'));
    for (const [path, type, linkpath, mode] of [['../outside', 'File', '', 0o444], ['/absolute', 'Directory', '', 0o555],
      ['/', 'Directory', '', 0o555], ['linked', 'SymbolicLink', '/outside', 0o555], ['file', 'File', '', 0o644]]) {
      const header = new tar.Header({ path, type, linkpath, size: 0, mode }); header.encode();
      assert.throws(() => inspectClosureArchive(Buffer.concat([header.block, Buffer.alloc(1024)])), /CLOSURE_ARCHIVE_ENTRY_INVALID/);
    }
  } finally { await removeFixtureSnapshot(root); }
});

test('missing builder configuration is NOT_RUN; closure stage cannot omit final immutable identity', async () => fixture(async ({ options }) => {
  const unavailable = await prepareNpmClosure({ ...options, builderImageDigest: undefined });
  assert.equal(unavailable.phase, 'NOT_RUN');
  assert.equal(unavailable.status, 'INCONCLUSIVE');
  assert.equal(unavailable.ready, false);
  const acquired = await acquireNpmClosure(options, { download: async () => { throw Error('private-download-error'); } });
  assert.equal(JSON.stringify(acquired).includes('private-download-error'), false);
  assert.throws(() => hashPreparedRuntimeDescriptor({ ...acquired.descriptor, stage: 'CLOSURE_PREPARED' }), /PREPARATION_INCOMPLETE/);
}));

test('actual Linux patched builder installs locked dependencies offline and final image contains the full closure', {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== '1' || !process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE,
  timeout: 300_000,
}, async () => fixture(async ({ options, bytes }) => {
  const result = await prepareNpmClosure(options, { download: async () => bytes });
  try {
    assert.deepEqual(result.issues, []);
    assert.equal(result.phase, 'CLOSURE_PREPARED');
    assert.equal(result.ready, false);
    assert.equal(result.descriptor.toolSurfaceHash, null);
    assert.equal(result.descriptorDigest, hashPreparedRuntimeDescriptor(result.descriptor));
    assert.ok(result.closure.files >= 5);
    const output = await exec('docker', ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL',
      '--security-opt=no-new-privileges', '--user=1000:1000', '--memory=128m', '--pids-limit=32',
      result.descriptor.finalImageDigest, ...result.descriptor.argv], { timeout: 10_000, maxBuffer: 64 * 1024 });
    assert.equal(output.stdout.trim(), 'SYNTHETIC_CLOSURE_EXECUTION_OK');
  } finally { await result.cleanup?.(); }
}));
