import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { artifactDigest } from '../../services/scanner/src/scanner.mjs';
import { removeFixtureSnapshot } from '../../services/scanner/src/snapshot.mjs';
import { resolveArtifact } from '../../services/resolver/src/resolver.mjs';
import { preflightNpmRuntime, preflightOciRuntime, hashPreparedRuntimeDescriptor } from '../../services/resolver/src/runtime-preflight.mjs';

const digest = `sha256:${'a'.repeat(64)}`;
const builderImageDigest = `sha256:${'b'.repeat(64)}`;
const platform = { os: 'linux', architecture: 'amd64' };
const pkg = () => ({ name: 'runtime-fixture', version: '1.0.0', bin: 'bin/server.js', dependencies: { fixture: '^1.0.0' },
  scripts: { postinstall: 'never-execute-this-script' } });
const lock = (manifest) => ({ name: manifest.name, version: manifest.version, lockfileVersion: 3,
  packages: { '': { name: manifest.name, version: manifest.version, dependencies: manifest.dependencies },
    'node_modules/fixture': { version: '1.0.0', resolved: 'https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz',
      integrity: `sha512-${Buffer.alloc(64, 7).toString('base64')}` } } });

async function fixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'mcpshield-runtime-test-'));
  try {
    await mkdir(join(root, 'bin'));
    await writeFile(join(root, 'bin/server.js'), 'throw new Error("UNTRUSTED ENTRYPOINT MUST NOT EXECUTE DURING PREFLIGHT");');
    const manifest = pkg();
    await writeFile(join(root, 'package.json'), JSON.stringify(manifest));
    await writeFile(join(root, 'package-lock.json'), JSON.stringify(lock(manifest)));
    const inspect = async (options = {}) => preflightNpmRuntime({ root, sourceDigest: digest,
      sourceTreeDigest: await artifactDigest(root), platform, builderImageDigest, ...options });
    await run({ root, manifest, inspect });
  } finally { await removeFixtureSnapshot(root); }
}

test('runtime preflight binds source/bin/lock bytes without executing or claiming a prepared closure', async () => fixture(async ({ root, inspect }) => {
  const result = await inspect();
  assert.deepEqual(result.issues, []);
  assert.equal(result.status, 'INCONCLUSIVE');
  assert.equal(result.ready, false);
  assert.equal(result.executionPerformed, false);
  assert.equal(result.checks.snapshotVerified, true);
  assert.equal(result.checks.entrypointVerified, true);
  assert.equal(result.checks.lock.archiveIntegrityVerified, false);
  assert.equal(result.checks.lock.graphVerifiedByNpm, false);
  assert.equal(result.descriptor.lockOrigin, 'SUPPLIED');
  assert.equal(result.descriptor.lockDigest, `sha256:${createHash('sha256').update(await readFile(join(root, 'package-lock.json'))).digest('hex')}`);
  assert.equal(result.descriptor.finalImageDigest, null);
  assert.equal(result.descriptor.toolSurfaceHash, null);
  assert.deepEqual(result.descriptor.argv, ['/usr/local/bin/node', '/app/bin/server.js']);
  assert.equal(result.descriptorDigest, hashPreparedRuntimeDescriptor(result.descriptor));
  // Existing resolver digests/surface state are unchanged; preflight is additional metadata, not v1 runtime approval.
  const sourceTreeDigest = await artifactDigest(root);
  const resolved = await resolveArtifact({ source: { type: 'local', path: root, platform, builderImageDigest } });
  try {
    assert.equal(resolved.artifactDigest, sourceTreeDigest);
    assert.equal(resolved.metadata.surfaceKnown, false);
    assert.equal(resolved.metadata.runtimePreparation.ready, false);
    assert.deepEqual(resolved.metadata.runtimePreparation.issues, []);
  } finally { await resolved.cleanup(); }
}));

test('versioned descriptor rejects forged READY/unknown fields and binds every downstream execution input', async () => fixture(async ({ inspect }) => {
  const { descriptor: value, descriptorDigest: original } = await inspect();
  for (const [key, replacement] of Object.entries({ sourceDigest: builderImageDigest, sourceTreeDigest: builderImageDigest,
    builderImageDigest: digest, finalImageDigest: digest, toolSurfaceHash: `0x${'a'.repeat(64)}`,
    lockDigest: builderImageDigest, lockOrigin: 'RESOLVER_GENERATED', platform: { os: 'linux', architecture: 'arm64' } })) {
    assert.notEqual(hashPreparedRuntimeDescriptor({ ...value, [key]: replacement }), original, key);
  }
  assert.notEqual(hashPreparedRuntimeDescriptor({ ...value, entrypoint: { ...value.entrypoint, digest } }), original);
  assert.throws(() => hashPreparedRuntimeDescriptor({ ...value, stage: 'READY' }), /DESCRIPTOR_INVALID/);
  assert.throws(() => hashPreparedRuntimeDescriptor({ ...value, ready: true }), /DESCRIPTOR_INVALID/);
  assert.throws(() => hashPreparedRuntimeDescriptor({ ...value, lockDigest: null }), /LOCK_ORIGIN/);
  assert.throws(() => hashPreparedRuntimeDescriptor({ ...value, builderImageDigest: 'node:22-alpine' }), /DIGEST_INVALID/);
  assert.throws(() => hashPreparedRuntimeDescriptor({ ...value, argv: ['node', '/tmp/other.js'] }), /ENTRYPOINT/);
  assert.throws(() => hashPreparedRuntimeDescriptor({ ...value, policy: { ...value.policy, installScripts: 'ENABLED' } }), /POLICY/);
  for (const badPlatform of [{ os: 'windows', architecture: 'amd64' }, { ...platform, variant: 'v8' }, { os: 'linux', architecture: 'x64' }]) {
    await assert.rejects(() => inspect({ platform: badPlatform }), /PLATFORM_UNSUPPORTED/);
  }
}));

test('bin selection never guesses main/index or accepts path aliases and ambiguity', async () => fixture(async ({ root, manifest, inspect }) => {
  for (const bin of [undefined, '../outside.js', './bin/server.js', '/bin/server.js', 'C:/bin/server.js', 'bin\\server.js',
    'bin/../bin/server.js', 'bin//server.js', 'bin/con.js', 'bin/server.js.', 'bin/server.sh', { first: 'bin/server.js', second: 'bin/server.js' }]) {
    await writeFile(join(root, 'package.json'), JSON.stringify({ ...manifest, bin }));
    const result = await inspect();
    assert.ok(result.issues.some((issue) => issue.startsWith('RUNTIME_BIN_')), JSON.stringify(bin));
    assert.equal(result.descriptor.entrypoint, null);
  }
  assert.equal((await inspect({ binName: 'second' })).checks.entrypointVerified, true);
  assert.ok((await inspect({ binName: 'missing' })).issues.includes('RUNTIME_BIN_SELECTION_INVALID'));
}));

test('preflight rejects symlink ancestors and source mutation before trusting entrypoint bytes', async () => fixture(async ({ root, manifest, inspect }) => {
  const original = await artifactDigest(root);
  await writeFile(join(root, 'bin/server.js'), 'modified but never executed');
  assert.ok((await inspect({ sourceTreeDigest: original })).issues.includes('RUNTIME_SOURCE_DIGEST_MISMATCH'));
  await symlink(join(root, 'bin'), join(root, 'alias'), process.platform === 'win32' ? 'junction' : 'dir');
  await writeFile(join(root, 'package.json'), JSON.stringify({ ...manifest, bin: 'alias/server.js' }));
  // artifactDigest's old algorithm is not a secure path reader; provide a fixed expected digest and let snapshot validation run first.
  const result = await preflightNpmRuntime({ root, sourceDigest: digest, sourceTreeDigest: original, platform, builderImageDigest });
  assert.ok(result.issues.includes('RUNTIME_SOURCE_SNAPSHOT_INVALID'));
  assert.equal(result.checks.entrypointVerified, false);
}));

test('lock preflight rejects missing locks, identity/range mismatch, weak SRI and non-registry sources', async () => fixture(async ({ root, manifest, inspect }) => {
  const cases = [
    [() => ({ invalid: true }), 'RUNTIME_LOCK_FORMAT_UNSUPPORTED'],
    [(value) => ({ ...value, version: '2.0.0' }), 'RUNTIME_LOCK_IDENTITY_MISMATCH'],
    [(value) => ({ ...value, packages: { ...value.packages, '': { ...value.packages[''], dependencies: { fixture: '^2.0.0' } } } }), 'RUNTIME_LOCK_MANIFEST_MISMATCH'],
    [(value) => ({ ...value, packages: { '': value.packages[''] } }), 'RUNTIME_LOCK_DEPENDENCY_MISSING'],
  ];
  for (const [change, issue] of cases) {
    await writeFile(join(root, 'package-lock.json'), JSON.stringify(change(lock(manifest))));
    assert.ok((await inspect()).issues.includes(issue), issue);
  }
  for (const [field, bad, issue] of [
    ['integrity', 'sha512-ZmFrZQ==', 'RUNTIME_LOCK_INTEGRITY_INVALID'],
    ['integrity', `sha1-${Buffer.alloc(20).toString('base64')}`, 'RUNTIME_LOCK_INTEGRITY_INVALID'],
    ['resolved', 'https://registry.npmjs.org.example.test/fixture.tgz', 'RUNTIME_LOCK_REGISTRY_INVALID'],
    ['resolved', 'https://registry.npmjs.org/fixture.tgz?token=synthetic-never-log', 'RUNTIME_LOCK_REGISTRY_INVALID'],
    ['resolved', 'file:/host/secret', 'RUNTIME_LOCK_REGISTRY_INVALID'],
    ['link', true, 'RUNTIME_LOCK_ENTRY_UNSUPPORTED'],
    ['version', 'v1.0.0', 'RUNTIME_LOCK_ENTRY_UNSUPPORTED'],
  ]) {
    const value = lock(manifest);
    value.packages['node_modules/fixture'][field] = bad;
    await writeFile(join(root, 'package-lock.json'), JSON.stringify(value));
    const result = await inspect();
    assert.ok(result.issues.includes(issue), `${field}: ${issue}`);
    assert.equal(result.descriptor.lockDigest, null);
    assert.equal(JSON.stringify(result).includes('synthetic-never-log'), false);
  }
  // A differently named dependency path cannot smuggle a traversal even with correct-looking integrity.
  const value = lock(manifest);
  value.packages['node_modules/../escape'] = value.packages['node_modules/fixture'];
  await writeFile(join(root, 'package-lock.json'), JSON.stringify(value));
  assert.ok((await inspect()).issues.includes('RUNTIME_LOCK_ENTRY_UNSUPPORTED'));
  await writeFile(join(root, 'package-lock.json'), JSON.stringify(lock(manifest)));
  await writeFile(join(root, 'npm-shrinkwrap.json'), JSON.stringify({ ...lock(manifest), version: '2.0.0' }));
  assert.ok((await inspect()).issues.includes('RUNTIME_LOCK_AMBIGUOUS'));
  await writeFile(join(root, 'npm-shrinkwrap.json'), JSON.stringify(lock(manifest)));
  assert.deepEqual((await inspect()).issues, []);
  const noLock = await mkdtemp(join(tmpdir(), 'mcpshield-no-lock-'));
  try {
    await writeFile(join(noLock, 'package.json'), JSON.stringify({ ...manifest, bin: 'server.js' }));
    await writeFile(join(noLock, 'server.js'), 'throw 0;');
    const result = await preflightNpmRuntime({ root: noLock, sourceDigest: digest, sourceTreeDigest: await artifactDigest(noLock) });
    assert.ok(result.issues.includes('RUNTIME_LOCK_REQUIRED'));
    assert.ok(result.issues.includes('RUNTIME_PLATFORM_REQUIRED'));
    assert.ok(result.issues.includes('RUNTIME_BUILDER_DIGEST_REQUIRED'));
    assert.equal(result.descriptor.lockOrigin, null);
  } finally { await removeFixtureSnapshot(noLock); }
}));

test('OCI binds image platform and observed container argv but never treats unexamined filesystem as executable', () => {
  const input = { sourceDigest: digest, sourceTreeDigest: builderImageDigest, platform,
    runtime: { rootUser: false, entrypoint: ['/usr/local/bin/python'], command: ['server.py'] } };
  const result = preflightOciRuntime(input);
  assert.equal(result.descriptor.profile, 'oci-image-v1');
  assert.equal(result.descriptor.lockOrigin, 'NOT_APPLICABLE');
  assert.equal(result.descriptor.entrypoint, null);
  assert.deepEqual(result.descriptor.argv, ['/usr/local/bin/python', 'server.py']);
  assert.ok(result.issues.includes('OCI_ENTRYPOINT_FILESYSTEM_UNVERIFIED'));
  assert.equal(result.ready, false);
  assert.equal(result.executionPerformed, false);
  assert.notEqual(preflightOciRuntime({ ...input, runtime: { ...input.runtime, command: ['other.py'] } }).descriptorDigest, result.descriptorDigest);
  for (const entrypoint of ['sh -c server.py', [], ['../escape'], ['./server.py'], ['server\n.py']]) {
    const invalid = preflightOciRuntime({ ...input, runtime: { rootUser: true, entrypoint, command: [] } });
    assert.ok(invalid.issues.includes('RUNTIME_OCI_ARGV_INVALID'));
    assert.ok(invalid.issues.includes('RUNTIME_OCI_NON_ROOT_REQUIRED'));
    assert.equal(invalid.descriptor.argv, null);
  }
});
