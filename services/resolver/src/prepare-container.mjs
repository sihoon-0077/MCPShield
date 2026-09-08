import { chmod, cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { inspectClosure } from './closure-files.mjs';

// This program belongs to the pinned builder image. Candidate packages cannot replace it.
const deadline = Date.now() + 100_000;
let stage = 'TOOLCHAIN';
function npm(args, cwd = '/work') {
  const result = spawnSync('/usr/local/bin/node', ['/usr/local/lib/node_modules/npm/bin/npm-cli.js', ...args,
    '--ignore-scripts', '--offline', '--audit=false', '--fund=false', '--bin-links=false', '--cache=/work/cache',
    '--userconfig=/work/user.npmrc', '--globalconfig=/work/global.npmrc', '--loglevel=error'], {
    cwd, env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/work/home', NODE_ENV: 'production' },
    timeout: Math.max(1, deadline - Date.now()), maxBuffer: 64 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.status !== 0 || result.error || Date.now() >= deadline) {
    const code = /(?:^|\n)npm error code (E[A-Z0-9]+)(?:\r?\n|$)/.exec(result.stderr?.toString('utf8') ?? '')?.[1];
    throw Error(['ENOTCACHED', 'EUSAGE', 'EINTEGRITY', 'ENOENT', 'EACCES', 'EPERM'].includes(code) ? code : 'NPM_FAILED');
  }
}

try {
  if (process.getuid() === 0 || process.getgid() === 0) throw Error('NON_ROOT_REQUIRED');
  for (const [name, version] of [['brace-expansion', '5.0.9'], ['ip-address', '10.3.1'], ['tar', '7.5.22']]) {
    if (JSON.parse(await readFile(`/usr/local/lib/node_modules/npm/node_modules/${name}/package.json`)).version !== version) throw Error('TOOLCHAIN_PATCH_REQUIRED');
  }
  stage = 'INPUT';
  await mkdir('/work/home');
  await mkdir('/work/cache');
  // npm rejects loading the same path twice, even /dev/null. These distinct
  // trusted empty files also prevent user/global config from enabling hooks.
  await writeFile('/work/user.npmrc', '', { flag: 'wx', mode: 0o400 });
  await writeFile('/work/global.npmrc', '', { flag: 'wx', mode: 0o400 });
  await cp('/input/artifact', '/work/app', { recursive: true, dereference: false });
  await chmod('/work/app', 0o700);
  // Do not read package-owned project configuration or previously installed dependencies.
  await rm('/work/app/.npmrc', { force: true });
  await rm('/work/app/node_modules', { recursive: true, force: true });
  const supplied = JSON.parse(await readFile('/input/preparation.json'));
  if (supplied.lockFile === 'npm-shrinkwrap.json') await rm('/work/app/package-lock.json', { force: true });
  else if (supplied.lockFile !== 'package-lock.json') throw Error('LOCK_FILE_INVALID');
  stage = 'CACHE';
  for (const file of (await readdir('/input/archives')).sort()) {
    if (!/^[a-f0-9]{64}\.tgz$/.test(file)) throw Error('ARCHIVE_NAME_INVALID');
    npm(['cache', 'add', `/input/archives/${file}`]);
  }
  stage = 'INSTALL';
  npm(['ci', '--omit=dev'], '/work/app');
  stage = 'MANIFEST';
  const manifest = await inspectClosure('/work/app', true);
  await writeFile('/work/closure-report.json', JSON.stringify({ ...manifest, installScripts: false, installNetwork: 'NONE',
    nodeVersion: process.version, npmVersion: '12.0.2', toolchainPatches: 'brace-expansion@5.0.9,ip-address@10.3.1,tar@7.5.22',
    sourceDescriptorDigest: supplied.sourceDescriptorDigest }));
  process.stdout.write('MCPSHIELD_CLOSURE_PREPARED\n');
} catch (error) {
  // npm output and candidate paths are private; never echo them through Docker build/run logs.
  const code = ['ENOTCACHED', 'EUSAGE', 'EINTEGRITY', 'ENOENT', 'EACCES', 'EPERM', 'NPM_FAILED'].includes(error.message) ? error.message : 'FAILED';
  process.stderr.write(`MCPSHIELD_CLOSURE_FAILURE:${stage}:${code}\n`);
  process.exitCode = 1;
}
