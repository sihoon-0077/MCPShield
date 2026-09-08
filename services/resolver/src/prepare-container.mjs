import { chmod, cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { inspectClosure } from './closure-files.mjs';

// This program belongs to the pinned builder image. Candidate packages cannot replace it.
const deadline = Date.now() + 100_000;
function npm(args, cwd = '/work') {
  const result = spawnSync('/usr/local/bin/node', ['/usr/local/lib/node_modules/npm/bin/npm-cli.js', ...args,
    '--ignore-scripts', '--offline', '--audit=false', '--fund=false', '--bin-links=false', '--cache=/work/cache',
    '--userconfig=/dev/null', '--globalconfig=/dev/null', '--loglevel=error'], {
    cwd, env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/work/home', NODE_ENV: 'production' },
    timeout: Math.max(1, deadline - Date.now()), maxBuffer: 64 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.status !== 0 || result.error || Date.now() >= deadline) throw Error('OFFLINE_NPM_FAILED');
}

try {
  if (process.getuid() === 0 || process.getgid() === 0) throw Error('NON_ROOT_REQUIRED');
  await mkdir('/work/home');
  await mkdir('/work/cache');
  await cp('/input/artifact', '/work/app', { recursive: true, dereference: false });
  await chmod('/work/app', 0o700);
  // Do not read package-owned project configuration or previously installed dependencies.
  await rm('/work/app/.npmrc', { force: true });
  await rm('/work/app/node_modules', { recursive: true, force: true });
  const supplied = JSON.parse(await readFile('/input/preparation.json'));
  if (supplied.lockFile === 'npm-shrinkwrap.json') await rm('/work/app/package-lock.json', { force: true });
  else if (supplied.lockFile !== 'package-lock.json') throw Error('LOCK_FILE_INVALID');
  for (const file of (await readdir('/input/archives')).sort()) {
    if (!/^[a-f0-9]{64}\.tgz$/.test(file)) throw Error('ARCHIVE_NAME_INVALID');
    npm(['cache', 'add', `/input/archives/${file}`]);
  }
  npm(['ci', '--omit=dev'], '/work/app');
  const manifest = await inspectClosure('/work/app', true);
  await writeFile('/work/closure-report.json', JSON.stringify({ ...manifest, installScripts: false, installNetwork: 'NONE',
    nodeVersion: process.version, npmVersion: '12.0.2', sourceDescriptorDigest: supplied.sourceDescriptorDigest }));
  process.stdout.write('MCPSHIELD_CLOSURE_PREPARED\n');
} catch {
  // npm output and candidate paths are private; never echo them through Docker build/run logs.
  process.stderr.write('MCPSHIELD_CLOSURE_PREPARATION_FAILED\n');
  process.exitCode = 1;
}
