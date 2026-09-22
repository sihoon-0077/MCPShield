import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, lstat } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

// Trusted program in the approved builder. Only package.json is mounted; no
// candidate .npmrc, extension, source code, scripts, executable or host home.
let stage = 'TOOLCHAIN';
let failureCode = 'FAILED';
try {
  if (process.getuid() === 0 || process.getgid() === 0) throw Error();
  for (const [name, version] of [['brace-expansion', '5.0.9'], ['ip-address', '10.3.1'], ['tar', '7.5.22']]) {
    if (JSON.parse(await readFile(`/usr/local/lib/node_modules/npm/node_modules/${name}/package.json`)).version !== version) throw Error();
  }
  if (JSON.parse(await readFile('/usr/local/lib/node_modules/npm/package.json')).version !== '12.0.2') throw Error();
  const token = process.env.REGISTRY_BROKER_TOKEN;
  if (!/^[a-f0-9]{48}$/.test(token)) throw Error();
  stage = 'INPUT';
  const pkg = await readFile('/input/package.json');
  if (pkg.length > 1024 * 1024) throw Error();
  await mkdir('/work/resolve'); await mkdir('/work/home'); await mkdir('/work/cache');
  await writeFile('/work/resolve/package.json', pkg, { flag: 'wx', mode: 0o444 });
  await writeFile('/work/user.npmrc', '', { flag: 'wx', mode: 0o400 });
  await writeFile('/work/global.npmrc', '', { flag: 'wx', mode: 0o400 });
  stage = 'SOLVE';
  const result = spawnSync('/usr/local/bin/node', ['/usr/local/lib/node_modules/npm/bin/npm-cli.js', 'install', '--package-lock-only',
    '--lockfile-version=3', '--ignore-scripts', '--ignore-extension', '--audit=false', '--fund=false', '--bin-links=false', '--workspaces=false',
    '--git=/bin/false', '--allow-directory=none', '--allow-file=none', '--allow-git=none', '--allow-remote=none',
    '--registry=http://registry-broker:8080/', '--replace-registry-host=never', '--userconfig=/work/user.npmrc', '--globalconfig=/work/global.npmrc',
    `--//registry-broker:8080/:_authToken=${token}`,
    '--cache=/work/cache', '--fetch-retries=0', '--fetch-timeout=8000', '--loglevel=error'], {
    cwd: '/work/resolve', env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/work/home', NODE_ENV: 'production' },
    timeout: 80_000, maxBuffer: 64 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0) {
    const code = /(?:^|\n)npm error code ([A-Z][A-Z0-9_]+)(?:\r?\n|$)/.exec(result.stderr?.toString('utf8') ?? '')?.[1];
    failureCode = result.error?.code === 'ETIMEDOUT' ? 'ETIMEDOUT' : [
      'E401', 'E403', 'E404', 'EUSAGE', 'ERESOLVE', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNREFUSED',
      'EAI_AGAIN', 'ENETUNREACH', 'EINTEGRITY', 'EACCES', 'EPERM', 'EBADENGINE',
      'EUNSUPPORTEDPROTOCOL', 'EINVALIDPACKAGENAME', 'EINVALIDTAGNAME', 'EJSONPARSE',
    ].includes(code) ? code : 'NPM_FAILED';
    throw Error();
  }
  stage = 'VERIFY';
  if (!(await readFile('/work/resolve/package.json')).equals(pkg)) throw Error();
  try { await lstat('/work/resolve/node_modules'); throw Error('UNEXPECTED_INSTALL'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const lock = await readFile('/work/resolve/package-lock.json');
  if (lock.length > 1024 * 1024) throw Error();
  await writeFile('/work/lock-report.json', JSON.stringify({ schemaVersion: 'mcpshield.lock-generation.v1',
    lockDigest: `sha256:${createHash('sha256').update(lock).digest('hex')}`, packageDigest: `sha256:${createHash('sha256').update(pkg).digest('hex')}`,
    npmVersion: '12.0.2', installScripts: false, candidateExecutionPerformed: false, installedNodeModules: false,
    registry: 'http://registry-broker:8080/', network: 'METADATA_BROKER_ONLY', git: 'DISABLED',
    configOrigin: 'DISTINCT_TRUSTED_FILES_NO_CANDIDATE_ENV', generatedAt: new Date().toISOString() }));
  process.stdout.write('MCPSHIELD_LOCK_GENERATED\n');
} catch {
  process.stderr.write(`MCPSHIELD_LOCK_FAILURE:${stage}:${failureCode}\n`);
  process.exitCode = 1;
}
