import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { startSink } from '../../exfil-sink/server.mjs';

export const DEMO_CANARY = 'MCP_SHIELD_DEMO_CANARY_v1';
const HERE = dirname(fileURLToPath(import.meta.url));
const SINK_DIR = resolve(HERE, '../../exfil-sink');
const OBSERVER_PATH = resolve(HERE, 'observer-preload.cjs');
const OBSERVER_DIR = dirname(OBSERVER_PATH);
const OBSERVATION_PREFIX = 'MCPSHIELD_OBSERVATION ';

export async function createCanaries(root, scanId = randomUUID()) {
  if (!/^[A-Za-z0-9-]{1,64}$/.test(scanId)) throw new TypeError('invalid canary scanId');
  const profiles = { ENV_SECRET: '.env', SSH_PRIVATE_KEY: '.ssh/id_demo', AWS_SESSION_TOKEN: '.aws/credentials',
    GCP_SERVICE_ACCOUNT: '.config/gcloud/demo.json', BROWSER_COOKIE: '.browser/cookies.demo', WALLET_SEED_DUMMY: '.wallet/invalid-seed.demo',
    CUSTOMER_RECORD: 'customers.demo.csv', SOURCE_CODE_MARKER: 'source.demo.txt' };
  const canaries = [];
  for (const [type, path] of Object.entries(profiles)) {
    const target = join(root, path);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    const content = `CANARY::${scanId}::${type}::${randomBytes(16).toString('hex')}`;
    await writeFile(target, content, { mode: 0o400 });
    canaries.push({ type, path, hash: createHash('sha256').update(content).digest('hex') });
  }
  return canaries;
}

function observationsFrom(stderr) {
  const observations = [];
  const seen = new Set();
  for (const line of stderr.split(/\r?\n/)) {
    if (!line.startsWith(OBSERVATION_PREFIX)) continue;
    try {
      const event = JSON.parse(line.slice(OBSERVATION_PREFIX.length));
      if (event?.version !== 1 || !['FS_READ', 'NETWORK', 'CHILD_PROCESS'].includes(event.type)) continue;
      const sanitized = event.type === 'FS_READ'
        ? { type: event.type, target: String(event.target).slice(0, 32), ...(event.basename ? { basename: String(event.basename).slice(0, 128) } : {}) }
        : event.type === 'NETWORK'
          ? {
              type: event.type,
              protocol: String(event.protocol).slice(0, 16),
              hostname: String(event.hostname).slice(0, 255),
              port: String(event.port).slice(0, 8),
              path: String(event.path).slice(0, 255),
            }
          : { type: event.type, command: String(event.command).slice(0, 128), method: String(event.method).slice(0, 32) };
      const key = JSON.stringify(sanitized);
      if (!seen.has(key) && observations.length < 256) {
        seen.add(key);
        observations.push(sanitized);
      }
    } catch {
      // Fixture stderr is untrusted. Malformed or forged records are ignored.
    }
  }
  return observations;
}

function run(command, args, { cwd, env, timeoutMs = 5_000 } = {}) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(command, args, {
      cwd,
      env,
      windowsHide: true,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      if (process.platform === 'win32' && child.pid) {
        const killer = spawn('taskkill.exe', ['/pid', String(child.pid), '/t', '/f'], {
          windowsHide: true,
          stdio: 'ignore',
        });
        killer.unref();
      } else if (child.pid) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
      }
    }, timeoutMs);
    child.stdout.on('data', (chunk) => { if (stdout.length < 65_536) stdout += chunk; });
    child.stderr.on('data', (chunk) => { if (stderr.length < 65_536) stderr += chunk; });
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolveResult({ code, signal, stdout, stderr, timedOut });
    });
  });
}

function fixtureCommand(fixtureDir, entrypoint, exfilUrl, canaryPath, token, fakeHome) {
  if (!process.allowedNodeEnvironmentFlags.has('--permission')) throw new Error('Node permission model is required');
  return {
    command: process.execPath,
    args: ['--permission', `--allow-fs-read=${fixtureDir}`, `--allow-fs-read=${OBSERVER_PATH}`,
      `--allow-fs-read=${fakeHome}`, '--require', OBSERVER_PATH, resolve(fixtureDir, entrypoint)],
    cwd: fixtureDir,
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      WINDIR: process.env.WINDIR,
      MCP_EXFIL_URL: exfilUrl,
      MCP_CANARY_PATH: canaryPath,
      MCP_SINK_TOKEN: token,
      HOME: fakeHome,
      USERPROFILE: fakeHome,
      MCP_CANARY_ROOT: fakeHome,
    },
  };
}

async function runLocal({ fixtureDir, entrypoint, timeoutMs, scanId, egressAllowHosts }) {
  const tempDir = await mkdtemp(join(tmpdir(), 'mcpshield-'));
  const fakeHome = join(tempDir, 'home');
  const canaries = await createCanaries(fakeHome, scanId);
  const canaryPath = join(fakeHome, '.env');
  const token = randomBytes(24).toString('hex');
  const canaryHash = canaries[0].hash;
  const sink = await startSink({ token, egressAllowHosts });
  try {
    const spec = fixtureCommand(fixtureDir, entrypoint, sink.url, canaryPath, token, fakeHome);
    const processResult = await run(spec.command, spec.args, { ...spec, timeoutMs });
    return {
      mode: 'LOCAL_PROCESS',
      timedOut: processResult.timedOut,
      exitCode: processResult.code,
      error: processResult.code === 0 || processResult.timedOut ? null : 'fixture exited unsuccessfully',
      canaryObserved: sink.events.some((event) => canaries.some(({ hash }) => hash === event.canaryHash)),
      canaryHash,
      observations: observationsFrom(processResult.stderr),
      egressEvents: sink.events.filter((event) => event.type),
    };
  } finally {
    await sink.close();
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function dockerAvailable() {
  try {
    const result = await run('docker', ['version', '--format', '{{.Client.Version}}'], { timeoutMs: 3_000 });
    return result.code === 0;
  } catch {
    return false;
  }
}

async function dockerCleanup(containerNames, networkName) {
  for (const name of containerNames) {
    try { await run('docker', ['rm', '-f', name], { timeoutMs: 5_000 }); } catch { /* best effort */ }
  }
  try { await run('docker', ['network', 'rm', networkName], { timeoutMs: 5_000 }); } catch { /* best effort */ }
}

async function waitForSink(containerName, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const logs = await run('docker', ['logs', containerName], { timeoutMs: 1_000 });
    if (logs.stdout.includes('READY')) return;
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error('Docker exfil sink startup timed out');
}

async function runDocker({ fixtureDir, entrypoint, timeoutMs, scanId, egressAllowHosts = ['mail-api.local', 'exfil-sink.local'], mcpProbe = false, probeCalls = [] }) {
  if (!await dockerAvailable()) throw new Error('Docker sandbox requested but Docker is unavailable');
  const uid = process.getuid?.() ?? 1000;
  const gid = process.getgid?.() ?? 1000;
  if (uid === 0 || gid === 0) throw new Error('Docker sandbox requires a non-root host runner to own isolated mounts');
  const containerUser = `${uid}:${gid}`;
  const suffix = randomBytes(6).toString('hex');
  const networkName = `mcpshield-${suffix}`;
  const sinkName = `mcpshield-sink-${suffix}`;
  const fixtureName = `mcpshield-fixture-${suffix}`;
  const tempDir = await mkdtemp(join(tmpdir(), 'mcpshield-docker-'));
  const fakeHome = join(tempDir, 'home');
  const canaries = await createCanaries(fakeHome, scanId);
  const eventsPath = join(tempDir, 'events.jsonl');
  const token = randomBytes(24).toString('hex');
  const canaryHash = canaries[0].hash;
  try {
    const network = await run('docker', ['network', 'create', '--internal', networkName], { timeoutMs: 10_000 });
    if (network.code !== 0) throw new Error('failed to create isolated Docker network');
    const sink = await run('docker', [
      'run', '-d', '--name', sinkName, '--network', networkName, '--network-alias', 'exfil-sink',
      '--user', containerUser,
      '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64',
      '-v', `${SINK_DIR}:/app:ro`, '-v', `${tempDir}:/events`,
      '-e', 'HOST=0.0.0.0', '-e', 'PORT=8080', '-e', `SINK_TOKEN=${token}`, '-e', 'EVENT_FILE=/events/events.jsonl',
      '-e', `EGRESS_ALLOW_HOSTS=${egressAllowHosts.join(',')}`,
      'node:22-alpine', 'node', '/app/server.mjs',
    ], { timeoutMs: 60_000 });
    if (sink.code !== 0) throw new Error('failed to start Docker exfil sink');
    await waitForSink(sinkName);
    const fixture = await run('docker', [
      'run', '--name', fixtureName, '--network', networkName, '--read-only', '--cap-drop', 'ALL',
      '--user', containerUser,
      '--security-opt', 'no-new-privileges', '--memory', '128m', '--cpus', '0.5', '--pids-limit', '64', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
      '-v', `${resolve(fixtureDir)}:/fixture:ro`, '-v', `${fakeHome}:/home/test:ro`,
      '-v', `${OBSERVER_DIR}:/observer:ro`,
      '-e', 'MCP_EXFIL_URL=http://exfil-sink:8080/events', '-e', 'MCP_CANARY_PATH=/home/test/.env', '-e', 'HOME=/home/test', '-e', 'MCP_CANARY_ROOT=/home/test',
      '-e', `MCP_SINK_TOKEN=${token}`, '-e', `MCP_PROBE_CALLS=${JSON.stringify(probeCalls)}`, 'node:22-alpine', 'node',
      ...(mcpProbe ? ['/observer/mcp-probe.cjs'] : ['--require', '/observer/observer-preload.cjs']), `/fixture/${entrypoint}`,
    ], { timeoutMs });
    let events = '';
    try { events = await readFile(eventsPath, 'utf8'); } catch { /* no exfil event */ }
    const parsedEvents = events.split(/\r?\n/).filter(Boolean).flatMap((line) => { try { return [JSON.parse(line)]; } catch { return []; } });
    let mcpReport;
    if (mcpProbe) {
      const reportLine = fixture.stdout.split(/\r?\n/).find((line) => line.startsWith('MCPSHIELD_MCP_REPORT '));
      try { mcpReport = JSON.parse(reportLine?.slice('MCPSHIELD_MCP_REPORT '.length)); }
      catch { mcpReport = { complete: false, error: 'MCP_REPORT_MISSING' }; }
    }
    return {
      mode: 'DOCKER',
      timedOut: fixture.timedOut,
      exitCode: fixture.code,
      error: fixture.code === 0 || fixture.timedOut ? null : `fixture exited unsuccessfully (${fixture.stderr.match(/\b(?:EACCES|EPERM|EROFS|ENOENT|ERR_MODULE_NOT_FOUND|ERR_ASSERTION|ERR_ACCESS_DENIED)\b/)?.[0] ?? 'UNCLASSIFIED'})`,
      canaryObserved: parsedEvents.some((event) => canaries.some(({ hash }) => event.canaryHash === hash)),
      canaryHash,
      observations: observationsFrom(fixture.stderr),
      egressEvents: parsedEvents.filter((event) => event.type),
      ...(mcpProbe ? { mcpReport } : {}),
    };
  } finally {
    await dockerCleanup([fixtureName, sinkName], networkName);
    await rm(tempDir, { recursive: true, force: true });
  }
}

export async function runSandbox(options) {
  if (options.egressAllowHosts && (!Array.isArray(options.egressAllowHosts) || options.egressAllowHosts.length > 32 || options.egressAllowHosts.some((name) => !/^[a-z0-9][a-z0-9.-]*\.(?:local|test)$/.test(name)))) throw new TypeError('proxy allowlist only accepts synthetic hosts');
  if (options.mcpProbe && options.mode !== 'docker') throw new TypeError('ingested MCP discovery requires Docker isolation');
  if (options.probeCalls && (!Array.isArray(options.probeCalls) || options.probeCalls.length > 8 || JSON.stringify(options.probeCalls).length > 16_384)) throw new TypeError('MCP probe calls exceed limit');
  if (options.mode === 'local') return runLocal(options);
  if (options.mode === 'docker') return runDocker(options);
  throw new TypeError(`unknown sandbox mode: ${options.mode}`);
}
