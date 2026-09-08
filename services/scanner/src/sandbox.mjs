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
    const observedCanary = canaries.find(({ hash }) => sink.events.some((event) => event.canaryHash === hash));
    return {
      mode: 'LOCAL_PROCESS',
      timedOut: processResult.timedOut,
      exitCode: processResult.code,
      error: processResult.code === 0 || processResult.timedOut ? null : 'fixture exited unsuccessfully',
      canaryObserved: Boolean(observedCanary),
      canaryHash: observedCanary?.hash ?? canaryHash,
      canaryType: observedCanary?.type ?? null,
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

export function sinkFailureCode(stderr, state = {}) {
  if (state.OOMKilled) return 'OOM_KILLED';
  if (/\b(?:EACCES|EPERM)\b/.test(stderr)) return 'PERMISSION_DENIED';
  if (/proxy allowlist only accepts|EGRESS_ALLOWLIST_INVALID/.test(stderr)) return 'EGRESS_ALLOWLIST_INVALID';
  if (/\b(?:EADDRINUSE|EADDRNOTAVAIL)\b/.test(stderr)) return 'PORT_UNAVAILABLE';
  if (/ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND/.test(stderr)) return 'MODULE_NOT_FOUND';
  if (/SyntaxError/.test(stderr)) return 'SYNTAX_ERROR';
  if (/sink token is required|SINK_TOKEN_REQUIRED/.test(stderr)) return 'SINK_TOKEN_REQUIRED';
  return 'UNCLASSIFIED';
}

const SINK_HEALTH_CHECK = "try{const r=await fetch('http://127.0.0.1:8080/health',{signal:AbortSignal.timeout(1000)});if(r.ok&&(await r.json()).ok===true)process.stdout.write('READY');else process.exitCode=2}catch{process.exitCode=2}";

// A log marker is diagnostic, not readiness. Check the actual trusted HTTP
// endpoint; slow/failed Docker control commands must not look like app startup.
// command is injectable for portable contract tests, never a public scan option.
export async function waitForSink(containerName, timeoutMs = 10_000, command = run) {
  if (!/^mcpshield-sink-[a-f0-9]{12}$/.test(containerName) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000) throw Error('SINK_READINESS_INPUT_INVALID');
  const started = Date.now();
  const deadline = Date.now() + timeoutMs;
  const checks = { attempts: 0, commandTimeouts: 0, commandFailures: 0, state: 'UNKNOWN', imageDigest: null,
    healthExit: null, inspectExit: null, logsExit: null, logReady: false, oomKilled: false, containerExit: null };
  let stderr = '';
  const inspect = async (grace = false) => {
    const result = await invoke(['inspect', '--format', '{"state":{{json .State}},"image":{{json .Image}}}', containerName], 'inspectExit', grace ? 1000 : Math.min(1000, deadline - Date.now()));
    try {
      const { state, image } = JSON.parse(result.stdout);
      checks.state = ['created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead'].includes(state?.Status) ? state.Status : 'UNKNOWN';
      checks.imageDigest = /^sha256:[a-f0-9]{64}$/.test(image) ? image : null;
      checks.oomKilled = state?.OOMKilled === true;
      checks.containerExit = Number.isSafeInteger(state?.ExitCode) ? state.ExitCode : null;
    } catch { /* command/result unavailable, never assume a running container */ }
  };
  const invoke = async (args, field, budget) => {
    if (budget < 1) return { code: null, stdout: '', stderr: '', timedOut: false };
    let result;
    try { result = await command('docker', args, { timeoutMs: budget }); }
    catch { result = { code: -1, stdout: '', stderr: '', timedOut: false }; }
    checks[field] = Number.isSafeInteger(result.code) ? result.code : null;
    if (result.timedOut) checks.commandTimeouts++;
    else if (result.code !== 0) checks.commandFailures++;
    stderr = typeof result.stderr === 'string' ? result.stderr : '';
    return result;
  };
  while (Date.now() < deadline) {
    checks.attempts++;
    const health = await invoke(['exec', containerName, '/usr/local/bin/node', '--input-type=module', '-e', SINK_HEALTH_CHECK],
      'healthExit', Math.min(3000, deadline - Date.now()));
    if (!health.timedOut && health.code === 0 && health.stdout === 'READY') return;
    await inspect();
    if (['exited', 'dead'].includes(checks.state) || checks.oomKilled) break;
    const pause = Math.min(100, deadline - Date.now());
    if (pause > 0) await new Promise((resolveWait) => setTimeout(resolveWait, pause));
  }
  // At most two extra one-second, read-only diagnostic commands after the work
  // deadline. Raw daemon/container output is never included in the exception.
  await inspect(true);
  const logs = await invoke(['logs', '--tail=20', containerName], 'logsExit', 1000);
  checks.logReady = logs.code === 0 && /^READY http:\/\//m.test(logs.stdout);
  const code = checks.oomKilled || ['exited', 'dead'].includes(checks.state)
    ? sinkFailureCode(stderr, { OOMKilled: checks.oomKilled })
    : checks.commandTimeouts ? 'DOCKER_CONTROL_TIMEOUT' : checks.commandFailures ? 'DOCKER_CONTROL_OR_HEALTH_FAILURE' : 'HEALTH_NOT_READY';
  const diagnostics = { ...checks, elapsedMs: Date.now() - started, logHash: createHash('sha256').update(stderr).digest('hex').slice(0, 16) };
  throw Object.assign(new Error(`Docker exfil sink readiness failed (${code}; ${JSON.stringify(diagnostics)})`), { diagnostics });
}

async function runDocker({ fixtureDir, entrypoint, timeoutMs, scanId, egressAllowHosts = ['mail-api.local', 'exfil-sink.local'], mcpProbe = false, probeCalls = [], preparedRuntime }) {
  if (!await dockerAvailable()) throw new Error('Docker sandbox requested but Docker is unavailable');
  if (preparedRuntime) {
    const inspected = await run('docker', ['image', 'inspect', preparedRuntime.imageDigest, '--format', '{{json .}}']);
    let image;
    try { image = JSON.parse(inspected.stdout); } catch { throw new Error('PREPARED_IMAGE_UNAVAILABLE'); }
    if (image.Id !== preparedRuntime.imageDigest || image.Os !== preparedRuntime.platform.os || image.Architecture !== preparedRuntime.platform.architecture) throw new Error('PREPARED_IMAGE_IDENTITY_MISMATCH');
  }
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
  const image = preparedRuntime?.imageDigest ?? 'node:22-alpine';
  const candidateEntrypoint = preparedRuntime ? preparedRuntime.argv[1] : `/fixture/${entrypoint}`;
  try {
    const network = await run('docker', ['network', 'create', '--internal', networkName], { timeoutMs: 10_000 });
    if (network.code !== 0) throw new Error('failed to create isolated Docker network');
    const sink = await run('docker', [
      'run', '-d', ...(preparedRuntime ? ['--pull=never', '--entrypoint=/usr/local/bin/node'] : []), '--name', sinkName, '--network', networkName, '--network-alias', 'exfil-sink',
      '--user', containerUser,
      '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64',
      '-v', `${SINK_DIR}:/app:ro`, '-v', `${tempDir}:/events`,
      '-e', 'HOST=0.0.0.0', '-e', 'PORT=8080', '-e', `SINK_TOKEN=${token}`, '-e', 'EVENT_FILE=/events/events.jsonl',
      '-e', `EGRESS_ALLOW_HOSTS=${egressAllowHosts.join(',')}`,
      image, ...(preparedRuntime ? [] : ['node']), '/app/server.mjs',
    ], { timeoutMs: 60_000 });
    if (sink.code !== 0) throw new Error('failed to start Docker exfil sink');
    await waitForSink(sinkName);
    const fixture = await run('docker', [
      'run', ...(preparedRuntime ? ['--pull=never', '--entrypoint=/usr/local/bin/node'] : []), '--name', fixtureName, '--network', networkName, '--read-only', '--cap-drop', 'ALL',
      '--user', containerUser,
      '--security-opt', 'no-new-privileges', '--memory', '128m', '--cpus', '0.5', '--pids-limit', '64', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
      ...(!preparedRuntime ? ['-v', `${resolve(fixtureDir)}:/fixture:ro`] : []), '-v', `${fakeHome}:/home/test:ro`,
      '-v', `${OBSERVER_DIR}:/observer:ro`,
      '-e', 'MCP_EXFIL_URL=http://exfil-sink:8080/events', '-e', 'MCP_CANARY_PATH=/home/test/.env', '-e', 'HOME=/home/test', '-e', 'MCP_CANARY_ROOT=/home/test',
      '-e', `MCP_SINK_TOKEN=${token}`, '-e', `MCP_PROBE_CALLS=${JSON.stringify(probeCalls)}`,
      ...(preparedRuntime ? ['-e', 'MCP_PREPARED_NODE_RESTRICTIONS=1'] : []), image, ...(preparedRuntime ? [] : ['node']),
      ...(mcpProbe ? ['/observer/mcp-probe.cjs'] : ['--require', '/observer/observer-preload.cjs']), candidateEntrypoint,
    ], { timeoutMs });
    let events = '';
    try { events = await readFile(eventsPath, 'utf8'); } catch { /* no exfil event */ }
    const parsedEvents = events.split(/\r?\n/).filter(Boolean).flatMap((line) => { try { return [JSON.parse(line)]; } catch { return []; } });
    const observedCanary = canaries.find(({ hash }) => parsedEvents.some((event) => event.canaryHash === hash));
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
      canaryObserved: Boolean(observedCanary),
      canaryHash: observedCanary?.hash ?? canaryHash,
      canaryType: observedCanary?.type ?? null,
      observations: observationsFrom(fixture.stderr),
      egressEvents: parsedEvents.filter((event) => event.type),
      ...(mcpProbe ? { mcpReport } : {}),
      ...(preparedRuntime ? { runtimeIdentity: preparedRuntime } : {}),
    };
  } finally {
    await dockerCleanup([fixtureName, sinkName], networkName);
    await rm(tempDir, { recursive: true, force: true });
  }
}

export async function runSandbox(options) {
  if (options.preparedRuntime) {
    const runtime = options.preparedRuntime;
    if (options.mode !== 'docker' || options.mcpProbe !== true || options.fixtureDir || options.entrypoint ||
      !/^sha256:[a-f0-9]{64}$/.test(runtime.imageDigest ?? '') || runtime.platform?.os !== 'linux' ||
      !['amd64', 'arm64'].includes(runtime.platform?.architecture) || !Array.isArray(runtime.argv) || runtime.argv.length !== 2 ||
      runtime.argv[0] !== '/usr/local/bin/node' || !/^\/app\/[A-Za-z0-9_@./-]+\.(?:js|mjs|cjs)$/.test(runtime.argv[1]) ||
      runtime.argv[1].split('/').slice(1).some((part) => !part || part === '.' || part === '..')) throw new TypeError('PREPARED_SANDBOX_INPUT_INVALID');
  }
  if (options.egressAllowHosts && (!Array.isArray(options.egressAllowHosts) || options.egressAllowHosts.length > 32 || options.egressAllowHosts.some((name) => !/^[a-z0-9][a-z0-9.-]*\.(?:local|test)$/.test(name)))) throw new TypeError('proxy allowlist only accepts synthetic hosts');
  if (options.mcpProbe && options.mode !== 'docker') throw new TypeError('ingested MCP discovery requires Docker isolation');
  if (options.probeCalls && (!Array.isArray(options.probeCalls) || options.probeCalls.length > 8 || JSON.stringify(options.probeCalls).length > 16_384)) throw new TypeError('MCP probe calls exceed limit');
  if (options.mode === 'local') return runLocal(options);
  if (options.mode === 'docker') return runDocker(options);
  throw new TypeError(`unknown sandbox mode: ${options.mode}`);
}
