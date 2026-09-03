import { randomBytes, createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { startSink } from '../../exfil-sink/server.mjs';

export const DEMO_CANARY = 'MCP_SHIELD_DEMO_CANARY_v1';
const HERE = dirname(fileURLToPath(import.meta.url));
const SINK_DIR = resolve(HERE, '../../exfil-sink');

function run(command, args, { cwd, env, timeoutMs = 5_000 } = {}) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(command, args, { cwd, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
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

function fixtureCommand(fixtureDir, entrypoint, exfilUrl, canaryPath, token) {
  return {
    command: process.execPath,
    args: [resolve(fixtureDir, entrypoint)],
    cwd: fixtureDir,
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      WINDIR: process.env.WINDIR,
      MCP_EXFIL_URL: exfilUrl,
      MCP_CANARY_PATH: canaryPath,
      MCP_SINK_TOKEN: token,
    },
  };
}

async function runLocal({ fixtureDir, entrypoint, timeoutMs }) {
  const tempDir = await mkdtemp(join(tmpdir(), 'mcpshield-'));
  const canaryPath = join(tempDir, 'canary.txt');
  const token = randomBytes(24).toString('hex');
  const canaryHash = createHash('sha256').update(DEMO_CANARY).digest('hex');
  await writeFile(canaryPath, DEMO_CANARY, { encoding: 'utf8', mode: 0o400 });
  const sink = await startSink({ token });
  try {
    const spec = fixtureCommand(fixtureDir, entrypoint, sink.url, canaryPath, token);
    const processResult = await run(spec.command, spec.args, { ...spec, timeoutMs });
    return {
      mode: 'LOCAL_PROCESS',
      timedOut: processResult.timedOut,
      exitCode: processResult.code,
      error: processResult.code === 0 || processResult.timedOut ? null : 'fixture exited unsuccessfully',
      canaryObserved: sink.events.some((event) => event.canaryHash === canaryHash),
      canaryHash,
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

async function runDocker({ fixtureDir, entrypoint, timeoutMs }) {
  if (!await dockerAvailable()) throw new Error('Docker sandbox requested but Docker is unavailable');
  const suffix = randomBytes(6).toString('hex');
  const networkName = `mcpshield-${suffix}`;
  const sinkName = `mcpshield-sink-${suffix}`;
  const fixtureName = `mcpshield-fixture-${suffix}`;
  const tempDir = await mkdtemp(join(tmpdir(), 'mcpshield-docker-'));
  const canaryPath = join(tempDir, 'canary.txt');
  const eventsPath = join(tempDir, 'events.jsonl');
  const token = randomBytes(24).toString('hex');
  const canaryHash = createHash('sha256').update(DEMO_CANARY).digest('hex');
  await writeFile(canaryPath, DEMO_CANARY, { encoding: 'utf8', mode: 0o400 });
  try {
    const network = await run('docker', ['network', 'create', '--internal', networkName], { timeoutMs: 10_000 });
    if (network.code !== 0) throw new Error('failed to create isolated Docker network');
    const sink = await run('docker', [
      'run', '-d', '--name', sinkName, '--network', networkName, '--network-alias', 'exfil-sink',
      '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64',
      '-v', `${SINK_DIR}:/app:ro`, '-v', `${tempDir}:/events`,
      '-e', 'HOST=0.0.0.0', '-e', 'PORT=8080', '-e', `SINK_TOKEN=${token}`, '-e', 'EVENT_FILE=/events/events.jsonl',
      'node:22-alpine', 'node', '/app/server.mjs',
    ], { timeoutMs: 60_000 });
    if (sink.code !== 0) throw new Error('failed to start Docker exfil sink');
    await waitForSink(sinkName);
    const fixture = await run('docker', [
      'run', '--name', fixtureName, '--network', networkName, '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges', '--memory', '128m', '--cpus', '0.5', '--pids-limit', '64',
      '-v', `${resolve(fixtureDir)}:/fixture:ro`, '-v', `${canaryPath}:/run/secrets/mcpshield_canary:ro`,
      '-e', 'MCP_EXFIL_URL=http://exfil-sink:8080/events', '-e', 'MCP_CANARY_PATH=/run/secrets/mcpshield_canary',
      '-e', `MCP_SINK_TOKEN=${token}`, 'node:22-alpine', 'node', `/fixture/${entrypoint}`,
    ], { timeoutMs });
    let events = '';
    try { events = await readFile(eventsPath, 'utf8'); } catch { /* no exfil event */ }
    return {
      mode: 'DOCKER',
      timedOut: fixture.timedOut,
      exitCode: fixture.code,
      error: fixture.code === 0 || fixture.timedOut ? null : 'fixture exited unsuccessfully',
      canaryObserved: events.split(/\r?\n/).filter(Boolean).some((line) => JSON.parse(line).canaryHash === canaryHash),
      canaryHash,
    };
  } finally {
    await dockerCleanup([fixtureName, sinkName], networkName);
    await rm(tempDir, { recursive: true, force: true });
  }
}

export async function runSandbox(options) {
  if (options.mode === 'local') return runLocal(options);
  if (options.mode === 'docker') return runDocker(options);
  throw new TypeError(`unknown sandbox mode: ${options.mode}`);
}
