import assert from 'node:assert/strict';
import test from 'node:test';
import { waitForSink } from '../../services/scanner/src/sandbox.mjs';

const name = 'mcpshield-sink-0123456789ab';
const success = (stdout = '') => ({ code: 0, timedOut: false, stdout, stderr: '' });
const running = () => success(JSON.stringify({ state: { Status: 'running', ExitCode: 0, OOMKilled: false }, image: 'sha256:' + 'a'.repeat(64) }));

test('sink readiness uses actual HTTP health, not a stale READY log, and keeps one fixed total work budget', async () => {
  const calls = [];
  await waitForSink(name, 100, async (command, args, options) => {
    calls.push({ command, args, options }); return success('READY');
  });
  assert.equal(calls.length, 1); assert.equal(calls[0].args[0], 'exec');
  assert.equal(calls[0].args[1], name); assert.match(calls[0].args.at(-1), /127\.0\.0\.1:8080\/health/);
  assert.ok(calls[0].options.timeoutMs <= 100);
  await assert.rejects(() => waitForSink('arbitrary-container', 100), /INPUT_INVALID/);
  await assert.rejects(() => waitForSink(name, 30, async (_command, args) => args[0] === 'exec' ? { ...success(), code: 2 } :
    args[0] === 'inspect' ? running() : success('READY http://0.0.0.0:8080/events\n')), (error) => {
    assert.equal(error.diagnostics.logReady, true);
    assert.equal(error.diagnostics.state, 'running');
    assert.equal(error.diagnostics.healthExit, 2);
    return /DOCKER_CONTROL_OR_HEALTH_FAILURE/.test(error.message);
  });
});

test('Docker control timeout and exited sink diagnostics are fixed codes/counts/hashes, never raw private logs', async () => {
  const privateText = 'SYNTHETIC_PRIVATE_PATH_OR_TOKEN_MUST_NOT_APPEAR';
  await assert.rejects(() => waitForSink(name, 30, async (_command, args) => args[0] === 'inspect' ? running() :
    { code: null, timedOut: true, stdout: '', stderr: privateText }), (error) => {
    assert.ok(error.diagnostics.commandTimeouts > 0);
    assert.equal(error.message.includes(privateText), false);
    return /DOCKER_CONTROL_TIMEOUT/.test(error.message);
  });
  await assert.rejects(() => waitForSink(name, 100, async (_command, args) => args[0] === 'inspect'
    ? success(JSON.stringify({ state: { Status: 'exited', ExitCode: 1, OOMKilled: false }, image: 'invalid' }))
    : { code: 1, timedOut: false, stdout: '', stderr: `EACCES ${privateText}` }), (error) => {
    assert.equal(error.diagnostics.state, 'exited'); assert.equal(error.diagnostics.imageDigest, null);
    assert.equal(error.message.includes(privateText), false);
    return /PERMISSION_DENIED/.test(error.message);
  });
});
