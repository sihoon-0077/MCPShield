import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { resolveOciArtifact } from '../../services/resolver/src/oci.mjs';

test('OCI acquisition shares one total deadline across auth/retry/stalled bodies and cancels initial 401', { timeout: 5000 }, async () => {
  for (const stalledStage of ['TOKEN', 'MANIFEST_BODY']) {
    let cancelled401 = false, calls = 0;
    const timers = [];
    const server = createServer((request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      if (request.url === '/token' && stalledStage !== 'TOKEN') {
        timers.push(setTimeout(() => response.end('{"token":"synthetic-anonymous-pull-token"}'), 40));
      } else { response.write('{"intentionally_stalled":'); }
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const fetchImpl = async (url, options) => {
        calls++;
        const target = new URL(url);
        assert.ok(['registry-1.docker.io', 'auth.docker.io'].includes(target.hostname));
        assert.equal(options.redirect, 'error');
        assert.ok(options.signal instanceof AbortSignal);
        if (calls === 1) return new Response(new ReadableStream({ cancel() { cancelled401 = true; } }), { status: 401 });
        if (target.hostname === 'auth.docker.io') {
          assert.equal(target.pathname, '/token');
          assert.equal(target.searchParams.get('scope'), 'repository:team/synthetic:pull');
          assert.equal(options.headers?.authorization, undefined);
        } else {
          assert.equal(options.headers.authorization, 'Bearer synthetic-anonymous-pull-token');
        }
        return fetch(`http://127.0.0.1:${server.address().port}/${target.hostname === 'auth.docker.io' ? 'token' : 'manifest'}`, options);
      };
      const started = Date.now();
      await assert.rejects(() => resolveOciArtifact({ type: 'oci', locator: 'registry-1.docker.io/team/synthetic:tag' },
        { fetchImpl, timeoutMs: 120 }), /OCI_ACQUISITION_TIMEOUT/);
      assert.equal(cancelled401, true);
      assert.equal(calls, stalledStage === 'TOKEN' ? 2 : 3);
      assert.ok(Date.now() - started < 1500, 'all requests share a bounded total acquisition deadline');
    } finally {
      for (const timer of timers) clearTimeout(timer);
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  }
});
