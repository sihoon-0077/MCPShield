import { assertScanResult } from './schema.mjs';
import { assertCanonicalScanResult } from './protocol-schema.mjs';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

function scanEndpoint(apiUrl) {
  const endpoint = new URL(apiUrl);
  if (!['http:', 'https:'].includes(endpoint.protocol)) throw new TypeError('scanner API URL must use http or https');
  if (endpoint.protocol !== 'https:' && !LOOPBACK_HOSTS.has(endpoint.hostname)) {
    throw new TypeError('plaintext scanner API submission is allowed only on loopback');
  }
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new TypeError('scanner API URL must not contain credentials, query, or fragment');
  }
  if (endpoint.pathname === '/' || endpoint.pathname === '') endpoint.pathname = '/api/scans';
  if (!endpoint.pathname.endsWith('/api/scans')) throw new TypeError('scanner API URL must target /api/scans');
  return endpoint;
}

export async function submitScanResult({ apiUrl, token, result, timeoutMs = 5_000 } = {}) {
  if (!apiUrl) throw new TypeError('scanner API URL is required');
  if (typeof token !== 'string' || token.length < 16) throw new TypeError('SCANNER_API_TOKEN must contain at least 16 characters');
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60_000) throw new TypeError('submit timeout must be between 1 and 60000 ms');
  assertScanResult(result);
  assertCanonicalScanResult(result);
  if (result.source !== 'LIVE') throw new TypeError('only LIVE scan results may be submitted to the backend');

  const response = await fetch(scanEndpoint(apiUrl), {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(result),
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'error',
  });
  const text = (await response.text()).slice(0, 1_048_576);
  let payload;
  try { payload = text ? JSON.parse(text) : null; } catch { payload = { message: text }; }
  if (!response.ok) {
    const code = payload?.error?.code ?? payload?.code ?? `HTTP_${response.status}`;
    throw new Error(`scanner API rejected scan: ${code}`);
  }
  const accepted = assertCanonicalScanResult(assertScanResult(payload));
  if (accepted.scanId !== result.scanId || accepted.releaseId !== result.releaseId) {
    throw new Error('scanner API response does not match the submitted scan');
  }
  return { status: response.status, result: accepted };
}
