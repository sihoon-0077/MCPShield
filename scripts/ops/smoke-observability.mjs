import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { setTimeout } from 'node:timers/promises';

// CI/local loopback only. Emit MOCK data, never fabricate live admission measurements.
assert.match(process.env.MCPSHIELD_GRAFANA_ADMIN_PASSWORD ?? '', /^[a-f0-9]{64}$/);
const url = 'http://127.0.0.1:3100/apis/dashboard.grafana.app/v1/namespaces/default/dashboards/mcpshield-operations';
const headers = { authorization: `Basic ${Buffer.from(`operator:${process.env.MCPSHIELD_GRAFANA_ADMIN_PASSWORD}`).toString('base64')}` };
const denied = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(5000) });
assert.ok([401, 403].includes(denied.status), 'Anonymous metrics dashboard must not be exposed');
const response = await fetch(url, { headers, redirect: 'error', signal: AbortSignal.timeout(5000) });
assert.equal(response.status, 200, 'Provisioned Grafana dashboard was not retrievable');
const actual = await response.json();
const expected = JSON.parse(await readFile(new URL('../../deploy/observability/grafana/dashboards/operations.json', import.meta.url)));
assert.equal(actual.kind, 'Dashboard'); assert.equal(actual.spec.title, expected.title);
assert.deepEqual(actual.spec.panels.map(p => p.targets?.[0]?.expr).filter(Boolean), expected.panels.map(p => p.targets?.[0]?.expr).filter(Boolean));
process.env.MCPSHIELD_TELEMETRY_ENABLED = 'true';
process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'http://127.0.0.1:4318';
process.env.OTEL_SERVICE_NAME = 'mcpshield-observability-smoke';
const { withSpan, recordAdmission, shutdownTelemetry } = await import('../../packages/telemetry/index.mjs');
await withSpan('admission.smoke', { 'mcpshield.source': 'MOCK' }, () => {
  recordAdmission({ decision: 'BLOCK', source: 'MOCK', riskTier: 'READ_ONLY', durationSeconds: 0.01 });
});
await shutdownTelemetry();
const query = async expression => {
  const result = await fetch(`http://127.0.0.1:9090/api/v1/query?query=${encodeURIComponent(expression)}`, { redirect: 'error', signal: AbortSignal.timeout(3000) });
  assert.equal(result.status, 200, 'Prometheus query failed');
  const body = await result.json(); assert.equal(body.status, 'success'); return body.data.result;
};
let observed = false;
for (let attempt = 0; attempt < 40; attempt++) {
  const result = await query('sum(mcpshield_admission_decisions_total{source="MOCK",decision="BLOCK"})');
  if (result.length && Number(result[0].value[1]) >= 1) { observed = true; break; }
  await setTimeout(1000);
}
assert.ok(observed, 'Actual exporter → collector → Prometheus metric was not observed');
for (const panel of expected.panels.filter(p => p.targets)) await query(panel.targets[0].expr);
console.log(JSON.stringify({ dashboardProvisioning: 'PASS', anonymousDenied: true, actualMetricPipeline: 'PASS', emittedData: 'SYNTHETIC_MOCK', panelQueriesParsed: 6, noDataIsNotZero: true }));
