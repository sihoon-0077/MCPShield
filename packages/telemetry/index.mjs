import { context, propagation, trace, metrics, ROOT_CONTEXT, SpanStatusCode } from '@opentelemetry/api';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { AlwaysOffSampler, NoopSpanProcessor } from '@opentelemetry/sdk-trace';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';

// Deliberate instrumentation only: automatic HTTP/DB instrumentation could copy
// source text, credential-bearing URLs, queries or tenant bodies into telemetry.
const attributeKeys = new Set([
  'mcpshield.scan_id', 'mcpshield.release_id', 'mcpshield.policy_hash_prefix',
  'mcpshield.artifact_digest_prefix', 'mcpshield.stage', 'mcpshield.finding_code',
  'mcpshield.verdict', 'mcpshield.validator_id', 'mcpshield.chain_id',
  'mcpshield.block_number', 'mcpshield.gateway_decision', 'mcpshield.source',
]);
const stages = new Set(['resolve', 'static', 'ai', 'sandbox', 'evidence', 'validator', 'chain', 'indexer', 'admission', 'scan', 'http']);
const traceparentPattern = /^00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-0[01]$/;
let sdk;

function collectorUrl(path) {
  const endpoint = new URL(process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://127.0.0.1:4318');
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname);
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
      (endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' &&
        (local || process.env.MCPSHIELD_OTEL_ALLOW_HTTP === 'true')))) {
    throw new Error('OTEL collector requires HTTPS or explicitly allowed internal HTTP');
  }
  return new URL(path, `${endpoint.href.replace(/\/$/, '')}/`).href;
}

export function startTelemetry() {
  if (sdk) return sdk;
  const enabled = process.env.MCPSHIELD_TELEMETRY_ENABLED === 'true';
  const resource = resourceFromAttributes({
    'service.name': (process.env.OTEL_SERVICE_NAME || 'mcpshield').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 64),
    'service.version': '0.2.0',
  });
  sdk = new NodeSDK({
    resource, autoDetectResources: false, instrumentations: [], logRecordProcessors: [],
    ...(enabled ? {
      traceExporter: new OTLPTraceExporter({ url: collectorUrl('v1/traces'), timeoutMillis: 3000 }),
      metricReaders: [new PeriodicExportingMetricReader({
        exporter: new OTLPMetricExporter({ url: collectorUrl('v1/metrics'), timeoutMillis: 3000 }),
        exportIntervalMillis: 15000, exportTimeoutMillis: 5000,
      })],
    // A processor registers the provider even without exports, so durable jobs
    // retain real trace IDs. No records or network exporters are created here.
    } : { spanProcessors: [new NoopSpanProcessor()], sampler: new AlwaysOffSampler(), metricReaders: [] }),
  });
  sdk.start();
  return sdk;
}

startTelemetry();
const tracer = trace.getTracer('mcpshield', '0.2.0');
const meter = metrics.getMeter('mcpshield', '0.2.0');
const stageDuration = meter.createHistogram('mcpshield.scan.stage.duration', { unit: 's', description: 'Observed instrumented stage duration, not a promised SLO' });
const stagesCompleted = meter.createCounter('mcpshield.scan.stages');
const admissionDecisions = meter.createCounter('mcpshield.admission.decisions');
const admissionLatency = meter.createHistogram('mcpshield.admission.latency', { unit: 's' });

function safeAttributes(attributes) {
  return Object.fromEntries(Object.entries(attributes || {}).filter(([key, value]) =>
    attributeKeys.has(key) && ((typeof value === 'number' && Number.isFinite(value)) ||
      (typeof value === 'string' && /^[a-zA-Z0-9._:@/-]{1,160}$/.test(value)))));
}

export function currentTraceId() {
  const id = trace.getSpan(context.active())?.spanContext().traceId;
  return typeof id === 'string' && /^(?!0{32})[0-9a-f]{32}$/.test(id) ? id : undefined;
}

export function traceHeaders() {
  const headers = {};
  propagation.inject(context.active(), headers);
  // Do not forward caller baggage or tracestate containing vendor/user data.
  return headers.traceparent ? { traceparent: headers.traceparent } : {};
}

export async function withSpan(name, attributes, fn, { traceparent } = {}) {
  if (!/^[a-z][a-z0-9._-]{0,63}$/.test(name)) throw new Error('Span name must be a bounded static identifier');
  const parent = typeof traceparent === 'string' && traceparentPattern.test(traceparent)
    ? propagation.extract(ROOT_CONTEXT, { traceparent }) : context.active();
  return tracer.startActiveSpan(name, { attributes: safeAttributes(attributes) }, parent, async (span) => {
    const started = performance.now();
    const candidate = name.split('.')[0];
    const stage = stages.has(candidate) ? candidate : 'other';
    let result = 'success';
    try {
      return await fn(span);
    } catch (error) {
      result = 'error';
      // Exception messages/stacks can include source text or credentials.
      span.setStatus({ code: SpanStatusCode.ERROR, message: 'STAGE_FAILED' });
      throw error;
    } finally {
      stageDuration.record((performance.now() - started) / 1000, { stage, result });
      stagesCompleted.add(1, { stage, result });
      span.end();
    }
  });
}

export function recordAdmission({ decision, riskTier, source, durationSeconds }) {
  const labels = {
    decision: ['ALLOW', 'BLOCK', 'DENY'].includes(decision) ? decision : 'UNKNOWN',
    risk_tier: ['READ_PUBLIC', 'READ_PRIVATE'].includes(riskTier) ? 'READ_ONLY'
      : ['READ_ONLY', 'WRITE', 'WRITE_EXTERNAL', 'DESTRUCTIVE', 'FINANCIAL'].includes(riskTier) ? riskTier : 'UNKNOWN',
    source: source === 'EVM' ? 'LIVE' : ['LIVE', 'LOCAL_DEMO', 'CACHE', 'REPLAY', 'MOCK'].includes(source) ? source : 'UNKNOWN',
  };
  admissionDecisions.add(1, labels);
  if (Number.isFinite(durationSeconds) && durationSeconds >= 0) admissionLatency.record(durationSeconds, labels);
}

export async function shutdownTelemetry() {
  await sdk?.shutdown();
}
