import type { Span } from '@opentelemetry/api';
import type { NodeSDK } from '@opentelemetry/sdk-node';
export function startTelemetry(): NodeSDK;
export function currentTraceId(): string | undefined;
export function traceHeaders(): { traceparent?: string };
export function withSpan<T>(name: string, attributes: Record<string, unknown>, fn: (span: Span) => Promise<T> | T, options?: { traceparent?: string }): Promise<T>;
export function recordAdmission(value: { decision: string; riskTier?: string; source: string; durationSeconds: number }): void;
export function shutdownTelemetry(): Promise<void>;
