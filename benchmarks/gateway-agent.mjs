import { createHash, randomUUID } from 'node:crypto';
import { realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { z } from 'zod';
import { decideAgentCalls } from './agent-mcp-harness.mjs';
import { canonicalJson } from '../services/scanner/src/evidence.mjs';
import { redactEvidenceDocument } from '../services/scanner/src/redaction.mjs';
import { createGatewayClient, gatewayControlEnvironmentKeys } from '../scripts/demo/mcp-client.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const loopbackHosts = ['127.0.0.1', 'localhost', '[::1]'];
const hash = value => `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const admissionFields = ['time', 'phase', 'toolName', 'releaseId', 'controlReleaseId', 'artifactDigest', 'manifestDigest',
  'toolSurfaceHash', 'policyHash', 'chainId', 'registryContract', 'decision', 'status', 'reasonCode', 'source', 'decisionSource', 'cacheHit', 'expiresAt'];
const mailResult = z.object({ ok: z.literal(true).optional(), total: z.number().int().min(1).optional(),
  messages: z.array(z.object({ id: z.string().min(1).max(128), subject: z.string().min(1).max(512) })).min(1).max(10) })
  .refine(value => value.total === undefined || value.total >= value.messages.length);

export function validateMailTools(tools, nextCursor) {
  const tool = tools?.[0], schema = tool?.inputSchema;
  // Both authored mail profiles are reads. Missing hints are NOT promoted to read-only admission;
  // Gateway still classifies them conservatively and enforces their signed operation class.
  if (nextCursor || tools?.length !== 1 || tool.name !== 'list_messages' || tool.annotations?.readOnlyHint === false ||
    tool.annotations?.destructiveHint === true || schema?.type !== 'object' || schema.additionalProperties !== false ||
    Object.keys(schema.properties ?? {}).some(key => key !== 'limit') || (schema.required ?? []).some(key => key !== 'limit') ||
    (schema.properties?.limit && (schema.properties.limit.type !== 'integer' || schema.properties.limit.minimum !== 1 || schema.properties.limit.maximum !== 10))) throw new Error('AGENT_MAIL_PROFILE_REQUIRED');
}

export function syntheticMailSubjects(result) {
  if (result.isError) return null;
  try {
    const payload = mailResult.parse(JSON.parse(result.content?.find(item => item.type === 'text')?.text));
    return redactEvidenceDocument(payload.messages.map(message => message.subject));
  } catch { return null; }
}

// This is the protected ON path, not an OFF/ON ASR evaluator. No bypass is exposed.
export async function runGatewayAgent({ preparedIdentityPath, apiUrl, controlEnvironment = {},
  localContractTest = false, artifactDir, replayFile, allowRemoteAi = false, ai = {},
  userTask = 'Show the subject of the latest synthetic email.', timeoutMs = 10_000 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new TypeError('Gateway timeout must be 1..120000 ms');
  if (localContractTest) {
    const endpoint = new URL(ai.url);
    if ((ai.provider ?? 'custom') !== 'custom' || !loopbackHosts.includes(endpoint.hostname)) throw new TypeError('contract tests require a loopback fake provider');
    const candidate = await realpath(artifactDir);
    const authored = await Promise.all(['1.0.0', '1.0.1'].map(version => realpath(resolve(root, `demo/fixtures/mail-mcp-${version}`))));
    if (!authored.includes(candidate) || preparedIdentityPath || Object.keys(controlEnvironment).length || !replayFile) throw new TypeError('contract tests permit only authored replay fixtures');
  } else if (!allowRemoteAi || !preparedIdentityPath || artifactDir || replayFile || !controlEnvironment.MCPSHIELD_POLICY_HASH) {
    throw new TypeError('live Agent requires explicit AI opt-in and prepared signed admission; no host fixture fallback');
  }
  const gateway = createGatewayClient({ root, artifactDir, preparedIdentityPath, apiUrl, controlEnvironment,
    mode: localContractTest ? 'replay' : 'live', replayFile });
  const report = { schemaVersion: '1.0.0', runId: randomUUID(), startedAt: new Date().toISOString(),
    evidenceKind: localContractTest ? 'LOCAL_PROVIDER_CONTRACT_TEST' : 'PREPARED_GATEWAY_AGENT_RUN',
    modelEvidenceMode: 'NOT_ATTEMPTED', providerQuality: 'NOT_MEASURED',
    protection: 'ON', admissionMode: 'strict', asrMeasured: false, modelAttempted: false, taskCompleted: false,
    userTaskHash: hash(redactEvidenceDocument(userTask)), toolRequests: [], admissions: [],
    limitations: ['Single-turn synthetic mail Agent; no multi-turn or OFF/ON ASR claim.',
      'Gateway logs are diagnostic identity/decision traces, not independent chain or candidate-spawn proof.',
      'taskCompleted confirms the tool result, not independent proof of candidate-container cleanup.',
      'Prepared network-none execution is stricter than the scanner observation network.'] };
  let phase = 'CONNECT';
  try {
    await gateway.client.connect(gateway.transport, { timeout: timeoutMs });
    phase = 'DISCOVERY';
    const { tools, nextCursor } = await gateway.client.listTools({}, { timeout: timeoutMs });
    // ponytail: this demo is one read-only mail tool; expand only with a separately reviewed synthetic profile.
    validateMailTools(tools, nextCursor);
    report.toolsCatalogueHash = hash(tools);
    phase = 'MODEL';
    report.modelAttempted = true;
    report.modelEvidenceMode = loopbackHosts.includes(new URL(ai.url ?? 'https://api.openai.com/v1/responses').hostname)
      ? 'LOCAL_CONTRACT_TEST' : 'EXTERNAL_PROVIDER_RESPONSE_UNVERIFIED';
    const decision = await decideAgentCalls({ ...ai, userTask, tools });
    report.model = decision.model;
    report.decisionStatus = decision.status;
    report.disposition = decision.disposition;
    report.selectedCallsHash = hash(decision.calls);
    report.status = decision.status !== 'VALID' ? 'MODEL_INVALID' : !decision.calls.length ? 'MODEL_NO_CALL' : 'TOOL_ERROR';
    if (decision.calls.length > 1) {
      report.status = 'MODEL_INVALID';
      report.decisionStatus = 'INVALID_OR_OUT_OF_PROFILE';
      report.errorCode = 'AGENT_SINGLE_CALL_REQUIRED';
    } else if (decision.status === 'VALID') for (const call of decision.calls) {
      phase = 'CALL';
      const entry = { name: call.name, argumentsHash: hash(call.arguments), requestedAt: new Date().toISOString(), outcome: 'REQUEST_FAILED' };
      report.toolRequests.push(entry);
      const result = await gateway.client.callTool(call, { timeout: timeoutMs });
      entry.outcome = result.isError ? 'TOOL_ERROR' : 'RESULT_RECEIVED';
      entry.result = redactEvidenceDocument(result);
      entry.completedAt = new Date().toISOString();
      if (result.isError) break;
      const subjects = syntheticMailSubjects(result);
      if (subjects) {
        report.subjects = subjects;
        report.taskCompleted = true;
      }
    }
    if (report.taskCompleted && report.toolRequests.every(call => call.outcome === 'RESULT_RECEIVED')) report.status = 'COMPLETED';
  } catch (error) {
    report.status = phase === 'MODEL' ? 'MODEL_ERROR' : 'GATEWAY_ERROR';
    report.failurePhase = phase;
    // Never print endpoint/token-bearing transport errors or untrusted protocol payloads.
    report.errorCode = /^AI_[A-Z_0-9]+$/.test(error.message) || error.message === 'AGENT_MAIL_PROFILE_REQUIRED' ? error.message : 'AGENT_REQUEST_FAILED';
  } finally {
    await gateway.close();
    report.admissions = gateway.stderr().split(/\r?\n/).flatMap(line => {
      try { const record = JSON.parse(line); return record.event === 'admission' ? [Object.fromEntries(admissionFields.filter(key => record[key] !== undefined).map(key => [key, record[key]]))] : []; }
      catch { return []; }
    });
    report.finishedAt = new Date().toISOString();
  }
  const blocked = report.admissions.findLast(record => record.decision === 'BLOCK');
  if (blocked && report.status === 'GATEWAY_ERROR') {
    report.status = 'GATEWAY_BLOCKED';
    report.reasonCode = blocked.reasonCode;
    report.userMessage = blocked.reasonCode === 'RELEASE_REVOKED' ? '안전하지 않은 도구로 확인되어 실행을 차단했습니다.' : '도구의 안전한 실행 승인을 확인할 수 없어 차단했습니다.';
  }
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const controlEnvironment = Object.fromEntries(gatewayControlEnvironmentKeys.filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
    const report = await runGatewayAgent({ preparedIdentityPath: process.env.MCPSHIELD_PREPARED_IDENTITY,
      apiUrl: process.env.MCPSHIELD_API_URL, controlEnvironment,
      allowRemoteAi: process.env.MCP_SHIELD_ENABLE_REMOTE_AI === 'true',
      ai: { provider: process.env.MCP_SHIELD_AI_PROVIDER ?? 'openai', url: process.env.MCP_SHIELD_AI_URL,
        model: process.env.MCP_SHIELD_AI_MODEL, token: process.env.MCP_SHIELD_AI_TOKEN,
        timeoutMs: 30_000, maxOutputTokens: 1024 } });
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (report.status !== 'COMPLETED' && report.status !== 'GATEWAY_BLOCKED') process.exitCode = 1;
  } catch {
    process.stderr.write('Agent configuration rejected. Use a prepared identity, pinned signed admission context and explicit AI opt-in.\n');
    process.exitCode = 1;
  }
}
