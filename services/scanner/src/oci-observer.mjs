import { randomBytes, randomUUID } from 'node:crypto';
import { chmod, mkdtemp, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { hashOciRuntimeDescriptor, ociHash, OCI_OBSERVATION_POLICY } from '../../resolver/src/oci-runtime-descriptor.mjs';
import { inspectImportedOciRuntime } from '../../resolver/src/oci-runtime.mjs';
import { runRuntimeDocker } from '../../resolver/src/npm-closure.mjs';
import { createCanaries } from './sandbox.mjs';
import { removeFixtureSnapshot } from './snapshot.mjs';
import { canonicalJson, createEvidenceBundle } from './evidence.mjs';
import { validateProbePlan, validateSyntheticToolCalls, generateSyntheticProbes } from './probes.mjs';
import { toolSurfaceHash } from './tool-surface.mjs';
import { redactEvidenceDocument } from './redaction.mjs';

const HERE = dirname(fileURLToPath(import.meta.url)), SINK = resolve(HERE, '../../exfil-sink');
const IMAGE = /^sha256:[a-f0-9]{64}$/;
const READ_EVENTS = "const r=await fetch('http://127.0.0.1:8080/events',{headers:{authorization:'Bearer '+process.env.SINK_TOKEN},signal:AbortSignal.timeout(2000)});if(!r.ok)process.exit(1);process.stdout.write(await r.text())";
async function readableSyntheticHome(root) {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (entry.isDirectory()) await readableSyntheticHome(join(root, entry.name));
    else await chmod(join(root, entry.name), 0o444);
  }
  await chmod(root, 0o555);
}

// Actual external SDK client. Candidate binaries never execute in this process.
// No roots, sampling, elicitation, filesystem or other server-request handlers.
export async function collectOciMcp({ container, calls = [], timeoutMs }) {
  if (!/^mcpshield-oci-candidate-[a-f0-9-]{36}$/.test(container)) throw Error('OCI_COLLECTOR_CONTAINER_INVALID');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const inner = new StdioClientTransport({ command: 'docker', args: ['start', '-ai', container], stderr: 'ignore', maxBufferSize: 64 * 1024 });
  let bytes = 0, messages = 0, protocolError = false;
  // Reuse SDK framing/JSON validation with a total parsed traffic budget as well
  // as its per-message bound. No candidate stderr or raw call result is retained.
  const transport = {
    start() {
      inner.onmessage = (message, extra) => {
        bytes += Buffer.byteLength(JSON.stringify(message)); messages++;
        if (bytes > 256 * 1024 || messages > 256) { protocolError = true; controller.abort(); void inner.close(); return; }
        transport.onmessage?.(message, extra);
      };
      inner.onerror = () => { protocolError = true; controller.abort(); transport.onerror?.(Error('OCI_MCP_PROTOCOL_FAILED')); };
      inner.onclose = () => transport.onclose?.();
      return inner.start();
    },
    send: (message) => inner.send(message), close: () => inner.close(),
    get pid() { return inner.pid; }, get stderr() { return inner.stderr; },
  };
  const client = new Client({ name: 'mcpshield-oci-observer', version: '1.0.0' }, {
    capabilities: {}, versionNegotiation: { mode: 'legacy' }, inputRequired: { autoFulfill: false }, enforceStrictCapabilities: true, listMaxPages: 32,
  });
  client.onerror = () => { protocolError = true; controller.abort(); };
  const options = () => ({ signal: controller.signal, timeout: Math.min(3000, timeoutMs), maxTotalTimeout: timeoutMs });
  try {
    await client.connect(transport, options());
    const tools = [], cursors = new Set();
    let cursor, pages = 0;
    do {
      const result = await client.request({ method: 'tools/list', params: cursor === undefined ? {} : { cursor } }, options());
      pages++;
      if (!Array.isArray(result.tools)) throw Error('OCI_MCP_TOOLS_INVALID');
      tools.push(...result.tools);
      if (tools.length > 128 || Buffer.byteLength(JSON.stringify(tools)) > 60 * 1024 || new Set(tools.map((tool) => tool.name)).size !== tools.length) throw Error('OCI_MCP_SURFACE_LIMIT');
      cursor = result.nextCursor;
      if (cursor !== undefined && (typeof cursor !== 'string' || !cursor || cursor.length > 1024 || cursors.has(cursor) || pages >= 32)) throw Error('OCI_MCP_PAGINATION_INVALID');
      cursors.add(cursor);
    } while (cursor !== undefined);
    const callResults = [];
    for (const call of validateSyntheticToolCalls(calls, tools)) {
      // The SDK's structural RPC schema is used; candidate output JSON Schema
      // is not compiled or used to generate code in this trusted process.
      const result = await client.request({ method: 'tools/call', params: call }, options());
      callResults.push({ name: call.name, isError: result.isError === true, contentHash: ociHash(canonicalJson(result)) });
    }
    if (protocolError || controller.signal.aborted) throw Error('OCI_MCP_PROTOCOL_FAILED');
    return { complete: true, tools, toolSurfaceHash: toolSurfaceHash(tools), pages, callResults, protocolVersion: client.getNegotiatedProtocolVersion(), receivedBytes: bytes };
  } catch {
    return { complete: false, tools: [], callResults: [], error: controller.signal.aborted ? 'OCI_MCP_TIMEOUT_OR_PROTOCOL_LIMIT' : 'OCI_MCP_PROTOCOL_FAILED' };
  } finally { clearTimeout(timer); controller.abort(); await client.close().catch(() => inner.close()); }
}

async function runOciStep({ descriptor, sinkImageDigest, calls, timeoutMs }) {
  const suffix = randomUUID(), candidate = `mcpshield-oci-candidate-${suffix}`, sink = `mcpshield-oci-sink-${suffix}`;
  const network = `mcpshield-oci-net-${suffix}`;
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-oci-observe-'));
  const home = join(workspace, 'home'), token = randomBytes(24).toString('hex');
  const canaries = await createCanaries(home);
  await readableSyntheticHome(home);
  const isolation = ['--pull=never', '--read-only', '--user=1000:1000', '--cap-drop=ALL', '--security-opt=no-new-privileges',
    '--pids-limit=64', '--memory=256m', '--cpus=1', '--no-healthcheck', '--tmpfs=/tmp:rw,noexec,nosuid,size=32m'];
  try {
    await runRuntimeDocker(['network', 'create', '--internal', network], 5000);
    await runRuntimeDocker(['run', '-d', '--name', sink, '--network', network, '--network-alias=exfil-sink', ...isolation,
      '--entrypoint=/usr/local/bin/node', '--mount', `type=bind,source=${SINK},target=/observer-sink,readonly`,
      '-e', 'HOST=0.0.0.0', '-e', 'PORT=8080',
      '-e', `SINK_TOKEN=${token}`, '-e', 'EGRESS_ALLOW_HOSTS=mail-api.local,exfil-sink.local',
      sinkImageDigest, '/observer-sink/server.mjs'], 5000);
    let ready = false;
    for (let attempt = 0; attempt < 40; attempt++) {
      if ((await runRuntimeDocker(['logs', sink], 1000)).toString().startsWith('READY http://')) { ready = true; break; }
      await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }
    if (!ready) throw Error('OCI_SYNTHETIC_SINK_UNAVAILABLE');
    await runRuntimeDocker(['create', '--interactive', '--name', candidate, '--network', network, '--dns=127.0.0.1', ...isolation,
      '--entrypoint', descriptor.argv[0], '--workdir', descriptor.workingDirectory,
      '--mount', `type=bind,source=${home},target=/home/test,readonly`,
      '-e', 'HOME=/home/test', '-e', 'MCP_CANARY_ROOT=/home/test', '-e', 'MCP_CANARY_PATH=/home/test/.env',
      '-e', 'MCP_EXFIL_URL=http://exfil-sink:8080/events', '-e', `MCP_SINK_TOKEN=${token}`,
      '-e', `HTTP_PROXY=http://mcpshield:${token}@exfil-sink:8080`, '-e', `http_proxy=http://mcpshield:${token}@exfil-sink:8080`,
      descriptor.finalImageDigest, ...descriptor.argv.slice(1)], 5000);
    const mcp = await collectOciMcp({ container: candidate, calls, timeoutMs });
    // Stop the candidate before taking the collector's final event snapshot.
    await runRuntimeDocker(['rm', '-f', candidate], 5000);
    const received = JSON.parse(await runRuntimeDocker(['exec', sink, '/usr/local/bin/node', '--input-type=module', '-e', READ_EVENTS], 3000));
    if (!Array.isArray(received.events) || received.events.length > 1024) throw Error('OCI_SINK_EVIDENCE_INVALID');
    const leaks = canaries.filter((canary) => received.events.some((event) => event.canaryHash === canary.hash));
    return { mcp, runtimeDigest: hashOciRuntimeDescriptor(descriptor),
      canaryHashes: leaks.map(({ hash }) => hash), canaryTypes: leaks.map(({ type }) => type),
      undeclaredEgress: received.events.some(({ type }) => type === 'EGRESS_BLOCKED'),
      eventBodyLimit: received.events.some(({ type }) => type === 'EGRESS_BODY_LIMIT'),
      eventCount: received.events.length, source: 'LIVE_DOCKER_EXTERNAL_MCP_CLIENT' };
  } finally {
    for (const args of [['rm', '-f', candidate], ['rm', '-f', sink], ['network', 'rm', network]]) {
      try { await runRuntimeDocker(args, 5000); } catch { /* exact task-owned resources */ }
    }
    await removeFixtureSnapshot(workspace);
  }
}

export async function readOciObservationPolicy(sinkImageDigest) {
  if (!IMAGE.test(sinkImageDigest)) throw Error('OCI_TRUSTED_SINK_IMAGE_REQUIRED');
  return { ...OCI_OBSERVATION_POLICY, sinkImageDigest, collectorDigest: ociHash(await readFile(fileURLToPath(import.meta.url))),
    sinkCodeDigest: ociHash(await readFile(join(SINK, 'server.mjs'))), clientSdk: '@modelcontextprotocol/client@2.0.0',
    protocolMode: '2025_LEGACY_NO_SIBLING_NEGOTIATION', egressAllowHosts: ['exfil-sink.local', 'mail-api.local'] };
}

export async function observeOciRuntime({ descriptor, expectedDescriptorDigest, sinkImageDigest, probePlan, ai, timeoutMs = 15_000 }) {
  if (hashOciRuntimeDescriptor(descriptor) !== expectedDescriptorDigest || descriptor.stage !== 'IMPORTED' || !IMAGE.test(sinkImageDigest) ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30_000 || probePlan && ai?.allowRemoteAi) throw Error('OCI_OBSERVATION_INPUT_INVALID');
  const steps = {}, issues = [], findings = [];
  let plan = { scenarios: [] }, observedDescriptor = null;
  const executionPolicy = await readOciObservationPolicy(sinkImageDigest);
  try {
    await inspectImportedOciRuntime({ descriptor, expectedDescriptorDigest });
    const image = JSON.parse(await runRuntimeDocker(['image', 'inspect', sinkImageDigest, '--format', '{{json .}}'], 5000));
    if (image.Id !== sinkImageDigest || image.Os !== 'linux' || image.Architecture !== descriptor.platform.architecture ||
      image.Config?.Labels?.['io.mcpshield.runtime-builder'] !== 'node-closure-v1') throw Error('OCI_TRUSTED_SINK_IMAGE_REQUIRED');
    const run = (calls) => runOciStep({ descriptor, sinkImageDigest, calls, timeoutMs });
    steps.discovery = await run([]);
    if (!steps.discovery.mcp.complete) throw Error('OCI_DISCOVERY_INCOMPLETE');
    observedDescriptor = { ...descriptor, stage: 'OBSERVED', toolSurfaceHash: steps.discovery.mcp.toolSurfaceHash };
    plan = probePlan ? validateProbePlan(probePlan, steps.discovery.mcp.tools) : ai?.allowRemoteAi ?
      await generateSyntheticProbes({ ...ai, tools: steps.discovery.mcp.tools }) : { scenarios: [] };
    if (!plan.scenarios.length) throw Error('OCI_NORMAL_AND_ADVERSARIAL_PROBES_REQUIRED');
    for (const [stage, kind] of [['normal', 'NORMAL'], ['adversarial', 'ADVERSARIAL']]) steps[stage] = await run(plan.scenarios.filter((scenario) => scenario.kind === kind).map(({ toolCall }) => toolCall));
  } catch (error) { issues.push(/^OCI_[A-Z_]+$/.test(error.message) ? error.message : 'OCI_OBSERVATION_FAILED'); }
  for (const [stage, step] of Object.entries(steps)) {
    if (step.canaryHashes.length) findings.push({ code: 'CANARY_EXFILTRATION', stage, deterministic: true, severity: 'CRITICAL',
      observer: 'INDEPENDENT_SYNTHETIC_SINK', canaryHashes: step.canaryHashes });
    if (step.undeclaredEgress) findings.push({ code: 'UNDECLARED_EGRESS', stage, deterministic: true, severity: 'HIGH', observer: 'INDEPENDENT_SYNTHETIC_PROXY' });
    if (step.mcp.complete && step.mcp.toolSurfaceHash !== steps.discovery?.mcp.toolSurfaceHash) findings.push({ code: 'TOOL_SURFACE_CHANGED', stage, deterministic: true, severity: 'HIGH' });
  }
  const completed = ['discovery', 'normal', 'adversarial'].every((stage) => steps[stage]?.mcp.complete && !steps[stage].eventBodyLimit &&
    steps[stage].mcp.toolSurfaceHash === steps.discovery.mcp.toolSurfaceHash);
  const checks = { discoveryComplete: steps.discovery?.mcp.complete === true, toolSurfaceStable: completed,
    normalProbeComplete: steps.normal?.mcp.complete === true, adversarialProbeComplete: steps.adversarial?.mcp.complete === true,
    normalToolCallsSucceeded: Boolean(steps.normal?.mcp.complete && steps.normal.mcp.callResults.length && steps.normal.mcp.callResults.every((call) => !call.isError)),
    adversarialToolCallsSucceeded: Boolean(steps.adversarial?.mcp.complete && steps.adversarial.mcp.callResults.length && steps.adversarial.mcp.callResults.every((call) => !call.isError)) };
  const report = redactEvidenceDocument({ schemaVersion: 'mcpshield.oci-observation.v1', scanId: randomUUID(), profile: 'oci-container-v1',
    source: Object.keys(steps).length ? 'LIVE_DOCKER_EXTERNAL_MCP_CLIENT' : 'NOT_RUN', status: findings.length ? 'FAILED' : 'INCONCLUSIVE',
    ready: false, approvalVerdict: 'ABSTAIN', observationStatus: completed ? 'COMPLETED_LIMITED_OCI_PROFILE' : 'INCOMPLETE',
    fullBehaviorCoverage: false, filesystemObservation: 'NOT_OBSERVED', binarySemantic: 'NOT_REVIEWED',
    preparationDescriptorDigest: expectedDescriptorDigest, observedDescriptorDigest: observedDescriptor ? hashOciRuntimeDescriptor(observedDescriptor) : null,
    executionPolicyDigest: ociHash(canonicalJson(executionPolicy)), findings, issues, checks,
    scenarios: plan.scenarios, generation: plan.execution ?? { status: plan.scenarios.length ? 'MANUAL_VALIDATED' : 'NOT_GENERATED' },
    steps: Object.fromEntries(Object.entries(steps).map(([stage, step]) => { const { tools: _tools, ...mcp } = step.mcp; return [stage, { ...step, mcp }]; })),
    pending: ['OCI_FILESYSTEM_OBSERVATION', 'OCI_STATIC_SBOM_BINARY_REVIEW', 'OCI_INDEPENDENT_SIGNING_POLICY', 'OCI_GATEWAY_BINDING'] });
  // Raw tools and descriptors are private encrypted evidence only; never public logs.
  const bundle = createEvidenceBundle({ 'report.json': report, 'runtime/oci-descriptor.json': observedDescriptor ?? descriptor,
    'runtime/execution-policy.json': executionPolicy, 'runtime/tools.json': steps.discovery?.mcp.tools ?? [],
    'runtime/tools.redacted.json': redactEvidenceDocument(steps.discovery?.mcp.tools ?? []) });
  return { report, observedDescriptor, bundle };
}
