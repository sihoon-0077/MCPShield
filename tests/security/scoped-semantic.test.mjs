import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { buildScopedSemanticInput, verifyScopedSemanticInput, reviewScopedSemantics, scopedSemanticPrompt, SCOPED_DISCLOSURE_POLICY } from '../../services/scanner/src/scoped-semantic.mjs';
import { redactPromptText } from '../../services/scanner/src/redaction.mjs';
import { canonicalJson } from '../../services/scanner/src/evidence.mjs';

const hash = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const content = '// harmless padding for an authored fixture\n'.repeat(30) + 'fetch("https://mail-api.local/messages");\n' + '// harmless end\n'.repeat(30);
const tools = [{ name: 'read_messages', description: 'Read packaged synthetic messages', inputSchema: { type: 'object', properties: {}, additionalProperties: false } }];
const original = () => ({ files: [{ path: '/private/operator/path/server.js', content, rawDigest: hash(content) }], tools,
  runtime: { profile: 'restricted-node-docker-v1', runtimeDigest: hash('actual runtime supplied by caller'), environmentDigest: hash('private environment, never sent') } });
const clean = { riskClaims: [], semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false };
const probes = { scenarios: [
  { scenarioId: 'normal', kind: 'NORMAL', goal: 'Read packaged data', toolName: 'read_messages', argumentsJson: '{}' },
  { scenarioId: 'boundary', kind: 'ADVERSARIAL', goal: 'Observe unrelated synthetic scope access', toolName: 'read_messages', argumentsJson: '{}' },
] };

test('scoped selection binds originals while excluding paths/env and limiting the union across all three roles', () => {
  const input = original(), selected = buildScopedSemanticInput(input);
  assert.equal(selected.proof.scopeComplete, true);
  assert.equal(verifyScopedSemanticInput({ ...input, ...selected }), true);
  const sent = canonicalJson(selected.input);
  assert.equal(sent.includes('/private/operator/path'), false);
  assert.equal(sent.includes(content), false);
  assert.equal(sent.includes('private environment, never sent'), false);
  assert.deepEqual(selected.proof.union.roles, ['analyzer', 'critic', 'probe']);
  assert.ok(selected.proof.union.sourceChars <= 32 * 1024);
  for (const file of selected.proof.union.selections) assert.ok(file.selectedChars <= Math.min(2048, file.redactedChars * 0.25));
  for (const role of selected.proof.union.roles) {
    const dto = JSON.parse(scopedSemanticPrompt(selected.input, role).split('\n').at(-1));
    delete dto.citations;
    assert.deepEqual(dto, JSON.parse(sent));
  }
  for (const mutate of [value => value.input.excerpts[0].content = 'fabricated benign snippet',
    value => value.proof.sourceInventoryDigest = hash('forged inventory'), value => value.proof.union.sourceChars = 0,
    value => value.proof.fullSourceCoverage = true, value => value.input.disclosurePolicy = 'LOCAL_CONTRACT_TEST']) {
    const bad = structuredClone(selected); mutate(bad);
    assert.equal(verifyScopedSemanticInput({ ...input, ...bad }), false);
  }
  assert.throws(() => buildScopedSemanticInput({ ...input, runtime: { ...input.runtime, environment: ['SECRET=PRIVATE'] } }), /RUNTIME_METADATA_INVALID/);
  assert.equal(verifyScopedSemanticInput({ ...input, tools: [{ ...tools[0], privateIgnoredMetadata: 'different' }], ...selected }), false);
});

test('scoped tools redact credential/canary descriptions, schema literal values and keys; private-key labels include PKCS8', () => {
  const canary = 'CANARY::CUSTOMER_RECORD_SYNTHETIC_123', credential = 'ghp_' + 'a'.repeat(24), queryToken = 'query-sensitive-value';
  const source = original();
  source.tools = [{ ...tools[0], description: `${canary} ${credential} https://host.test/?token=${queryToken}`,
    inputSchema: { ...tools[0].inputSchema, properties: { [canary]: { type: 'string', enum: [canary, credential], description: credential, default: 'UNSENT_DEFAULT', examples: ['UNSENT_EXAMPLE'] },
      password: { type: 'string', const: 'UNSENT_PASSWORD_LITERAL' } } } }];
  const selected = buildScopedSemanticInput(source), sent = canonicalJson(selected.input);
  for (const value of [canary, credential, queryToken, 'UNSENT_DEFAULT', 'UNSENT_EXAMPLE', 'UNSENT_PASSWORD_LITERAL']) assert.equal(sent.includes(value), false);
  for (const label of ['PRIVATE KEY', 'RSA PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'EC PRIVATE KEY']) {
    assert.equal(redactPromptText(`-----BEGIN ${label}-----\nSYNTHETIC_NOT_A_KEY\n-----END ${label}-----`), '[REDACTED_PRIVATE_KEY]');
  }
});

test('unreviewable changes, excessive risk coverage and whole source smuggled into metadata are explicitly incomplete', () => {
  for (const value of ['fetch("https://mail-api.local");', '// authored non-risk text\n'.repeat(30)]) {
    const result = buildScopedSemanticInput({ ...original(), files: [{ path: 'server.js', content: value }] });
    assert.equal(result.proof.scopeComplete, false);
  }
  const copied = buildScopedSemanticInput({ ...original(), tools: [{ ...tools[0], description: content }] });
  assert.ok(copied.proof.issues.includes('SCOPED_DISCLOSURE_UNION_EXCEEDED'));
  const repeated = buildScopedSemanticInput({ ...original(), files: [{ path: 'a.js', content: ('x'.repeat(100) + ' fetch(); ').repeat(100) }] });
  assert.ok(repeated.proof.issues.includes('SCOPED_RISK_SELECTION_BUDGET_EXCEEDED'));
  const unchanged = original(); unchanged.baselineFiles = unchanged.files;
  assert.equal(buildScopedSemanticInput(unchanged).input.excerpts.length, 0);
  const changed = original();
  changed.baselineFiles = [{ path: changed.files[0].path, content: content.replace('/messages', '/old-messages') }];
  changed.baselineTools = [{ ...tools[0], description: 'Previous declared purpose' }];
  const compared = buildScopedSemanticInput(changed);
  assert.equal(compared.proof.scopeComplete, true);
  assert.equal(compared.input.changes[0].kind, 'MODIFIED');
  assert.deepEqual(compared.proof.union.selections.map(({ side }) => side), ['before', 'after']);
  assert.equal(compared.input.baselineTools[0].description, 'Previous declared purpose');
});

async function server(context, handler) {
  const local = createServer(async (request, response) => {
    const chunks = []; for await (const part of request) chunks.push(part);
    handler(JSON.parse(Buffer.concat(chunks)), response);
  });
  await new Promise((done) => local.listen(0, '127.0.0.1', done));
  context.after(() => { local.closeAllConnections(); local.close(); });
  return `http://127.0.0.1:${local.address().port}`;
}

test('actual HTTP Responses contract sends one frozen scoped DTO to blind analyzer/critic/probe without tools or storage', async (context) => {
  const requests = [];
  const url = await server(context, (body, response) => {
    requests.push(body);
    const report = body.text.format.name.endsWith('_probe') ? probes : clean;
    response.end(JSON.stringify({ status: 'completed', model: 'synthetic-contract', output: [
      { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify(report) }] }], usage: { total_tokens: 100 } }));
  });
  const ai = { allowRemoteAi: true, disclosurePolicy: SCOPED_DISCLOSURE_POLICY, evidenceMode: 'LOCAL_CONTRACT_TEST',
    provider: 'openai', url, model: 'synthetic-contract', token: 'SYNTHETIC_NOT_REAL_KEY', timeoutMs: 1000 };
  const result = await reviewScopedSemantics({ ...original(), ai });
  assert.equal(result.scopeComplete, true); assert.equal(result.noUnresolvedRisk, true);
  assert.equal(result.approvalVerdict, 'ABSTAIN'); assert.equal(result.evidenceMode, 'LOCAL_CONTRACT_TEST');
  assert.equal(result.providerQuality, 'PROVIDER_QUALITY_NOT_MEASURED');
  assert.equal(result.fullSourceCoverage, false); assert.equal(requests.length, 3);
  for (const body of requests) {
    assert.deepEqual(body.tools, []); assert.equal(body.tool_choice, 'none'); assert.equal(body.store, false); assert.equal(body.text.format.strict, true);
    const dto = JSON.parse(body.input[0].content.split('\n').at(-1)); delete dto.citations;
    assert.deepEqual(dto, JSON.parse(canonicalJson(result.input)));
    assert.equal(body.input[0].content.includes('/private/operator/path'), false);
  }
  assert.equal(JSON.stringify(result).includes(ai.token), false);
  for (const override of [{ critic: { disclosurePolicy: undefined } }, { probe: { evidenceMode: 'PROVIDER_EXECUTION' } },
    { evidenceMode: undefined }, { disclosurePolicy: 'LOCAL_CONTRACT_TEST' }]) {
    assert.equal((await reviewScopedSemantics({ ...original(), ai: { ...ai, ...override } })).scopeComplete, false);
  }
  const oversized = { ...original(), files: [{ path: 'server.js', content: 'fetch("short")' }], ai };
  assert.equal((await reviewScopedSemantics(oversized)).scopeComplete, false);
  assert.equal(requests.length, 3, 'all role configurations and full union budget must pass before any HTTP call');
});

test('scoped critic incomplete response is not a clean semantic result and stops further disclosure', async (context) => {
  let count = 0;
  const url = await server(context, (_body, response) => { count++; response.end(JSON.stringify(count === 1 ? clean : { malformed: 'PRIVATE_PROVIDER_DIAGNOSTIC' })); });
  const result = await reviewScopedSemantics({ ...original(), ai: { allowRemoteAi: true, disclosurePolicy: SCOPED_DISCLOSURE_POLICY,
    evidenceMode: 'LOCAL_CONTRACT_TEST', provider: 'custom', url, timeoutMs: 1000 } });
  assert.equal(count, 2); assert.equal(result.scopeComplete, false); assert.equal(result.noUnresolvedRisk, false);
  assert.deepEqual(result.issues, ['SCOPED_CRITIC_INCOMPLETE']);
  assert.equal(JSON.stringify(result).includes('PRIVATE_PROVIDER_DIAGNOSTIC'), false);
});

test('metadata union rejects source split across fields, keys and arrays, including short sources, before any role sends HTTP', async (context) => {
  let count = 0;
  const url = await server(context, (body, response) => { count++; response.end(JSON.stringify(body.responseSchema.properties.scenarios ? probes : clean)); });
  const ai = { allowRemoteAi: true, disclosurePolicy: SCOPED_DISCLOSURE_POLICY, evidenceMode: 'LOCAL_CONTRACT_TEST', provider: 'custom', url, timeoutMs: 1000 };
  const source = Array.from({ length: 20 }, (_, index) => `const harmless${index}='synthetic${index}';\n`).join('');
  for (const raw of [source, "const x='demo';", 'x']) {
    const half = Math.ceil(raw.length / 2), parts = [raw.slice(0, half), raw.slice(half)];
    for (const changedTools of [
      [{ ...tools[0], description: parts[0], title: parts[1] }],
      [{ ...tools[0], description: parts[1], title: parts[0] }],
      [{ ...tools[0], inputSchema: { type: 'object', properties: Object.fromEntries(parts.filter(Boolean).map(part => [part, { type: 'string' }])) } }],
      [{ ...tools[0], inputSchema: { type: 'string', enum: [...parts].reverse() } }],
      [{ ...tools[0], inputSchema: { type: 'string', enum: Array.from(raw) } }],
    ]) {
      const files = [{ path: 'server.js', content: raw }];
      const result = await reviewScopedSemantics({ ...original(), files, baselineFiles: files, tools: changedTools, ai });
      assert.equal(result.scopeComplete, false);
      assert.ok(result.issues.includes('SCOPED_DISCLOSURE_UNION_EXCEEDED'));
      assert.equal(result.proof.union.snippetChars, 0);
      assert.equal(result.proof.union.metadataChars, raw.length);
      assert.equal(result.proof.union.sourceChars, raw.length);
      assert.deepEqual(Object.keys(result.reviews), []);
    }
  }
  assert.equal(count, 0, 'no analyzer, critic or probe may receive any fragment of the rejected DTO');
});

test('metadata plus selected snippets use one coverage budget and exact-fragment work is bounded before HTTP', async (context) => {
  let count = 0;
  const url = await server(context, (_body, response) => { count++; response.end(JSON.stringify(clean)); });
  const ai = { allowRemoteAi: true, disclosurePolicy: SCOPED_DISCLOSURE_POLICY, evidenceMode: 'LOCAL_CONTRACT_TEST', provider: 'custom', url, timeoutMs: 1000 };
  const mixed = original(); mixed.tools = [{ ...tools[0], description: content.slice(0, 200) }];
  const rejected = await reviewScopedSemantics({ ...mixed, ai });
  assert.ok(rejected.proof.union.snippetChars > 0);
  assert.ok(rejected.proof.union.sourceChars > rejected.proof.union.snippetChars);
  assert.ok(rejected.issues.includes('SCOPED_DISCLOSURE_UNION_EXCEEDED'));
  const large = original();
  large.files = [{ path: 'large.js', content: 'z'.repeat(8 * 1024 * 1024) }];
  large.baselineFiles = large.files;
  large.tools = [{ ...tools[0], description: 'public description '.repeat(3200) }];
  const started = performance.now(), bounded = await reviewScopedSemantics({ ...large, ai });
  assert.equal(bounded.scopeComplete, false);
  assert.ok(bounded.issues.includes('SCOPED_DISCLOSURE_WORK_INCOMPLETE'));
  assert.equal(bounded.proof.union.accounting.work, bounded.proof.union.limits.disclosureWork);
  assert.equal(bounded.proof.union.sourceChars, null);
  assert.equal(bounded.proof.union.accounting.arbitraryEncodedOrRewrittenData, 'NOT_PROVEN_SAFE');
  assert.ok(performance.now() - started < 10_000, '8 MiB source x near-limit metadata must not use quadratic searches');
  assert.equal(count, 0);
});
