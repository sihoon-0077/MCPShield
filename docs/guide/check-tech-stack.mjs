// Run from the repository root: node docs/guide/check-tech-stack.mjs
// Checks this explainer's model, not the production security engine.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const html = readFileSync(new URL('./tech-stack-workflow.html', import.meta.url), 'utf8');
const model = html.match(/<script id="guide-model">([\s\S]*?)<\/script>/)?.[1];
const ui = html.match(/<script id="guide-ui">([\s\S]*?)<\/script>/)?.[1];
assert.ok(model && ui, 'Both local scripts must exist');
new vm.Script(ui);
const { flows, nodes, getStep } = vm.runInNewContext(`${model}\n;({flows,nodes,getStep});`, Object.create(null));
assert.equal(Object.keys(nodes).length, 8);
assert.deepEqual(Object.keys(flows), ['safe', 'malicious', 'uncertain', 'outage']);
for (const flow of Object.values(flows)) {
  assert.ok(flow.description && flow.summary && flow.steps.length);
  for (const stage of flow.steps) {
    for (const field of ['name', 'owner', 'title', 'description', 'input', 'output', 'status', 'note']) {
      assert.equal(typeof stage[field], 'string');
      assert.ok(stage[field].length, `Missing ${field}`);
    }
    assert.ok(['blue', 'green', 'red', 'amber'].includes(stage.tone));
  }
}
const statuses = mode => Array.from(flows[mode].steps, stage => stage.status);
assert.equal(statuses('safe').at(-1), 'EXECUTED');
assert.ok(statuses('safe').indexOf('VERIFIED') < statuses('safe').indexOf('ALLOW'));
assert.ok(statuses('malicious').indexOf('REVOKED') < statuses('malicious').lastIndexOf('BLOCK'));
assert.ok(statuses('uncertain').includes('ABSTAIN'));
assert.ok(statuses('outage').includes('UNAVAILABLE'));
for (const mode of ['malicious', 'uncertain', 'outage']) {
  assert.equal(statuses(mode).at(-1), 'BLOCK');
  assert.ok(!statuses(mode).some(status => ['ALLOW', 'EXECUTED'].includes(status)));
}
assert.ok(!statuses('outage').includes('REVOKED'), 'An outage must not be taught as malicious revocation');
assert.equal(getStep('safe', -1), flows.safe.steps[0]);
assert.equal(getStep('safe', 999), flows.safe.steps.at(-1));
assert.throws(() => getStep('unknown', 0));
const ids = Array.from(html.matchAll(/\bid="([^"]+)"/g), match => match[1]);
assert.equal(new Set(ids).size, ids.length, 'Duplicate HTML IDs');
for (const [, id] of html.matchAll(/href="#([^"]+)"/g)) assert.ok(ids.includes(id), `Missing anchor: ${id}`);
assert.ok(!/<(?:script|link|img)\b[^>]*(?:src|href)=["']https?:/i.test(html), 'Keep the guide usable offline');
console.log('PASS: 4 teaching flows, fail-closed boundaries, 8 architecture nodes, script syntax and offline document anchors.');
