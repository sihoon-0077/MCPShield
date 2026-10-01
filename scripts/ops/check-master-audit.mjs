import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// Recount the published ledger; this verifies arithmetic/shape, not audit judgments.
const report = new URL('../../docs/MASTER_REQUIREMENTS_AUDIT_2026-09-19.md', import.meta.url);
const rows = [], groups = ['핵심 FR', '추가: 비기능·확장', '추가: Backend·Trust·복구', '추가: 분석·평가·윤리', '추가: Gateway·운영·제출'];
let group = groups[0];
for (const line of readFileSync(report, 'utf8').split(/\r?\n/)) {
  const section = /^### 4\.([1-4]) /.exec(line);
  if (section) group = groups[Number(section[1])];
  if (!/^\| (?:FR|EX)-\d{3} \|/.test(line)) continue;
  const cells = line.split('|').slice(1, -1).map(value => value.trim());
  const core = cells[0].startsWith('FR-'), status = cells[core ? 3 : 4];
  assert.equal(cells.length, core ? 5 : 6, `column count: ${cells[0]}`);
  assert.ok(['완료', '부분', '미완료'].includes(status), `status: ${cells[0]}`);
  rows.push({ id: cells[0], status, group: core ? groups[0] : group });
}
assert.equal(new Set(rows.map(row => row.id)).size, rows.length, 'duplicate requirement ID');
const expected = [[1, 8], [101, 113], [201, 212], [301, 310], [401, 407]]
  .flatMap(([start, end]) => Array.from({ length: end - start + 1 }, (_, i) => `FR-${String(start + i).padStart(3, '0')}`));
assert.deepEqual(rows.filter(row => row.id.startsWith('FR-')).map(row => row.id).sort(), expected.sort());
const extras = rows.filter(row => row.id.startsWith('EX-')).map(row => row.id).sort();
assert.deepEqual(extras, extras.map((_, i) => `EX-${String(i + 1).padStart(3, '0')}`));
const coverage = readFileSync(report, 'utf8').split('## 2. 전체 원문 범위 확인')[1].split('## 3.')[0];
let coveredThrough = 0;
for (const match of coverage.matchAll(/^\| (\d+)–(\d+) \|/gm)) {
  assert.equal(Number(match[1]), coveredThrough + 1, 'source coverage gap/overlap');
  coveredThrough = Number(match[2]);
}
assert.equal(coveredThrough, 5997, 'full source coverage');
const count = list => {
  const result = Object.fromEntries(['완료', '부분', '미완료'].map(status => [status, list.filter(row => row.status === status).length]));
  return { 전체: list.length, ...result, 엄격완료율: (100 * result.완료 / list.length).toFixed(2) + '%', 착수범위: (100 * (result.완료 + result.부분) / list.length).toFixed(2) + '%' };
};
if (process.argv[2]) {
  const source = readFileSync(process.argv[2]);
  assert.equal(createHash('sha256').update(source).digest('hex'), '702268984174af450276b5292a4afccd6a4d5dce79738fe3abde41c4d30d4ea2');
  assert.equal(source.toString('utf8').split(/\r?\n/).length, 5997);
}
console.log(JSON.stringify({ 전체: count(rows), 영역별: Object.fromEntries(groups.map(name => [name, count(rows.filter(row => row.group === name))])) }, null, 2));
