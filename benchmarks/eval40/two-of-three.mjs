// System-level view of eval40: three validators vote on each sample with the ReleaseRegistryV3 rule (two PASS approve,
// two FAIL revoke, anything else holds the release). A validator's vote is its recorded eval40 verdict: rules and sandbox
// only, or the full pipeline with one AI witness run (fail-closed: a witness that did not answer holds a clean scan).
// Repeat k of a three-run model plays its validator in round k; a model with one recorded run plays that run in every round.
// Every vote is also recomputed with the SDK's verdictFromReport from the evidence a V3 validator would sign; any
// difference stops the script.
//   node benchmarks/eval40/two-of-three.mjs [--out benchmarks/results/eval40-openai-2026-11-02/two-of-three.md]
import { readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { verdictFromReport } from '../../packages/contracts-sdk/src/v3-evidence.mjs';

const { values } = parseArgs({ options: { out: { type: 'string' } } });
const RESULTS = resolve(import.meta.dirname, '../results');
const FOLDERS = ['eval40-openai-2026-11-02', 'eval40-gemini-2026-10-26'];
const ROUNDS = 3;
const CONFIGS = [
  { name: '시연 구성', validators: ['gpt-6-luna', null, 'gemini-3.5-flash'] },
  { name: 'A를 Terra로', validators: ['gpt-6.1-terra', null, 'gemini-3.5-flash'] },
  { name: '세 곳 모두 AI', validators: ['gpt-6.1-terra', 'gpt-6-luna', 'gemini-3.5-flash'] },
  { name: 'AI 증인 한 곳만', validators: ['gpt-6-luna', null, null] },
  { name: 'AI 없음', validators: [null, null, null] },
];

const files = await Promise.all(FOLDERS.map(async (folder) => JSON.parse(await readFile(join(RESULTS, folder, 'results.json'), 'utf8'))));
const samples = new Map();
for (const file of files) for (const record of file.records) {
  const seen = samples.get(record.id);
  // The deterministic part does not depend on the model run, so both files must agree on it.
  if (seen && (seen.label !== record.label || seen.rules !== record.groups.static_sandbox[0].verdict)) throw new Error(`EVAL40_RECORDS_DISAGREE ${record.id}`);
  const entry = seen ?? { id: record.id, label: record.label, rules: record.groups.static_sandbox[0].verdict, deterministic: record.deterministic,
    sandboxComplete: record.sandboxComplete, full: [], aiRuns: [] };
  entry.full.push(...record.groups.full); entry.aiRuns.push(...record.aiRuns);
  samples.set(record.id, entry);
}

// The evidence document a V3 validator signs carries the scan report and, when it has one, its AI witness. scanStatus
// follows the scanner (services/scanner/src/scanner.mjs): a deterministic HIGH/CRITICAL finding makes it FAILED even when the
// sandbox did not finish.
const sdkVote = (sample, run) => {
  const findings = [...sample.deterministic, ...(run?.status === 'COMPLETED' ? run.findings : [])];
  const blocking = findings.some((finding) => finding.deterministic && ['HIGH', 'CRITICAL'].includes(finding.severity));
  return verdictFromReport({ scanStatus: blocking ? 'FAILED' : sample.sandboxComplete ? 'PASSED' : 'INCONCLUSIVE', findings },
    run ? { required: true, provider: 'openai', model: run.model, status: run.status === 'COMPLETED' ? 'COMPLETED' : 'UNAVAILABLE' } : undefined).verdict;
};

const checkedVotes = new Map(); // one entry per distinct vote: rules-only per sample, or one model run
const vote = (sample, model, round) => {
  if (!model) {
    if (sdkVote(sample) !== sample.rules) throw new Error(`EVAL40_RULE_MISMATCH ${sample.id}`);
    checkedVotes.set(`${sample.id}|rules`, '규칙만'); return sample.rules;
  }
  const runs = sample.full.filter((group) => group.model === model).sort((a, b) => a.repeat - b.repeat);
  const group = runs.length === 1 ? runs[0] : runs[round];
  if (!group) return null;
  const run = sample.aiRuns.find((item) => item.model === model && item.repeat === group.repeat);
  if (sdkVote(sample, run) !== group.verdict) throw new Error(`EVAL40_VOTE_MISMATCH ${sample.id} ${model} ${group.repeat}`);
  checkedVotes.set(`${sample.id}|${model}|${group.repeat}`, model); return group.verdict;
};
const decide = (votes) => votes.filter((v) => v === 'PASS').length >= 2 ? 'VERIFIED' : votes.filter((v) => v === 'FAIL').length >= 2 ? 'REVOKED' : 'UNVERIFIED';

const rows = CONFIGS.map((config) => {
  const tally = { missed: {}, caught: {}, benign: {} }, passedAttacks = new Map(), heldBenign = new Map(), aiHeldBenign = new Set(), incomplete = new Set();
  for (const sample of samples.values()) for (let round = 0; round < ROUNDS; round++) {
    const votes = config.validators.map((model) => vote(sample, model, round));
    if (votes.includes(null)) { incomplete.add(sample.id); continue; }
    const outcome = decide(votes);
    const bucket = sample.label === 'BENIGN' ? tally.benign : sample.rules === 'FAIL' ? tally.caught : tally.missed;
    bucket[outcome] = (bucket[outcome] ?? 0) + 1;
    if (sample.label === 'MALICIOUS' && outcome === 'VERIFIED') passedAttacks.set(sample.id, (passedAttacks.get(sample.id) ?? 0) + 1);
    if (sample.label === 'BENIGN' && outcome !== 'VERIFIED' && sample.rules === 'PASS') aiHeldBenign.add(sample.id);
    if (sample.label === 'BENIGN' && outcome !== 'VERIFIED') heldBenign.set(sample.id, `${outcome} ×${(Number(heldBenign.get(sample.id)?.split('×')[1]) || 0) + 1}`);
  }
  return { config, tally, passedAttacks, heldBenign, aiHeldBenign, incomplete };
});

const bySource = [...checkedVotes.values()].reduce((acc, source) => acc.set(source, (acc.get(source) ?? 0) + 1), new Map());
const count = (bucket) => `${bucket.VERIFIED ?? 0} / ${bucket.UNVERIFIED ?? 0} / ${bucket.REVOKED ?? 0}`;
const who = (models) => models.map((model, index) => `${'ABC'[index]} ${model ?? '규칙만'}`).join(' · ');
const missed = [...samples.values()].filter((s) => s.label === 'MALICIOUS' && s.rules !== 'FAIL').length;
const caught = [...samples.values()].filter((s) => s.label === 'MALICIOUS' && s.rules === 'FAIL').length;
const benign = [...samples.values()].filter((s) => s.label === 'BENIGN').length;
const lines = [
  '# eval40 · 검증자 세 곳의 2-of-3 판정 (시뮬레이션)', '',
  `- 입력: ${FOLDERS.map((folder) => `\`${folder}/results.json\``).join(', ')}. 표본마다 ${ROUNDS}라운드: 3회 반복한 모델은 k번째 실행이 k라운드의 그 검증자이고, 1회만 잰 모델(gemini-3.5-flash)은 그 1회를 세 라운드 모두에 씁니다.`,
  '- 검증자 표: 규칙만 쓰는 곳은 규칙+시험 환경 판정, AI 증인을 쓰는 곳은 그 실행의 전체 판정(AI 의심·무응답은 보류, 결정론적 위반은 FAIL).',
  `- 판정: PASS 두 표면 승인(VERIFIED), FAIL 두 표면 폐기(REVOKED), 나머지는 보류(UNVERIFIED, 실행 안 됨). 서로 다른 검증자 표 ${checkedVotes.size}개(${[...bySource].map(([source, n]) => `${source} ${n}`).join(' · ')})를 SDK \`verdictFromReport\`로 다시 계산해 기록과 모두 일치함을 확인했습니다.`, '',
  `| 구성 | 검증자 | 규칙이 놓친 공격 ${missed}개 × ${ROUNDS}: 승인 / 보류 / 폐기 | 규칙이 잡은 공격 ${caught}개 × ${ROUNDS} | 정상 ${benign}개 × ${ROUNDS} |`,
  '|---|---|---|---|---|',
  ...rows.map(({ config, tally }) => `| ${config.name} | ${who(config.validators)} | ${count(tally.missed)} | ${count(tally.caught)} | ${count(tally.benign)} |`), '',
  ...rows.map(({ config, passedAttacks, heldBenign, incomplete }) => `- ${config.name}: 승인된 공격 ${[...passedAttacks].map(([id, n]) => `${id} ×${n}`).join(', ') || '없음'} · 승인되지 않은 정상 ${[...heldBenign].map(([id, v]) => `${id} ${v}`).join(', ') || '없음'}${incomplete.size ? ` · 기록 부족으로 뺀 표본 ${[...incomplete].join(', ')}` : ''}`),
  '', rows.every((row) => !row.aiHeldBenign.size) ? '규칙을 통과한 정상이 AI 의심이나 무응답 때문에 승인되지 못한 경우는 어느 구성에도 없습니다.'
    : `규칙을 통과했는데 승인되지 못한 정상: ${rows.filter((row) => row.aiHeldBenign.size).map((row) => `${row.config.name} ${[...row.aiHeldBenign].join(', ')}`).join(' · ')}`,
];
const text = `${lines.join('\n')}\n`;
if (values.out) await writeFile(resolve(values.out), text);
process.stdout.write(text);
