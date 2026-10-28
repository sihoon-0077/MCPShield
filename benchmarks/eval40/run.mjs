// Runs the frozen eval40 set through five comparison groups and writes results.json + summary.md.
//
//   node --import tsx benchmarks/eval40/run.mjs [--models a,b] [--repeats 3] [--out DIR] [--ai-url URL] [--append results.json] [--overwrite]
//
// One scan without AI gives the STATIC and SANDBOX findings. Each (model, repeat) scan adds the AI findings of a
// real model call through an OpenAI-compatible /v1/responses endpoint (local Ollama, or benchmarks/eval40/ai-adapter.mjs
// for the free-tier Gemini API; the bearer token comes from EVAL40_AI_TOKEN). A run whose AI call failed and
// fell back to the local rule is AI_ERROR, never an AI result. Refusals that say nothing about the model are NOT_RUN
// and left out of every count: quota, auth and unknown-model refusals (HTTP 401/403/404/429/503) also stop that model
// for the rest of the execution; an input over the provider's per-request limit (HTTP 413) skips only that sample.
// --repeats is the target number of runs per model and sample, so --append (which reuses an earlier results.json and
// its deterministic scans) fills in what a free daily quota cut off and can be repeated on later days. Group verdicts
// use the validator's own rule (apps/validator/src/v3.ts verdictFromFindings), so the tables show what a V3 validator
// would sign.
import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { scanRelease, scanReleaseDetailed } from '../../services/scanner/src/scanner.mjs';
import { verdictFromFindings } from '../../apps/validator/src/v3.ts';
import { SAMPLE_LABELS, SAMPLES_DIR, treeHash } from './build-samples.mjs';

const { values } = parseArgs({ options: { models: { type: 'string', default: '' }, repeats: { type: 'string', default: '3' }, out: { type: 'string' },
  'ai-url': { type: 'string', default: 'http://127.0.0.1:11434/v1/responses' }, only: { type: 'string' }, append: { type: 'string' }, overwrite: { type: 'boolean', default: false } } });
const newModels = values.models.split(',').filter(Boolean), repeats = Number(values.repeats);
if (!Number.isInteger(repeats) || repeats < 0 || repeats > 10) throw new TypeError('--repeats must be 0..10');
const ROOT = resolve(import.meta.dirname, '../..');
const day = new Date().toISOString().slice(0, 10);
const previous = values.append ? JSON.parse(await readFile(resolve(values.append), 'utf8')) : null;
const outDir = resolve(values.out ?? join(ROOT, 'benchmarks/results', `eval40-${day}`));
// Committed result folders carry hand-written notes in summary.md; never write over one by accident.
if (existsSync(join(outDir, 'results.json')) && !values.overwrite) throw new Error(`EVAL40_OUT_EXISTS ${outDir} (pick a new --out or pass --overwrite)`);
if (previous && values.only) throw new Error('EVAL40_APPEND_ONLY_UNSUPPORTED (it would drop the other samples)');
const lock = JSON.parse(await readFile(join(import.meta.dirname, 'samples.lock.json'), 'utf8'));
const labels = JSON.parse(await readFile(join(import.meta.dirname, 'labels.json'), 'utf8'));
const baselineDir = join(SAMPLES_DIR, '_baseline');
if (await treeHash(baselineDir) !== lock.baseline) throw new Error('EVAL40_BASELINE_CHANGED');
if (previous && JSON.stringify(previous.lock) !== JSON.stringify(lock)) throw new Error('EVAL40_APPEND_LOCK_MISMATCH');

const MODEL_LABEL = { 'mcpshield-qwen2.5-coder-7b-16k': '로컬 qwen2.5-coder 7B (Ollama)', 'mcpshield-gemma4-e2b-16k': '로컬 gemma4 e2b (Ollama)',
  'gemini-2.5-flash': 'Gemini 2.5 Flash (Gemini API 무료)', 'gemini-3.5-flash': 'Gemini 3.5 Flash (Gemini API 무료)',
  'gemini-3.5-flash-lite': 'Gemini 3.5 Flash-Lite (Gemini API 무료)', 'gemini-3.1-flash-lite': 'Gemini 3.1 Flash-Lite (Gemini API 무료)',
  'gemma-4-26b-a4b-it': 'Gemma 4 26B A4B (공개 모델, Gemini API 무료)', 'gemma-4-31b-it': 'Gemma 4 31B (공개 모델, Gemini API 무료)' };
const GROUPS = { static: ['STATIC'], ai: ['AI'], sandbox: ['SANDBOX'], static_sandbox: ['STATIC', 'SANDBOX'], full: ['STATIC', 'AI', 'SANDBOX'] };
const STOP = /^AI_HTTP_(401|403|404|429|503)$/, SKIP = /^AI_HTTP_413$/;
const slim = (f) => ({ code: f.code, severity: f.severity, stage: f.stage, deterministic: f.deterministic });
const suspicious = (run) => run.status === 'COMPLETED' && run.findings.some((f) => ['HIGH', 'CRITICAL'].includes(f.severity));
const samples = SAMPLE_LABELS.filter((s) => !values.only || values.only.split(',').includes(s.id));
const prior = new Map((previous?.records ?? []).map((r) => [r.id, r]));
const stopped = new Set(), records = [], notRun = [];
const started = Date.now();
const executionStart = new Date(started).toISOString();

// A run whose critic call failed (execution REVIEW_REQUIRED) right before its model hit a quota/auth stop most likely lost
// that critic call to the same quota, so its verdict is not the model's. It is dropped (a later --append runs it again)
// and listed. Only runs of the execution that stopped are considered.
function dropCriticVictim(rows, model, since) {
  let last = null;
  for (const row of rows) for (const [i, run] of row.aiRuns.entries())
    if (run.model === model && run.at && run.at >= since && (!last || run.at > last.run.at)) last = { row, i, run };
  if (last?.run.execution !== 'REVIEW_REQUIRED') return null;
  last.row.aiRuns.splice(last.i, 1);
  if (last.row.groups) last.row.groups = groupsFor(last.row.deterministic, last.row.sandboxComplete, last.row.aiRuns);
  return last.row.id;
}
const redone = [...(previous?.redone ?? [])];
for (const x of previous?.notRun ?? []) if (String(x.error).startsWith('CRITIC_LOST')) redone.push({ id: x.id, model: x.model, reason: x.error });
for (const model of previous?.stopped ?? []) {
  if ((previous.notRun ?? []).some((x) => x.model === model && String(x.error).startsWith('CRITIC_LOST'))) continue;
  const id = dropCriticVictim(previous.records, model, new Date(Date.parse(previous.ranAt) - previous.durationMs).toISOString());
  if (id) redone.push({ id, model, reason: 'CRITIC_LOST_TO_QUOTA' });
}

async function aiRun(dir, model, repeat) {
  const t1 = performance.now();
  let status, findings = [], needsHumanReview = null, error = null, execution = null;
  try {
    const detail = await scanReleaseDetailed({ fixtureDir: dir, baselineDir, sandbox: 'local', aiUrl: values['ai-url'], aiProvider: 'openai', aiModel: model,
      aiToken: process.env.EVAL40_AI_TOKEN ?? 'ollama-local', allowRemoteAi: true, aiTimeoutMs: 120_000, logger: () => {} });
    const semantic = JSON.parse(detail.bundle.files['semantic/model-output.json']);
    execution = semantic.execution?.status ?? null;
    if (execution === 'LOCAL_FALLBACK') { error = semantic.execution.reason; status = STOP.test(error) || SKIP.test(error) ? 'NOT_RUN' : 'AI_ERROR'; }
    else { status = 'COMPLETED'; findings = detail.result.findings.filter((f) => f.stage === 'AI').map(slim); needsHumanReview = semantic.execution?.needsHumanReview ?? null; }
  } catch (e) { status = 'AI_ERROR'; error = String(e?.message ?? e).slice(0, 120); }
  // execution REVIEW_REQUIRED = the analyzer answered but its critic call failed; the scanner then holds every claim.
  return { model, repeat, status, error, execution, findings, needsHumanReview, ms: Math.round(performance.now() - t1), at: new Date().toISOString() };
}

function groupsFor(deterministic, sandboxComplete, aiRuns) {
  const groups = {};
  for (const [name, stages] of Object.entries(GROUPS)) {
    const complete = !stages.includes('SANDBOX') || sandboxComplete;
    const base = deterministic.filter((f) => stages.includes(f.stage));
    if (!stages.includes('AI')) { groups[name] = [{ ...verdictFromFindings(base, complete) }]; continue; }
    // AI-only has no answer without the model. In the full pipeline a failed AI call is fail-closed review:
    // the deterministic verdict stands if it is FAIL, otherwise the release is held (ABSTAIN), flagged aiError.
    groups[name] = aiRuns.filter((run) => run.status !== 'NOT_RUN').map((run) => {
      if (run.status === 'COMPLETED') return { model: run.model, repeat: run.repeat, ...verdictFromFindings([...base, ...run.findings], complete) };
      if (name === 'ai') return { model: run.model, repeat: run.repeat, verdict: 'AI_ERROR', basis: [run.error ?? 'AI_ERROR'] };
      const fallback = verdictFromFindings(base, complete);
      return { model: run.model, repeat: run.repeat, verdict: fallback.verdict === 'FAIL' ? 'FAIL' : 'ABSTAIN', basis: [...fallback.basis, run.error ?? 'AI_ERROR'], aiError: true };
    });
  }
  return groups;
}

for (const [index, sample] of samples.entries()) {
  const dir = join(SAMPLES_DIR, sample.id);
  if (await treeHash(dir) !== lock.samples[sample.id]) throw new Error(`EVAL40_SAMPLE_CHANGED ${sample.id}`);
  const old = prior.get(sample.id);
  let deterministic, sandboxComplete, plainMs;
  if (old) ({ deterministic, sandboxComplete, plainMs } = old);
  else {
    const events = [], t0 = performance.now();
    const plain = await scanRelease({ fixtureDir: dir, baselineDir, sandbox: 'local', logger: (e) => events.push(e) });
    plainMs = Math.round(performance.now() - t0);
    sandboxComplete = !events.some((e) => ['sandbox_failed', 'sandbox_timeout', 'snapshot_integrity_failed'].includes(e.event));
    deterministic = plain.findings.filter((f) => f.stage !== 'AI').map(slim);
  }
  const aiRuns = (old?.aiRuns ?? []).filter((run) => run.status !== 'NOT_RUN');
  for (const model of newModels) {
    for (let repeat = aiRuns.filter((run) => run.model === model).length; repeat < repeats && !stopped.has(model); repeat++) {
      const run = await aiRun(dir, model, repeat);
      if (run.status !== 'NOT_RUN') { aiRuns.push(run); continue; }
      notRun.push({ id: sample.id, model, error: run.error });
      if (SKIP.test(run.error)) { console.log(`skip ${sample.id} ${model}: ${run.error} (input over the provider limit)`); break; }
      stopped.add(model); console.log(`stop ${model}: ${run.error} (quota/auth); later runs of this model are not attempted`);
      const victim = dropCriticVictim([...records, { id: sample.id, aiRuns }], model, executionStart);
      if (victim) { notRun.push({ id: victim, model, error: 'CRITIC_LOST_TO_QUOTA' }); console.log(`drop ${victim} ${model}: its critic call likely hit the same quota`); }
      break;
    }
  }
  const groups = groupsFor(deterministic, sandboxComplete, aiRuns);
  records.push({ ...sample, sandboxComplete, plainMs, deterministic, aiRuns, groups });
  const L = { PASS: 'P', ABSTAIN: 'H', FAIL: 'F', AI_ERROR: 'E' };
  console.log(`[${index + 1}/${samples.length}] ${sample.id} ${sample.label} rules=${groups.static_sandbox[0].verdict} ai=${groups.ai.map((g) => L[g.verdict]).join('')} full=${groups.full.map((g) => L[g.verdict]).join('')}`);
}

// ---- aggregate ----
const models = [...new Set(records.flatMap((r) => r.aiRuns.map((a) => a.model)))];
const tally = (list) => Object.fromEntries(['PASS', 'ABSTAIN', 'FAIL', 'AI_ERROR'].map((v) => [v, list.filter((x) => x === v).length]));
const pct = (k, n) => n ? `${k}/${n} (${Math.round(100 * k / n)}%)` : '0/0';
const rules = (r) => r.groups.static_sandbox[0].verdict;
const benign = records.filter((r) => r.label === 'BENIGN'), malicious = records.filter((r) => r.label === 'MALICIOUS');
const missed = malicious.filter((r) => rules(r) !== 'FAIL'), passedBenign = benign.filter((r) => rules(r) === 'PASS');
const perModel = {};
for (const model of models) {
  const runsOf = (rows) => rows.flatMap((r) => r.aiRuns.filter((a) => a.model === model));
  const all = runsOf(records), done = all.filter((a) => a.status === 'COMPLETED');
  const ms = all.map((a) => a.ms).sort((a, b) => a - b);
  const fullDone = (rows) => tally(rows.flatMap((r) => r.groups.full.filter((g) => g.model === model && !g.aiError).map((g) => g.verdict)));
  const fullHeld = (rows) => tally(rows.flatMap((r) => r.groups.full.filter((g) => g.model === model).map((g) => g.verdict)));
  const repeatsOf = records.map((r) => r.groups.ai.filter((g) => g.model === model).map((g) => g.verdict)).filter((v) => v.length > 1);
  perModel[model] = {
    label: MODEL_LABEL[model] ?? model, runs: all.length, completed: done.length, errors: all.length - done.length,
    errorReasons: Object.entries(all.filter((a) => a.status === 'AI_ERROR').reduce((acc, a) => ({ ...acc, [a.error]: (acc[a.error] ?? 0) + 1 }), {})),
    criticUnavailable: done.filter((a) => a.execution === 'REVIEW_REQUIRED').length,
    missedAttacks: { completed: runsOf(missed).filter((a) => a.status === 'COMPLETED').length, suspicious: runsOf(missed).filter(suspicious).length },
    allAttacks: { completed: runsOf(malicious).filter((a) => a.status === 'COMPLETED').length, suspicious: runsOf(malicious).filter(suspicious).length },
    passedBenign: { completed: runsOf(passedBenign).filter((a) => a.status === 'COMPLETED').length, suspicious: runsOf(passedBenign).filter(suspicious).length },
    allBenign: { completed: runsOf(benign).filter((a) => a.status === 'COMPLETED').length, suspicious: runsOf(benign).filter(suspicious).length },
    fullCompleted: { BENIGN: fullDone(benign), MALICIOUS: fullDone(malicious) }, fullErrorsHeld: { BENIGN: fullHeld(benign), MALICIOUS: fullHeld(malicious) },
    repeatAgreement: { agree: repeatsOf.filter((v) => v.every((x) => x === v[0])).length, of: repeatsOf.length },
    latencyMs: { p50: ms[Math.floor(ms.length / 2)] ?? null, p90: ms[Math.floor(ms.length * 0.9)] ?? null, max: ms.at(-1) ?? null },
    flaggedMissed: missed.map((r) => ({ id: r.id, flagged: r.aiRuns.filter((a) => a.model === model && suspicious(a)).length,
      completed: r.aiRuns.filter((a) => a.model === model && a.status === 'COMPLETED').length })).filter((x) => x.flagged),
  };
}
const aggregate = {};
for (const group of ['static', 'sandbox', 'static_sandbox']) for (const subset of ['BENIGN', 'MALICIOUS', 'BENIGN:hard']) {
  const rows = records.filter((r) => subset === 'BENIGN:hard' ? r.label === 'BENIGN' && r.difficulty === 'hard' : r.label === subset);
  aggregate[`${group}|${subset}`] = tally(rows.map((r) => r.groups[group][0].verdict));
}
const categories = {};
for (const r of malicious) {
  const c = (categories[r.category] ??= { samples: 0, rulesFail: 0, models: {} });
  c.samples++; if (rules(r) === 'FAIL') c.rulesFail++;
  for (const model of models) {
    const m = (c.models[model] ??= { suspicious: 0, completed: 0 });
    m.completed += r.aiRuns.filter((a) => a.model === model && a.status === 'COMPLETED').length; m.suspicious += r.aiRuns.filter((a) => a.model === model && suspicious(a)).length;
  }
}

const result = { benchmark: 'eval40-v1', ranAt: new Date().toISOString(), durationMs: Date.now() - started, appendedTo: previous ? previous.ranAt : null,
  labels: labels.labeling, reviewers: labels.reviewers, models, repeatsTarget: repeats, notRun, redone, stopped: [...stopped], modelLabels: Object.fromEntries(models.map((m) => [m, MODEL_LABEL[m] ?? m])),
  sandbox: 'LOCAL_PROCESS (Node permission model, no MCP tool-call probes)', verdictRule: 'apps/validator/src/v3.ts verdictFromFindings',
  suspicionRule: 'a COMPLETED AI run with a HIGH/CRITICAL AI finding (the validator then signs ABSTAIN)', lock, aggregate, perModel, categories, records };
await mkdir(outDir, { recursive: true });
await writeFile(join(outDir, 'results.json'), `${JSON.stringify(result, null, 2)}\n`);

const fmt = (t) => `${t.PASS} / ${t.ABSTAIN} / ${t.FAIL}`;
const L = { PASS: 'P', ABSTAIN: 'H', FAIL: 'F', AI_ERROR: 'E' };
const lines = [
  `# eval40 결과 (${day})`, '',
  ...(repeats && models.some((m) => records.some((r) => r.aiRuns.filter((a) => a.model === m).length < repeats))
    ? [`> 아직 목표(표본마다 모델별 ${repeats}회)를 다 채우지 못한 모델이 있습니다. 무료 한도가 풀린 뒤 \`--append\`로 이어서 돌립니다.`, ''] : []),
  `- 표본: 정상 ${benign.length}개(어려운 정상 ${benign.filter((r) => r.difficulty === 'hard').length}개 포함), 공격 ${malicious.length}개. 정답은 작성자 라벨이며 2인 검토 ${labels.reviewers.length ? '완료' : '대기'}.`,
  '- 샌드박스: 로컬 프로세스 실행, 도구 호출 프로브 없음(Docker 경로는 CI). 판정 규칙은 V3 검증자와 같음: 규칙 위반 확정=FAIL, AI의 HIGH 이상 의심·검사 미완료=ABSTAIN(보류).',
  '- AI "의심"은 AI 호출이 성공했고 HIGH 이상 의심을 낸 실행입니다. 한도 초과·인증 거부·입력 크기 초과(HTTP 401/403/404/413/429/503)는 모델 성능과 무관해 모든 수에서 뺐습니다.', '',
  '## 규칙만 (AI 없음)', '', '| 비교군 | 정상 PASS / 보류 / FAIL | 공격 PASS / 보류 / FAIL | 어려운 정상 PASS / 보류 / FAIL |', '|---|---|---|---|',
  ...[['static', '정적 규칙만'], ['sandbox', '샌드박스만'], ['static_sandbox', '정적+샌드박스']].map(([g, name]) => `| ${name} | ${fmt(aggregate[`${g}|BENIGN`])} | ${fmt(aggregate[`${g}|MALICIOUS`])} | ${fmt(aggregate[`${g}|BENIGN:hard`])} |`), '',
  `규칙이 놓친 공격 ${missed.length}개: ${missed.map((r) => r.id).join(', ') || '없음'}. 규칙을 통과한 정상 ${passedBenign.length}개.`, '',
  '## 모델별 AI 결과', '',
  '| 모델 | 실행 (성공 / 오류) | 규칙이 놓친 공격에서 의심 | 규칙 통과 정상에서 오탐 의심 | 전체 공격에서 의심 | 반복 일치 | 지연 p50 / p90 |', '|---|---|---|---|---|---|---|',
  ...models.map((m) => { const p = perModel[m]; return `| ${p.label} | ${p.runs} (${p.completed} / ${p.errors}) | ${pct(p.missedAttacks.suspicious, p.missedAttacks.completed)} | ${pct(p.passedBenign.suspicious, p.passedBenign.completed)} | ${pct(p.allAttacks.suspicious, p.allAttacks.completed)} | ${p.repeatAgreement.of ? `${p.repeatAgreement.agree}/${p.repeatAgreement.of}` : '-'} | ${p.latencyMs.p50} / ${p.latencyMs.p90} ms |`; }), '',
  '| 모델 | 전체 비교군, AI 성공 실행만: 정상 PASS / 보류 / FAIL | 공격 PASS / 보류 / FAIL | AI 오류를 보류로 셀 때 정상 보류 |', '|---|---|---|---|',
  ...models.map((m) => { const p = perModel[m], held = p.fullErrorsHeld.BENIGN, n = held.PASS + held.ABSTAIN + held.FAIL; return `| ${p.label} | ${fmt(p.fullCompleted.BENIGN)} | ${fmt(p.fullCompleted.MALICIOUS)} | ${pct(held.ABSTAIN, n)} |`; }), '',
  ...models.map((m) => { const p = perModel[m]; return `- ${p.label}: 오류 사유 ${p.errorReasons.map(([k, v]) => `${k} ${v}회`).join(', ') || '없음'}. 놓친 공격 중 의심을 낸 표본: ${p.flaggedMissed.map((x) => `${x.id} ${x.flagged}/${x.completed}`).join(', ') || '없음'}.${p.criticUnavailable ? ` 2차 확인(critic) 호출이 실패해 보류된 실행 ${p.criticUnavailable}회.` : ''}`; }),
  ...[...new Set(notRun.map((x) => x.model))].map((m) => { const rows = notRun.filter((x) => x.model === m); return `- ${MODEL_LABEL[m] ?? m}: 이번 실행에서 못 돌린 호출 ${rows.length}건(${[...new Set(rows.map((x) => x.error))].join(', ')}: ${rows.map((x) => x.id).join(', ')}). 성능 수에서 뺐습니다.`; }),
  ...redone.map((x) => `- 다시 돌린 실행: ${x.id} (${MODEL_LABEL[x.model] ?? x.model}). 2차 확인(critic) 호출이 무료 한도에 걸린 것으로 보여 그 결과를 빼고 다음 실행에서 다시 돌렸습니다.`), '',
  '## 공격 종류별', '', `| 종류 | 표본 | 규칙 FAIL | ${models.map((m) => `${perModel[m].label} 의심/성공`).join(' | ')} |`, `|---|---|---|${models.map(() => '---').join('|')}|`,
  ...Object.entries(categories).map(([c, v]) => `| ${c} | ${v.samples} | ${v.rulesFail} | ${models.map((m) => `${v.models[m].suspicious}/${v.models[m].completed}`).join(' | ')} |`), '',
  '## 표본별', '', `| id | 정답 | 종류 | 정적 | 샌드박스 | 정적+샌드박스 | ${models.map((m) => `${perModel[m].label} (AI만)`).join(' | ')} |`, `|---|---|---|---|---|---|${models.map(() => '---').join('|')}|`,
  ...records.map((r) => `| ${r.id} | ${r.label} | ${r.category} | ${r.groups.static[0].verdict} | ${r.groups.sandbox[0].verdict} | ${rules(r)} | ${models.map((m) => r.groups.ai.filter((g) => g.model === m).map((g) => L[g.verdict]).join('') || '-').join(' | ')} |`), '',
  '기호: P=의심 없음, H=의심(보류), E=AI 오류. 반복 순서대로 적었습니다.', '',
  'MCPTox(외부 공개 공격 485건)는 별도로 보고합니다: `benchmarks/results/mcptox-static-2026-09-09.json` (정적 메타데이터 규칙 탐지 25.98%). 이번 실행에서 다시 돌리지 않았습니다.', '',
];
await writeFile(join(outDir, 'summary.md'), `${lines.join('\n')}\n`);
console.log(JSON.stringify({ outDir, durationMs: result.durationMs, models, stopped: [...stopped] }));
