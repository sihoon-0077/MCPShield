// Runs the frozen eval40 set through five comparison groups and writes results.json + summary.md.
//
//   node --import tsx benchmarks/eval40/run.mjs [--models a,b] [--repeats 3] [--out DIR]
//
// One scan without AI gives the STATIC and SANDBOX findings. Each (model, repeat) scan adds the AI findings of a
// real local model call (Ollama, OpenAI-compatible /v1/responses). A run whose AI call failed and fell back to the
// local rule is counted as AI_ERROR, never as an AI result. Group verdicts use the validator's own rule
// (apps/validator/src/v3.ts verdictFromFindings), so the table shows what a V3 validator would sign.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { scanRelease, scanReleaseDetailed } from '../../services/scanner/src/scanner.mjs';
import { verdictFromFindings } from '../../apps/validator/src/v3.ts';
import { SAMPLE_LABELS, SAMPLES_DIR, treeHash } from './build-samples.mjs';

const { values } = parseArgs({ options: { models: { type: 'string', default: 'mcpshield-qwen2.5-coder-7b-16k,mcpshield-gemma4-e2b-16k' },
  repeats: { type: 'string', default: '3' }, out: { type: 'string' }, 'ai-url': { type: 'string', default: 'http://127.0.0.1:11434/v1/responses' },
  only: { type: 'string' } } });
const models = values.models.split(',').filter(Boolean), repeats = Number(values.repeats);
if (!Number.isInteger(repeats) || repeats < 0 || repeats > 10) throw new TypeError('--repeats must be 0..10');
const ROOT = resolve(import.meta.dirname, '../..');
const day = new Date().toISOString().slice(0, 10);
const outDir = resolve(values.out ?? join(ROOT, 'benchmarks/results', `eval40-${day}`));
const lock = JSON.parse(await readFile(join(import.meta.dirname, 'samples.lock.json'), 'utf8'));
const labels = JSON.parse(await readFile(join(import.meta.dirname, 'labels.json'), 'utf8'));
const baselineDir = join(SAMPLES_DIR, '_baseline');
if (await treeHash(baselineDir) !== lock.baseline) throw new Error('EVAL40_BASELINE_CHANGED');

const GROUPS = { static: ['STATIC'], ai: ['AI'], sandbox: ['SANDBOX'], static_sandbox: ['STATIC', 'SANDBOX'], full: ['STATIC', 'AI', 'SANDBOX'] };
const slim = (f) => ({ code: f.code, severity: f.severity, stage: f.stage, deterministic: f.deterministic });
const samples = SAMPLE_LABELS.filter((s) => !values.only || values.only.split(',').includes(s.id));
const records = [];
const started = Date.now();
for (const [index, sample] of samples.entries()) {
  const dir = join(SAMPLES_DIR, sample.id);
  if (await treeHash(dir) !== lock.samples[sample.id]) throw new Error(`EVAL40_SAMPLE_CHANGED ${sample.id}`);
  const events = [];
  const t0 = performance.now();
  const plain = await scanRelease({ fixtureDir: dir, baselineDir, sandbox: 'local', logger: (e) => events.push(e) });
  const plainMs = Math.round(performance.now() - t0);
  const sandboxComplete = !events.some((e) => ['sandbox_failed', 'sandbox_timeout', 'snapshot_integrity_failed'].includes(e.event));
  const deterministic = plain.findings.filter((f) => f.stage !== 'AI').map(slim);
  const aiRuns = [];
  for (const model of models) for (let repeat = 0; repeat < repeats; repeat++) {
    const t1 = performance.now();
    let status, findings = [], needsHumanReview = null, error = null;
    try {
      const detail = await scanReleaseDetailed({ fixtureDir: dir, baselineDir, sandbox: 'local', aiUrl: values['ai-url'], aiProvider: 'openai', aiModel: model,
        aiToken: 'ollama-local', allowRemoteAi: true, aiTimeoutMs: 120_000, logger: () => {} });
      const semantic = JSON.parse(detail.bundle.files['semantic/model-output.json']);
      status = semantic.execution?.status === 'LOCAL_FALLBACK' ? 'AI_ERROR' : 'COMPLETED';
      error = semantic.execution?.status === 'LOCAL_FALLBACK' ? semantic.execution.reason : null;
      if (status === 'COMPLETED') { findings = detail.result.findings.filter((f) => f.stage === 'AI').map(slim); needsHumanReview = semantic.execution?.needsHumanReview ?? null; }
    } catch (e) { status = 'AI_ERROR'; error = String(e?.message ?? e).slice(0, 120); }
    aiRuns.push({ model, repeat, status, error, findings, needsHumanReview, ms: Math.round(performance.now() - t1) });
  }
  const groups = {};
  for (const [name, stages] of Object.entries(GROUPS)) {
    const needsSandbox = stages.includes('SANDBOX');
    const base = deterministic.filter((f) => stages.includes(f.stage));
    if (!stages.includes('AI')) { groups[name] = [{ ...verdictFromFindings(base, !needsSandbox || sandboxComplete) }]; continue; }
    // AI-only has no answer without the model. In the full pipeline a failed AI call is fail-closed review:
    // the deterministic verdict stands if it is FAIL, otherwise the release is held (ABSTAIN), flagged aiError.
    groups[name] = aiRuns.map((run) => {
      if (run.status === 'COMPLETED') return { model: run.model, repeat: run.repeat, ...verdictFromFindings([...base, ...run.findings], !needsSandbox || sandboxComplete) };
      if (name === 'ai') return { model: run.model, repeat: run.repeat, verdict: 'AI_ERROR', basis: [run.error ?? 'AI_ERROR'] };
      const fallback = verdictFromFindings(base, !needsSandbox || sandboxComplete);
      return { model: run.model, repeat: run.repeat, verdict: fallback.verdict === 'FAIL' ? 'FAIL' : 'ABSTAIN', basis: [...fallback.basis, run.error ?? 'AI_ERROR'], aiError: true };
    });
  }
  records.push({ ...sample, sandboxComplete, plainMs, deterministic, aiRuns, groups });
  console.log(`[${index + 1}/${samples.length}] ${sample.id} ${sample.label} static=${groups.static[0].verdict} sandbox=${groups.sandbox[0].verdict} `
    + `static+sandbox=${groups.static_sandbox[0].verdict} ai=${groups.ai.map((g) => ({ PASS: 'P', ABSTAIN: 'H', FAIL: 'F', AI_ERROR: 'E' })[g.verdict]).join('')} full=${groups.full.map((g) => ({ PASS: 'P', ABSTAIN: 'H', FAIL: 'F' })[g.verdict]).join('')}`);
}

// ---- aggregate ----
const verdicts = ['PASS', 'ABSTAIN', 'FAIL', 'AI_ERROR'];
const LETTER = { PASS: 'P', ABSTAIN: 'H', FAIL: 'F', AI_ERROR: 'E' };
const letters = (list) => list.map((g) => LETTER[g.verdict]).join('');
const tally = (list) => Object.fromEntries(verdicts.map((v) => [v, list.filter((x) => x === v).length]));
const runsOf = (record, group) => record.groups[group].map((g) => g.verdict);
const aggregate = {};
for (const group of Object.keys(GROUPS)) for (const subset of ['BENIGN', 'MALICIOUS', 'BENIGN:hard']) {
  const rows = records.filter((r) => subset === 'BENIGN:hard' ? r.label === 'BENIGN' && r.difficulty === 'hard' : r.label === subset);
  // Per-run counts; for single-run groups this is the sample count.
  aggregate[`${group}|${subset}`] = { samples: rows.length, runs: tally(rows.flatMap((r) => runsOf(r, group))) };
}
const byModel = {};
for (const model of models) for (const group of ['ai', 'full']) for (const label of ['BENIGN', 'MALICIOUS']) {
  const rows = records.filter((r) => r.label === label);
  byModel[`${model}|${group}|${label}`] = tally(rows.flatMap((r) => r.groups[group].filter((g) => g.model === model).map((g) => g.verdict)));
}
// Repeat consistency: share of (sample, model) whose repeats all agree on the AI-only verdict.
const consistency = Object.fromEntries(models.map((model) => {
  const pairs = records.map((r) => r.groups.ai.filter((g) => g.model === model).map((g) => g.verdict));
  const agree = pairs.filter((p) => p.length && p.every((v) => v === p[0])).length;
  return [model, { agree, of: pairs.length }];
}));
const categories = {};
for (const r of records.filter((x) => x.label === 'MALICIOUS')) {
  const c = (categories[r.category] ??= { samples: 0, static_sandbox_fail: 0, full_runs: tally([]) });
  c.samples++; if (r.groups.static_sandbox[0].verdict === 'FAIL') c.static_sandbox_fail++;
  for (const v of runsOf(r, 'full')) c.full_runs[v]++;
}
// What AI changes: samples whose full-pipeline majority differs from static+sandbox.
const majority = (list) => { const counts = tally(list); return verdicts.reduce((a, b) => counts[b] > counts[a] ? b : a, 'PASS'); };
const aiChanged = records.map((r) => ({ id: r.id, label: r.label, without: r.groups.static_sandbox[0].verdict, withAiMajority: majority(runsOf(r, 'full')) }))
  .filter((x) => x.without !== x.withAiMajority);
const aiLatency = models.map((model) => { const ms = records.flatMap((r) => r.aiRuns.filter((a) => a.model === model).map((a) => a.ms)).sort((a, b) => a - b);
  return { model, p50: ms[Math.floor(ms.length / 2)] ?? null, max: ms.at(-1) ?? null, errors: records.flatMap((r) => r.aiRuns).filter((a) => a.model === model && a.status === 'AI_ERROR').length }; });

const result = { benchmark: 'eval40-v1', ranAt: new Date().toISOString(), durationMs: Date.now() - started, labels: labels.labeling, reviewers: labels.reviewers,
  models, repeats, aiEndpoint: 'local Ollama (OpenAI-compatible /v1/responses)', sandbox: 'LOCAL_PROCESS (Node permission model, no MCP tool-call probes)',
  verdictRule: 'apps/validator/src/v3.ts verdictFromFindings', lock, aggregate, byModel, consistency, categories, aiChanged, aiLatency, records };
await mkdir(outDir, { recursive: true });
await writeFile(join(outDir, 'results.json'), `${JSON.stringify(result, null, 2)}\n`);

const fmt = (t) => `${t.PASS} / ${t.ABSTAIN} / ${t.FAIL}${t.AI_ERROR ? ` (오류 ${t.AI_ERROR})` : ''}`;
const groupName = { static: '정적 규칙만', ai: 'AI만', sandbox: '샌드박스만', static_sandbox: '정적+샌드박스', full: '전체(정적+AI+샌드박스)' };
const lines = [
  `# eval40 결과 (${day})`, '',
  `- 표본: 정상 ${records.filter((r) => r.label === 'BENIGN').length}개(그중 어려운 정상 ${records.filter((r) => r.label === 'BENIGN' && r.difficulty === 'hard').length}개), 공격 ${records.filter((r) => r.label === 'MALICIOUS').length}개. 정답은 작성자 라벨이며 2인 검토 ${labels.reviewers.length ? '완료' : '대기'}.`,
  `- AI: ${models.join(', ')} (로컬 Ollama), 모델당 ${repeats}회 반복. AI가 들어간 비교군의 수는 실행 횟수(표본 × 모델 × 반복) 기준.`,
  `- 샌드박스: 로컬 프로세스 실행, 도구 호출 프로브 없음(Docker 경로는 CI). 판정 규칙은 V3 검증자와 같음: 규칙 위반 확정=FAIL, AI 의심·검사 미완료=ABSTAIN.`,
  `- AI 호출 오류: ${records.flatMap((r) => r.aiRuns).filter((a) => a.status === 'AI_ERROR').length}/${records.flatMap((r) => r.aiRuns).length}회 (형식 위반·인용 불일치·시간 초과). AI만 비교군에서는 오류로, 전체 비교군에서는 보류로 셉니다.`, '',
  '| 비교군 | 정상 PASS / ABSTAIN / FAIL | 공격 PASS / ABSTAIN / FAIL | 어려운 정상 PASS / ABSTAIN / FAIL |', '|---|---|---|---|',
  ...Object.keys(GROUPS).map((g) => `| ${groupName[g]} | ${fmt(aggregate[`${g}|BENIGN`].runs)} | ${fmt(aggregate[`${g}|MALICIOUS`].runs)} | ${fmt(aggregate[`${g}|BENIGN:hard`].runs)} |`), '',
  '## 공격 종류별 (전체 비교군, 실행 기준)', '', '| 종류 | 표본 | 정적+샌드박스 FAIL | 전체 PASS / ABSTAIN / FAIL |', '|---|---|---|---|',
  ...Object.entries(categories).map(([c, v]) => `| ${c} | ${v.samples} | ${v.static_sandbox_fail} | ${fmt(v.full_runs)} |`), '',
  '## AI를 넣으면 달라지는 표본 (정적+샌드박스 → 전체의 다수결)', '',
  ...(aiChanged.length ? aiChanged.map((x) => `- ${x.id} (${x.label}): ${x.without} → ${x.withAiMajority}`) : ['- 없음. AI를 빼도 판정이 같았습니다.']), '',
  '## 모델별·반복 일관성', '',
  ...models.map((m) => `- ${m}: AI만 정상 ${fmt(byModel[`${m}|ai|BENIGN`])}, 공격 ${fmt(byModel[`${m}|ai|MALICIOUS`])}. 반복 ${repeats}회 판정 일치 ${consistency[m].agree}/${consistency[m].of} 표본. 지연 p50 ${aiLatency.find((a) => a.model === m).p50} ms, 오류 ${aiLatency.find((a) => a.model === m).errors}회.`), '',
  '## 표본별', '', '| id | 정답 | 종류 | 정적 | 샌드박스 | 정적+샌드박스 | AI만 (실행별) | 전체 (실행별) |', '|---|---|---|---|---|---|---|---|',
  ...records.map((r) => `| ${r.id} | ${r.label} | ${r.category} | ${r.groups.static[0].verdict} | ${r.groups.sandbox[0].verdict} | ${r.groups.static_sandbox[0].verdict} | ${letters(r.groups.ai)} | ${letters(r.groups.full)} |`), '',
  '표본별 실행 기호: P=PASS, H=ABSTAIN(보류), F=FAIL, E=AI 오류. 순서는 모델별 반복 순서입니다. 전체 비교군에서 AI 호출이 실패하면 확정 FAIL은 유지하고 그 밖에는 보류(H)로 셉니다.', '',
  'MCPTox(외부 공개 공격 485건)는 별도로 보고합니다: `benchmarks/results/mcptox-static-2026-09-09.json` (정적 메타데이터 규칙 탐지 25.98%). 이번 실행에서 다시 돌리지 않았습니다.', '',
];
await writeFile(join(outDir, 'summary.md'), `${lines.join('\n')}\n`);
console.log(JSON.stringify({ outDir, durationMs: result.durationMs, aiChanged: aiChanged.length }));
