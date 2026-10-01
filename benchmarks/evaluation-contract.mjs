import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { z } from 'zod';
import { canonicalJson } from '../services/scanner/src/canonical-json.mjs';

export const EVALUATION_ARMS = Object.freeze(['STATIC', 'AI', 'SANDBOX', 'STATIC_SANDBOX', 'FULL']);
const stagesByArm = { STATIC: ['STATIC'], AI: ['AI'], SANDBOX: ['SANDBOX'], STATIC_SANDBOX: ['STATIC', 'SANDBOX'], FULL: ['STATIC', 'AI', 'SANDBOX'] };
const noAiArms = new Set(['STATIC', 'SANDBOX', 'STATIC_SANDBOX']);
const id = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/);
const text = z.string().min(1).max(1024);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const nonnegative = z.number().finite().nonnegative();
const label = z.enum(['BENIGN', 'ATTACK']);
const stratum = z.enum(['METADATA_ONLY', 'BEHAVIOR']);
const review = z.strictObject({ reviewerId: id, kind: z.literal('HUMAN'), label, rationale: text,
  recordRef: text, recordHash: digest });
const sampleSchema = z.strictObject({ id, label, split: z.enum(['DEV', 'HOLDOUT']), family: id,
  attackGroup: id.nullable(), stratum, contentHash: digest,
  source: z.strictObject({ uri: text, version: text, license: text }),
  supportedProfiles: z.array(id).min(1).max(16), expectedObservation: text,
  reviews: z.array(review).max(8),
  resolution: z.strictObject({ label, rationale: text, recordRef: text, recordHash: digest }).nullable() });
const manifestSchema = z.strictObject({ schemaVersion: z.literal('capstone-evaluation-v1'), id,
  targetSplit: z.enum(['DEV', 'HOLDOUT']), provenance: z.enum(['SYNTHETIC', 'EXTERNAL', 'MIXED']),
  policyHash: digest, frozenAt: z.iso.datetime(),
  detectionRules: z.strictObject(Object.fromEntries(EVALUATION_ARMS.map((arm) => [arm, text]))),
  samples: z.array(sampleSchema).min(1).max(1024) });
const stageSchema = z.strictObject({ stage: z.enum(['STATIC', 'AI', 'SANDBOX']), evidenceHash: digest,
  originRunId: id, reused: z.boolean(), probeSource: z.enum(['NONE', 'FIXED', 'AI']),
  requests: z.number().int().min(0).max(1_000_000), durationMs: nonnegative.nullable(), costUSD: nonnegative.nullable() });
const recordSchema = z.strictObject({ sampleId: id, arm: z.enum(EVALUATION_ARMS), manifestHash: digest,
  recordedAt: z.iso.datetime(), outcome: z.enum(['DETECTED', 'NOT_DETECTED', 'ABSTAIN_OR_ERROR', 'NOT_APPLICABLE']),
  attempted: z.boolean(), reason: z.enum(['COMPLETED', 'NOT_RUN', 'STAGE_ERROR', 'POLICY_ABSTAIN', 'BEHAVIOR_NOT_APPLICABLE']),
  stageEvidenceReused: z.boolean(), stages: z.array(stageSchema).max(3),
  freshDurationMs: nonnegative.nullable(), aggregationDurationMs: nonnegative.nullable() });

export const evaluationHash = (value) => `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const requireCondition = (condition, code) => { if (!condition) throw new TypeError(code); };
const ratio = (numerator, denominator) => denominator === 0 ? null : numerator / denominator;

export function validateEvaluationManifest(value) {
  const manifest = manifestSchema.parse(value);
  const ids = new Set(), contents = new Map(), families = new Map();
  for (const sample of manifest.samples) {
    requireCondition(!ids.has(sample.id), 'DUPLICATE_SAMPLE'); ids.add(sample.id);
    requireCondition(!contents.has(sample.contentHash), 'DUPLICATE_SAMPLE_CONTENT'); contents.set(sample.contentHash, sample.split);
    requireCondition(!families.has(sample.family) || families.get(sample.family) === sample.split, 'FAMILY_SPLIT_LEAK');
    families.set(sample.family, sample.split);
    requireCondition(sample.label === 'ATTACK' ? sample.attackGroup !== null : sample.attackGroup === null, 'ATTACK_GROUP_LABEL_MISMATCH');
    requireCondition(new Set(sample.reviews.map(({ reviewerId }) => reviewerId)).size === sample.reviews.length, 'DUPLICATE_REVIEWER');
    requireCondition(new Set(sample.supportedProfiles).size === sample.supportedProfiles.length, 'DUPLICATE_PROFILE');
    if (sample.resolution) requireCondition(sample.resolution.label === sample.label, 'RESOLUTION_LABEL_MISMATCH');
  }
  requireCondition(manifest.samples.some(({ split }) => split === manifest.targetSplit), 'EMPTY_TARGET_SPLIT');
  return manifest;
}

export function holdoutReadiness(manifest) {
  const holdout = manifest.samples.filter(({ split }) => split === 'HOLDOUT');
  const counts = { benign: holdout.filter(({ label }) => label === 'BENIGN').length,
    attack: holdout.filter(({ label }) => label === 'ATTACK').length,
    attackGroups: new Set(holdout.filter(({ label }) => label === 'ATTACK').map(({ attackGroup }) => attackGroup)).size };
  const issues = [];
  if (counts.benign < 20 || counts.attack < 20) issues.push('HOLDOUT_REQUIRES_20_BENIGN_AND_20_ATTACK');
  if (counts.attackGroups < 5) issues.push('HOLDOUT_REQUIRES_FIVE_ATTACK_GROUPS');
  if (!manifest.samples.some(({ split }) => split === 'DEV')) issues.push('DEVELOPMENT_FAMILY_INVENTORY_MISSING');
  for (const sample of holdout) {
    if (sample.reviews.length < 2) issues.push(`TWO_REVIEW_RECORDS_MISSING:${sample.id}`);
    if (sample.reviews.some(({ label }) => label !== sample.label) && !sample.resolution) issues.push(`DISAGREEMENT_UNRESOLVED:${sample.id}`);
  }
  return { counts, structuralRequirementsSatisfied: issues.length === 0, humanReviewAuthenticityVerified: false, issues };
}

function summarize(records, samples) {
  const counts = { total: records.length, applicable: 0, applicableAttacks: 0, decided: 0, attempted: 0,
    detected: 0, notDetected: 0, abstainOrError: 0, notRun: 0, notApplicable: 0 };
  const matrix = { truePositives: 0, trueNegatives: 0, falsePositives: 0, falseNegatives: 0 };
  for (const row of records) {
    if (row.outcome === 'NOT_APPLICABLE') { counts.notApplicable++; continue; }
    const attack = samples.get(row.sampleId).label === 'ATTACK';
    counts.applicable++; counts.applicableAttacks += Number(attack); counts.attempted += Number(row.attempted);
    if (row.outcome === 'ABSTAIN_OR_ERROR') { counts.abstainOrError++; counts.notRun += Number(!row.attempted); continue; }
    const detected = row.outcome === 'DETECTED';
    counts.decided++; counts[detected ? 'detected' : 'notDetected']++;
    matrix[attack ? detected ? 'truePositives' : 'falseNegatives' : detected ? 'falsePositives' : 'trueNegatives']++;
  }
  const { truePositives: tp, trueNegatives: tn, falsePositives: fp, falseNegatives: fn } = matrix;
  const precision = ratio(tp, tp + fp), recall = ratio(tp, tp + fn);
  return { counts, matrix, coverage: ratio(counts.decided, counts.applicable),
    abstainOrErrorRate: ratio(counts.abstainOrError, counts.applicable),
    fullAttackDetectionRate: ratio(tp, counts.applicableAttacks),
    conditional: { recall, falsePositiveRate: ratio(fp, fp + tn), precision,
      f1: precision === null || recall === null ? null : ratio(2 * precision * recall, precision + recall) },
    freshDurationMs: records.filter((row) => !row.stageEvidenceReused && row.freshDurationMs !== null).map(({ freshDurationMs }) => freshDurationMs),
    reusedAggregationDurationMs: records.filter((row) => row.stageEvidenceReused && row.aggregationDurationMs !== null).map(({ aggregationDurationMs }) => aggregationDurationMs) };
}

export function reduceEvaluation(manifestInput, recordsInput, { requireHoldoutReady = false } = {}) {
  const manifest = validateEvaluationManifest(manifestInput), manifestHash = evaluationHash(manifest);
  const samples = new Map(manifest.samples.filter(({ split }) => split === manifest.targetSplit).map((sample) => [sample.id, sample]));
  const records = z.array(recordSchema).max(5120).parse(recordsInput), cells = new Set(), evidence = new Map();
  for (const row of records) {
    requireCondition(samples.has(row.sampleId) && row.manifestHash === manifestHash, 'RECORD_MANIFEST_MISMATCH');
    requireCondition(Date.parse(row.recordedAt) >= Date.parse(manifest.frozenAt), 'RECORD_PREDATES_FROZEN_PLAN');
    const cell = `${row.sampleId}/${row.arm}`;
    requireCondition(!cells.has(cell), 'DUPLICATE_ARM_SAMPLE'); cells.add(cell);
    const applicable = samples.get(row.sampleId).stratum !== 'METADATA_ONLY' || !['SANDBOX', 'STATIC_SANDBOX'].includes(row.arm);
    requireCondition(applicable === (row.outcome !== 'NOT_APPLICABLE'), 'APPLICABILITY_MISMATCH');
    requireCondition(row.stageEvidenceReused === row.stages.some(({ reused }) => reused), 'EVIDENCE_REUSE_MISMATCH');
    requireCondition(new Set(row.stages.map(({ stage }) => stage)).size === row.stages.length, 'DUPLICATE_STAGE');
    for (const stage of row.stages) {
      requireCondition(stagesByArm[row.arm].includes(stage.stage), 'ARM_STAGE_MISMATCH');
      requireCondition(!noAiArms.has(row.arm) || (stage.stage !== 'AI' && stage.probeSource !== 'AI'), 'AI_EVIDENCE_IN_NO_AI_ARM');
      requireCondition(stage.stage === 'SANDBOX' || stage.probeSource === 'NONE', 'PROBE_STAGE_MISMATCH');
      const { reused, ...identity } = stage;
      const identityHash = evaluationHash(identity);
      requireCondition(!evidence.has(stage.evidenceHash) || evidence.get(stage.evidenceHash) === identityHash, 'EVIDENCE_PROVENANCE_CONFLICT');
      evidence.set(stage.evidenceHash, identityHash);
    }
    if (!row.attempted) {
      requireCondition(row.stages.length === 0 && row.freshDurationMs === null && row.aggregationDurationMs === null, 'UNATTEMPTED_HAS_MEASUREMENTS');
      requireCondition(row.outcome === 'NOT_APPLICABLE' ? row.reason === 'BEHAVIOR_NOT_APPLICABLE'
        : row.outcome === 'ABSTAIN_OR_ERROR' && row.reason === 'NOT_RUN', 'UNATTEMPTED_OUTCOME_MISMATCH');
    } else {
      requireCondition(!['NOT_RUN', 'BEHAVIOR_NOT_APPLICABLE'].includes(row.reason), 'ATTEMPTED_REASON_MISMATCH');
      requireCondition(row.stageEvidenceReused ? row.freshDurationMs === null : row.aggregationDurationMs === null, 'FRESH_REUSED_LATENCY_MIX');
      if (row.outcome === 'ABSTAIN_OR_ERROR') requireCondition(['STAGE_ERROR', 'POLICY_ABSTAIN'].includes(row.reason), 'ERROR_REASON_MISMATCH');
      else {
        requireCondition(row.reason === 'COMPLETED' && row.outcome !== 'NOT_APPLICABLE', 'DECISION_REASON_MISMATCH');
        // Full metadata review has no executable behavior stage; that limitation stays in its own stratum.
        const required = stagesByArm[row.arm].filter((stage) => !(stage === 'SANDBOX' && samples.get(row.sampleId).stratum === 'METADATA_ONLY'));
        requireCondition(required.every((stage) => row.stages.some((item) => item.stage === stage)), 'DECISION_STAGE_MISSING');
      }
    }
  }
  requireCondition(cells.size === samples.size * EVALUATION_ARMS.length, 'MISSING_ARM_SAMPLE');
  const readiness = holdoutReadiness(manifest);
  if (requireHoldoutReady) requireCondition(manifest.targetSplit === 'HOLDOUT' && readiness.structuralRequirementsSatisfied, 'HOLDOUT_NOT_STRUCTURALLY_READY');
  return { schemaVersion: 'capstone-evaluation-summary-v1', manifestHash, targetSplit: manifest.targetSplit,
    provenance: manifest.provenance, sampleCount: samples.size, readiness,
    byStratum: Object.fromEntries(['METADATA_ONLY', 'BEHAVIOR'].map((stratum) => [stratum,
      Object.fromEntries(EVALUATION_ARMS.map((arm) => [arm, summarize(records.filter((row) => row.arm === arm && samples.get(row.sampleId).stratum === stratum), samples)]))])),
    records,
    limitations: ['Conditional metrics exclude abstentions/errors; coverage and full-attack denominators include them.',
      'Human review records and frozen-plan declarations require independent verification; schema validity is not completed holdout evidence.',
      'Detection decisions are not operational approval/revocation or Agent attack-success measurements.',
      'Stage request/time/cost values describe their origin runs; reused evidence is not a fresh execution or another billable call.'] };
}

async function readBoundedJson(path) {
  const limit = 4 * 1024 * 1024, chunks = [];
  let size = 0;
  for await (const chunk of createReadStream(path, { start: 0, end: limit })) { size += chunk.length; chunks.push(chunk); }
  requireCondition(size <= limit, 'INPUT_TOO_LARGE');
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { values } = parseArgs({ options: { manifest: { type: 'string' }, records: { type: 'string' }, 'require-holdout-ready': { type: 'boolean' } } });
    requireCondition(values.manifest && values.records, 'INPUT_PATHS_REQUIRED');
    const report = reduceEvaluation(await readBoundedJson(values.manifest), await readBoundedJson(values.records), { requireHoldoutReady: values['require-holdout-ready'] === true });
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch {
    // Never echo malformed input, raw provider diagnostics, keys, or user-supplied paths.
    process.stderr.write('{"status":"NOT_MEASURED","reason":"INVALID_EVALUATION_INPUT"}\n');
    process.exitCode = 1;
  }
}
