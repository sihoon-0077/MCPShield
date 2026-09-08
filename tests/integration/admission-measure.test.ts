import assert from "node:assert/strict";
import { test } from "node:test";
import { latencySummary, measureAdmission } from "./admission-measure.js";
test("load report uses nearest-rank quantiles, all samples, and bounded opt-in inputs", async () => {
  assert.deepEqual(latencySummary([100, 1, 3, 2]), { samples: 4, p50Ms: 2, p95Ms: 100, p99Ms: 100, maxMs: 100 });
  assert.throws(() => latencySummary([])); assert.throws(() => latencySummary([NaN]));
  await assert.rejects(measureAdmission({ requests: 0 })); await assert.rejects(measureAdmission({ concurrency: 17 }));
});
