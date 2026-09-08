import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { latencySummary, measureAdmission, measuredDecision, assertFreshRevocation } from "./admission-measure.js";
import { sourceSnapshot, withSourceProvenance } from "../../scripts/ops/evaluate-admission.js";
test("load report uses nearest-rank quantiles, all samples, and bounded opt-in inputs", async () => {
  assert.deepEqual(latencySummary([100, 1, 3, 2]), { samples: 4, p50Ms: 2, p95Ms: 100, p99Ms: 100, maxMs: 100 });
  assert.throws(() => latencySummary([])); assert.throws(() => latencySummary([NaN]));
  await assert.rejects(measureAdmission({ requests: 0 })); await assert.rejects(measureAdmission({ concurrency: 17 }));
});

test("measurement rejects unexpected errors and distinguishes signed BLOCK from explicitly expected fail-closed errors", async () => {
  for (const message of ["Invalid signed admission snapshot fields", "Signed admission signature is invalid", "Admission API returned 403", "unexpected failure"]) {
    const run = async () => { throw Error(message); };
    await assert.rejects(measuredDecision(run), { message });
    await assert.rejects(measuredDecision(run, "OFFLINE_STRICT_OR_WRITE"), { message });
  }
  const failClosed = await measuredDecision(async () => { throw Error("Admission unavailable; strict or non-read-only calls fail closed"); }, "OFFLINE_STRICT_OR_WRITE");
  assert.equal(failClosed.outcome, "FAIL_CLOSED_ERROR"); assert.equal(failClosed.failureCode, "OFFLINE_STRICT_OR_WRITE");
  assert.throws(() => assertFreshRevocation(failClosed));
  const revoked = await measuredDecision(async () => ({ decision: "BLOCK", releaseStatus: "REVOKED", reasonCode: "RELEASE_REVOKED", cacheHit: false }));
  assertFreshRevocation(revoked);
  for (const changed of [{ releaseStatus: "UNVERIFIED" }, { reasonCode: "STATUS_UNAVAILABLE" }, { cacheHit: true }, { outcome: "FAIL_CLOSED_ERROR" as const }]) assert.throws(() => assertFreshRevocation({ ...revoked, ...changed }));
});

test("source provenance compares HEAD, dirty state and actual tracked/untracked bytes at measurement boundaries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-provenance-test-"));
  assert.equal(dirname(directory), tmpdir());
  const git = (...args: string[]) => execFileSync("git", ["-c", "core.hooksPath=" + join(directory, "no-hooks"), "-c", "commit.gpgsign=false", "-c", "user.name=Synthetic Test", "-c", "user.email=synthetic@example.invalid", ...args], { cwd: directory, windowsHide: true, stdio: "pipe" });
  try {
    git("init", "-q"); await writeFile(join(directory, "source.txt"), "synthetic source v1"); git("add", "source.txt"); git("commit", "-qm", "synthetic initial source");
    const unchanged = await withSourceProvenance(async () => ({ status: "MEASURED" }), directory);
    assert.equal(unchanged.worktreeDirty, false); assert.deepEqual(unchanged.provenance.start, unchanged.provenance.end);
    await mkdir(join(directory, "nested")); assert.deepEqual(sourceSnapshot(directory), sourceSnapshot(join(directory, "nested")));
    await assert.rejects(withSourceProvenance(async () => { git("commit", "--allow-empty", "-qm", "synthetic HEAD change"); return {}; }, directory), { code: "NOT_COMPARABLE" });
    await assert.rejects(withSourceProvenance(async () => { await writeFile(join(directory, "source.txt"), "dirty source v2"); return {}; }, directory), { code: "NOT_COMPARABLE" });
    const before = sourceSnapshot(directory);
    await assert.rejects(withSourceProvenance(async () => { await writeFile(join(directory, "source.txt"), "dirty source v3"); return {}; }, directory), { code: "NOT_COMPARABLE" });
    const after = sourceSnapshot(directory);
    assert.equal(before.dirty, true); assert.equal(after.dirty, true); assert.equal(before.statusHash, after.statusHash); assert.notEqual(before.sourceHash, after.sourceHash);
    await writeFile(join(directory, "untracked.txt"), "synthetic untracked v1");
    await assert.rejects(withSourceProvenance(async () => { await writeFile(join(directory, "untracked.txt"), "synthetic untracked v2"); return {}; }, directory), { code: "NOT_COMPARABLE" });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
