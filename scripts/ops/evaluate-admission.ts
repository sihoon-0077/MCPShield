import { parseArgs } from "node:util";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export function sourceSnapshot(cwd = process.cwd()) {
  let root = cwd;
  const git = (args: string[]) => execFileSync("git", args, { cwd: root, encoding: "utf8", windowsHide: true, maxBuffer: 16 * 1024 * 1024 });
  root = git(["rev-parse", "--show-toplevel"]).trim();
  const commit = git(["rev-parse", "HEAD"]).trim();
  const status = git(["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
  const files = [...new Set(git(["ls-files", "--cached", "--others", "--exclude-standard", "-z"]).split("\0").filter(Boolean))].sort();
  const digest = createHash("sha256");
  for (const file of files) {
    let contentHash;
    try {
      const path = join(root, file);
      if (!lstatSync(path).isFile()) throw new Error("SOURCE_SNAPSHOT_REQUIRES_REGULAR_FILES");
      contentHash = createHash("sha256").update(readFileSync(path)).digest("hex");
    } catch (error: any) { if (error.code !== "ENOENT") throw error; contentHash = "MISSING"; }
    digest.update(JSON.stringify([file, contentHash]));
  }
  return { commit, dirty: status.length > 0, statusHash: createHash("sha256").update(status).digest("hex"), sourceHash: digest.digest("hex"), files: files.length };
}

export async function withSourceProvenance<T extends object>(run: () => Promise<T>, cwd = process.cwd()) {
  const start = sourceSnapshot(cwd);
  const result = await run();
  const end = sourceSnapshot(cwd);
  if (JSON.stringify(start) !== JSON.stringify(end)) throw Object.assign(new Error("NOT_COMPARABLE: source, HEAD or worktree state changed during measurement"), { code: "NOT_COMPARABLE" });
  return { ...result, sourceCommit: start.commit, worktreeDirty: start.dirty, sourceComparability: "MATCHING_BOUNDARY_SNAPSHOTS", provenance: { scope: "GIT_TRACKED_AND_NONIGNORED_UNTRACKED_FILES", start, end } };
}

async function main() {
  const { values } = parseArgs({ options: { requests: { type: "string" }, concurrency: { type: "string" }, identities: { type: "string" },
    profile: { type: "string", default: "smoke" }, plan: { type: "boolean", default: false }, "matrix-child": { type: "boolean", default: false }, "full-matrix": { type: "boolean", default: false } } });
  if (!["smoke", "matrix"].includes(values.profile)) throw Error("Profile must be smoke or matrix");
  const fullMatrix = values["full-matrix"];
  if (fullMatrix && (values.profile !== "matrix" || values.requests !== undefined)) throw Error("--full-matrix requires --profile matrix and fixes hot=1000/uniform=10000 requests; omit --requests");
  const options = { requests: Number(values.requests ?? 40), concurrency: Number(values.concurrency ?? (fullMatrix ? 16 : 4)),
    identities: Number(values.identities ?? (fullMatrix ? 10_000 : values.profile === "matrix" ? 64 : 4)), fullMatrix };
  if (values.plan) {
    if (values.profile !== "matrix") throw Error("--plan requires --profile matrix");
    const { admissionMatrixPlan } = await import("../../tests/integration/admission-measure.js");
    console.log(JSON.stringify({ status: "PLAN_ONLY_NOT_MEASURED", ...admissionMatrixPlan(options) }, null, 2)); return;
  }
  if (values.profile === "matrix" && !values["matrix-child"]) {
    // A parent-process watchdog also bounds synchronous solc/EVM work that an
    // event-loop AbortSignal alone cannot interrupt. No grandchild processes.
    const child = spawn(process.execPath, [...process.execArgv, process.argv[1], ...process.argv.slice(2), "--matrix-child"], {
      stdio: "inherit", windowsHide: true, env: { ...process.env, MCPSHIELD_TELEMETRY_ENABLED: "false" }
    });
    let timedOut = false;
    const budgetMs = fullMatrix ? 3_600_000 : 180_000;
    const deadline = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, budgetMs);
    try {
      const code = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("exit", resolve); });
      if (timedOut) throw Error(`BENCHMARK_TOTAL_BUDGET_EXCEEDED: child terminated at ${budgetMs / 1000} seconds; no completed measurement`);
      if (code !== 0) throw Error("Benchmark child failed; no completed measurement");
    } finally { clearTimeout(deadline); }
    return;
  }
  if (fullMatrix && sourceSnapshot().dirty) throw Error("FULL_MATRIX_REQUIRES_CLEAN_SOURCE");
  const result = await withSourceProvenance(async () => {
    // Snapshot before importing the code that will actually be measured.
    const { measureAdmission, measureAdmissionMatrix } = await import("../../tests/integration/admission-measure.js");
    return values.profile === "matrix" ? measureAdmissionMatrix(options) : measureAdmission(options);
  });
  console.log(JSON.stringify(result, null, 2));
  if (result.status === "PARTIAL_FAILED") process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
