import { parseArgs } from "node:util";
import { execFileSync } from "node:child_process";
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
  const { values } = parseArgs({ options: { requests: { type: "string", default: "40" }, concurrency: { type: "string", default: "4" }, identities: { type: "string", default: "4" } } });
  const result = await withSourceProvenance(async () => {
    // Snapshot before importing the code that will actually be measured.
    const { measureAdmission } = await import("../../tests/integration/admission-measure.js");
    return measureAdmission({ requests: Number(values.requests), concurrency: Number(values.concurrency), identities: Number(values.identities) });
  });
  console.log(JSON.stringify(result, null, 2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
