import { parseArgs } from "node:util";
import { execFileSync } from "node:child_process";
import { measureAdmission } from "../../tests/integration/admission-measure.js";
const { values } = parseArgs({ options: { requests: { type: "string", default: "40" }, concurrency: { type: "string", default: "4" }, identities: { type: "string", default: "4" } } });
const result = await measureAdmission({ requests: Number(values.requests), concurrency: Number(values.concurrency), identities: Number(values.identities) });
const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", windowsHide: true }).trim();
const dirty = Boolean(execFileSync("git", ["status", "--porcelain"], { encoding: "utf8", windowsHide: true }).trim());
console.log(JSON.stringify({ ...result, sourceCommit: commit, worktreeDirty: dirty }, null, 2));
