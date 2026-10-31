import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

// The rehearsal stack teams run before the final demo: operator API, outbox, indexer and three independent validators on
// an in-process Ganache. --smoke drives 1.0.0 and 1.0.1 through the same API the dashboard uses and exits non-zero on any miss.
test("V3 local stack smoke: three validators approve 1.0.0 and revoke 1.0.1 through the operator relay, admission follows", { timeout: 300000 }, async () => {
  const script = fileURLToPath(new URL("../../scripts/demo/v3-local-stack.mts", import.meta.url));
  const child = spawn(process.execPath, ["--import", "tsx", script, "--smoke", "--api-port", "0"], { stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", () => {});
  const exitCode = await new Promise<number | null>((resolve) => child.once("exit", resolve));
  const lines = output.split("\n").filter((line) => line.includes("[점검]"));
  assert.equal(exitCode, 0, lines.join("\n"));
  assert.ok(lines.some((line) => /mail-mcp 1\.0\.0 · VERIFIED · 실행 판정 ALLOW/.test(line)), lines.join("\n"));
  assert.ok(lines.some((line) => /mail-mcp 1\.0\.1 · REVOKED · 실행 판정 BLOCK/.test(line)), lines.join("\n"));
  assert.match(output, /\[검증자 C\] mail-mcp-1\.0\.1 · 자기 검사 FAIL .*긴급 격리/);
  // The stack's own lines (banner and [actor] lines; scanner JSON events aside) never carry a key, a token or a full hash.
  const own = output.split("\n").filter((line) => !line.startsWith("{"));
  assert.ok(own.every((line) => !/BEGIN PRIVATE KEY|[0-9a-f]{48}/i.test(line)), "no secret-length hex in the stack log");
});
