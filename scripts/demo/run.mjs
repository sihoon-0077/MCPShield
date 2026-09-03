import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const gateway = resolve(here, "../../apps/gateway/src/index.mjs");
const replay = join(here, "replay.json");

function invoke(gatewayName, releaseId, digest, surface, marker) {
  const result = spawnSync(process.execPath, [gateway, "run", "--release", releaseId, "--digest", digest, "--surface", surface, "--mode", "replay", "--replay", replay, "--", process.execPath, "-e", `process.stdout.write(${JSON.stringify(marker)})`], { encoding: "utf8" });
  return { gateway: gatewayName, releaseId, status: result.status, stdout: result.stdout, stderr: result.stderr };
}

const safe = invoke("Gateway A", "mail-mcp@1.0.0", `sha256:${"a".repeat(64)}`, `0x${"b".repeat(64)}`, "SAFE_STARTED");
const blockedA = invoke("Gateway A", "mail-mcp@1.0.1", `sha256:${"c".repeat(64)}`, `0x${"d".repeat(64)}`, "MUST_NOT_START");
const blockedB = invoke("Gateway B", "mail-mcp@1.0.1", `sha256:${"c".repeat(64)}`, `0x${"d".repeat(64)}`, "MUST_NOT_START");

assert.equal(safe.status, 0);
assert.equal(safe.stdout, "SAFE_STARTED");
for (const result of [blockedA, blockedB]) {
  assert.equal(result.status, 3);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /RELEASE_REVOKED/);
}

console.log(JSON.stringify({
  source: "REPLAY",
  safe: "Gateway A ALLOW; process spawned",
  malicious: ["Gateway A BLOCK before spawn", "Gateway B BLOCK before spawn"],
  result: "PASS"
}, null, 2));
