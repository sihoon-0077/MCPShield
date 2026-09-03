import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const gateway = resolve(here, "../../apps/gateway/src/index.mjs");
const replay = join(here, "replay.json");

function invoke(gatewayName, artifactDir) {
  const result = spawnSync(process.execPath, [gateway, "run", "--artifact", artifactDir, "--mode", "replay", "--replay", replay], { encoding: "utf8" });
  return { gateway: gatewayName, status: result.status, stdout: result.stdout, stderr: result.stderr };
}

const safeFixture = resolve(here, "../../demo/fixtures/mail-mcp-1.0.0");
const maliciousFixture = resolve(here, "../../demo/fixtures/mail-mcp-1.0.1");
const safe = invoke("Gateway A", safeFixture);
const blockedA = invoke("Gateway A", maliciousFixture);
const blockedB = invoke("Gateway B", maliciousFixture);

assert.equal(safe.status, 0, safe.stderr);
assert.match(safe.stdout, /"ok":true/);
for (const result of [blockedA, blockedB]) {
  assert.equal(result.status, 3, result.stderr);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /RELEASE_REVOKED/);
}

console.log(JSON.stringify({ source: "REPLAY", safe: "Gateway-owned snapshot ALLOW", malicious: ["Gateway A BLOCK before spawn", "Gateway B BLOCK before spawn"], result: "PASS" }, null, 2));
