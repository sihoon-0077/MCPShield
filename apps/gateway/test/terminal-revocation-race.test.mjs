import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

// Builtin mutation lives only in this disposable child, never the test runner.
async function regression() {
  const { default: assert } = await import("node:assert/strict");
  const { default: fs } = await import("node:fs/promises");
  const { syncBuiltinESMExports } = await import("node:module");
  const { generateKeyPairSync, sign } = await import("node:crypto");
  const { execFileSync } = await import("node:child_process");
  const { join } = await import("node:path");
  const [moduleUrl, barrier, directory] = process.argv.slice(1);
  const cacheFile = join(directory, "admission.json");
  const originalWrite = fs.writeFile, originalOpen = fs.open;
  let entered, resume, first;
  const reached = new Promise(resolve => { entered = resolve; });
  const released = new Promise(resolve => { resume = resolve; });
  fs.writeFile = async (path, ...args) => {
    if (barrier === "temporary-write" && String(path) === `${cacheFile}.${process.pid}.tmp`) { entered(); await released; }
    return originalWrite(path, ...args);
  };
  fs.open = async (path, ...args) => {
    const handle = await originalOpen(path, ...args);
    if (barrier === "lock-cleanup" && String(path) === `${cacheFile}.lock`) {
      const close = handle.close.bind(handle);
      handle.close = async () => { entered(); await released; return close(); };
    }
    return handle;
  };
  syncBuiltinESMExports();
  try {
    const { getSignedAdmission } = await import(moduleUrl);
    const keys = generateKeyPairSync("ed25519"), now = Date.now();
    const identity = { releaseId: `0x${"1".repeat(64)}`, artifactDigest: `sha256:${"2".repeat(64)}`, toolSurfaceHash: `0x${"3".repeat(64)}` };
    const context = { identity, controlReleaseId: identity.releaseId, publicKey: keys.publicKey.export({ type: "spki", format: "pem" }), keyId: "synthetic-race-key",
      policyHash: `0x${"4".repeat(64)}`, chainId: 31337, registryContract: `0x${"5".repeat(40)}`, validatorSetVersion: 1,
      operationClass: "READ_PRIVATE", tenantId: "synthetic-tenant-a", apiToken: "synthetic-race-credential-only", apiBaseUrl: "http://127.0.0.1:3901", admissionMode: "balanced", timeoutMs: 1000 };
    const base = { schemaVersion: "1.0.0", keyId: context.keyId, ...identity, policyHash: context.policyHash, validatorSetVersion: 1,
      chainId: context.chainId, registryContract: context.registryContract, observedBlock: 123, blockHash: `0x${"6".repeat(64)}`,
      issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 30000).toISOString(), status: "VERIFIED", decision: "ALLOW",
      operationClass: context.operationClass, tenantId: context.tenantId, reasonCode: "RELEASE_VERIFIED", reportUrl: `/v1/releases/${identity.releaseId}` };
    const signed = snapshot => ({ snapshot, signature: sign(null, Buffer.from(JSON.stringify(Object.fromEntries(Object.keys(snapshot).sort().map(key => [key, snapshot[key]])))), keys.privateKey).toString("base64url") });
    const allow = signed(base);
    first = getSignedAdmission({ ...context, cacheFile, now: () => now, fetchImpl: async () => Response.json(allow) }).then(value => ({ value }), error => ({ error }));
    await reached;
    const changed = { tenantId: "synthetic-tenant-b", policyHash: `0x${"7".repeat(64)}` };
    const denial = signed({ ...base, ...changed, decision: "BLOCK", status: "REVOKED", reasonCode: "RELEASE_REVOKED" });
    const fresh = await getSignedAdmission({ ...context, ...changed, cacheFile: null, now: () => now, fetchImpl: async () => Response.json(denial) });
    assert.equal(fresh.decision, "BLOCK"); assert.equal(fresh.releaseStatus, "REVOKED"); assert.equal(fresh.cacheHit, false);
    resume();
    const late = await first;
    assert.equal(late.value, undefined, `A late ALLOW escaped after another tenant's completed REVOKED at ${barrier}`);
    assert.match(late.error?.message ?? "", /revoked|superseded/i);
    assert.equal(await fs.readFile(cacheFile, "utf8"), "null", "A superseded ALLOW must not remain in the persisted cache");
    const journal = JSON.parse(await fs.readFile(`${cacheFile}.revoked`, "utf8"));
    assert.equal(journal.schemaVersion, "mcpshield.revocation.v1"); assert.deepEqual(journal.envelope, denial);
    await assert.rejects(fs.stat(`${cacheFile}.lock`), { code: "ENOENT" });
    // Fresh process: rejection must depend on the authenticated journal, not this child's memory map.
    const restart = `import assert from 'node:assert/strict'; import {readFileSync} from 'node:fs';
      const {getSignedAdmission}=await import(process.argv[1]); const x=JSON.parse(readFileSync(0,'utf8'));
      await assert.rejects(getSignedAdmission({...x.context,cacheFile:x.cacheFile,now:()=>x.now,fetchImpl:async()=>Response.json(x.allow)}),/previously revoked/);
      console.log('RESTART_BLOCKED');`;
    assert.equal(execFileSync(process.execPath, ["--input-type=module", "-e", restart, moduleUrl], {
      windowsHide: true, encoding: "utf8", timeout: 5000, input: JSON.stringify({ context, cacheFile, now, allow }),
    }).trim(), "RESTART_BLOCKED");
    console.log("TERMINAL_RACE_BLOCKED");
  } finally {
    resume(); await first;
    fs.writeFile = originalWrite; fs.open = originalOpen; syncBuiltinESMExports();
  }
}

for (const barrier of ["temporary-write", "lock-cleanup"]) {
  test(`cross-tenant terminal revocation wins at ${barrier}, clears ALLOW and survives restart`, { timeout: 15000 }, async () => {
    const directory = await mkdtemp(join(tmpdir(), "mcpshield-terminal-race-"));
    assert.equal(dirname(directory), tmpdir());
    try {
      let result;
      try { result = execFileSync(process.execPath, ["--input-type=module", "-e", `(${regression.toString()})()`, new URL("../src/signed-admission.mjs", import.meta.url).href, barrier, directory], {
        windowsHide: true, encoding: "utf8", timeout: 10000, stdio: ["ignore", "pipe", "pipe"],
      }); } catch (error) {
        // Report the assertion, not the entire child source or signed fixture payload.
        assert.fail(String(error.stderr ?? "").match(/AssertionError[^:\n]*: ([^\r\n]+)/)?.[1] ?? `Terminal race child failed at ${barrier} (exit ${error.status}, signal ${error.signal ?? "none"})`);
      }
      assert.equal(result.trim(), "TERMINAL_RACE_BLOCKED");
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}
