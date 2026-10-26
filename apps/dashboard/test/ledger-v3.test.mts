import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import ganache from "ganache";
import { Contract, JsonRpcProvider, NonceManager, Wallet } from "ethers";
import { compileReleaseRegistry } from "../../../contracts/scripts/compile.js";
import { deployV2 } from "../../../contracts/scripts/deploy-v2.js";
import { defaultPolicy } from "../../api/src/control-policy.js";
import { hash } from "../../api/src/control-plane.js";
import { runValidatorV3 } from "../../validator/src/v3.js";
import { bytes32, createReleaseRegistryV3, exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v3.js";
import { readLedger } from "../lib/ledger-v3.js";
// @ts-expect-error Resolver is shared ESM JavaScript.
import { resolveArtifact } from "../../../services/resolver/src/resolver.mjs";

const repo = resolve(import.meta.dirname, "../../..");
const SAFE = join(repo, "demo/fixtures/mail-mcp-1.0.0"), MALICIOUS = join(repo, "demo/fixtures/mail-mcp-1.0.1");

test("ledger reads V3 from chain receipts only, shows dissent, and both companies' Gateways allow 1.0.0 and block revoked 1.0.1", { timeout: 120000 }, async () => {
  // Compile before the in-process chain starts: a multi-second solc stall during chain traffic times out RPC requests.
  for (const name of ["ValidatorRegistry", "PolicyRegistry", "ReleaseRegistryV3"]) compileReleaseRegistry(name);
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  const evidenceDir = await mkdtemp(join(tmpdir(), "mcpshield-ledger-"));
  let provider: JsonRpcProvider | undefined;
  try {
    await chain.listen(0, "127.0.0.1");
    const rpc = `http://127.0.0.1:${chain.address().port}`;
    const keys = (Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[]).map((a) => a.secretKey);
    const validators = keys.slice(1, 4).map((k) => new Wallet(k).address);
    const deployment = await deployV2(rpc, keys[0], validators, 1337, undefined, "ReleaseRegistryV3");
    provider = new JsonRpcProvider(rpc, 1337, { staticNetwork: true, cacheTimeout: -1 });
    const owner = new NonceManager(new Wallet(keys[0], provider));
    const registry: any = createReleaseRegistryV3(deployment.releaseRegistry.address, owner);
    const policyHash = hash(defaultPolicy), txHashes: string[] = [];
    txHashes.push((await (await new Contract(deployment.policyRegistry.address, ["function publish(bytes32,bytes32)"], owner).publish(policyHash, policyHash)).wait()).hash);
    const ids: Record<string, string> = {};
    for (const [name, dir] of [["mail-mcp-1.0.0", SAFE], ["mail-mcp-1.0.1", MALICIOUS]]) {
      const resolved = await resolveArtifact({ sourceType: "local", locator: dir }), exact = exactReleaseIdentity(resolved);
      txHashes.push((await (await registry.registerRelease(exact.toolId, bytes32(resolved.artifactDigest), bytes32(resolved.manifestDigest), bytes32(resolved.toolSurfaceHash))).wait()).hash);
      ids[name] = exact.releaseId;
    }
    const t = Number((await provider.getBlock("latest"))!.timestamp), window = { validFrom: t - 5, validUntil: t + 3600 };
    const base = { rpcUrl: rpc, chainId: 1337, registryAddress: deployment.releaseRegistry.address, policyHash, evidenceDir, relayerKey: keys[0], ...window };
    const runs = [
      await runValidatorV3({ ...base, privateKey: keys[1], releaseId: ids["mail-mcp-1.0.0"], artifactDir: SAFE }),
      await runValidatorV3({ ...base, privateKey: keys[2], releaseId: ids["mail-mcp-1.0.0"], artifactDir: SAFE }),
      await runValidatorV3({ ...base, privateKey: keys[3], releaseId: ids["mail-mcp-1.0.1"], artifactDir: MALICIOUS, baselineDir: SAFE, quarantine: true, relayerKey: undefined }),
      await runValidatorV3({ ...base, privateKey: keys[1], releaseId: ids["mail-mcp-1.0.1"], artifactDir: MALICIOUS, baselineDir: SAFE }),
      await runValidatorV3({ ...base, privateKey: keys[2], releaseId: ids["mail-mcp-1.0.1"], artifactDir: MALICIOUS, baselineDir: SAFE }),
    ];
    for (const run of runs) txHashes.push(...run.transactions.map((tx: any) => tx.txHash));
    // A pointer to someone else's transaction must not inject events.
    const stranger = (await (await new Wallet(keys[4], provider).sendTransaction({ to: validators[0], value: 1n })).wait())!.hash;
    const ledger = await readLedger({ rpcUrl: rpc, chainId: 1337, registry: deployment.releaseRegistry.address, policyRegistry: deployment.policyRegistry.address,
      validators, txHashes: [...txHashes, stranger, `0x${"0".repeat(64)}`], names: { [ids["mail-mcp-1.0.0"]]: "mail-mcp-1.0.0" },
      companies: [{ name: "A사", rpcUrl: rpc }, { name: "B사", rpcUrl: rpc }] });
    assert.equal(ledger.policyHash, policyHash);
    const safe = ledger.releases.find((r) => r.releaseId === ids["mail-mcp-1.0.0"])!, bad = ledger.releases.find((r) => r.releaseId === ids["mail-mcp-1.0.1"])!;
    assert.deepEqual([safe.name, safe.status, bad.name, bad.status], ["mail-mcp-1.0.0", "VERIFIED", null, "REVOKED"]);
    assert.deepEqual(safe.rounds[0].votes.map((v) => [v.label, v.verdict, v.afterDecision]), [["A", "PASS", false], ["B", "PASS", false]]);
    assert.deepEqual(bad.events.map((e) => e.kind), ["REGISTERED", "QUARANTINE", "VOTE", "VOTE", "REVOKED", "VOTE"]);
    assert.equal(bad.rounds[0].outcome, "REJECTED");
    assert.deepEqual(safe.admission.map((a) => [a.company, a.decision, a.reasonCode]), [["A사", "ALLOW", "RELEASE_VERIFIED"], ["B사", "ALLOW", "RELEASE_VERIFIED"]]);
    assert.deepEqual(bad.admission.map((a) => [a.company, a.decision, a.reasonCode]), [["A사", "BLOCK", "RELEASE_REVOKED"], ["B사", "BLOCK", "RELEASE_REVOKED"]]);
  } finally {
    provider?.destroy();
    await chain.close();
    await rm(evidenceDir, { recursive: true, force: true });
  }
});
