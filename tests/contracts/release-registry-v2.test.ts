import assert from "node:assert/strict";
import { test } from "node:test";
import ganache from "ganache";
import { BrowserProvider, ContractFactory, Wallet, id } from "ethers";
import { compileReleaseRegistry } from "../../contracts/scripts/compile.js";
import { attestationV2Domain, attestationV2Types, exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";

const dig = `0x${"a".repeat(64)}`, surface = `0x${"b".repeat(64)}`, root = `0x${"c".repeat(64)}`, policy = id("policy-v1");
const compiled = Object.fromEntries(["ValidatorRegistry", "PolicyRegistry", "ReleaseRegistryV2"].map((name) => [name, compileReleaseRegistry(name)]));
async function fixture() {
  const chain: any = ganache.provider({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  const provider = new BrowserProvider(chain), owner = await provider.getSigner(0);
  const accounts = Object.values(chain.getInitialAccounts()) as {secretKey: string}[];
  const keys = accounts.map((a) => new Wallet(a.secretKey, provider));
  const deploy = async (name: string, args: any[]) => {
    const factory = new ContractFactory(compiled[name].abi, compiled[name].bytecode, owner), instance: any = await factory.deploy(...args);
    await instance.waitForDeployment(); return instance;
  };
  const validators = await deploy("ValidatorRegistry", [await owner.getAddress(), keys.slice(1, 4).map((k) => k.address)]);
  const policies = await deploy("PolicyRegistry", [await owner.getAddress()]);
  await (await policies.publish(policy, policy)).wait();
  const registry = await deploy("ReleaseRegistryV2", [await owner.getAddress(), await validators.getAddress(), await policies.getAddress()]);
  const identity = exactReleaseIdentity({ toolId: "npm:mail-mcp", artifactDigest: dig, manifestDigest: dig, toolSurfaceHash: surface });
  await (await registry.registerRelease(identity.toolId, dig, dig, surface)).wait();
  const now = Number((await provider.getBlock("latest"))!.timestamp);
  const payload = { releaseId: identity.releaseId, artifactDigest: dig, manifestDigest: dig, toolSurfaceDigest: surface,
    policyHash: policy, reportRoot: root, verdict: 0, validFrom: now, validUntil: now + 3600, validatorSetVersion: 1, nonce: 0, deadline: now + 3600 };
  const domain = attestationV2Domain(1337, await registry.getAddress());
  const sign = (index: number, value = payload, customDomain = domain) => keys[index].signTypedData(customDomain, attestationV2Types, value);
  return { chain, provider, registry, validators, policies, keys, payload, domain, sign, close: () => chain.disconnect() };
}
test("V2 binds report/policy/validity/identity and rejects replay, other domain, stale validator set", async () => {
  const f = await fixture();
  try {
    const signature = await f.sign(1);
    await assert.rejects(f.registry.submitAttestation({ ...f.payload, artifactDigest: surface }, signature));
    await assert.rejects(f.registry.submitAttestation(f.payload, await f.sign(1, f.payload, { ...f.domain, chainId: 999 })));
    await (await f.registry.submitAttestation(f.payload, signature)).wait();
    await assert.rejects(async () => { await (await f.registry.submitAttestation(f.payload, signature)).wait(); });
    await assert.rejects(f.registry.submitAttestation({ ...f.payload, reportRoot: surface }, await f.sign(2, { ...f.payload, reportRoot: surface })));
    await (await f.registry.submitAttestation(f.payload, await f.sign(2))).wait();
    assert.equal((await f.registry.getDecision(f.payload.releaseId, policy)).status, 1n);
    const next = { ...f.payload, nonce: 1 };
    await (await f.validators.disable(f.keys[3].address)).wait();
    await assert.rejects(f.registry.submitAttestation(next, await f.sign(1, next)));
    assert.equal((await f.registry.getDecision(f.payload.releaseId, policy)).status, 4n);
  } finally { await f.close(); }
});
test("V2 quarantine is deterministic, <=24h, global across policies, expires without restoring old approval", async () => {
  const f = await fixture();
  try {
    for (const index of [1, 2]) await (await f.registry.submitAttestation(f.payload, await f.sign(index))).wait();
    const validator = f.registry.connect(await f.provider.getSigner(1));
    const expiry = f.payload.validFrom + 60;
    await assert.rejects(validator.quarantine(f.payload.releaseId, policy, root, id("AI_SCORE"), expiry));
    await assert.rejects(validator.quarantine(f.payload.releaseId, policy, root, id("CANARY_EXFILTRATION"), expiry + 86400));
    await (await validator.quarantine(f.payload.releaseId, policy, root, id("CANARY_EXFILTRATION"), expiry)).wait();
    assert.equal((await f.registry.getDecision(f.payload.releaseId, id("other-policy"))).status, 2n);
    await f.chain.request({ method: "evm_increaseTime", params: [65] }); await f.chain.request({ method: "evm_mine", params: [] });
    assert.equal((await f.registry.getDecision(f.payload.releaseId, policy)).status, 4n);
    await (await f.registry.syncExpiry(f.payload.releaseId, policy)).wait();
  } finally { await f.close(); }
});
test("V2 matching FAIL quorum permanently revokes exact bytes across policies", async () => {
  const f = await fixture();
  try {
    const fail = { ...f.payload, verdict: 1 };
    for (const index of [1, 2]) await (await f.registry.submitAttestation(fail, await f.sign(index, fail))).wait();
    assert.equal((await f.registry.getDecision(f.payload.releaseId, policy)).status, 3n);
    assert.equal((await f.registry.getDecision(f.payload.releaseId, id("another-policy"))).status, 3n);
    await assert.rejects(f.registry.submitAttestation(f.payload, await f.sign(3)));
  } finally { await f.close(); }
});

test("V2 PASS majority is independent of dissent order and TTL finalization needs no third signature", async () => {
  const f = await fixture();
  try {
    const fail = { ...f.payload, verdict: 1 };
    await (await f.registry.submitAttestation(fail, await f.sign(3, fail))).wait();
    for (const index of [1, 2]) await (await f.registry.submitAttestation(f.payload, await f.sign(index))).wait();
    assert.equal((await f.registry.getDecision(f.payload.releaseId, policy)).status, 1n);
    const now = Number((await f.provider.getBlock("latest"))!.timestamp);
    const validator = f.registry.connect(await f.provider.getSigner(1));
    await (await validator.quarantine(f.payload.releaseId, policy, root, id("CANARY_EXFILTRATION"), now + 60)).wait();
    await f.chain.request({ method: "evm_increaseTime", params: [2] }); await f.chain.request({ method: "evm_mine", params: [] });
    const fresh = { ...f.payload, reportRoot: surface, nonce: 1, validFrom: now + 2, validUntil: now + 3602 };
    for (const index of [1, 2]) await (await f.registry.submitAttestation(fresh, await f.sign(index, fresh))).wait();
    assert.equal((await f.registry.getDecision(f.payload.releaseId, policy)).status, 2n);
    await f.chain.request({ method: "evm_increaseTime", params: [65] }); await f.chain.request({ method: "evm_mine", params: [] });
    await (await f.registry.syncExpiry(f.payload.releaseId, policy)).wait();
    assert.equal((await f.registry.getDecision(f.payload.releaseId, policy)).status, 1n);
  } finally { await f.close(); }
});
