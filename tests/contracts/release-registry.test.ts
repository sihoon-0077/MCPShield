import assert from "node:assert/strict";
import { test } from "node:test";
import ganache from "ganache";
import { BrowserProvider, ContractFactory, Wallet } from "ethers";
import { compileReleaseRegistry } from "../../contracts/scripts/compile.js";
import { attestationDomain, attestationTypes, chainDecisions } from "../../packages/contracts-sdk/src/index.js";

const artifact = `0x${"a".repeat(64)}`;
const toolHash = `0x${"b".repeat(64)}`;
const evidence = `0x${"c".repeat(64)}`;

async function fixture() {
  const ganacheProvider: any = ganache.provider({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  const provider = new BrowserProvider(ganacheProvider);
  const accounts = Object.values(ganacheProvider.getInitialAccounts()) as Array<{ secretKey: string }>;
  const wallets = accounts.map((account) => new Wallet(account.secretKey, provider));
  const [owner, ...rest] = wallets;
  const validators = rest.slice(0, 3);
  const outsider = rest[3];
  const compiled = compileReleaseRegistry();
  const factory = new ContractFactory(compiled.abi, compiled.bytecode, owner);
  const registry: any = await factory.deploy(validators.map((validator) => validator.address));
  await registry.waitForDeployment();
  await (await registry.registerRelease("mail-mcp@1.0.1", artifact, toolHash)).wait();
  const key = await registry.releaseKey("mail-mcp@1.0.1");
  const domain = attestationDomain(1337, await registry.getAddress());
  return { ganacheProvider, registry, validators, outsider, key, domain };
}

async function sign(wallet: Wallet, domain: ReturnType<typeof attestationDomain>, key: string, decision: "PASS" | "FAIL", nonce = 0, deadline = Math.floor(Date.now() / 1000) + 300) {
  return wallet.signTypedData(domain, attestationTypes, {
    releaseKey: key, decision: chainDecisions[decision], evidenceHash: evidence, nonce, deadline,
  });
}

test("contract recovers validator signer and rejects outsider, replay, and expiry", async () => {
  const { ganacheProvider, registry, validators, outsider, key, domain } = await fixture();
  try {
    assert.equal(await registry.isValidator(validators[0].address), true);
    assert.equal(await registry.isValidator(outsider.address), false);
    const deadline = Math.floor(Date.now() / 1000) + 300;
    const outsiderSig = await sign(outsider, domain, key, "FAIL", 0, deadline);
    await assert.rejects(registry.submitAttestation(key, 1, evidence, 0, deadline, outsiderSig));
    const signature = await sign(validators[0], domain, key, "FAIL", 0, deadline);
    await (await registry.submitAttestation(key, 1, evidence, 0, deadline, signature)).wait();
    const storedVote = await registry.getValidatorVote(key, validators[0].address);
    assert.equal(storedVote.releaseKey, key);
    assert.equal(storedVote.signer, validators[0].address);
    assert.equal(storedVote.decision, 1n);
    assert.equal(storedVote.evidenceHash, evidence);
    assert.equal(storedVote.nonce, 0n);
    assert.equal(storedVote.exists, true);
    await assert.rejects(async () => {
      await (await registry.submitAttestation(key, 1, evidence, 0, deadline, signature)).wait();
    });
    const expired = Math.floor(Date.now() / 1000) - 1;
    const expiredSig = await sign(validators[1], domain, key, "FAIL", 0, expired);
    await assert.rejects(registry.submitAttestation(key, 1, evidence, 0, expired, expiredSig));
  } finally { await ganacheProvider.disconnect(); }
});

test("two relayed FAIL attestations revoke and two PASS attestations verify", async () => {
  const first = await fixture();
  try {
    const deadline = Math.floor(Date.now() / 1000) + 300;
    for (let index = 0; index < 2; index++) {
      const sig = await sign(first.validators[index], first.domain, first.key, "FAIL", 0, deadline);
      await (await first.registry.submitAttestation(first.key, 1, evidence, 0, deadline, sig)).wait();
    }
    assert.equal((await first.registry.getRelease(first.key)).status, 3n);
  } finally { await first.ganacheProvider.disconnect(); }

  const second = await fixture();
  try {
    const deadline = Math.floor(Date.now() / 1000) + 300;
    for (let index = 0; index < 2; index++) {
      const sig = await sign(second.validators[index], second.domain, second.key, "PASS", 0, deadline);
      await (await second.registry.submitAttestation(second.key, 0, evidence, 0, deadline, sig)).wait();
    }
    assert.equal((await second.registry.getRelease(second.key)).status, 1n);
  } finally { await second.ganacheProvider.disconnect(); }
});
