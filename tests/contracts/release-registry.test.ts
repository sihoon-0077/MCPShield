import assert from "node:assert/strict";
import { test } from "node:test";
import ganache from "ganache";
import { BrowserProvider, ContractFactory } from "ethers";
import { compileReleaseRegistry } from "../../contracts/scripts/compile.js";

const artifact = `0x${"a".repeat(64)}`;
const toolHash = `0x${"b".repeat(64)}`;
const evidence = `0x${"c".repeat(64)}`;

async function fixture() {
  const ganacheProvider = ganache.provider({ logging: { quiet: true }, wallet: { totalAccounts: 5 } });
  const provider = new BrowserProvider(ganacheProvider as never);
  const owner = await provider.getSigner(0);
  const validators = await Promise.all([1, 2, 3].map((index) => provider.getSigner(index)));
  const outsider = await provider.getSigner(4);
  const compiled = compileReleaseRegistry();
  const factory = new ContractFactory(compiled.abi, compiled.bytecode, owner);
  const registry: any = await factory.deploy(
    (await Promise.all(validators.map((validator) => validator.getAddress()))) as [
      string,
      string,
      string,
    ],
  );
  await registry.waitForDeployment();
  await (await registry.registerRelease("mail-mcp@1.0.1", artifact, toolHash)).wait();
  const key = await registry.releaseKey("mail-mcp@1.0.1");
  return { ganacheProvider, registry, validators, outsider, key };
}

test("contract rejects outsiders and one vote per validator", async () => {
  const { ganacheProvider, registry, validators, outsider, key } = await fixture();
  try {
    await assert.rejects(registry.connect(outsider).submitVote(key, 1, evidence));
    await (await registry.connect(validators[0]).submitVote(key, 1, evidence)).wait();
    await assert.rejects(async () => {
      await (await registry.connect(validators[0]).submitVote(key, 1, evidence)).wait();
    });
  } finally {
    await ganacheProvider.disconnect();
  }
});

test("first FAIL quarantines and second FAIL irrevocably revokes", async () => {
  const { ganacheProvider, registry, validators, key } = await fixture();
  try {
    const first = await registry.connect(validators[0]).submitVote(key, 1, evidence);
    const firstReceipt = await first.wait();
    assert.ok(firstReceipt.logs.length >= 2);
    assert.equal((await registry.getRelease(key)).status, 2n);

    await (await registry.connect(validators[1]).submitVote(key, 1, evidence)).wait();
    const release = await registry.getRelease(key);
    assert.equal(release.status, 3n);
    assert.equal(release.failVotes, 2n);
    await assert.rejects(async () => {
      await (await registry.connect(validators[2]).submitVote(key, 0, evidence)).wait();
    });
  } finally {
    await ganacheProvider.disconnect();
  }
});

test("two PASS votes verify an unverified release", async () => {
  const { ganacheProvider, registry, validators, key } = await fixture();
  try {
    await (await registry.connect(validators[0]).submitVote(key, 0, evidence)).wait();
    assert.equal((await registry.getRelease(key)).status, 0n);
    await (await registry.connect(validators[1]).submitVote(key, 0, evidence)).wait();
    assert.equal((await registry.getRelease(key)).status, 1n);
  } finally {
    await ganacheProvider.disconnect();
  }
});
