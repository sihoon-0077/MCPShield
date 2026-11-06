import assert from "node:assert/strict";
import { test } from "node:test";
import ganache from "ganache";
import { BrowserProvider, ContractFactory, Wallet, ZeroHash, id } from "ethers";
import { compileReleaseRegistry } from "../../contracts/scripts/compile.js";
import { receiptAnchorDomain, receiptBatchTypes } from "../../packages/contracts-sdk/src/receipts.js";

test("receipt anchors pin writer, domain, root, range and previous checkpoint on a real local EVM", async (t) => {
  const chain = ganache.provider({ logging: { quiet: true }, wallet: { deterministic: true } });
  const provider = new BrowserProvider(chain as any), signer = await provider.getSigner();
  const accounts = Object.values(chain.getInitialAccounts()) as { secretKey: string }[];
  const writer = new Wallet(accounts[1].secretKey), other = new Wallet(accounts[2].secretKey);
  try {
    const compiled = compileReleaseRegistry("ReceiptAnchorRegistry"), factory = new ContractFactory(compiled.abi, compiled.bytecode, signer);
    const registry: any = await factory.deploy(await signer.getAddress()), second: any = await factory.deploy(await signer.getAddress());
    await registry.waitForDeployment(); await second.waitForDeployment();
    const domain = receiptAnchorDomain(1337, await registry.getAddress()), ledgerKey = id("synthetic-ledger"), otherLedger = id("synthetic-other-ledger");
    await assert.rejects(registry.connect(await provider.getSigner(2)).registerLedger(ledgerKey, writer.address));
    const registration = await (await registry.registerLedger(ledgerKey, writer.address)).wait();
    await (await registry.registerLedger(otherLedger, writer.address)).wait();
    await (await second.registerLedger(ledgerKey, writer.address)).wait();
    await assert.rejects(registry.registerLedger(ledgerKey, other.address));
    const now = (await provider.getBlock("latest"))!.timestamp;
    const batch = { ledgerKey, root: id("synthetic-root-1"), fromSequence: 1, toSequence: 2, previousReceiptHash: ZeroHash,
      tipReceiptHash: id("synthetic-tip-2"), previousBatchRoot: ZeroHash, nonce: 0, deadline: now + 600 };
    const signature = await writer.signTypedData(domain, receiptBatchTypes, batch);
    await assert.rejects(second.anchor(batch, signature));
    await assert.rejects(registry.anchor({ ...batch, ledgerKey: otherLedger }, signature));
    await assert.rejects(registry.anchor(batch, await other.signTypedData(domain, receiptBatchTypes, batch)));
    await assert.rejects(registry.anchor(batch, await writer.signTypedData({ ...domain, chainId: 1 }, receiptBatchTypes, batch)));
    for (const change of [{ fromSequence: 2 }, { toSequence: 128 }, { previousReceiptHash: id("bad") }, { previousBatchRoot: id("bad") }, { nonce: 1 }, { deadline: now - 1 }]) {
      const tampered = { ...batch, ...change };
      await assert.rejects(registry.anchor(tampered, await writer.signTypedData(domain, receiptBatchTypes, tampered)));
    }
    const first = await (await registry.anchor(batch, signature)).wait();
    assert.equal((await registry.ledgers(ledgerKey)).lastSequence, 2n);
    assert.equal(await registry.rootLedger(batch.root), ledgerKey);
    await assert.rejects(registry.anchor.staticCall(batch, signature));
    const copied = { ...batch, ledgerKey: otherLedger };
    await assert.rejects(registry.anchor(copied, await writer.signTypedData(domain, receiptBatchTypes, copied)));
    const next = { ...batch, root: id("synthetic-root-2"), fromSequence: 3, toSequence: 3,
      previousReceiptHash: batch.tipReceiptHash, tipReceiptHash: id("synthetic-tip-3"), previousBatchRoot: batch.root, nonce: 1 };
    const secondBatch = await (await registry.anchor(next, await writer.signTypedData(domain, receiptBatchTypes, next))).wait();
    assert.equal((await registry.ledgers(ledgerKey)).lastSequence, 3n);
    t.diagnostic(JSON.stringify({ chain: "LOCAL_GANACHE", deploymentGas: (await registry.deploymentTransaction()!.wait())!.gasUsed.toString(),
      registrationGas: registration.gasUsed.toString(), firstBatchGas: first.gasUsed.toString(), nextBatchGas: secondBatch.gasUsed.toString(), bytecodeBytes: (compiled.bytecode.length - 2) / 2 }));
  } finally { provider.destroy(); await chain.disconnect(); }
});
