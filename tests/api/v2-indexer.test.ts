import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as pause } from "node:timers/promises";
import ganache from "ganache";
import { Wallet, id } from "ethers";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { V2Relayer } from "../../apps/api/src/chain-outbox.js";
import { indexV2 } from "../../apps/indexer/src/v2-indexer.js";
import { attestationV2Types, exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";

test("V2 indexer: atomic audits, canonical order, duplicate/restart/reorg recovery and observation lag on real EVM/SQL", { timeout: 60000 }, async () => {
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  let store: ControlStore | undefined, relayer: V2Relayer | undefined, dir: string | undefined;
  let primaryFailure: unknown;
  try {
    await chain.listen(0, "127.0.0.1");
    const rpc = `http://127.0.0.1:${chain.address().port}`;
    const accounts = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
    const deployment = await deployV2(rpc, accounts[0].secretKey, accounts.slice(1, 4).map(account => new Wallet(account.secretKey).address), 1337);
    relayer = new V2Relayer(rpc, deployment.releaseRegistry.address, 1337, accounts[0].secretKey);
    dir = await mkdtemp(join(tmpdir(), "mcpshield-v2-indexer-"));
    store = await ControlStore.open(join(dir, "control.sqlite"));
    let registry: any = relayer.registry.connect(await relayer.provider.getSigner(0));
    const digest = id("synthetic-indexer-source"), surface = id("synthetic-indexer-tools");
    const identity = exactReleaseIdentity({ toolId: "npm:synthetic-indexer", artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: surface });
    const release = { ...identity, artifactDigest: `sha256:${digest.slice(2)}`, manifestDigest: digest, toolSurfaceHash: surface, status: "UNVERIFIED" };
    for (const tenant of ["tenant-a", "tenant-b"]) await store.put(tenant, "release", identity.releaseId, release);
    const registration = await (await registry.registerRelease(identity.toolId, digest, digest, surface)).wait();
    const options = { deploymentBlock: deployment.releaseRegistry.blockNumber, confirmations: 1 };
    // Inject a real SQL write failure after tenant-a's audit, not a mocked transaction.
    await store.query(`CREATE TRIGGER fail_indexer_audit BEFORE INSERT ON cp_events
      WHEN NEW.tenant_id = 'tenant-b' AND NEW.event_name = 'chain.ReleaseRegistered'
      BEGIN SELECT RAISE(ABORT, 'SYNTHETIC_INDEXER_AUDIT_FAILURE'); END`);
    await assert.rejects(indexV2(store, relayer, options), /SYNTHETIC_INDEXER_AUDIT_FAILURE/);
    assert.equal((await store.query("SELECT * FROM cp_v2_events")).length, 0, "event insertion must roll back with a failed tenant audit");
    assert.equal((await store.query("SELECT * FROM cp_events WHERE event_name LIKE 'chain.%'")).length, 0, "earlier tenant audit must also roll back");
    assert.equal((await store.query("SELECT * FROM cp_v2_blocks WHERE block_number = ?", [registration.blockNumber])).length, 0);
    await store.query("DROP TRIGGER fail_indexer_audit");
    assert.equal((await indexV2(store, relayer, options)).observed, 1);
    for (const tenant of ["tenant-a", "tenant-b"]) assert.equal((await store.events(tenant, identity.releaseId)).length, 1);

    const policyHash = id("synthetic-indexer-policy"), root = id("synthetic-indexer-report");
    const policy: any = (await relayer.policyContract()).connect(await relayer.provider.getSigner(0));
    await (await policy.publish(policyHash, policyHash)).wait();
    for (const tenant of ["tenant-a", "tenant-b"]) {
      await store.put(tenant, "policy", policyHash, { policyHash });
      // Explicit report fixture: this test covers real indexer/chain persistence, not scanner execution.
      const { scan } = await store.enqueue(tenant, { releaseId: identity.releaseId, policyHash }, "indexer-scan", "indexer-scan", "a".repeat(32));
      await store.query("UPDATE cp_scans SET state = 'COMPLETED', result_json = '{}' WHERE scan_id = ?", [scan.scanId]);
    }
    const now = Number((await relayer.provider.getBlock("latest"))!.timestamp);
    const attestation = { releaseId: identity.releaseId, artifactDigest: digest, manifestDigest: digest, toolSurfaceDigest: surface,
      policyHash, reportRoot: root, verdict: 0, validFrom: now, validUntil: now + 3600, validatorSetVersion: 1, nonce: 0, deadline: now + 3600 };
    for (const account of accounts.slice(1, 3)) await (await registry.submitAttestation(attestation,
      await new Wallet(account.secretKey).signTypedData(relayer.domain, attestationV2Types, attestation))).wait();
    await pause(300); // Expire ethers' bounded block cache before observing actual newly mined blocks.
    const originalGetLogs = relayer.provider.getLogs.bind(relayer.provider);
    let canonicalLogs: Awaited<ReturnType<typeof originalGetLogs>> = [];
    for (const fault of ["range", "hash"]) {
      relayer.provider.getLogs = async filter => (await originalGetLogs(filter)).map((log, index) => index ? log :
        { ...log, ...(fault === "range" ? { blockNumber: options.deploymentBlock - 1 } : { blockHash: id("synthetic-wrong-block") }) } as typeof log);
      await assert.rejects(indexV2(store, relayer, options), new RegExp(fault === "range" ? "INDEXER_LOG_RANGE_MISMATCH" : "INDEXER_LOG_BLOCK_MISMATCH"));
      assert.equal((await store.query("SELECT * FROM cp_v2_events")).length, 1);
      assert.equal((await store.query("SELECT * FROM cp_events WHERE event_name LIKE 'chain.%'")).length, 2);
    }
    // Reorder and repeat genuine RPC logs only; block hashes and contract data remain real.
    relayer.provider.getLogs = async (filter) => {
      canonicalLogs = await originalGetLogs(filter);
      return [...canonicalLogs].reverse().flatMap(log => [log, log]);
    };
    const started = Date.now(), indexed = await indexV2(store, relayer, options);
    assert.equal(indexed.observed, canonicalLogs.length); assert.ok(canonicalLogs.length >= 3);
    assert.deepEqual(Object.keys(indexed).sort(), ["head", "indexedBlock", "lag", "observed", "observedAt"]);
    assert.ok(Date.parse(indexed.observedAt) >= started && Date.parse(indexed.observedAt) <= Date.now());
    const persisted = await store.query("SELECT transaction_hash,log_index,block_hash FROM cp_v2_events ORDER BY block_number,log_index");
    assert.equal(persisted.length, canonicalLogs.length + 1);
    for (const log of canonicalLogs) assert.ok(persisted.some(row => row.transaction_hash === log.transactionHash && row.log_index === log.index && row.block_hash === log.blockHash));
    const audits = () => store!.query("SELECT event_name,payload FROM cp_events WHERE tenant_id = 'tenant-a' AND event_name LIKE 'chain.%' ORDER BY rowid");
    const ordered = (await audits()).slice(1);
    assert.deepEqual(ordered.map(row => [row.event_name, JSON.parse(row.payload).txHash]), canonicalLogs.map(log => [`chain.${relayer!.registry.interface.parseLog(log)!.name}`, log.transactionHash]));
    for (const tenant of ["tenant-a", "tenant-b"]) {
      const projected: Record<string, any> = (await store.get(tenant, "release", identity.releaseId))!;
      assert.equal(projected.status, "VERIFIED"); assert.equal(projected.chainUnavailable, false);
      assert.ok(Date.parse(projected.chain.observedAt) >= started && Date.parse(projected.chain.observedAt) <= Date.parse(indexed.observedAt));
      assert.equal(projected.chain.txHash, canonicalLogs.at(-1)!.transactionHash);
      assert.equal(projected.chain.blockHash, (await relayer.provider.getBlock(projected.chain.observedBlock))!.hash);
    }
    const auditCount = (await audits()).length;
    assert.equal((await indexV2(store, relayer, options)).observed, 0);
    assert.equal((await audits()).length, auditCount);

    // Restart durable DB/provider handles, not the chain. This is not an OS process-restart claim.
    await store.close(); store = undefined; relayer.close(); relayer = undefined;
    store = await ControlStore.open(join(dir, "control.sqlite"));
    relayer = new V2Relayer(rpc, deployment.releaseRegistry.address, 1337, accounts[0].secretKey);
    registry = relayer.registry.connect(await relayer.provider.getSigner(0));
    const resumed = await indexV2(store, relayer, options);
    assert.equal(resumed.observed, 0); assert.equal(resumed.lag, 0); assert.equal((await audits()).length, auditCount);
    const competingReplacement = async (name: string) => {
      const otherStore = await ControlStore.open(join(dir!, "control.sqlite"));
      const other = new V2Relayer(rpc, deployment.releaseRegistry.address, 1337, accounts[0].secretKey);
      try {
        const writer: any = other.registry.connect(await other.provider.getSigner(0));
        const replacement = await (await writer.registerRelease(id(name), digest, digest, surface)).wait();
        await pause(300); await indexV2(otherStore, other, options);
        return replacement;
      } finally { other.close(); await otherStore.close(); }
    };
    let getBlock = relayer.provider.getBlock.bind(relayer.provider), replacement: any;
    // Another indexer may commit the same canonical block while A waits; that is a safe duplicate.
    const sameBlock = await (await registry.registerRelease(id("synthetic-same-block"), digest, digest, surface)).wait();
    await pause(300);
    let competed = false;
    relayer.provider.getBlock = async (...args) => {
      const captured = await getBlock(...args);
      if (args[0] === sameBlock.blockNumber && !competed) {
        competed = true;
        const otherStore = await ControlStore.open(join(dir!, "control.sqlite"));
        const other = new V2Relayer(rpc, deployment.releaseRegistry.address, 1337, accounts[0].secretKey);
        try { assert.equal((await indexV2(otherStore, other, options)).observed, 1); }
        finally { other.close(); await otherStore.close(); }
      }
      return captured;
    };
    assert.equal((await indexV2(store, relayer, options)).observed, 0);
    relayer.provider.getBlock = getBlock;
    assert.equal(competed, true);
    assert.equal((await store.query("SELECT * FROM cp_v2_events WHERE transaction_hash = ?", [sameBlock.hash])).length, 1);
    assert.equal((await store.query("SELECT block_hash FROM cp_v2_blocks WHERE block_number = ?", [sameBlock.blockNumber]))[0].block_hash, sameBlock.blockHash);
    // A has actual old RPC logs/block in flight; B persists a same-height or shorter replacement fork first.
    for (const shorterFork of [false, true]) {
      const staleSnapshot = await chain.provider.request({ method: "evm_snapshot", params: [] });
      let oldParent: any;
      if (shorterFork) {
        oldParent = await (await registry.registerRelease(id("synthetic-old-parent"), digest, digest, surface)).wait();
        await pause(300); await indexV2(store, relayer, options);
      }
      const staleRegistration = await (await registry.registerRelease(id(`synthetic-stale-rpc-${shorterFork}`), digest, digest, surface)).wait();
      await pause(300); replacement = undefined;
      getBlock = relayer.provider.getBlock.bind(relayer.provider);
      relayer.provider.getBlock = async (...args) => {
        const captured = await getBlock(...args);
        if (args[0] === staleRegistration.blockNumber && !replacement) {
          assert.equal(await chain.provider.request({ method: "evm_revert", params: [staleSnapshot] }), true);
          replacement = await competingReplacement(`synthetic-competing-insert-${shorterFork}`);
        }
        return captured;
      };
      let rejected: unknown;
      // A changed deployment setting cannot exempt resumed blocks below the new boundary.
      try { await indexV2(store, relayer, shorterFork ? { ...options, deploymentBlock: staleRegistration.blockNumber + 10 } : options); }
      catch (error) { rejected = error; }
      relayer.provider.getBlock = getBlock;
      assert.equal(replacement.blockNumber, staleRegistration.blockNumber - Number(shorterFork));
      assert.notEqual(replacement.blockHash, (oldParent ?? staleRegistration).blockHash);
      assert.equal((await store.query("SELECT * FROM cp_v2_events WHERE transaction_hash = ?", [staleRegistration.hash])).length, 0, "stale child cannot be committed over a replacement parent");
      assert.ok(rejected instanceof Error && rejected.message === "INDEXER_CHECKPOINT_CONFLICT");
      assert.deepEqual((await store.query("SELECT transaction_hash FROM cp_v2_events WHERE block_number = ?", [replacement.blockNumber])).map(row => row.transaction_hash), [replacement.hash]);
      assert.equal((await store.query("SELECT block_hash FROM cp_v2_blocks WHERE block_number = ?", [replacement.blockNumber]))[0].block_hash, replacement.blockHash);
      if (shorterFork) {
        assert.equal((await store.query("SELECT * FROM cp_v2_events WHERE transaction_hash = ?", [oldParent.hash])).length, 0);
        assert.equal((await store.query("SELECT * FROM cp_v2_blocks WHERE block_number = ?", [staleRegistration.blockNumber])).length, 0);
      }
      await pause(300); await indexV2(store, relayer, options);
    }
    let snapshot = await chain.provider.request({ method: "evm_snapshot", params: [] });
    let quarantine = await (await registry.connect(await relayer.provider.getSigner(1)).quarantine(identity.releaseId, policyHash, root, id("CANARY_EXFILTRATION"), now + 600)).wait();
    await pause(300);
    await store.query(`CREATE TRIGGER fail_indexer_checkpoint BEFORE INSERT ON cp_v2_blocks
      WHEN NEW.block_number = ${quarantine.blockNumber}
      BEGIN SELECT RAISE(ABORT, 'SYNTHETIC_INDEXER_CHECKPOINT_FAILURE'); END`);
    await assert.rejects(indexV2(store, relayer, options), /SYNTHETIC_INDEXER_CHECKPOINT_FAILURE/);
    assert.equal((await store.query("SELECT * FROM cp_v2_events WHERE transaction_hash = ?", [quarantine.hash])).length, 0, "checkpoint failure cannot leave an untracked event");
    assert.equal((await audits()).length, auditCount, "checkpoint failure must also roll back its tenant audits");
    assert.equal((await store.query("SELECT * FROM cp_v2_blocks WHERE block_number = ?", [quarantine.blockNumber])).length, 0);
    await store.query("DROP TRIGGER fail_indexer_checkpoint");
    assert.equal(await chain.provider.request({ method: "evm_revert", params: [snapshot] }), true);
    await store.close(); store = undefined; relayer.close(); relayer = undefined;
    store = await ControlStore.open(join(dir, "control.sqlite"));
    relayer = new V2Relayer(rpc, deployment.releaseRegistry.address, 1337, accounts[0].secretKey);
    registry = relayer.registry.connect(await relayer.provider.getSigner(0));
    assert.equal((await indexV2(store, relayer, options)).observed, 0);
    assert.equal((await store.query("SELECT * FROM cp_v2_events WHERE transaction_hash = ?", [quarantine.hash])).length, 0);
    assert.equal((await audits()).length, auditCount);
    assert.equal((await store.get("tenant-a", "release", identity.releaseId))!.status, "VERIFIED");
    snapshot = await chain.provider.request({ method: "evm_snapshot", params: [] });
    quarantine = await (await registry.connect(await relayer.provider.getSigner(1)).quarantine(identity.releaseId, policyHash, root, id("CANARY_EXFILTRATION"), now + 600)).wait();
    await pause(300);
    assert.equal((await indexV2(store, relayer, options)).observed, 1);
    assert.equal((await store.get("tenant-a", "release", identity.releaseId))!.status, "QUARANTINED");
    assert.equal(await chain.provider.request({ method: "evm_revert", params: [snapshot] }), true);
    await pause(300);
    await store.query(`CREATE TRIGGER fail_orphan_audit BEFORE INSERT ON cp_events
      WHEN NEW.tenant_id = 'tenant-b' AND NEW.event_name = 'chain.event.orphaned'
      BEGIN SELECT RAISE(ABORT, 'SYNTHETIC_ORPHAN_AUDIT_FAILURE'); END`);
    await assert.rejects(indexV2(store, relayer, options), /SYNTHETIC_ORPHAN_AUDIT_FAILURE/);
    assert.equal((await store.query("SELECT * FROM cp_v2_events WHERE transaction_hash = ?", [quarantine.hash])).length, 1);
    assert.equal((await store.query("SELECT * FROM cp_events WHERE event_name = 'chain.event.orphaned'")).length, 0);
    await store.query("DROP TRIGGER fail_orphan_audit");
    // A sees an orphaned saved head. B rewinds and installs the replacement before A's SQL lock.
    getBlock = relayer.provider.getBlock.bind(relayer.provider); replacement = undefined;
    relayer.provider.getBlock = async (...args) => {
      const captured = await getBlock(...args);
      if (args[0] === quarantine.blockNumber && !replacement) replacement = await competingReplacement("synthetic-competing-rewind");
      return captured;
    };
    await assert.rejects(indexV2(store, relayer, options), /INDEXER_CHECKPOINT_CONFLICT/);
    relayer.provider.getBlock = getBlock;
    assert.equal((await store.query("SELECT * FROM cp_v2_events WHERE transaction_hash = ?", [quarantine.hash])).length, 0);
    assert.equal(replacement.blockNumber, quarantine.blockNumber); assert.notEqual(replacement.blockHash, quarantine.blockHash);
    assert.equal((await store.query("SELECT block_hash FROM cp_v2_blocks WHERE block_number = ?", [replacement.blockNumber]))[0].block_hash, replacement.blockHash);
    assert.deepEqual((await store.query("SELECT transaction_hash FROM cp_v2_events WHERE block_number = ?", [replacement.blockNumber])).map(row => row.transaction_hash), [replacement.hash]);
    for (const tenant of ["tenant-a", "tenant-b"]) {
      assert.equal((await store.get(tenant, "release", identity.releaseId))!.status, "VERIFIED");
      assert.equal((await store.events(tenant)).filter(event => event.eventName === "chain.event.orphaned").length, 1);
    }
    await pause(300); await indexV2(store, relayer, options);
    assert.equal((await store.query("SELECT * FROM cp_events WHERE event_name = 'chain.event.orphaned'")).length, 2);

    // The existing fixed 500-block window reports block lag, not elapsed seconds.
    for (let block = 0; block < 501; block++) await chain.provider.request({ method: "evm_mine", params: [] });
    await pause(300);
    const behind = await indexV2(store, relayer, options);
    assert.equal(behind.lag, 1); assert.equal(behind.head - behind.indexedBlock, 1); assert.equal(behind.observed, 0);
    const caughtUp = await indexV2(store, relayer, options);
    assert.equal(caughtUp.lag, 0); assert.equal(caughtUp.indexedBlock, behind.head);

    const prior = (await store.get("tenant-a", "release", identity.releaseId))!;
    assert.equal(prior.status, "VERIFIED");
    await chain.provider.request({ method: "evm_setTime", params: [Date.now() - 60000] });
    await chain.provider.request({ method: "evm_mine", params: [] }); await pause(300);
    await indexV2(store, relayer, options);
    const stale = (await store.get("tenant-a", "release", identity.releaseId))!;
    assert.equal(stale.status, "UNVERIFIED"); assert.equal(stale.chainUnavailable, true);
    assert.deepEqual(stale.chain, prior.chain, "failed fresh proof cannot refresh historical observation metadata");
    await chain.provider.request({ method: "evm_setTime", params: [Date.now()] });
    await chain.provider.request({ method: "evm_mine", params: [] }); await pause(300);
    await indexV2(store, relayer, options);
    const recovered = (await store.get("tenant-a", "release", identity.releaseId))!;
    assert.equal(recovered.status, "VERIFIED"); assert.equal(recovered.chainUnavailable, false);
    assert.ok(Date.parse(recovered.chain.observedAt) > Date.parse(prior.chain.observedAt));
  } catch (error) { primaryFailure = error; throw error; }
  finally {
    const cleanup = await Promise.allSettled([Promise.resolve().then(() => relayer?.close()), Promise.resolve().then(() => store?.close()), Promise.resolve().then(() => chain.close())]);
    if (dir) cleanup.push(...await Promise.allSettled([rm(dir, { recursive: true, force: true })]));
    const failures = cleanup.filter(result => result.status === "rejected");
    if (failures.length) throw new AggregateError(failures.map(result => result.reason), "INDEXER_TEST_CLEANUP_FAILED", { cause: primaryFailure });
  }
});
