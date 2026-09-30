import type { ControlStore } from "../../api/src/control-store.js";
import type { V2Relayer } from "../../api/src/chain-outbox.js";
import { v2ChainReader } from "../../api/src/registry-v2-client.js";
import { currentTraceId, withSpan } from "../../../packages/telemetry/index.mjs";

async function indexedTransaction<T>(store: ControlStore, client: V2Relayer, txHash: string, blockNumber: number, execute: () => Promise<T>) {
  const [action] = await store.query("SELECT submission_trace_parent,trace_parent FROM cp_chain_actions WHERE chain_id = ? AND registry_address = ? AND tx_hash = ? LIMIT 1", [client.chainId, client.registryAddress.toLowerCase(), txHash]);
  return withSpan("indexer.observe", { "mcpshield.chain_id": client.chainId, "mcpshield.block_number": blockNumber }, execute,
    { traceparent: action?.submission_trace_parent ?? action?.trace_parent ?? undefined });
}

export async function indexV2(store: ControlStore, client: V2Relayer, { deploymentBlock = 0, confirmations = 2 } = {}) {
  const chainId = client.chainId, registry = client.registryAddress.toLowerCase();
  const transactionKey = `v2-indexer:${chainId}:${registry}`;
  let checkpoints;
  while (true) {
    const [saved] = await store.query("SELECT block_number,block_hash FROM cp_v2_blocks WHERE chain_id = ? AND registry_address = ? ORDER BY block_number DESC LIMIT 1", [chainId, registry]);
    if (!saved) break;
    const canonical = await client.provider.getBlock(saved.block_number);
    if (canonical?.hash === saved.block_hash) break;
    await store.forTenant(transactionKey, async (tx) => {
      const [current] = await tx.query("SELECT block_number,block_hash FROM cp_v2_blocks WHERE chain_id = ? AND registry_address = ? ORDER BY block_number DESC LIMIT 1", [chainId, registry]);
      if (current?.block_number !== saved.block_number || current.block_hash !== saved.block_hash) throw new Error("INDEXER_CHECKPOINT_CONFLICT");
      const orphaned = await tx.query("SELECT release_id,transaction_hash,block_hash FROM cp_v2_events WHERE chain_id = ? AND registry_address = ? AND block_number >= ?", [chainId, registry, saved.block_number]);
      const releases = await tx.query("SELECT tenant_id,document FROM cp_records WHERE kind = 'release'");
      for (const event of orphaned) for (const row of releases) {
        const release = JSON.parse(row.document);
        if (release.releaseId === event.release_id) await indexedTransaction(tx, client, event.transaction_hash, saved.block_number,
          () => tx.event(row.tenant_id, event.release_id, "chain.event.orphaned", { txHash: event.transaction_hash, blockHash: event.block_hash, chainId }, currentTraceId()));
      }
      await tx.query("DELETE FROM cp_v2_events WHERE chain_id = ? AND registry_address = ? AND block_number >= ?", [chainId, registry, saved.block_number]);
      await tx.query("DELETE FROM cp_v2_blocks WHERE chain_id = ? AND registry_address = ? AND block_number >= ?", [chainId, registry, saved.block_number]);
    });
  }
  checkpoints = await store.query("SELECT block_number FROM cp_v2_blocks WHERE chain_id = ? AND registry_address = ? ORDER BY block_number DESC LIMIT 1", [chainId, registry]);
  const head = await client.provider.getBlock("latest"); if (!head) throw new Error("BLOCK_UNAVAILABLE");
  const from = checkpoints.length ? Number(checkpoints[0].block_number) + 1 : deploymentBlock;
  const to = Math.min(head.number, from + 499);
  const tenants = (await store.query("SELECT tenant_id,document FROM cp_records WHERE kind = 'release'")).map((row) => ({ tenantId: row.tenant_id, release: JSON.parse(row.document) }));
  let observed = 0;
  if (from <= to) {
    const logs = await client.provider.getLogs({ address: registry, fromBlock: from, toBlock: to });
    logs.sort((a, b) => a.blockNumber - b.blockNumber || a.transactionIndex - b.transactionIndex || a.index - b.index);
    const blocks = new Map<number, typeof logs>();
    for (const log of logs) {
      if (!Number.isSafeInteger(log.blockNumber) || log.blockNumber < from || log.blockNumber > to) throw new Error("INDEXER_LOG_RANGE_MISMATCH");
      if (!blocks.has(log.blockNumber)) blocks.set(log.blockNumber, []);
      blocks.get(log.blockNumber)!.push(log);
    }
    // RPC stays outside SQL transactions. Each block's events, tenant audits and
    // checkpoint commit together, including empty blocks needed for reorg rewind.
    for (let number = from; number <= to; number++) {
      const block = await client.provider.getBlock(number); if (!block?.hash) throw new Error("BLOCK_UNAVAILABLE");
      const blockLogs = blocks.get(number) ?? [];
      if (blockLogs.some(log => log.blockHash !== block.hash)) throw new Error("INDEXER_LOG_BLOCK_MISMATCH");
      observed += await store.forTenant(transactionKey, async (tx) => {
        const [current] = await tx.query("SELECT block_hash FROM cp_v2_blocks WHERE chain_id = ? AND registry_address = ? AND block_number = ?", [chainId, registry, number]);
        if (current && current.block_hash !== block.hash) throw new Error("INDEXER_CHECKPOINT_CONFLICT");
        // Only the configured first block has no indexed predecessor. A shorter
        // replacement fork must not accept an old child whose height is still empty.
        if (number !== deploymentBlock) {
          const [previous] = await tx.query("SELECT block_hash FROM cp_v2_blocks WHERE chain_id = ? AND registry_address = ? AND block_number = ?", [chainId, registry, number - 1]);
          if (!previous || previous.block_hash !== block.parentHash) throw new Error("INDEXER_CHECKPOINT_CONFLICT");
        }
        let insertedCount = 0;
        for (const log of blockLogs) {
          const event = client.registry.interface.parseLog(log); if (!event) continue;
          const payload = Object.fromEntries(event.fragment.inputs.map((input, index) => [input.name, typeof event.args[index] === "bigint" ? event.args[index].toString() : event.args[index]]));
          const releaseId = payload.releaseId ?? null;
          await indexedTransaction(tx, client, log.transactionHash, log.blockNumber, async () => {
            const inserted = await tx.query(`INSERT INTO cp_v2_events(chain_id,registry_address,block_number,block_hash,transaction_hash,log_index,release_id,event_name,payload)
              VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(chain_id,registry_address,transaction_hash,log_index) DO NOTHING RETURNING log_index`,
              [chainId, registry, log.blockNumber, log.blockHash, log.transactionHash, log.index, releaseId, event.name, JSON.stringify(payload)]);
            if (inserted.length) {
              insertedCount++;
              for (const entry of tenants.filter((entry) => entry.release.releaseId === releaseId)) await tx.event(entry.tenantId, releaseId, `chain.${event.name}`, { ...payload, blockNumber: log.blockNumber, blockHash: log.blockHash, txHash: log.transactionHash, chainId }, currentTraceId());
            }
          });
        }
        await tx.query("INSERT INTO cp_v2_blocks(chain_id,registry_address,block_number,block_hash) VALUES(?,?,?,?) ON CONFLICT(chain_id,registry_address,block_number) DO NOTHING", [chainId, registry, number, block.hash]);
        return insertedCount;
      });
    }
  }
  const read = v2ChainReader({ rpcUrls: [client.rpcUrl], registryContract: client.registryAddress, chainId, confirmations });
  try { for (const { tenantId, release } of tenants) {
    const scans = (await store.scans(tenantId)).filter((scan) => scan.releaseId === release.releaseId && scan.status === "COMPLETED");
    const latest = scans[0]; if (!latest) continue;
    const policy = await store.get(tenantId, "policy", latest.policyHash); if (!policy) continue;
    try {
      const state = await read(release, policy);
      if (state.unavailable) throw new Error("STATUS_UNAVAILABLE");
      // Observation metadata only; Gateway authorization still uses its fresh signed proof.
      const observedAt = "checkedAt" in state && typeof state.checkedAt === "string" ? state.checkedAt : new Date().toISOString();
      const [event] = await store.query("SELECT transaction_hash FROM cp_v2_events WHERE chain_id = ? AND registry_address = ? AND release_id = ? ORDER BY block_number DESC,log_index DESC LIMIT 1", [chainId, registry, release.releaseId]);
      await store.put(tenantId, "release", release.releaseId, { ...release, status: state.status, chainUnavailable: false, policyHash: policy.policyHash,
        reportRoot: state.reportRoot, validUntil: state.validUntil, chain: { chainId, registryContract: client.registryAddress,
          observedBlock: state.observedBlock, blockHash: state.blockHash, txHash: event?.transaction_hash ?? null, observedAt } }, true);
    } catch {
      await store.put(tenantId, "release", release.releaseId, { ...release, status: "UNVERIFIED", chainUnavailable: true }, true);
    }
  } } finally { read.close(); }
  return { observed, head: head.number, indexedBlock: to, lag: Math.max(0, head.number - to), observedAt: new Date().toISOString() };
}
