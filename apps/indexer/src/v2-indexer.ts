import type { ControlStore } from "../../api/src/control-store.js";
import type { V2Relayer } from "../../api/src/chain-outbox.js";
import { v2ChainReader } from "../../api/src/registry-v2-client.js";

export async function indexV2(store: ControlStore, client: V2Relayer, { deploymentBlock = 0, confirmations = 2 } = {}) {
  const chainId = client.chainId, registry = client.registryAddress.toLowerCase();
  let checkpoints = await store.query("SELECT block_number,block_hash FROM cp_v2_blocks WHERE chain_id = ? AND registry_address = ? ORDER BY block_number DESC", [chainId, registry]);
  for (const saved of checkpoints) {
    const canonical = await client.provider.getBlock(saved.block_number);
    if (canonical?.hash === saved.block_hash) break;
    const orphaned = await store.query("SELECT release_id,transaction_hash,block_hash FROM cp_v2_events WHERE chain_id = ? AND registry_address = ? AND block_number >= ?", [chainId, registry, saved.block_number]);
    const releases = await store.query("SELECT tenant_id,document FROM cp_records WHERE kind = 'release'");
    for (const event of orphaned) for (const row of releases) {
      const release = JSON.parse(row.document);
      if (release.releaseId === event.release_id) await store.event(row.tenant_id, event.release_id, "chain.event.orphaned", { txHash: event.transaction_hash, blockHash: event.block_hash, chainId });
    }
    await store.query("DELETE FROM cp_v2_events WHERE chain_id = ? AND registry_address = ? AND block_number >= ?", [chainId, registry, saved.block_number]);
    await store.query("DELETE FROM cp_v2_blocks WHERE chain_id = ? AND registry_address = ? AND block_number >= ?", [chainId, registry, saved.block_number]);
  }
  checkpoints = await store.query("SELECT block_number FROM cp_v2_blocks WHERE chain_id = ? AND registry_address = ? ORDER BY block_number DESC LIMIT 1", [chainId, registry]);
  const head = await client.provider.getBlock("latest"); if (!head) throw new Error("BLOCK_UNAVAILABLE");
  const from = checkpoints.length ? Number(checkpoints[0].block_number) + 1 : deploymentBlock;
  const to = Math.min(head.number, from + 499);
  const tenants = (await store.query("SELECT tenant_id,document FROM cp_records WHERE kind = 'release'")).map((row) => ({ tenantId: row.tenant_id, release: JSON.parse(row.document) }));
  let observed = 0;
  if (from <= to) {
    const logs = await client.provider.getLogs({ address: registry, fromBlock: from, toBlock: to });
    for (const log of logs) {
      const event = client.registry.interface.parseLog(log); if (!event) continue;
      const payload = Object.fromEntries(event.fragment.inputs.map((input, index) => [input.name, typeof event.args[index] === "bigint" ? event.args[index].toString() : event.args[index]]));
      const releaseId = payload.releaseId ?? null;
      const inserted = await store.query(`INSERT INTO cp_v2_events(chain_id,registry_address,block_number,block_hash,transaction_hash,log_index,release_id,event_name,payload)
        VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(chain_id,registry_address,transaction_hash,log_index) DO NOTHING RETURNING log_index`,
        [chainId, registry, log.blockNumber, log.blockHash, log.transactionHash, log.index, releaseId, event.name, JSON.stringify(payload)]);
      if (inserted.length) {
        observed++;
        for (const entry of tenants.filter((entry) => entry.release.releaseId === releaseId)) await store.event(entry.tenantId, releaseId, `chain.${event.name}`, { ...payload, blockNumber: log.blockNumber, blockHash: log.blockHash, txHash: log.transactionHash, chainId });
      }
    }
    // Keep every observed block hash: rewind can find a precise common ancestor even across empty blocks.
    for (let number = from; number <= to; number++) {
      const block = await client.provider.getBlock(number); if (!block?.hash) throw new Error("BLOCK_UNAVAILABLE");
      await store.query("INSERT INTO cp_v2_blocks(chain_id,registry_address,block_number,block_hash) VALUES(?,?,?,?) ON CONFLICT(chain_id,registry_address,block_number) DO NOTHING", [chainId, registry, number, block.hash]);
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
      const [event] = await store.query("SELECT transaction_hash FROM cp_v2_events WHERE chain_id = ? AND registry_address = ? AND release_id = ? ORDER BY block_number DESC,log_index DESC LIMIT 1", [chainId, registry, release.releaseId]);
      await store.put(tenantId, "release", release.releaseId, { ...release, status: state.status, chainUnavailable: false, policyHash: policy.policyHash,
        reportRoot: state.reportRoot, validUntil: state.validUntil, chain: { chainId, registryContract: client.registryAddress,
          observedBlock: state.observedBlock, blockHash: state.blockHash, txHash: event?.transaction_hash ?? null } }, true);
    } catch {
      await store.put(tenantId, "release", release.releaseId, { ...release, status: "UNVERIFIED", chainUnavailable: true }, true);
    }
  } } finally { read.close(); }
  return { observed, head: head.number, indexedBlock: to, lag: Math.max(0, head.number - to) };
}
