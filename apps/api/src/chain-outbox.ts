import { randomUUID } from "node:crypto";
import { AbiCoder, Contract, JsonRpcProvider, TypedDataEncoder, Wallet, keccak256, verifyTypedData } from "ethers";
import { attestationV2Domain, attestationV2Types, bytes32, createReleaseRegistryV2, quarantineV2Types } from "../../../packages/contracts-sdk/src/v2.js";
import { ControlStore } from "./control-store.js";
import { hash } from "./control-plane.js";
import { currentTraceId, traceHeaders, withSpan } from "../../../packages/telemetry/index.mjs";
import { v2RpcRequest } from "../../../packages/contracts-sdk/src/transport.js";

export type ChainActionKind = "REGISTER_RELEASE" | "PUBLISH_POLICY" | "DEPRECATE_POLICY" | "ATTEST" | "QUARANTINE" | "SYNC_EXPIRY" | "REGISTER_RECEIPT_LEDGER" | "ANCHOR_RECEIPTS";
export type ChainRelayer = Pick<V2Relayer, "provider" | "signer" | "chainId" | "registryAddress" | "alreadyApplied" | "prepare">;
export const chainRetryBudget = Object.freeze({ maxAttempts: 12, maxElapsedMs: 300000, baseDelayMs: 1000, maxDelayMs: 30000 });
export const chainActionId = (relayer: ChainRelayer, tenantId: string, kind: ChainActionKind, payload: Record<string, any>) =>
  hash({ tenantId, kind, payload, chainId: relayer.chainId, registryAddress: relayer.registryAddress.toLowerCase() });
export class V2Relayer {
  readonly provider: JsonRpcProvider;
  readonly signer: Wallet;
  readonly registry: ReturnType<typeof createReleaseRegistryV2>;
  constructor(readonly rpcUrl: string, readonly registryAddress: string, readonly chainId: number, key: string) {
    const request = v2RpcRequest(rpcUrl);
    this.provider = new JsonRpcProvider(request, undefined, { batchMaxCount: 1 });
    this.signer = new Wallet(key, this.provider);
    this.registry = createReleaseRegistryV2(registryAddress, this.signer);
  }
  get domain() { return attestationV2Domain(this.chainId, this.registryAddress); }
  async context(validator?: string) {
    const network = await this.provider.getNetwork(); if (network.chainId !== BigInt(this.chainId)) throw new Error("CHAIN_ID_MISMATCH");
    const address = await this.registry.validators();
    const validators = new Contract(address, ["function version() view returns(uint32)", "function isActiveValidator(address,uint32) view returns(bool)"], this.provider);
    const version = Number(await validators.version());
    if (validator && !await validators.isActiveValidator(validator, version)) throw new Error("NOT_VALIDATOR");
    const nonce = validator ? Number(await this.registry.nonces(validator)) : 0;
    if (!Number.isSafeInteger(nonce)) throw new Error("NONCE_RANGE_UNSUPPORTED");
    return { validatorSetVersion: version, nonce };
  }
  async policyContract() { return new Contract(await this.registry.policies(), [
    "function policies(bytes32) view returns(bytes32 documentDigest,uint64 publishedAt,bool deprecated)",
    "function publish(bytes32,bytes32)", "function deprecate(bytes32)",
  ], this.signer); }
  async alreadyApplied(kind: ChainActionKind, payload: any) {
    if (kind === "REGISTER_RELEASE") return (await this.registry.releases(payload.releaseId)).exists;
    if (kind === "PUBLISH_POLICY") return (await (await this.policyContract()).policies(payload.policyHash)).publishedAt > 0n;
    if (kind === "DEPRECATE_POLICY") return (await (await this.policyContract()).policies(payload.policyHash)).deprecated;
    if (kind === "ATTEST") {
      const digest = TypedDataEncoder.hash(this.domain, attestationV2Types, payload.attestation);
      const validator = verifyTypedData(this.domain, attestationV2Types, payload.attestation, payload.signature);
      return await this.registry.usedDigest(keccak256(AbiCoder.defaultAbiCoder().encode(["bytes32", "address"], [digest, validator])));
    }
    return false;
  }
  async prepare(kind: ChainActionKind, payload: any, nonce: number) {
    let tx;
    if (kind === "REGISTER_RELEASE") tx = await this.registry.registerRelease.populateTransaction(payload.toolId, bytes32(payload.artifactDigest), bytes32(payload.manifestDigest), payload.toolSurfaceHash);
    else if (kind === "PUBLISH_POLICY") tx = await (await this.policyContract()).publish.populateTransaction(payload.policyHash, payload.policyHash);
    else if (kind === "DEPRECATE_POLICY") tx = await (await this.policyContract()).deprecate.populateTransaction(payload.policyHash);
    else if (kind === "ATTEST") tx = await this.registry.submitAttestation.populateTransaction(payload.attestation, payload.signature);
    else if (kind === "QUARANTINE") tx = await this.registry.quarantineBySignature.populateTransaction(payload.quarantine, payload.signature);
    else if (kind === "SYNC_EXPIRY") tx = await this.registry.syncExpiry.populateTransaction(payload.releaseId, payload.policyHash);
    else throw new Error("UNSUPPORTED_CHAIN_ACTION");
    const populated = await this.signer.populateTransaction({ ...tx, nonce, chainId: this.chainId });
    const raw = await this.signer.signTransaction(populated);
    return { raw, txHash: keccak256(raw) };
  }
  async validateSignature(payload: any, signature: string, quarantine = false) {
    const recovered = verifyTypedData(this.domain, quarantine ? quarantineV2Types : attestationV2Types, payload, signature);
    const context = await this.context(recovered);
    if (context.validatorSetVersion !== payload.validatorSetVersion || context.nonce !== payload.nonce) throw new Error("STALE_NONCE_OR_VALIDATOR_SET");
    return recovered;
  }
  close() { this.provider.destroy(); }
}

export async function enqueueChainAction(store: ControlStore, relayer: ChainRelayer, tenantId: string, kind: ChainActionKind, payload: Record<string, any>, traceparent = traceHeaders().traceparent) {
  const actionId = chainActionId(relayer, tenantId, kind, payload), now = new Date().toISOString();
  await store.query(`INSERT INTO cp_chain_actions(action_id,tenant_id,release_id,kind,payload,chain_id,relayer_address,created_at,updated_at,trace_parent,registry_address)
    VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(action_id) DO NOTHING`, [actionId, tenantId, payload.releaseId ?? payload.attestation?.releaseId ?? payload.quarantine?.releaseId ?? null,
    kind, JSON.stringify(payload), relayer.chainId, relayer.signer.address.toLowerCase(), now, now, traceparent ?? null, relayer.registryAddress.toLowerCase()]);
  return (await chainActions(store, tenantId, actionId))[0];
}
export async function chainActions(store: ControlStore, tenantId: string, actionId?: string) {
  return (await store.query(`SELECT action_id,release_id,kind,state,tx_hash,error_code,created_at,updated_at,chain_id,registry_address,attempts,retry_started_at,next_attempt_at FROM cp_chain_actions WHERE tenant_id = ?${actionId ? " AND action_id = ?" : ""} ORDER BY created_at DESC LIMIT 250`, [tenantId, ...(actionId ? [actionId] : [])])).map((row) => ({ actionId: row.action_id, releaseId: row.release_id, kind: row.kind, status: row.state, txHash: row.tx_hash, errorCode: row.error_code, createdAt: row.created_at, updatedAt: row.updated_at, chainId: row.chain_id, registryAddress: row.registry_address,
    attempts: row.attempts, retryStartedAt: row.retry_started_at, nextAttemptAt: row.next_attempt_at, retryBudget: chainRetryBudget }));
}
export async function runChainActionOnce(store: ControlStore, relayer: ChainRelayer) {
  const owner = randomUUID(), now = new Date().toISOString();
  const address = relayer.signer.address.toLowerCase(), expires = new Date(Date.now() + 60000).toISOString();
  await store.query("INSERT INTO cp_relayer_leases(chain_id,relayer_address) VALUES(?,?) ON CONFLICT(chain_id,relayer_address) DO NOTHING", [relayer.chainId, address]);
  // Serialize one account's nonce stream, not all tenants or all relayers. A crash releases this lease by TTL.
  const lease = await store.query(`UPDATE cp_relayer_leases SET lease_owner = ?, lease_expires_at = ?
    WHERE chain_id = ? AND relayer_address = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?) RETURNING chain_id`, [owner, expires, relayer.chainId, address, now]);
  if (!lease.length) return false;
  const releaseLease = () => store.query("UPDATE cp_relayer_leases SET lease_owner = NULL, lease_expires_at = NULL WHERE chain_id = ? AND relayer_address = ? AND lease_owner = ?", [relayer.chainId, address, owner]);
  // Backoff must not let another registry/tenant jump ahead of this account's reserved nonce.
  // An uncertain signed DLQ entry pauses this account until an operator reconciles chain truth.
  const [action] = await store.query(`UPDATE cp_chain_actions SET lease_owner = ?, lease_expires_at = ?, retry_started_at = COALESCE(retry_started_at, ?) WHERE action_id = (
    SELECT action_id FROM cp_chain_actions WHERE chain_id = ? AND relayer_address = ? AND state IN ('NEW','PREPARED','SUBMITTED')
      AND (registry_address = ? OR nonce IS NOT NULL OR raw_tx IS NOT NULL)
      ORDER BY CASE WHEN nonce IS NULL THEN 1 ELSE 0 END, nonce, created_at, action_id LIMIT 1${store.driver === "POSTGRESQL" ? " FOR UPDATE SKIP LOCKED" : ""})
    AND (registry_address = ? OR registry_address IS NULL) AND (lease_expires_at IS NULL OR lease_expires_at <= ?) AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
    AND NOT EXISTS (SELECT 1 FROM cp_chain_actions blocked WHERE blocked.chain_id = ? AND blocked.relayer_address = ? AND blocked.state = 'DEAD_LETTER' AND blocked.raw_tx IS NOT NULL) RETURNING *`,
    [owner, expires, now, relayer.chainId, address, relayer.registryAddress.toLowerCase(), relayer.registryAddress.toLowerCase(), now, now, relayer.chainId, address]);
  if (!action) { await releaseLease(); return false; }
  const exhausted = () => action.attempts >= chainRetryBudget.maxAttempts || Date.now() - Date.parse(action.retry_started_at) >= chainRetryBudget.maxElapsedMs;
  const fail = async (code: string, terminal = false, manual = false) => {
    const dead = manual || !terminal && exhausted(), state = terminal ? "FAILED" : dead ? "DEAD_LETTER" : action.raw_tx ? action.state === "SUBMITTED" ? "SUBMITTED" : "PREPARED" : "NEW";
    const delay = Math.min(chainRetryBudget.maxDelayMs, chainRetryBudget.baseDelayMs * 2 ** Math.max(0, action.attempts - 1));
    const next = terminal || dead ? null : new Date(Date.now() + delay).toISOString();
    await store.forTenant(action.tenant_id, async (tx) => {
      const rows = await tx.query(`UPDATE cp_chain_actions SET state = ?, error_code = ?, next_attempt_at = ?, updated_at = ?,
        nonce = CASE WHEN raw_tx IS NULL AND ? IN ('FAILED','DEAD_LETTER') THEN NULL ELSE nonce END WHERE action_id = ? AND lease_owner = ? RETURNING action_id`,
        [state, code, next, new Date().toISOString(), state, action.action_id, owner]);
      if (rows.length) await tx.event(action.tenant_id, action.release_id, dead ? "chain.action.dead_letter" : terminal ? "chain.action.failed" : "chain.action.retry_scheduled",
        { actionId: action.action_id, txHash: action.tx_hash, code, attempts: action.attempts, nextAttemptAt: next, retryBudget: chainRetryBudget }, currentTraceId());
    });
  };
  try {
    // A historical signed transaction without a registry domain must never be sent
    // to whichever registry happens to be configured after upgrading.
    if (!action.registry_address) { await fail("CHAIN_REGISTRY_UNRESOLVED", false, true); return true; }
    if (exhausted()) { await fail(action.error_code ?? "WORKER_LOST"); return true; }
    const started = await store.query("UPDATE cp_chain_actions SET attempts = attempts + 1 WHERE action_id = ? AND lease_owner = ? RETURNING attempts", [action.action_id, owner]);
    if (!started.length) return false;
    action.attempts = Number(started[0].attempts);
    const payload = JSON.parse(action.payload);
    await withSpan("chain.submit", { "mcpshield.chain_id": relayer.chainId }, async () => {
      await store.query("UPDATE cp_chain_actions SET submission_trace_parent = ? WHERE action_id = ? AND lease_owner = ?", [traceHeaders().traceparent ?? null, action.action_id, owner]);
      if (action.state === "NEW" && await relayer.alreadyApplied(action.kind, payload)) {
        await store.query("UPDATE cp_chain_actions SET state = 'COMPLETED', error_code = NULL, next_attempt_at = NULL, updated_at = ? WHERE action_id = ? AND lease_owner = ?", [new Date().toISOString(), action.action_id, owner]); return;
      }
      if (!action.raw_tx) {
        if (action.kind === "ATTEST") {
          const head = await relayer.provider.getBlock("latest");
          if (!head || Number(payload.attestation.validFrom) > head.timestamp) throw new Error("CHAIN_TIME_PENDING");
        }
        if (action.nonce === null) {
          const pendingNonce = await relayer.provider.getTransactionCount(relayer.signer.address, "pending");
          for (let attempt = 0; attempt < 5; attempt++) {
            try {
              const [reserved] = await store.query(`UPDATE cp_chain_actions SET nonce = (SELECT ${store.driver === "POSTGRESQL" ? "GREATEST" : "MAX"}(COALESCE(MAX(nonce),-1) + 1,?) FROM cp_chain_actions WHERE chain_id = ? AND relayer_address = ?)
                WHERE action_id = ? AND nonce IS NULL AND lease_owner = ? RETURNING nonce`, [pendingNonce, relayer.chainId, relayer.signer.address.toLowerCase(), action.action_id, owner]);
              if (!reserved) throw new Error("LEASE_LOST"); action.nonce = Number(reserved.nonce); break;
            } catch (error: any) { if (attempt === 4 || !(error.code === "23505" || /UNIQUE/.test(error.message))) throw error; }
          }
        }
        const prepared = await relayer.prepare(action.kind, payload, action.nonce);
        const updated = await store.query("UPDATE cp_chain_actions SET raw_tx = ?, tx_hash = ?, state = 'PREPARED', updated_at = ? WHERE action_id = ? AND lease_owner = ? RETURNING action_id",
          [prepared.raw, prepared.txHash, new Date().toISOString(), action.action_id, owner]);
        if (!updated.length) throw new Error("LEASE_LOST"); action.raw_tx = prepared.raw; action.tx_hash = prepared.txHash;
      }
      let receipt = await relayer.provider.getTransactionReceipt(action.tx_hash);
      if (!receipt) {
        try { await relayer.provider.broadcastTransaction(action.raw_tx); }
        catch (error: any) { if (!/already known|known transaction|nonce/i.test(error.message)) throw error; }
        await store.query("UPDATE cp_chain_actions SET state = 'SUBMITTED', updated_at = ? WHERE action_id = ? AND lease_owner = ?", [new Date().toISOString(), action.action_id, owner]);
        action.state = "SUBMITTED";
        receipt = await relayer.provider.getTransactionReceipt(action.tx_hash);
      }
      if (receipt) {
        const state = receipt.status === 1 ? "COMPLETED" : "FAILED";
        await store.query("UPDATE cp_chain_actions SET state = ?, error_code = ?, next_attempt_at = NULL, updated_at = ? WHERE action_id = ? AND lease_owner = ?",
          [state, state === "FAILED" ? "TRANSACTION_REVERTED" : null, new Date().toISOString(), action.action_id, owner]);
        await store.event(action.tenant_id, action.release_id, "chain.action.completed", { actionId: action.action_id, txHash: action.tx_hash, status: state }, currentTraceId());
      } else throw new Error("CHAIN_RECEIPT_PENDING");
    }, { traceparent: action.trace_parent ?? undefined });
  } catch (error: any) {
    // Prepared bytes are retained on every uncertain outcome; recovery rebroadcasts the identical tx.
    const terminal = (["CALL_EXCEPTION", "INVALID_ARGUMENT", "UNSUPPORTED_OPERATION"].includes(error.code)
      || ["UNSUPPORTED_CHAIN_ACTION", "CHAIN_ID_MISMATCH"].includes(error.message) || error instanceof SyntaxError) && !action.raw_tx;
    await fail(terminal ? "CHAIN_ACTION_REJECTED" : ["CHAIN_TIME_PENDING", "CHAIN_RECEIPT_PENDING"].includes(error.message) ? error.message : "RPC_UNAVAILABLE", terminal);
  } finally {
    await store.query("UPDATE cp_chain_actions SET lease_owner = NULL, lease_expires_at = NULL WHERE action_id = ? AND lease_owner = ?", [action.action_id, owner]);
    await releaseLease();
  }
  return true;
}

export async function reconcileV2Actions(store: ControlStore, relayer: ChainRelayer) {
  const completed = await store.query("SELECT action_id,tx_hash FROM cp_chain_actions WHERE chain_id = ? AND relayer_address = ? AND registry_address = ? AND state = 'COMPLETED' AND tx_hash IS NOT NULL ORDER BY updated_at DESC LIMIT 100", [relayer.chainId, relayer.signer.address.toLowerCase(), relayer.registryAddress.toLowerCase()]);
  let rewound = 0;
  for (const action of completed) {
    const receipt = await relayer.provider.getTransactionReceipt(action.tx_hash);
    if (!receipt) {
      await store.query("UPDATE cp_chain_actions SET state = 'PREPARED', error_code = 'REORG_RECEIPT_LOST', attempts = 0, retry_started_at = NULL, next_attempt_at = NULL, updated_at = ? WHERE action_id = ? AND state = 'COMPLETED'", [new Date().toISOString(), action.action_id]);
      rewound++;
    }
  }
  return rewound;
}
