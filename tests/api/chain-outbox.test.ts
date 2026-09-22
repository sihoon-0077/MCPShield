import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { chainActions, chainRetryBudget, enqueueChainAction, reconcileV2Actions, runChainActionOnce, type ChainRelayer } from "../../apps/api/src/chain-outbox.js";

// Queue fault injection only: these tests make no real-chain/finality claim.
function fixture() {
  const calls = { prepared: 0, broadcast: [] as string[], receipts: 0, applied: 0 };
  const relayer = { chainId: 1337, registryAddress: `0x${"1".repeat(40)}`, signer: { address: `0x${"2".repeat(40)}` },
    provider: { getTransactionCount: async () => 0, getTransactionReceipt: async (_hash: string): Promise<any> => { calls.receipts++; return null; },
      broadcastTransaction: async (raw: string) => { calls.broadcast.push(raw); } },
    alreadyApplied: async () => { calls.applied++; return false; },
    prepare: async () => { calls.prepared++; return { raw: "0x1234", txHash: `0x${"3".repeat(64)}` }; } };
  return { calls, relayer, client: relayer as unknown as ChainRelayer };
}
const due = (store: ControlStore, id: string) => store.query("UPDATE cp_chain_actions SET next_attempt_at = NULL WHERE action_id = ?", [id]);

async function transientFailures(databaseUrl?: string) {
  const store = await ControlStore.open(databaseUrl), f = fixture();
  f.relayer.alreadyApplied = async () => { f.calls.applied++; throw Error("provider URL or secret must not persist"); };
  try {
    const action = await enqueueChainAction(store, f.client, "team", "REGISTER_RELEASE", { releaseId: "synthetic-release" });
    await runChainActionOnce(store, f.client);
    const [first] = await chainActions(store, "team", action.actionId);
    assert.equal(first.attempts, 1); assert.equal(first.errorCode, "RPC_UNAVAILABLE");
    assert.ok(Date.parse(first.nextAttemptAt) > Date.now());
    assert.equal(await runChainActionOnce(store, f.client), false);
    for (let i = 1; i < chainRetryBudget.maxAttempts; i++) { await due(store, action.actionId); await runChainActionOnce(store, f.client); }
    const [dead] = await chainActions(store, "team", action.actionId);
    assert.equal(dead.status, "DEAD_LETTER"); assert.equal(dead.attempts, 12); assert.equal(dead.nextAttemptAt, null);
    assert.equal(dead.errorCode, "RPC_UNAVAILABLE"); assert.equal(await runChainActionOnce(store, f.client), false);
    assert.equal(f.calls.applied, 12); assert.equal(f.calls.prepared, 0);
    assert.deepEqual(await enqueueChainAction(store, f.client, "team", "REGISTER_RELEASE", { releaseId: "synthetic-release" }), dead);
    const events = await store.events("team");
    assert.equal(events.filter(event => event.eventName === "chain.action.dead_letter").length, 1);
    assert.equal(JSON.stringify(events).includes("provider URL or secret"), false);
    assert.deepEqual(await chainActions(store, "other-team"), []);
  } finally { await store.close(); }
}
test("chain transient failures have bounded attempts, durable backoff, tenant-visible reasons and idempotent DLQ", () => transientFailures());

test("a lost broadcast response reconciles its receipt without preparing or sending another transaction", async () => {
  const store = await ControlStore.open(), f = fixture();
  f.relayer.provider.broadcastTransaction = async raw => { f.calls.broadcast.push(raw); throw Error("response lost"); };
  try {
    const action = await enqueueChainAction(store, f.client, "team", "REGISTER_RELEASE", {});
    await runChainActionOnce(store, f.client);
    const [pending] = await store.query("SELECT * FROM cp_chain_actions WHERE action_id = ?", [action.actionId]);
    assert.equal(pending.state, "PREPARED"); assert.equal(pending.raw_tx, "0x1234"); assert.equal(pending.nonce, 0);
    f.relayer.provider.getTransactionReceipt = async () => ({ status: 1 });
    await due(store, action.actionId); await runChainActionOnce(store, f.client);
    const [done] = await chainActions(store, "team", action.actionId);
    assert.equal(done.status, "COMPLETED"); assert.equal(done.errorCode, null); assert.equal(done.nextAttemptAt, null);
    assert.equal(f.calls.prepared, 1); assert.deepEqual(f.calls.broadcast, ["0x1234"]);
  } finally { await store.close(); }
});

async function pendingReceipts(databaseUrl?: string) {
  const store = await ControlStore.open(databaseUrl), f = fixture();
  try {
    const action = await enqueueChainAction(store, f.client, "team", "REGISTER_RELEASE", {});
    assert.equal((await Promise.all([runChainActionOnce(store, f.client), runChainActionOnce(store, f.client)])).filter(Boolean).length, 1);
    assert.equal((await chainActions(store, "team", action.actionId))[0].status, "SUBMITTED");
    const other = { ...f.client, registryAddress: `0x${"4".repeat(40)}` };
    const next = await enqueueChainAction(store, other, "another-team", "REGISTER_RELEASE", {});
    assert.equal(await runChainActionOnce(store, other), false, "backoff cannot skip this account's nonce head");
    for (let i = 1; i < chainRetryBudget.maxAttempts; i++) { await due(store, action.actionId); await runChainActionOnce(store, f.client); }
    const [dead] = await store.query("SELECT * FROM cp_chain_actions WHERE action_id = ?", [action.actionId]);
    assert.equal(dead.state, "DEAD_LETTER"); assert.equal(dead.error_code, "CHAIN_RECEIPT_PENDING");
    assert.equal(dead.raw_tx, "0x1234"); assert.equal(dead.nonce, 0); assert.equal(f.calls.prepared, 1);
    assert.equal(f.calls.broadcast.length, 12); assert.ok(f.calls.broadcast.every(raw => raw === dead.raw_tx));
    assert.equal(await runChainActionOnce(store, other), false);
    assert.equal((await chainActions(store, "another-team", next.actionId))[0].attempts, 0);
  } finally { await store.close(); }
}
test("pending receipts stop at DLQ and retain signed bytes/nonce while pausing the account across registries", () => pendingReceipts());

test("crash exhaustion and elapsed budgets stop before RPC; malformed/rejected requests do not retry", async () => {
  const store = await ControlStore.open(), f = fixture();
  try {
    for (const expired of [false, true]) {
      const action = await enqueueChainAction(store, f.client, "team", "REGISTER_RELEASE", { expired });
      await store.query("UPDATE cp_chain_actions SET attempts = ?, retry_started_at = ?, lease_owner = 'lost-worker', lease_expires_at = ? WHERE action_id = ?",
        [expired ? 1 : chainRetryBudget.maxAttempts, new Date(Date.now() - (expired ? chainRetryBudget.maxElapsedMs + 1 : 1)).toISOString(), new Date(0).toISOString(), action.actionId]);
      await runChainActionOnce(store, f.client);
      assert.equal((await chainActions(store, "team", action.actionId))[0].status, "DEAD_LETTER");
    }
    assert.equal(f.calls.applied, 0);
    for (const malformed of [false, true]) {
      const action = await enqueueChainAction(store, f.client, "team", "REGISTER_RELEASE", { malformed });
      if (malformed) await store.query("UPDATE cp_chain_actions SET payload = '{' WHERE action_id = ?", [action.actionId]);
      else f.relayer.prepare = async () => { throw Object.assign(Error("no permission"), { code: "CALL_EXCEPTION" }); };
      await runChainActionOnce(store, f.client);
      const [row] = await store.query("SELECT * FROM cp_chain_actions WHERE action_id = ?", [action.actionId]);
      assert.equal(row.state, "FAILED"); assert.equal(row.error_code, "CHAIN_ACTION_REJECTED"); assert.equal(row.attempts, 1); assert.equal(row.nonce, null);
    }
  } finally { await store.close(); }
});

test("only a newly observed reorg starts a fresh bounded recovery cycle without discarding signed bytes", async () => {
  const store = await ControlStore.open(), f = fixture();
  try {
    const action = await enqueueChainAction(store, f.client, "team", "REGISTER_RELEASE", {});
    await store.query("UPDATE cp_chain_actions SET state = 'COMPLETED', raw_tx = '0x1234', tx_hash = ?, nonce = 0, attempts = 12, retry_started_at = ? WHERE action_id = ?",
      [`0x${"3".repeat(64)}`, new Date(0).toISOString(), action.actionId]);
    assert.equal(await reconcileV2Actions(store, f.client), 1);
    assert.equal(await reconcileV2Actions(store, f.client), 0);
    const [recovered] = await store.query("SELECT * FROM cp_chain_actions WHERE action_id = ?", [action.actionId]);
    assert.equal(recovered.attempts, 0); assert.equal(recovered.retry_started_at, null); assert.equal(recovered.raw_tx, "0x1234");
    f.relayer.provider.getTransactionReceipt = async () => ({ status: 1 });
    await runChainActionOnce(store, f.client);
    assert.equal((await chainActions(store, "team", action.actionId))[0].status, "COMPLETED");
    assert.equal(f.calls.prepared, 0); assert.equal(f.calls.broadcast.length, 0);
  } finally { await store.close(); }
});

test("legacy unowned unsigned rows do not starve known domains, but uncertain signed legacy rows require manual reconciliation", async () => {
  for (const signed of [false, true]) {
    const store = await ControlStore.open(), f = fixture();
    try {
      const legacy = await enqueueChainAction(store, f.client, "old-team", "REGISTER_RELEASE", { legacy: true });
      await store.query("UPDATE cp_chain_actions SET registry_address = NULL, raw_tx = ?, nonce = ?, created_at = ? WHERE action_id = ?",
        [signed ? "0x1234" : null, signed ? 0 : null, new Date(0).toISOString(), legacy.actionId]);
      const current = await enqueueChainAction(store, f.client, "team", "REGISTER_RELEASE", { current: true });
      f.relayer.alreadyApplied = async () => true;
      await runChainActionOnce(store, f.client);
      const [old] = await chainActions(store, "old-team", legacy.actionId), [next] = await chainActions(store, "team", current.actionId);
      if (signed) {
        assert.equal(old.status, "DEAD_LETTER"); assert.equal(old.errorCode, "CHAIN_REGISTRY_UNRESOLVED");
        assert.equal(next.status, "NEW"); assert.equal(next.attempts, 0);
        assert.equal(await runChainActionOnce(store, f.client), false);
        assert.equal(f.calls.receipts, 0); assert.equal(f.calls.broadcast.length, 0);
        assert.equal((await store.query("SELECT raw_tx FROM cp_chain_actions WHERE action_id = ?", [legacy.actionId]))[0].raw_tx, "0x1234");
      } else {
        assert.equal(old.status, "NEW"); assert.equal(old.attempts, 0); assert.equal(next.status, "COMPLETED");
      }
    } finally { await store.close(); }
  }
});

test("PostgreSQL outbox budgets, account lease/head, backoff and signed DLQ persist in native SQL", { skip: !process.env.MCPSHIELD_POSTGRES_TEST_URL }, async () => {
  const { Pool } = await import("pg"), pool = new Pool({ connectionString: process.env.MCPSHIELD_POSTGRES_TEST_URL });
  const schema = `mcpshield_outbox_${randomUUID().replace(/-/g, "")}`;
  assert.match(schema, /^mcpshield_outbox_[a-f0-9]{32}$/);
  try {
    await pool.query(`CREATE SCHEMA ${schema}`);
    const target = new URL(process.env.MCPSHIELD_POSTGRES_TEST_URL!); target.searchParams.set("options", `-csearch_path=${schema}`);
    await transientFailures(target.href);
    await pendingReceipts(target.href);
    const reopened = await ControlStore.open(target.href);
    try {
      assert.equal(reopened.driver, "POSTGRESQL");
      assert.equal((await reopened.query("SELECT attempts FROM cp_chain_actions WHERE state = 'DEAD_LETTER'")).filter(row => row.attempts === 12).length, 2);
      assert.equal(await runChainActionOnce(reopened, fixture().client), false, "reopen cannot restart signed DLQ work");
    } finally { await reopened.close(); }
  } finally {
    // Only this fresh, regex-validated test schema, never public or the shared database.
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await pool.end();
  }
});
