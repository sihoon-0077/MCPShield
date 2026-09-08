import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir, availableParallelism } from "node:os";
import { join } from "node:path";
import ganache from "ganache";
import { Contract, JsonRpcProvider, NonceManager, Wallet, id } from "ethers";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { attestationV2Domain, attestationV2Types, bytes32, createReleaseRegistryV2, exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
import { v2RpcRequest } from "../../packages/contracts-sdk/src/transport.js";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { defaultPolicy, hash } from "../../apps/api/src/control-plane.js";
import { v2ChainReader } from "../../apps/api/src/registry-v2-client.js";
// @ts-expect-error Gateway is shared native ESM.
import { getSignedAdmission } from "../../apps/gateway/src/signed-admission.mjs";

export function latencySummary(samples: number[]) {
  assert.ok(samples.length && samples.every((n) => Number.isFinite(n) && n >= 0));
  const sorted = [...samples].sort((a, b) => a - b);
  const percentile = (p: number) => Number(sorted[Math.ceil(sorted.length * p) - 1].toFixed(3));
  return { samples: sorted.length, p50Ms: percentile(0.5), p95Ms: percentile(0.95), p99Ms: percentile(0.99), maxMs: percentile(1) };
}

// Integration measurement, not a production SLO: actual local EVM, SQL, HTTP and
// signature checks; only the stated outage conditions and scan reports are synthetic.
export async function measureAdmission({ requests = 40, concurrency = 4, identities = 4 } = {}) {
  for (const [value, max] of [[requests, 1000], [concurrency, 16], [identities, 16]]) assert.ok(Number.isInteger(value) && value >= 1 && value <= max, "bounded benchmark options required");
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 4 } });
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-admission-measure-"));
  let provider: JsonRpcProvider | undefined, app: Awaited<ReturnType<typeof buildApp>> | undefined, store: ControlStore | undefined;
  let reader: ReturnType<typeof v2ChainReader> | undefined;
  const started = new Date().toISOString(), gas: Record<string, number[]> = {};
  try {
    await chain.listen(0, "127.0.0.1");
    const rpc = `http://127.0.0.1:${chain.address().port}`;
    const keys = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
    const validators = keys.slice(1).map((key) => new Wallet(key.secretKey));
    const deployment = await deployV2(rpc, keys[0].secretKey, validators.map((wallet) => wallet.address), 1337);
    provider = new JsonRpcProvider(v2RpcRequest(rpc), undefined, { batchMaxCount: 1 });
    const signer = new NonceManager(new Wallet(keys[0].secretKey, provider));
    const registry = createReleaseRegistryV2(deployment.releaseRegistry.address, signer), policyHash = hash(defaultPolicy);
    const policy = new Contract(deployment.policyRegistry.address, ["function publish(bytes32,bytes32)"], signer);
    const mined = async (kind: string, transaction: any) => {
      const receipt = await (await transaction).wait(); assert.equal(receipt.status, 1);
      (gas[kind] ??= []).push(Number(receipt.gasUsed)); return receipt;
    };
    await mined("publishPolicy", policy.publish(policyHash, policyHash));
    const releases: Record<string, any>[] = [], payloads: Record<string, any>[] = [];
    const now = Number((await provider.getBlock("latest"))!.timestamp);
    store = await ControlStore.open(join(directory, "control.sqlite"));
    for (let index = 0; index < identities; index++) {
      const artifactDigest = `sha256:${id(`synthetic-artifact-${index}`).slice(2)}`;
      const release = { ...exactReleaseIdentity({ toolId: "benchmark:synthetic", artifactDigest, manifestDigest: id(`manifest-${index}`), toolSurfaceHash: id(`surface-${index}`) }),
        artifactDigest, manifestDigest: id(`manifest-${index}`), toolSurfaceHash: id(`surface-${index}`), status: "UNVERIFIED" };
      await mined("registerRelease", registry.registerRelease(release.toolId, bytes32(artifactDigest), release.manifestDigest, release.toolSurfaceHash));
      const payload = { releaseId: release.releaseId, artifactDigest: bytes32(artifactDigest), manifestDigest: release.manifestDigest,
        toolSurfaceDigest: release.toolSurfaceHash, policyHash, reportRoot: id(`SYNTHETIC_REPORT_NOT_SCANNER_${index}`), verdict: 0,
        validFrom: now - 1, validUntil: now + 3600, validatorSetVersion: 1, nonce: 0, deadline: now + 1800 };
      for (const validator of validators.slice(0, 2)) {
        payload.nonce = Number(await registry.nonces(validator.address));
        const signature = await validator.signTypedData(attestationV2Domain(1337, deployment.releaseRegistry.address), attestationV2Types, payload);
        await mined("passAttestation", registry.submitAttestation(payload, signature));
      }
      await store.put("benchmark", "release", release.releaseId, release); releases.push(release); payloads.push({ ...payload });
    }
    const key = generateKeyPairSync("ed25519"), token = randomUUID();
    reader = v2ChainReader({ rpcUrls: [rpc], registryContract: deployment.releaseRegistry.address, chainId: 1337, confirmations: 1 });
    let rpcFault = false;
    app = await buildApp({ adminApiToken: randomUUID(), scannerApiToken: randomUUID(), controlPlane: {
      store, credentials: [{ token, tenantId: "benchmark", role: "reader" }], artifactPath: directory, evidencePath: directory,
      evidenceKey: "a".repeat(64), signingKey: key.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), signingKeyId: "benchmark",
      chainDecision: async (release, policyDocument) => { if (rpcFault) throw Error("INJECTED_RPC_OUTAGE"); return reader!(release, policyDocument); },
    } });
    await app.listen({ host: "127.0.0.1", port: 0 });
    const base = { apiBaseUrl: `http://127.0.0.1:${(app.server.address() as any).port}`, timeoutMs: 5000, fetchImpl: fetch,
      publicKey: key.publicKey.export({ type: "spki", format: "pem" }).toString(), keyId: "benchmark", policyHash, chainId: 1337,
      registryContract: deployment.releaseRegistry.address, validatorSetVersion: 1, tenantId: "benchmark", apiToken: token, operationClass: "READ_PRIVATE" };
    const phases: Array<ReturnType<typeof latencySummary> & { name: string; elapsedMs: number; throughputQps: number; allowed: number; blocked: number; cacheHits: number }> = [];
    const measure = async (name: string, run: (index: number) => Promise<{ allowed: boolean; cacheHit?: boolean }>, expectedAllow: boolean) => {
      const latencies: number[] = []; let next = 0, allowed = 0, cacheHits = 0;
      const start = performance.now();
      await Promise.all(Array.from({ length: Math.min(concurrency, requests) }, async () => {
        while (next < requests) {
          const index = next++, begin = performance.now(), result = await run(index);
          latencies.push(performance.now() - begin); allowed += Number(result.allowed); cacheHits += Number(result.cacheHit === true);
          assert.equal(result.allowed, expectedAllow, `${name} decision mismatch`);
        }
      }));
      const elapsedMs = performance.now() - start;
      phases.push({ name, ...latencySummary(latencies), elapsedMs: Number(elapsedMs.toFixed(3)), throughputQps: Number((requests * 1000 / elapsedMs).toFixed(2)), allowed, blocked: requests - allowed, cacheHits });
    };
    const check = async (index: number, options: Record<string, any> = {}) => {
      try {
        const result = await getSignedAdmission({ ...base, identity: releases[index % identities], ...options });
        return { allowed: result.decision === "ALLOW", cacheHit: result.cacheHit };
      } catch { return { allowed: false, cacheHit: false }; }
    };
    await measure("actual_http_evm_strict_hot_key", () => check(0), true);
    await measure("actual_http_evm_strict_uniform_keys", (index) => check(index), true);
    for (let index = 0; index < identities; index++) assert.equal((await check(index)).allowed, true);
    // Explicit fast network-failure injection. Its latency is not a real TCP timeout measurement.
    const offline = async () => { throw new TypeError("INJECTED_API_OFFLINE"); };
    await measure("injected_api_offline_balanced_read_signed_cache", (index) => check(index, { admissionMode: "balanced", fetchImpl: offline }), true);
    await measure("injected_api_offline_strict_read", (index) => check(index, { fetchImpl: offline }), false);
    await measure("injected_api_offline_balanced_write", (index) => check(index, { admissionMode: "balanced", operationClass: "WRITE_EXTERNAL", fetchImpl: offline }), false);
    await measure("injected_api_offline_expired_signed_cache", (index) => check(index, { admissionMode: "balanced", fetchImpl: offline, now: () => Date.now() + 60000 }), false);
    rpcFault = true;
    await measure("actual_http_injected_rpc_failure", (index) => check(index, { admissionMode: "balanced" }), false);
    rpcFault = false;
    assert.equal((await check(0)).allowed, true);
    // Existing approvals cannot be replaced mid-round. Quarantine first, then
    // attest a genuinely newer scan round, exactly as the incident flow requires.
    const incidentAt = Number((await provider.getBlock("latest"))!.timestamp);
    const quarantiner = createReleaseRegistryV2(deployment.releaseRegistry.address, validators[0].connect(provider));
    await mined("quarantine", quarantiner.quarantine(releases[0].releaseId, policyHash, id("SYNTHETIC_INCIDENT"), id("CANARY_EXFILTRATION"), incidentAt + 600));
    await chain.provider.request({ method: "evm_increaseTime", params: [2] });
    await chain.provider.request({ method: "evm_mine", params: [] });
    const freshTime = Number((await chain.provider.request({ method: "eth_getBlockByNumber", params: ["latest", false] })).timestamp);
    let receipt;
    for (const validator of validators.slice(0, 2)) {
      const payload = { ...payloads[0], reportRoot: id("SYNTHETIC_REVOKE_REPORT"), verdict: 1, validFrom: freshTime, validUntil: freshTime + 3600, nonce: Number(await registry.nonces(validator.address)) };
      const signature = await validator.signTypedData(attestationV2Domain(1337, deployment.releaseRegistry.address), attestationV2Types, payload);
      receipt = await mined("failAttestation", registry.submitAttestation(payload, signature));
    }
    const propagationStart = performance.now(), blocked = await check(0);
    assert.equal(blocked.allowed, false);
    const propagationMs = performance.now() - propagationStart;
    assert.equal((await check(0, { admissionMode: "balanced", fetchImpl: offline })).allowed, false, "fresh revoke must invalidate older signed allow");
    return { status: "MEASURED", measuredAt: started, environment: { chain: "LOCAL_GANACHE_EVM", database: "SQLITE_WAL", http: "LOOPBACK", node: process.version, platform: process.platform, logicalProcessors: availableParallelism() },
      inputs: { requestsPerPhase: requests, concurrency, identities, confirmations: 1 }, phases,
      gas: Object.fromEntries(Object.entries(gas).map(([kind, values]) => [kind, { samples: values.length, min: Math.min(...values), max: Math.max(...values), mean: Math.round(values.reduce((a, b) => a + b, 0) / values.length) }])),
      revocation: { actualEvm: true, blockNumber: receipt!.blockNumber, receiptToNextCheckBlockedMs: Number(propagationMs.toFixed(3)), staleCacheResurrection: false },
      limitations: ["Synthetic scan reports; this benchmark does not measure scanner detection.", "Local single-host closed-loop measurements are not production load capacity or a Base Sepolia SLO.",
        "API and RPC outages are explicitly injected; separate transport tests cover slow/stalled networks.", "No proactive notification latency claim: revocation is measured at the next admission check.", "p99 from small samples is a smoke measurement; use larger repeated trials for capacity planning."] };
  } finally {
    reader?.close(); if (app) await app.close(); else if (store) await store.close();
    provider?.destroy(); await chain.close(); await rm(directory, { recursive: true, force: true });
  }
}
